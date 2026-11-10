#!/usr/bin/env python3
"""Check your own exported ChatGPT cookies without disclosing response data.

Python >=3.10; install: python -m pip install 'curl_cffi==0.17.0'
Examples:
  python check.py --file ./cookies.json
  python check.py --directory ./cookies --workers 2 --report ./report.json
  python check.py --self-test

Only immediate *.json files in the explicit directory are inspected (no recursion
or symlink traversal). Supported exports: a cookie array or {"cookies": [...]}.
Exit codes: 0 all VALID; 1 at least one NO_SESSION; 2 CLI/input/dependency/report
error or ERROR result; 3 UNKNOWN (unless ERROR/NO_SESSION also occurs); 130 Ctrl+C.
An UNKNOWN result says nothing about cookie validity. The endpoint is internal.
"""

from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import os
from pathlib import Path
import re
import tempfile
import threading
import time

ENDPOINT = "https://chatgpt.com/api/auth/session"
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_COOLDOWN = 60.0
TRANSIENT_CODES = frozenset({5, 6, 7, 16, 18, 28, 52, 55, 56, 92})
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")


@dataclass(frozen=True)
class Result:
    filename: str
    status: str
    reason: str
    http_status: int | None = None


def safe_filename(path: Path) -> str:
    # Escape terminal controls, including bidi characters, without printing paths.
    return json.dumps(path.name, ensure_ascii=True)[1:-1]


class RateGate:
    """One shared, interruptible cooldown for all jobs in a batch."""

    def __init__(self, stop: threading.Event | None = None):
        self.stop = stop if stop is not None else threading.Event()
        self.lock = threading.Lock()
        self.until = 0.0

    def pause(self, header: str | None) -> None:
        delay = retry_after(header)
        with self.lock:
            self.until = max(self.until, time.monotonic() + delay)

    def ready(self) -> bool:
        while not self.stop.is_set():
            with self.lock:
                delay = self.until - time.monotonic()
            if delay <= 0:
                return True
            self.stop.wait(min(delay, 0.2))
        return False


def retry_after(value: str | None) -> float:
    """Honor seconds or HTTP-date, clamped to 1..60 seconds; default 5."""
    delay = 5.0
    if isinstance(value, str):
        try:
            if re.fullmatch(r"[0-9]+", value.strip()):
                # Avoid converting arbitrarily large integer headers.
                delay = float(value.strip()[:12])
            else:
                date = parsedate_to_datetime(value)
                if date.tzinfo is not None:
                    delay = date.timestamp() - time.time()
        except (ValueError, TypeError, OverflowError):
            pass
    return min(MAX_COOLDOWN, max(1.0, delay))


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate field")
        obj[key] = value
    return obj


def load_cookies(path: Path, now: float | None = None) -> list[dict]:
    """Validate the entire export before sending any nonexpired target cookies."""
    now = time.time() if now is None else now
    if path.is_symlink() or not path.is_file():
        raise ValueError("not a regular cookie file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("cookie file too large")
    data = json.loads(raw, object_pairs_hook=_unique_object)
    if isinstance(data, dict):
        data = data.get("cookies")
    if not isinstance(data, list) or len(data) > 3000:
        raise ValueError("invalid cookie array")
    accepted, seen = [], set()
    for cookie in data:
        if not isinstance(cookie, dict):
            raise ValueError("invalid cookie entry")
        name, value, domain = (cookie.get(key) for key in ("name", "value", "domain"))
        path_value = cookie.get("path", "/")
        if not isinstance(name, str) or not TOKEN.fullmatch(name):
            raise ValueError("invalid cookie name")
        if not isinstance(value, str) or any(
            ord(c) < 0x21 or ord(c) > 0x7e or c in '\",;\\' for c in value
        ):
            raise ValueError("invalid cookie value")
        if not isinstance(domain, str):
            raise ValueError("invalid cookie domain")
        normalized = domain.removeprefix(".").lower()
        if len(normalized) > 253 or not DOMAIN.fullmatch(normalized):
            raise ValueError("invalid cookie domain")
        if not isinstance(path_value, str) or not path_value.startswith("/") or any(
            ord(c) < 0x20 or ord(c) > 0x7e or c == ";" for c in path_value
        ):
            raise ValueError("invalid cookie path")
        expirations = []
        for key in ("expires", "expirationDate"):
            if key in cookie:
                expiry = cookie[key]
                if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
                    raise ValueError("invalid cookie expiration")
                try:
                    finite = math.isfinite(expiry)
                except OverflowError:
                    finite = False
                if not finite or expiry < -1:
                    raise ValueError("invalid cookie expiration")
                expirations.append(expiry)
        if len(set(expirations)) > 1:
            raise ValueError("conflicting cookie expirations")
        if expirations and expirations[0] != -1 and expirations[0] <= now:
            continue
        # A valid subdomain cookie is retained with its original scope; it is
        # never promoted to a parent domain by the checker.
        if normalized != "chatgpt.com" and not normalized.endswith(".chatgpt.com"):
            continue
        identity = (normalized, path_value, name)
        if identity in seen:
            raise ValueError("duplicate cookie identity")
        seen.add(identity)
        accepted.append({"name": name, "value": value,
                         "domain": ("." if domain.startswith(".") else "") + normalized,
                         "path": path_value,
                         "_expires": expirations[0] if expirations else -1})
    return accepted


def classify(response, filename: str) -> Result:
    status = response.status_code
    def result(state, reason):
        return Result(filename, state, reason, status)
    if status == 429:
        return result("UNKNOWN", "rate limited")
    if 300 <= status < 400:
        return result("UNKNOWN", "redirect received")
    if status in (401, 403):
        return result("UNKNOWN", "access denied; session undetermined")
    if status != 200:
        return result("UNKNOWN", "unexpected HTTP status")
    media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        return result("UNKNOWN", "non-JSON response")
    try:
        data = response.json()
    except (ValueError, TypeError, RecursionError):
        return result("UNKNOWN", "unreadable JSON response")
    if data == {}:
        return result("NO_SESSION", "empty session object")
    if not isinstance(data, dict):
        return result("UNKNOWN", "unrecognized session structure")
    user, token, expires = data.get("user"), data.get("accessToken"), data.get("expires")
    if not (isinstance(user, dict) and isinstance(user.get("id"), str)
            and user["id"].strip() and isinstance(token, str) and token.strip()
            and isinstance(expires, str)):
        return result("UNKNOWN", "unrecognized session structure")
    try:
        expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            raise ValueError
        expired = expiry <= datetime.now(timezone.utc)
    except (ValueError, OverflowError):
        return result("UNKNOWN", "unrecognized session expiration")
    if expired:
        return result("NO_SESSION", "session expiration passed")
    return result("VALID", "authenticated session structure confirmed")


def check_file(path: str | Path, *, gate: RateGate | None = None,
               timeout: float = 30.0, retries: int = 2) -> Result:
    """Return only sanitized metadata; one independent Session per invocation.

    Share a RateGate across concurrent calls. HTTP responses are never retried.
    Cancellation is cooperative; an in-flight request finishes within timeout.
    """
    path = Path(path)
    filename = safe_filename(path)
    gate = gate if gate is not None else RateGate()
    if (isinstance(timeout, bool) or not isinstance(timeout, (float, int))
            or not 0 < timeout <= 120 or isinstance(retries, bool)
            or not isinstance(retries, int) or not 0 <= retries <= 2):
        return Result(filename, "ERROR", "invalid checker options")
    try:
        cookies = load_cookies(path)
    except (OSError, ValueError, TypeError, RecursionError):
        return Result(filename, "ERROR", "invalid or unreadable cookie file")
    if not cookies:
        return Result(filename, "NO_SESSION", "no unexpired ChatGPT cookies")
    try:
        from curl_cffi import requests
        from curl_cffi.requests.exceptions import RequestException, Timeout
    except ImportError:
        return Result(filename, "ERROR", "curl_cffi dependency unavailable")
    try:
        with requests.Session(impersonate="chrome") as session:
            for attempt in range(retries + 1):
                if not gate.ready():
                    return Result(filename, "ERROR", "cancelled")
                # Cookies can expire while waiting for a shared cooldown or retry.
                live = [c for c in cookies if c["_expires"] == -1 or c["_expires"] > time.time()]
                if not live:
                    return Result(filename, "NO_SESSION", "no unexpired ChatGPT cookies")
                session.cookies.clear()
                for cookie in live:
                    session.cookies.set(**{k: v for k, v in cookie.items() if k != "_expires"})
                try:
                    response = session.get(ENDPOINT, headers={"Accept": "application/json"},
                                           timeout=timeout, allow_redirects=False)
                except RequestException as exc:
                    transient = isinstance(exc, Timeout) or exc.code in TRANSIENT_CODES
                    if transient and attempt < retries:
                        if gate.stop.wait(min(2 ** attempt, 4)):
                            return Result(filename, "ERROR", "cancelled")
                        continue
                    return Result(filename, "ERROR", "temporary network failure" if transient
                                  else "request failed; no retry")
                if response.status_code == 429:
                    gate.pause(response.headers.get("Retry-After"))
                return classify(response, filename)
    except Exception:
        # Exception messages can contain URLs, headers or response data.
        return Result(filename, "ERROR", "session operation failed")


def write_report(path: Path, results: list[Result], inputs: list[Path]) -> None:
    """Atomic private report; refuse overwriting an input or an existing file."""
    if path.resolve() in {item.resolve() for item in inputs} or path.exists() or path.is_symlink():
        raise ValueError("report destination already exists or is an input")
    fd, temporary = tempfile.mkstemp(prefix=".check-report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump([asdict(item) for item in results], handle, ensure_ascii=True, indent=2)
            handle.write("\n")
        # Link is atomic and fails if another process creates the destination.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path)
    source.add_argument("--directory", type=Path)
    source.add_argument("--self-test", action="store_true")
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=2)
    parser.add_argument("--timeout", type=float, default=30, help="seconds, >0 and <=120")
    parser.add_argument("--retries", type=int, choices=range(3), default=2)
    parser.add_argument("--report", type=Path, help="new JSON report file; never overwritten")
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 120:
        parser.error("timeout must be >0 and <=120")
    if args.self_test:
        return run_tests()
    try:
        if args.file:
            paths = [args.file]
            if args.file.suffix.lower() != ".json" or not args.file.is_file() or args.file.is_symlink():
                raise ValueError
        else:
            if args.directory.is_symlink() or not args.directory.is_dir():
                raise ValueError
            paths = sorted((p for p in args.directory.iterdir()
                            if p.suffix.lower() == ".json" and p.is_file() and not p.is_symlink()),
                           key=lambda p: p.name)
            if not paths:
                raise ValueError
        if args.report and (args.report.exists() or args.report.is_symlink()
                            or not args.report.parent.is_dir()
                            or args.report.resolve() in {p.resolve() for p in paths}):
            raise ValueError
    except (OSError, ValueError):
        print("ERROR: invalid input selection or report destination")
        return 2
    results, pending = [], {}
    gate = RateGate()
    pool = ThreadPoolExecutor(max_workers=args.workers)
    remaining = iter(paths)
    exhausted = False
    try:
        while pending or not exhausted:
            while not exhausted and len(pending) < args.workers:
                path = next(remaining, None)
                if path is None:
                    exhausted = True
                    break
                if not gate.ready():
                    break
                future = pool.submit(check_file, path, gate=gate,
                                     timeout=args.timeout, retries=args.retries)
                pending[future] = path
            if not pending:
                break
            done, _ = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in done:
                path = pending.pop(future)
                try:
                    result = future.result()
                except Exception:
                    result = Result(safe_filename(path), "ERROR", "worker failed")
                results.append(result)
                print(f"{result.filename}: {result.status} — {result.reason}", flush=True)
    except KeyboardInterrupt:
        gate.stop.set()
        for future in pending:
            future.cancel()
        print("Interrupted; pending work cancelled; finishing in-flight requests.")
        return 130
    finally:
        gate.stop.set()
        # No forced thread termination; each network request has a finite timeout.
        try:
            pool.shutdown(wait=True, cancel_futures=True)
        except KeyboardInterrupt:
            pass
    if args.report:
        try:
            write_report(args.report, sorted(results, key=lambda r: r.filename), paths)
        except (OSError, ValueError):
            print("ERROR: report could not be written")
            return 2
    states = {r.status for r in results}
    return 2 if "ERROR" in states else 1 if "NO_SESSION" in states else 3 if "UNKNOWN" in states else 0


def run_tests() -> int:
    """Offline regression tests, embedded to keep the deliverable one file."""
    import unittest
    from unittest.mock import Mock, patch

    class Tests(unittest.TestCase):
        def setUp(self):
            self.tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self.tmp.cleanup)
            self.path = Path(self.tmp.name) / "cookies.json"
            self.cookie = {"name": "session", "value": "private-value", "domain": ".chatgpt.com", "path": "/"}
            self.save([self.cookie])

        def save(self, data):
            self.path.write_text(json.dumps(data), encoding="utf-8")

        def response(self, data, status=200, content_type="application/json"):
            return Mock(status_code=status, headers={"Content-Type": content_type}, json=Mock(return_value=data))

        def test_exports_and_expiration(self):
            self.save({"cookies": [self.cookie, dict(self.cookie, name="old", expires=1),
                                   dict(self.cookie, name="other", domain="evilchatgpt.com")]})
            self.assertEqual(len(load_cookies(self.path)), 1)
            self.save([dict(self.cookie, expires=-1)])
            self.assertEqual(len(load_cookies(self.path)), 1)

        def test_invalid_fields(self):
            for change in ({"domain": "..chatgpt.com"}, {"domain": "chatgpt.com/"},
                           {"path": "relative"}, {"path": "/\n"}, {"expires": True},
                           {"expires": float("nan")}, {"expires": -2},
                           {"expires": 1, "expirationDate": 2}, {"value": "a\nb"}):
                with self.subTest(change=tuple(change)):
                    self.save([dict(self.cookie, **change)])
                    with self.assertRaises(ValueError):
                        load_cookies(self.path)

        def test_invalid_json_and_duplicates(self):
            for raw in ('{"cookies":[],"cookies":[]}', 'null', '{'):
                self.path.write_text(raw)
                self.assertEqual(check_file(self.path).status, "ERROR")
            self.save([self.cookie, self.cookie])
            self.assertEqual(check_file(self.path).status, "ERROR")

        def test_classification(self):
            valid = {"user": {"id": "test-id", "email": "secret@example.test"},
                     "accessToken": "private-token", "expires": "2999-01-01T00:00:00Z"}
            self.assertEqual(classify(self.response(valid), "x").status, "VALID")
            self.assertEqual(classify(self.response({}), "x").status, "NO_SESSION")
            valid["expires"] = "2000-01-01T00:00:00Z"
            self.assertEqual(classify(self.response(valid), "x").status, "NO_SESSION")
            for data in (None, [], {"user": {}}, {"error": "blocked"}, {"accessToken": "x"}):
                self.assertEqual(classify(self.response(data), "x").status, "UNKNOWN")
            for status in (302, 401, 403, 429, 500):
                self.assertEqual(classify(self.response({}, status), "x").status, "UNKNOWN")
            self.assertEqual(classify(self.response({}, content_type="text/html"), "x").status, "UNKNOWN")

        def test_retry_and_independent_session(self):
            from curl_cffi.requests.exceptions import Timeout, CertificateVerifyError
            with patch("curl_cffi.requests.Session") as factory:
                session = factory.return_value.__enter__.return_value
                session.get.side_effect = [Timeout("private", code=28), self.response({})]
                gate = RateGate()
                with patch.object(gate.stop, "wait", return_value=False):
                    self.assertEqual(check_file(self.path, gate=gate).status, "NO_SESSION")
                self.assertEqual(session.get.call_count, 2)
                self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
                session.get.reset_mock()
                session.get.side_effect = CertificateVerifyError("private", code=60)
                self.assertEqual(check_file(self.path).status, "ERROR")
                self.assertEqual(session.get.call_count, 1)
                self.assertEqual(factory.call_count, 2)

        def test_rate_limit_and_cancellation(self):
            self.assertEqual(retry_after("9999999999999999999"), 60)
            self.assertEqual(retry_after("bad"), 5)
            self.assertEqual(retry_after("Tue, 01 Jan 2030 00:00:00 GMT"), 60)
            gate = RateGate()
            with patch("curl_cffi.requests.Session") as factory:
                session = factory.return_value.__enter__.return_value
                response = self.response({}, 429)
                response.headers["Retry-After"] = "60"
                session.get.return_value = response
                self.assertEqual(check_file(self.path, gate=gate).status, "UNKNOWN")
                self.assertEqual(session.get.call_count, 1)
                self.assertGreater(gate.until, time.monotonic() + 59)
                gate.stop.set()
                self.assertFalse(gate.ready())
                self.assertEqual(check_file(self.path, gate=gate).reason, "cancelled")
                self.assertEqual(session.get.call_count, 1)

        def test_report_privacy_and_input_protection(self):
            report = self.path.parent / "report.json"
            result = classify(self.response({"user": {"id": "secret-id"},
                              "accessToken": "private-token", "expires": "2999-01-01T00:00:00Z"}), "cookies.json")
            write_report(report, [result], [self.path])
            text = report.read_text()
            self.assertNotIn("private-token", text)
            self.assertNotIn("secret-id", text)
            self.assertEqual(set(json.loads(text)[0]), {"filename", "status", "reason", "http_status"})
            with self.assertRaises(ValueError):
                write_report(self.path, [result], [self.path])

        def test_expired_cookies_never_make_requests(self):
            self.save([dict(self.cookie, expires=0)])
            with patch("curl_cffi.requests.Session") as factory:
                self.assertEqual(check_file(self.path).status, "NO_SESSION")
                factory.assert_not_called()

        def test_expiry_during_cooldown(self):
            self.save([dict(self.cookie, expires=time.time() + 30)])
            gate = RateGate()
            def ready():
                # Advance only the expiry comparison, without sleeping.
                clock.start()
                return True
            clock = patch("time.time", return_value=time.time() + 60)
            with patch("curl_cffi.requests.Session") as factory, patch.object(gate, "ready", side_effect=ready):
                try:
                    self.assertEqual(check_file(self.path, gate=gate).status, "NO_SESSION")
                    factory.return_value.__enter__.return_value.get.assert_not_called()
                finally:
                    clock.stop()

        def test_timeout_exhaustion_and_http_no_retry(self):
            from curl_cffi.requests.exceptions import Timeout
            with patch("curl_cffi.requests.Session") as factory:
                session = factory.return_value.__enter__.return_value
                session.get.side_effect = Timeout("never disclose this", code=28)
                gate = RateGate()
                with patch.object(gate.stop, "wait", return_value=False):
                    result = check_file(self.path, gate=gate)
                self.assertEqual(result.status, "ERROR")
                self.assertEqual(session.get.call_count, 3)
                self.assertNotIn("disclose", repr(result))
                session.get.reset_mock()
                session.get.side_effect = None
                session.get.return_value = self.response({}, 503)
                self.assertEqual(check_file(self.path).status, "UNKNOWN")
                self.assertEqual(session.get.call_count, 1)

        def test_cli_bounded_workers_and_report(self):
            import contextlib
            import io
            for i in range(6):
                (self.path.parent / f"{i}.json").write_text("[]")
            # Files below nested directories are deliberately not discovered.
            nested = self.path.parent / "nested"
            nested.mkdir()
            (nested / "ignored.json").write_text("[]")
            active, maximum, calls = 0, 0, []
            lock = threading.Lock()
            def check(path, **kwargs):
                nonlocal active, maximum
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                    calls.append(path.name)
                time.sleep(0.01)
                with lock:
                    active -= 1
                return Result(safe_filename(path), "VALID", "test")
            report = self.path.parent / "report.json"
            with patch(f"{__name__}.check_file", side_effect=check), contextlib.redirect_stdout(io.StringIO()):
                code = main(["--directory", str(self.path.parent), "--workers", "2", "--report", str(report)])
            self.assertEqual(code, 0)
            self.assertEqual(maximum, 2)
            self.assertEqual(len(calls), 7)
            self.assertEqual(len(json.loads(report.read_text())), 7)

        def test_scheduler_waits_after_429(self):
            import contextlib
            import io
            (self.path.parent / "second.json").write_text("[]")
            observed = []
            def check(path, *, gate, **kwargs):
                observed.append(time.monotonic())
                if len(observed) == 1:
                    # Shorten the cooldown only for this offline timing test.
                    with gate.lock:
                        gate.until = time.monotonic() + 0.05
                return Result(safe_filename(path), "UNKNOWN", "rate limited", 429)
            with patch(f"{__name__}.check_file", side_effect=check), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--directory", str(self.path.parent), "--workers", "1"]), 3)
            self.assertEqual(len(observed), 2)
            self.assertGreaterEqual(observed[1] - observed[0], 0.045)

        def test_cli_interrupt_and_bad_workers(self):
            import contextlib
            import io
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["--file", str(self.path), "--workers", "5"])
                self.assertEqual(raised.exception.code, 2)
            gates = []
            def check(path, *, gate, **kwargs):
                gates.append(gate)
                gate.stop.wait(1)
                return Result(safe_filename(path), "ERROR", "cancelled")
            with patch(f"{__name__}.check_file", side_effect=check), \
                    patch(f"{__name__}.wait", side_effect=KeyboardInterrupt), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--file", str(self.path)]), 130)
            self.assertTrue(all(gate.stop.is_set() for gate in gates))

        def test_last_rate_limit_does_not_delay_exit(self):
            import contextlib
            import io
            def check(path, *, gate, **kwargs):
                gate.pause("60")
                return Result(safe_filename(path), "UNKNOWN", "rate limited", 429)
            # A third readiness check would wait for the final, unnecessary cooldown.
            with patch(f"{__name__}.check_file", side_effect=check), \
                    patch.object(RateGate, "ready", side_effect=[True]) as ready, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--file", str(self.path), "--workers", "1"]), 3)
            self.assertEqual(ready.call_count, 1)

    outcome = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    return 0 if outcome.wasSuccessful() else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted.")
        raise SystemExit(130)
