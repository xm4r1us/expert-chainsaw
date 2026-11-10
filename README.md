# ChatGPT oturum kontrolü

Kendi hesabınıza ait JSON veya Netscape cookie dosyalarını kontrol eder. Cookie,
token, e-posta veya ham sunucu yanıtı kaydetmez. Yalnızca `VALID` sonuçların dosya
adı, durum, kısa neden ve HTTP kodu raporlanır. `UNKNOWN`, geçersiz cookie demek
değildir. Worker sayısı varsayılan 2, en fazla 4'tür.

## Worker ayarları

`.env.example` dosyasını `check.py` veya `.exe` ile aynı klasöre `.env` adıyla
kopyalayın. Değişiklikler uygulama yeniden açıldığında okunur:

```dotenv
MAX_WORKERS=4
WORKERS=2
```

`MAX_WORKERS` izin verilen üst sınır, `WORKERS` varsayılan sayıdır.
`1 <= WORKERS <= MAX_WORKERS <= 4` olmalıdır. Yalnızca `MAX_WORKERS=1` verilirse
varsayılan sayı da 1 olur. İşlem ortam değişkenleri `.env` değerlerinden önce
gelir. CLI'daki `--workers`, varsayılanı değiştirir ancak üst sınırı aşamaz.
Tkinter seçicisi de aynı sınırı kullanır. Başka `.env` anahtarları yüklenmez;
dosya içeriği komut olarak çalıştırılmaz veya loglanmaz.

## Windows uygulaması

GitHub'da **Actions → Windows executable** bölümünden başarılı çalışmayı açın.
**Artifacts → ChatGPTCookieCheck-windows-x64** paketini indirip ZIP'i açın ve
`ChatGPTCookieCheck.exe` dosyasını çalıştırın. GitHub oturumu gerekebilir.
Uygulama Python kurulumu gerektirmez. Derleme `main` güncellemelerinde otomatik
çalışır; **Run workflow** ile elle de başlatılabilir.

Arayüzde dosya veya klasör seçin, gerekirse rapor yolunu değiştirin ve
**Kontrol et** düğmesine basın. Alt klasörler taranmaz. **Durdur**, yeni işleri
iptal eder; devam eden isteklerin zaman aşımı en fazla 30 saniyedir. Kapatma
sırasında da devam eden isteklerin tamamlanması beklenir.

Varsayılan rapor `valid/results.json`, uygulama başlatılırken kullanılan çalışma
klasörüne göre belirlenir ve arayüzde gösterilir. Var olan raporun üzerine
yazılmaz; sonraki kontrol için yeni bir rapor yolu seçin. `VALID` yoksa veya işlem
durdurulursa rapor oluşturulmaz. Sonuç listesi yalnızca uygulama belleğinde kalır.

## Python ile kullanım

Python 3.10 veya üzeri ve Tkinter gerekir (Windows Python kurulumunda bulunur;
Linux'ta dağıtımınızın `python3-tk` paketi gerekebilir).

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install "curl_cffi==0.17.0"
python check.py --gui
```

CLI kullanımı korunmuştur:

```bash
python check.py --file sa.txt
python check.py --directory ./cookies --workers 2 --report valid/ikinci.json
python check.py --self-test
```

Testler çevrimdışıdır; gerçek hesap cookie'si kullanmaz. Actions, kaynak testlerine
ek olarak paketlenmiş `.exe` üzerinde de `--self-test` çalıştırır. Çıkış kodları:
`0` tüm sonuçlar VALID, `1` NO_SESSION, `2` hata, `3` UNKNOWN, `130` Ctrl+C.
Karma sonuçlarda öncelik `2 > 1 > 3 > 0` olur.
