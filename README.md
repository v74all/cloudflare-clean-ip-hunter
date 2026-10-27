# cloudflare-clean-ip-hunter

پیدا کردن آی‌پی‌هایی از کلودفلر که روی اینترنت خودت (همون اپراتوری که باهاش وصل میشی) بهتر جواب میدن، برای کانفیگ‌هایی که پشت کلودفلر هستن.
English version: [below](#english)

آموزش ویدیویی (فارسی): کانال یوتیوب [@V7lthronyx](https://www.youtube.com/@V7lthronyx)

## آی‌پی تمیز یعنی چی

وقتی کانفیگت پشت کلودفلره (دامنه‌ات با ابر نارنجی، ترنسپورت ws یا xhttp یا grpc یا httpupgrade)، کلاینتت لازم نیست حتماً به همون آی‌پی‌ای وصل بشه که DNS میده. هر آی‌پی از شبکه‌ی کلودفلر سایت تو رو هم سرو می‌کنه، چون همه‌ی سرورهای لبه‌ی کلودفلر همه‌ی دامنه‌هاش رو می‌شناسن (anycast).

اپراتورها بعضی وقت‌ها بعضی از این آی‌پی‌ها یا رنج‌ها رو کند می‌کنن یا می‌بندن. «آی‌پی تمیز» یعنی آی‌پی‌ای که همین الان، روی اینترنت تو، خوب جواب میده. این برای هر اپراتور و هر ساعت فرق داره؛ واسه همین باید خودت از روی شبکه‌ی خودت اسکن کنی.

این ابزار برای کانفیگ REALITY، یا هر کانفیگی که مستقیم به آی‌پی سرور خودت وصل میشه، به درد نمی‌خوره. REALITY مستقیم با سرورت حرف می‌زنه و پشت کلودفلر نمیره؛ اگه لینک REALITY بدی، اسکنر همینو بهت میگه.

## چی کار می‌کنه

برای هر آی‌پی همون کاری رو می‌کنه که کلاینتت می‌کنه:

1. اتصال TCP به پورت ۴۴۳ (یا پورت کانفیگت) و اندازه‌گیری زمانش (پینگ)
2. دست‌دادن TLS با دامنه‌ی خودت به‌عنوان SNI، با چک کردن گواهی
3. درخواست `/cdn-cgi/trace` با Host دامنه‌ی خودت. این آدرس رو فقط خود کلودفلر جواب میده و اسم دیتاسنتری که جواب داده (`colo`، مثلاً `FRA` یا `IST`) توشه. پس آی‌پی‌ای که از این مرحله رد بشه واقعاً لبه‌ی کلودفلره و سایت تو رو سرو می‌کنه، نه یه صفحه‌ی مسدودی یا یه سرور دیگه.

آی‌پی‌های سالم چند بار دیگه تست میشن (پیش‌فرض در کل ۴ بار، هر بار با اتصال تازه) و به ترتیب درصد از دست رفتن (loss)، پینگ و نوسان (jitter) مرتب میشن.

- با `--speed` روی بهترین‌ها تست دانلود هم انجام میده.
- با `--link` لینک کانفیگت رو می‌گیره، دامنه و پورت و TLS رو از خودش برمی‌داره، و همون لینک رو با بهترین آی‌پی‌ها برمی‌گردونه. SNI و Host روی دامنه‌ی خودت می‌مونن تا کانفیگ خراب نشه.

فقط یه فایل پایتون، بدون هیچ کتابخونه‌ی اضافه (پایتون ۳.۸ یا جدیدتر). تست‌شده روی Ubuntu 24.04 (پایتون 3.12)، Debian 12 (پایتون 3.11)، پایتون 3.8 و 3.14. روی ویندوز و Termux هم از همون کتابخونه‌ی استاندارد پایتون استفاده می‌کنه.

## قبل از اسکن: فیلترشکن رو خاموش کن

اسکن باید از روی همون اینترنتی باشه که کانفیگ رو باهاش استفاده می‌کنی (دیتای گوشی، وای‌فای خونه). اگه فیلترشکن یا WARP روشن باشه، داری مسیر سرور فیلترشکن رو تست می‌کنی، نه اپراتور خودت رو. اسکنر از جواب کلودفلر می‌فهمه اتصالت از کدوم کشور دیده میشه؛ اگه ایران نباشه یا WARP روشن باشه بهت هشدار میده.

## دانلود و اجرا

### اندروید (Termux)

Termux رو از F-Droid یا گیت‌هاب خودش نصب کن (نسخه‌ی گوگل‌پلی قدیمیه). بعد:

```bash
pkg install python
curl -fsSLO https://github.com/v74all/cloudflare-clean-ip-hunter/releases/latest/download/scanner.py
python scanner.py -d your.domain.com
```

### ویندوز

پایتون رو از [python.org](https://www.python.org/downloads/) نصب کن (موقع نصب تیک `Add python.exe to PATH` رو بزن). فایل `scanner.py` رو از بخش [Releases](https://github.com/v74all/cloudflare-clean-ip-hunter/releases/latest) دانلود کن، توی همون پوشه CMD یا PowerShell باز کن و بزن:

```
py scanner.py -d your.domain.com
```

### لینوکس و مک

```bash
curl -fsSLO https://github.com/v74all/cloudflare-clean-ip-hunter/releases/latest/download/scanner.py
curl -fsSLO https://github.com/v74all/cloudflare-clean-ip-hunter/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS       # مک: shasum -a 256 -c SHA256SUMS
python3 scanner.py -d your.domain.com
```

## استفاده

```bash
python3 scanner.py -d your.domain.com                    # ۲۰۰ آی‌پی تصادفی از رنج‌های رسمی کلودفلر
python3 scanner.py --link 'vless://...'                  # دامنه رو از لینکت برمی‌داره، لینک رو با بهترین آی‌پی‌ها میده
python3 scanner.py -d your.domain.com --speed            # تست دانلود روی ۵ آی‌پی برتر، هر کدوم ۵ مگابایت
python3 scanner.py -d your.domain.com -n 500             # آی‌پی بیشتر
python3 scanner.py -d your.domain.com -r my_ips.txt      # فقط آی‌پی‌ها یا رنج‌های خودت (مثلاً خروجی دفعه‌ی قبل)
python3 scanner.py -d your.domain.com --no-tls -p 8080   # کانفیگ بدون TLS روی پورت‌های http
python3 scanner.py --link 'vless://...' -q               # فقط لینک‌های آماده رو چاپ کن (برای کپی)
```

- لینک رو توی لینوکس، مک و Termux بین `'` بذار؛ توی CMD ویندوز بین `"`.
- `your.domain.com` رو با دامنه‌ی کانفیگ خودت عوض کن. اگه ندی، با `speed.cloudflare.com` تست می‌کنه؛ ولی فیلترینگ می‌تونه با هر SNI جور دیگه‌ای رفتار کنه، پس نتیجه‌ی واقعی با دامنه‌ی خودته.

خروجی:

| ستون | معنی |
|---|---|
| PING | میانه‌ی زمان اتصال TCP (تقریباً همون پینگ) |
| JITTER | نوسان پینگ بین تست‌ها |
| LOSS | درصد درخواست‌هایی که جواب نگرفتن |
| COLO | کد دیتاسنتر کلودفلر که جواب داده |
| SPEED | سرعت دانلود (فقط با `--speed`) |

همه‌ی آی‌پی‌های سالم توی `results.csv` ذخیره میشن، و با `--link` لینک‌های آماده توی `links.txt`. خروجی باریکه تا روی صفحه‌ی گوشی (Termux) هم نشکنه.

| گزینه | پیش‌فرض | کار |
|---|---|---|
| `-d`, `--domain` | `speed.cloudflare.com` | دامنه‌ی کانفیگت (SNI و Host) |
| `--link` | | لینک vless، trojan یا vmess؛ دامنه، پورت و TLS از خودش خونده میشه |
| `-p`, `--port` | ۴۴۳ یا پورت لینک | پورت |
| `--no-tls` | | http ساده (پورت‌های 80، 8080، 8880، 2052، 2082، 2086، 2095) |
| `-n`, `--count` | 200 | تعداد آی‌پی تصادفی (از هر بلوک ‎/24 حداکثر یکی) |
| `-r`, `--ranges` | لیست رسمی کلودفلر | فایل رنج‌ها و آی‌پی‌ها (نمونه: `cidr_ranges.txt`) |
| `--ip` | | فقط این آی‌پی (می‌شه چند بار داد) |
| `-w`, `--workers` | 32 | چند آی‌پی همزمان |
| `-t`, `--timeout` | 2.5 | ثانیه برای هر مرحله |
| `--rounds` | 4 | تعداد تست برای هر آی‌پی سالم |
| `--top` | 10 | چند تا نشون داده بشه |
| `--speed` | | تست دانلود |
| `--speed-top`, `--speed-mb` | 5، 5 | روی چند آی‌پی و هر کدوم چند مگابایت |
| `--speed-url` | `speed.cloudflare.com/__down` | فایلی که دانلود میشه (اگه این آدرس روی شبکه‌ات بسته‌ست، یه فایل روی دامنه‌ی خودت بده) |
| `--links` | 3 | با `--link`: چند لینک ساخته بشه |
| `-o`, `--output` | `results.csv` | فایل CSV (`''` یعنی ذخیره نکن) |
| `-q`, `--quiet` | | فقط نتیجه: با `--link` لینک‌ها، وگرنه بهترین آی‌پی‌ها هر کدوم توی یه خط |

## گذاشتن آی‌پی توی کلاینت

توی v2rayNG، v2rayN، Hiddify یا NekoBox فقط **Address** رو آی‌پی تمیز بذار. **SNI** و **Host** (یا Request host) باید دامنه‌ی خودت بمونن؛ اگه خالی بودن، دامنه‌ات رو توشون بنویس. اگه SNI خالی بمونه، کلاینت آی‌پی رو به‌جای دامنه می‌فرسته و کلودفلر نمی‌دونه سایت کیه.

راه ساده‌تر: لینک‌هایی که `--link` ساخته رو import کن. اون‌ها همین کار رو انجام دادن.

## چیزهایی که باید بدونی

- پینگ به فاصله بستگی داره. کلودفلر توی ایران دیتاسنتر نداره، پس جواب از نزدیک‌ترین دیتاسنتر خارج میاد (ستون COLO) و هیچ ابزاری پینگ رو از اون فاصله کمتر نمی‌کنه. اگه کسی از ایران «پینگ زیر ۲۰ میلی‌ثانیه» نشونت داد، عددش واقعی نیست.
- آی‌پی‌ای که امروز تمیزه ممکنه فردا کند بشه. هر وقت کند شد دوباره اسکن کن.
- اثر انگشت TLS پایتون با کلاینتت (مثلاً Xray با `fp=chrome`) یکی نیست. اسکن آی‌پی‌های امیدوارکننده رو پیدا می‌کنه؛ تست آخر، وصل شدن با خود کلاینتته.
- همه‌ی آی‌پی‌های رنج‌های کلودفلر سایت مشتری‌ها رو سرو نمی‌کنن؛ برای همین بخشی از آی‌پی‌ها همیشه timeout میدن. طبیعیه.
- اسکن سبکه: برای هر آی‌پی چند درخواست HTTPS معمولی به سرورهای خود کلودفلر. توی حلقه‌ی بی‌نهایت اجراش نکن.

## تست

```bash
python3 -m unittest discover -s tests
```

تست‌ها اینترنت لازم ندارن: یه سرور TLS محلی که مثل لبه‌ی کلودفلر جواب میده، کل مسیر اسکن و تست سرعت و ساختن لینک رو تست می‌کنه.

## لایسنس

MIT

---

<a name="english"></a>
## English

Find Cloudflare edge IPs that work well **from your own network**, for proxy configs that sit behind the Cloudflare CDN (ws, xhttp, grpc or httpupgrade, with TLS or on the plain-http ports). Any Cloudflare edge IP serves any proxied hostname (anycast), so the client can connect to whichever edge IP your ISP treats best, while SNI and Host stay your domain. It is useless for REALITY or any config that connects straight to your own server; the scanner says so if you give it a REALITY link.

**Turn your VPN off before scanning**: the result must describe your ISP's path. The scanner reads the country Cloudflare sees and warns when it isn't Iran or when WARP is on.

What it checks on every IP, exactly like a client would: a TCP connect (timed: the ping), a TLS handshake with your domain as SNI and the certificate verified, then `GET /cdn-cgi/trace` with your domain as Host. Only Cloudflare answers that path, and the answer names the datacenter (`colo`). IPs that pass get more rounds on fresh connections and are ranked by loss, ping and jitter. `--speed` adds a download test on the best ones; `--link` takes domain, port and TLS from your `vless://`, `trojan://` or `vmess://` link and prints it back with the best IPs (SNI and Host pinned to your domain).

One file, Python 3.8+ standard library only. Tested on Ubuntu 24.04 (Python 3.12), Debian 12 (3.11), Python 3.8 and 3.14.

```bash
curl -fsSLO https://github.com/v74all/cloudflare-clean-ip-hunter/releases/latest/download/scanner.py
python3 scanner.py -d your.domain.com
python3 scanner.py --link 'vless://...' --speed
python3 scanner.py --link 'vless://...' -q        # only the ready links
```

Windows: install Python from python.org, then `py scanner.py -d your.domain.com`. Android: Termux, `pkg install python`.

Notes: ping is bound by distance (there is no Cloudflare datacenter in Iran, so nothing gets you near-zero latency from there); a clean IP today may be slow tomorrow, so scan again; Python's TLS fingerprint differs from your client's, so the final test is connecting with your client; part of Cloudflare's ranges never serve customer sites, so timeouts on a share of the sample are normal. The scan is light (a few ordinary HTTPS requests per IP to Cloudflare's own edge); don't run it in a loop.

Tests (no network needed): `python3 -m unittest discover -s tests`

License: MIT
