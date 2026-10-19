# Cloudflare Clean IP Hunter

[English](#english) | [فارسی](#persian)

High-performance, multi-threaded Cloudflare Anycast clean IP scanner and latency benchmarker. Designed to discover unthrottled edge IP addresses with sub-20ms RTT and minimal jitter across censored ISPs.

---

<a name="english"></a>
## English Documentation

### Overview
National firewalls and DPI appliances selectively drop packets and throttle standard Cloudflare Anycast IP ranges to cripple proxy connections. By decoupling the physical connection endpoint from the TLS SNI domain header, this scanner probes Cloudflare edge subnets directly on port 443 with TLS 1.3 handshakes to harvest clean, unthrottled nodes.

### Features
- Multi-threaded concurrent TCP connect & TLS 1.3 socket probing
- Real-time RTT latency measurement in milliseconds
- Direct CIDR subnet random sampling
- Zero external dependencies (pure Python 3 standard library: `socket`, `ssl`, `concurrent.futures`)
- Automatic sorting and clean node export
- Ready-to-use Sing-box and Xray outbound templates

### Subnets Scanned
- `104.16.0.0/13`
- `104.24.0.0/14`
- `172.64.0.0/13`
- `162.158.0.0/15`
- `198.41.128.0/17`
- `188.114.96.0/20`
- `162.159.0.0/16`

### Requirements
- Python 3.8+
- No third-party packages required

### Quick Start
1. Clone the repository:
```bash
git clone git@github.com:v74all/cloudflare-clean-ip-hunter.git
cd cloudflare-clean-ip-hunter
```

2. Run the scanner:
```bash
python3 scanner.py
```

3. Custom scan options:
```bash
python3 scanner.py -c cidr_ranges.txt -s 20 -w 48 -t 1.2 -o clean_ips.txt
```

#### Arguments
- `-c, --cidr`: Path to CIDR subnet list (default: `cidr_ranges.txt`)
- `-s, --samples`: Number of random IP candidates sampled per subnet block (default: `12`)
- `-w, --workers`: Concurrent thread count (default: `32`)
- `-t, --timeout`: Connection timeout in seconds (default: `1.5`)
- `-o, --output`: Output file for ranked clean IPs (default: `clean_ips.txt`)
- `--sni`: Target SNI hostname for TLS handshake validation (default: `cloudflare.com`)
- `--port`: Destination port (default: `443`)

### Client Integration (Sing-box)
In your Sing-box configuration outbound object, inject the discovered clean IP into `server`, while keeping your camouflage domain in `tls.server_name`:

```json
{
  "type": "vless",
  "tag": "vless-clean-ip",
  "server": "104.17.48.21",
  "server_port": 443,
  "uuid": "YOUR_UUID_HERE",
  "tls": {
    "enabled": true,
    "server_name": "YOUR_SNI_DOMAIN.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
```

---

<a name="persian"></a>
## راهنمای فارسی

### معرفی ابزار
سیستم فیلترینگ با اعمال اختلال عمدی و تزریق پکت‌لاس روی رنج‌های Anycast پیش‌فرض کلودفلر، سرعت کانکشن‌های فیلترشکن را به شدت کاهش می‌دهد. این اسکنر سبک و پرسرعت، مستقیماً ساب‌نت‌های رسمی کلودفلر را با ایجاد هندشیک امن TLS 1.3 روی پورت ۴۴۳ بررسی کرده و آی‌پی‌های بدون اختلال (Clean IP) با کمترین تاخیر (پینگ زیر ۲۰ میلی‌ثانیه) را برای همراه اول، ایرانسل و مخابرات شناسایی می‌کند.

### قابلیت‌ها
- اسکن چندنخی (Multi-threaded) فوق‌العاده سریع بدون اشغال منابع
- اندازه‌گیری دقیق تاخیر RTT به میلی‌ثانیه بر مبنای برقراری کامل هندشیک TLS 1.3
- نمونه‌برداری هوشمند از ساب‌نت‌های Anycast بدون نیاز به اسکن دستی هزاران آی‌پی
- بدون نیاز به نصب هیچ پیش‌نیاز یا کتابخانه اضافی (استفاده از کتابخانه استاندارد پایتون)
- استخراج و رتبه‌بندی آی‌پی‌ها از کمترین پینگ به بیشترین
- سازگاری کامل با کلاینت‌های Sing-box، v2rayN، Nekobox و Clash

### نحوه اجرا
۱. دریافت مخزن:
```bash
git clone git@github.com:v74all/cloudflare-clean-ip-hunter.git
cd cloudflare-clean-ip-hunter
```

۲. اجرای اسکن:
```bash
python3 scanner.py
```

۳. اجرای اختصاصی با تنظیم تعداد نخ‌ها و خروجی:
```bash
python3 scanner.py -s 15 -w 40 -t 1.2 -o clean_ips.txt
```

### نحوه استفاده در کلاینت‌ها
کافیست در کانفیگ خود (مانند Sing-box یا v2rayN):
- مقدار `server` یا `Address` را برابر با آی‌پی تمیز کشف‌شده قرار دهید.
- مقدار `server_name` یا `SNI` را روی دامنه مبدا/استتار خود نگه دارید.

---

### کانال‌های ارتباطی
- **YouTube**: [V7lthronyx](https://youtube.com/@V7lthronyx)
- **Telegram**: [@V7LTHRONYX](https://t.me/V7LTHRONYX)
- **GitHub**: [v74all](https://github.com/v74all)

### لایسنس
MIT License - توسعه داده شده توسط V7lthronyx (Aiden Azad).
