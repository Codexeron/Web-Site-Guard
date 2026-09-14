# 🛡️ Web Site Guard

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-336791)

> **Çok katmanlı, açık kaynaklı web sitesi koruma sistemi.** Python + FastAPI + PostgreSQL ile geliştirilmiş, WAF, DDoS koruması, bot engelleme, brute force koruması, CSRF, XSS, SQLi ve daha fazlasını tek çatı altında sunar.

---

## 📖 İçindekiler

- [Özellikler](#-özellikler)
- [Koruma Türleri](#-koruma-türleri)
- [Mimari](#-mimari)
- [Kurulum](#-kurulum)
- [Yapılandırma](#-yapılandırma)
- [Veritabanı Şeması](#-veritabanı-şeması)
- [Kullanım](#-kullanım)
- [API Endpoint'leri](#-api-endpointleri)
- [Test](#-test)
- [Katkıda Bulunma](#-katkıda-bulunma)
- [Lisans](#-lisans)

---

## ✨ Özellikler

- 🧱 **16 Katmanlı Koruma** – WAF'tan honeypot'a kadar tüm güvenlik katmanları
- ⚡ **Asenkron Mimari** – FastAPI + asyncpg ile yüksek performans
- 🗄️ **PostgreSQL Tabanlı** – Tüm olaylar, kurallar ve loglar merkezi veritabanında
- 🔧 **Kolay Yapılandırma** – Ortam değişkenleri + DB tabanlı ayarlar
- 📊 **Detaylı Loglama** – Request, threat ve audit logları
- 🚫 **Otomatik IP Engelleme** – Şüpheli davranışlarda otomatik blacklist
- 🌍 **Geo-Blocking** – Ülke bazlı erişim kontrolü
- 🍯 **Honeypot Tuzakları** – Botları yakalamak için sahte endpoint'ler
- 🔐 **Güvenlik Header'ları** – CSP, HSTS, X-Frame-Options otomatik eklenir

---

## 🛡️ Koruma Türleri

| # | Koruma | Açıklama | Dosya |
|---|--------|----------|-------|
| 1 | DDoS / Rate Limiting | IP başına istek sınırı | `rate_limiter.py` |
| 2 | SQL Injection | Zararlı SQL kalıpları tespiti | `waf.py` |
| 3 | XSS | Script enjeksiyonunu engelleme | `waf.py` |
| 4 | CSRF | Token doğrulama | `csrf.py` |
| 5 | WAF | İmza + anomali tabanlı firewall | `waf.py` |
| 6 | Bot Engelleme | User-Agent & davranış analizi | `bot_guard.py` |
| 7 | Brute Force | Login denemelerini sınırlama | `bruteforce.py` |
| 8 | IP Black/White List | Kara/beyaz liste yönetimi | `ip_manager.py` |
| 9 | Geo-Blocking | Ülke bazlı engelleme | `geo_guard.py` |
| 10 | Dosya Yükleme | MIME, uzantı, boyut kontrolü | `upload_scanner.py` |
| 11 | Header Güvenliği | CSP, HSTS, X-Frame-Options | `headers_guard.py` |
| 12 | SSL/TLS İzleme | Sertifika süresi & zayıf şifre | `ssl_monitor.py` |
| 13 | Log & Audit | Tüm olayların kaydı | PostgreSQL |
| 14 | Anomali Tespiti | Davranış analizi | `anomaly.py` |
| 15 | Honeypot | Tuzak endpoint'ler | `main.py` |
| 16 | Malware Taraması | Yüklenen içerik taraması | `upload_scanner.py` |

---

## 🏗️ Mimari

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP
       ▼
┌─────────────────────────────────────────┐
│         FastAPI Middleware              │
│  ┌───────────────────────────────────┐  │
│  │  1. Whitelist Check               │  │
│  │  2. Blacklist Check               │  │
│  │  3. Rate Limiting                 │  │
│  │  4. Bot Detection                 │  │
│  │  5. WAF Scan (SQLi/XSS/LFI/RCE)   │  │
│  │  6. Brute Force Check             │  │
│  │  7. CSRF Validation               │  │
│  │  8. Geo Blocking                  │  │
│  └───────────────────────────────────┘  │
└──────────────┬──────────────────────────┘
               │
               ▼
       ┌───────────────┐
       │  Application  │
       └───────┬───────┘
               │
               ▼
       ┌───────────────┐
       │  PostgreSQL   │
       └───────────────┘
```

---

## 🚀 Kurulum

### Gereksinimler

- Python **3.10+**
- PostgreSQL **14+**
- (Opsiyonel) Redis **6+** – rate-limit hızlandırma için
- (Opsiyonel) Nginx – reverse proxy olarak

### 1. Depoyu Klonlayın

```bash
git clone https://github.com/kullanici/webshield.git
cd webshield
```

### 2. Sanal Ortam Oluşturun

```bash
python -m venv venv
source venv/bin/activate     # Linux/macOS
# venv\Scripts\activate      # Windows
```

### 3. Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

### 4. Veritabanını Hazırlayın

```bash
createdb webshield
psql webshield -f schema.sql
```

### 5. Ortam Değişkenlerini Ayarlayın

```bash
cp .env.example .env
# .env dosyasını düzenleyin
```

### 6. Uygulamayı Başlatın

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## ⚙️ Yapılandırma

### Ortam Değişkenleri (`.env`)

```env
# Veritabanı
DB_HOST=localhost
DB_PORT=5432
DB_NAME=webshield
DB_USER=postgres
DB_PASS=postgres

# Rate Limiting
RATE_LIMIT_PER_MIN=120
RATE_LIMIT_PER_HOUR=3000

# Brute Force
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_MINUTES=30

# CSRF
CSRF_EXPIRE_MIN=30

# Otomatik IP Engelleme
BLOCK_DURATION_MIN=60

# Güvenilen Proxy'ler
TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
```

### Ayarlar (`settings` tablosu)

```json
{
  "rate_limit":      { "per_minute": 120, "per_hour": 3000 },
  "bruteforce":      { "max_attempts": 5, "lock_minutes": 30 },
  "bot_protection":  { "enabled": true, "challenge": true }
}
```

---

## 🗄️ Veritabanı Şeması

| Tablo | Amaç |
|-------|------|
| `visitors` | Ziyaretçi bilgileri ve toplam istekler |
| `request_logs` | Tüm HTTP istek logları (partitioned) |
| `rate_limits` | Rate-limit sayaçları |
| `ip_lists` | Blacklist / Whitelist (IP + CIDR) |
| `waf_rules` | Regex tabanlı WAF kuralları |
| `threat_events` | Tespit edilen saldırılar |
| `login_attempts` | Brute force takibi |
| `csrf_tokens` | CSRF token deposu |
| `geo_rules` | Ülke bazlı engelleme kuralları |
| `bot_signatures` | Bot User-Agent imzaları |
| `upload_scans` | Dosya yükleme taramaları |
| `ssl_certificates` | SSL sertifika izleme |
| `honeypot_hits` | Honeypot tuzak kayıtları |
| `settings` | Sistem ayarları |
| `audit_logs` | Yönetici işlem logları |

Detaylı şema için → [`schema.sql`](./schema.sql)

---

## 💻 Kullanım

### Middleware Otomatik Çalışır

Uygulamanıza gelen **her istek** otomatik olarak şu kontrollerden geçer:

```
Whitelist → Blacklist → Rate Limit → Bot → WAF → Brute Force → CSRF → Geo → App
```

### Örnek: Login Endpoint

```python
@app.post("/auth/login")
async def login(request: Request, username: str, password: str):
    ip = client_ip(request)
    success = verify_credentials(username, password)
    await bruteforce.record(ip, username, success)
    if not success:
        raise HTTPException(401, "Invalid credentials")
    return {"ok": True, "csrf": await csrf_guard.issue(username, ip)}
```

### Örnek: Honeypot

```python
@app.get("/honeypot/admin.php")
async def honeypot(request: Request):
    ip = client_ip(request)
    await ip_manager.blacklist(ip, "honeypot_triggered", 1440)
    raise HTTPException(404)
```

---

## 🔌 API Endpoint'leri

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/auth/login` | Giriş + brute force koruması |
| GET | `/honeypot/{path}` | Tuzak endpoint |
| GET | `/admin/ip-lists` | IP listelerini görüntüle |
| POST | `/admin/ip-lists` | IP ekle (black/white) |
| GET | `/admin/threats` | Saldırı olayları |
| GET | `/admin/stats` | İstatistikler |
| GET | `/health` | Sistem sağlığı |

---

## 🧪 Test

```bash
# Tüm testler
pytest tests/ -v

# WAF testleri
pytest tests/test_waf.py -v

# Rate limit testleri
pytest tests/test_rate_limiter.py -v
```

### Manuel Test – SQLi Denemesi

```bash
curl "http://localhost:8000/?id=1' UNION SELECT * FROM users--"
# → 403 Forbidden (WAF tarafından engellendi)
```

### Manuel Test – Rate Limit

```bash
for i in {1..200}; do curl -s http://localhost:8000/ > /dev/null; done
# → 429 Too Many Requests (limit aşıldı)
```

---

## 📁 Proje Yapısı

```
webshield/
├── main.py                 # FastAPI ana uygulama
├── config.py               # Yapılandırma
├── database.py             # PostgreSQL bağlantı havuzu
├── waf.py                  # WAF motoru (SQLi, XSS, LFI, RCE)
├── rate_limiter.py         # Rate limiting
├── ip_manager.py           # IP black/white list
├── bruteforce.py           # Brute force koruması
├── bot_guard.py            # Bot engelleme
├── csrf.py                 # CSRF token yönetimi
├── geo_guard.py            # Geo blocking
├── headers_guard.py        # Güvenlik header'ları
├── upload_scanner.py       # Dosya yükleme taraması
├── ssl_monitor.py          # SSL/TLS izleme
├── anomaly.py              # Anomali tespiti
├── schema.sql              # Veritabanı şeması
├── requirements.txt        # Python bağımlılıkları
├── .env.example            # Örnek ortam değişkenleri
├── LICENSE                 # MIT Lisans
├── README.md               # Bu dosya
└── tests/
    ├── test_waf.py
    ├── test_rate_limiter.py
    ├── test_bruteforce.py
    └── test_csrf.py
```

---

## 🛠️ Yol Haritası

- [x] WAF (SQLi, XSS, LFI, RCE)
- [x] Rate Limiting
- [x] Brute Force Koruması
- [x] CSRF Token
- [x] IP Black/White List
- [x] Bot Engelleme
- [x] Geo Blocking
- [x] Honeypot
- [x] Güvenlik Header'ları
- [ ] Redis tabanlı rate-limit
- [ ] GeoIP2 entegrasyonu
- [ ] ML tabanlı anomali tespiti
- [ ] ClamAV dosya taraması
- [ ] Prometheus + Grafana dashboard
- [ ] Docker & docker-compose desteği

---

## 🤝 Katkıda Bulunma

Katkılarınız bizim için değerli! Lütfen şu adımları izleyin:

1. Fork'layın (`https://github.com/kullanici/webshield/fork`)
2. Feature branch oluşturun:
   ```bash
   git checkout -b feature/yeni-ozellik
   ```
3. Değişikliklerinizi commit'leyin:
   ```bash
   git commit -m "feat: yeni özellik eklendi"
   ```
4. Push'layın:
   ```bash
   git push origin feature/yeni-ozellik
   ```
5. Pull Request açın.

### Commit Kuralları (Conventional Commits)

- `feat:` yeni özellik
- `fix:` hata düzeltme
- `docs:` dokümantasyon
- `refactor:` kod iyileştirme
- `test:` test ekleme
- `chore:` bakım işleri

---

## 🔐 Güvenlik Bildirimi

Bir güvenlik açığı bulursanız lütfen **public issue açmayın**. Bunun yerine doğrudan iletişime geçin: **security@example.com**

---

## 📄 Lisans

Bu proje **MIT Lisansı** altında lisanslanmıştır. Detaylar için [`LICENSE`](./LICENSE) dosyasına bakın.

```
MIT License

Copyright (c) 2026 Web Site Guard Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Teşekkürler

- [FastAPI](https://fastapi.tiangolo.com/)
- [asyncpg](https://github.com/MagicStack/asyncpg)
- [PostgreSQL](https://www.postgresql.org/)
- [OWASP](https://owasp.org/) – güvenlik rehberleri için

---

<div align="center">

**⭐ Projeyi faydalı bulduysanız yıldız vermeyi unutmayın!**

[🐛 Bug Bildir](https://github.com/kullanici/webshield/issues) · [💡 Özellik Öner](https://github.com/kullanici/webshield/issues) · [📖 Dokümantasyon](https://github.com/kullanici/webshield/wiki)

</div>
