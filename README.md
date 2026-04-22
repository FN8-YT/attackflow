<div align="center">

```
 █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███████╗██╗      ██████╗ ██╗    ██╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║     ██╔═══██╗██║    ██║
███████║   ██║      ██║   ███████║██║     █████╔╝ █████╗  ██║     ██║   ██║██║ █╗ ██║
██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██║     ██║   ██║██║███╗██║
██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗██║     ███████╗╚██████╔╝╚███╔███╔╝
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝
```

**Open-source security auditing & continuous monitoring platform for pentesters and defenders.**

[![Django](https://img.shields.io/badge/Django-5.0+-092E20?style=flat-square&logo=django)](https://www.djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)](https://www.python.org/)
[![Celery](https://img.shields.io/badge/Celery-5.4-37814A?style=flat-square&logo=celery)](https://docs.celeryq.dev/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis)](https://redis.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What is AttackFlow?

AttackFlow is a **self-hosted web security platform** that combines two core capabilities:

- **Security Auditing** — Run comprehensive scans against any target with 24 modular scanners covering the full OWASP Top 10, JavaScript analysis, port scanning, SSL/TLS inspection, and subdomain enumeration. Nuclei integration gives you access to 9 000+ community-maintained vulnerability templates.

- **Continuous Monitoring** — Track any target 24/7 with configurable intervals from 5 seconds to 24 hours. Detect changes in HTTP status, SSL certificates, security headers, WAF presence, technology stack, exposed sensitive paths, discovered subdomains, and visual defacement via Playwright screenshots.

Everything runs on your own infrastructure. No SaaS fees, no data leaving your server.

---

## Who is it for?

| Persona | Use case |
|---|---|
| **Pentesters** | Rapid recon, OWASP coverage, JS secret extraction, Nuclei CVE detection |
| **Security engineers** | Continuous posture monitoring, change detection alerts, security score trending |
| **Bug bounty hunters** | Subdomain enumeration, exposed paths, tech fingerprinting, visual diff |
| **DevSecOps teams** | Integration into CI pipelines via REST API, PDF reports for stakeholders |

---

## Feature Overview

### Security Auditing — 24 Scanners

#### Passive / Safe (7 scanners)
| Scanner | What it checks |
|---|---|
| **DNS** | A/AAAA/MX/NS records, DNS misconfiguration |
| **TLS/SSL** | Certificate chain, expiry, weak protocols (via sslyze) |
| **Security Headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| **Technology Fingerprint** | Server stack, frameworks, CMS, languages |
| **Port Scanner** | Top 100+ TCP ports with nmap service/version detection |
| **Subdomain Enumeration** | Certificate Transparency logs (crt.sh) |
| **Vulnerability Hints** | Info disclosure, server banners, version leaks |

#### Active / OWASP Top 10 (10 scanners)
| Scanner | OWASP ID | What it checks |
|---|---|---|
| **Broken Access Control** | A01 | CORS misconfig, exposed admin panels, dangerous HTTP methods |
| **Cryptographic Failures** | A02 | Insecure cookies, mixed content, HTTP-only forms |
| **Insecure Design** | A04 | Stack traces, debug mode, missing rate limiting |
| **Vulnerable Components** | A06 | jQuery, Bootstrap, Angular CVEs in loaded JS libraries |
| **Auth Failures** | A07 | CSRF on login, account enumeration, session fixation |
| **Software Integrity** | A08 | Scripts without SRI, MIME type protection |
| **Logging Exposure** | A09 | Exposed debug/log endpoints |
| **SSRF** | A10 | Open redirects, URL parameter injection |
| **XSS** | — | DOM XSS sinks, reflected canary payloads |
| **SQL Injection** | — | DB error signatures via crafted inputs |

#### JavaScript Deep Analysis (3 scanners)
| Scanner | What it finds |
|---|---|
| **JS Analysis** | `eval()`, `document.write()`, DOM XSS sinks, `postMessage` |
| **JS Secrets** | API keys, tokens, AWS credentials, debug flags, source maps |
| **JS Endpoints** | Hidden API routes, WebSocket endpoints, internal parameters |

#### Nuclei Integration
- Runs the full ProjectDiscovery Nuclei engine (v3.3.2) with **9 000+ templates**
- Covers CVEs, default credentials, misconfigurations, exposed panels
- Filters: `critical`, `high`, `medium` severity only; `--no-interactsh` for safe execution
- Rate-limited to 50 req/s with 10s per-host timeout

---

### Continuous Monitoring

| Feature | Details |
|---|---|
| **Check intervals** | 5s ⚡ / 30s ⚡ / 1m ⚡ / 5m / 15m / 30m / 1h / 6h / 24h |
| **Uptime tracking** | HTTP status, response time, consecutive failures, uptime % |
| **SSL monitoring** | Days until expiry, issuer, fingerprint change detection |
| **Security headers** | Detects header additions/removals between checks |
| **Tech & WAF** | Identifies Cloudflare, AWS WAF, Akamai, tech stack changes |
| **Attack surface** | Subdomain discovery (60+ wordlist, DNS+HTTP probe) every 6h |
| **Sensitive paths** | Scans for exposed `/admin`, `/.git`, `/.env`, `/backup`, etc. |
| **Visual monitoring** | Playwright screenshot + pixel diff — defacement alert at 30% change |
| **Change timeline** | Every detected change logged with severity, old/new values |
| **Real-time UI** | WebSocket (Django Channels) — check log updates without polling |
| **Email alerts** | Instant alerts for `CRITICAL` and `HIGH` severity changes |
| **Security score** | 0–100 score with letter grade (A–F) per check |

---

### Platform

- **Multi-user** — each user sees only their own audits and targets
- **REST API** — session + token auth via Django REST Framework
- **PDF reports** — export full audit to PDF (WeasyPrint)
- **Brute-force protection** — django-axes (10 failures = 1h lockout)
- **Rate limiting** — max 10 audits/hour per user
- **Anti-SSRF** — all URLs validated against private IP ranges before scanning

---

## Tech Stack

```
┌─────────────────────────────────────────────────────────────┐
│                        nginx (TLS)                          │
│          HTTP → HTTPS redirect · Static files              │
│              WebSocket proxy (/ws/)                         │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│               Daphne (ASGI server)                          │
│         Django 5 · Channels 4 · DRF 3.15                   │
│    WebSocket consumers · REST endpoints · HTML views         │
└───────┬──────────────────────────┬──────────────────────────┘
        │                          │
┌───────▼──────────┐    ┌──────────▼────────────────────────┐
│  PostgreSQL 16   │    │      Redis 7                       │
│  All app data    │    │  Cache · Celery broker             │
└──────────────────┘    │  Channels layer (WebSocket)        │
                        └──────────┬───────────────────────  ┘
                                   │
                   ┌───────────────┴──────────────┐
                   │         Celery               │
                   │  worker · beat (5s dispatch) │
                   │  Audits · Monitoring tasks   │
                   └──────────────────────────────┘

External tools (bundled in Docker image):
  nmap · Nuclei 3.3.2 · Playwright Chromium · sslyze
```

| Layer | Technology |
|---|---|
| Web framework | Django 5.0, Django REST Framework 3.15 |
| Real-time | Django Channels 4.1, Daphne 4.1 (ASGI) |
| Task queue | Celery 5.4 + Redis |
| Database | PostgreSQL 16 (psycopg 3) |
| Cache | Redis 7 + django-redis |
| Port scanning | python-nmap + nmap binary |
| Vulnerability scanning | Nuclei 3.3.2 (ProjectDiscovery) |
| SSL analysis | sslyze 6.0 |
| Screenshots | Playwright 1.44 (Chromium headless) |
| Image diffing | Pillow 10 |
| PDF export | WeasyPrint 60 |
| Auth hardening | django-axes 6.4 + django-ratelimit 4.1 |
| Certificate parsing | cryptography 42 |
| WHOIS | python-whois 0.9 |
| Containerization | Docker + Docker Compose |
| Reverse proxy | nginx 1.27 |

---

## Quick Start (Docker — recommended)

The fastest way to run AttackFlow. Everything — Postgres, Redis, Celery, Nuclei, Playwright — is bundled in the Docker image.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24
- [Docker Compose](https://docs.docker.com/compose/install/) ≥ 2.20
- 4 GB RAM (Playwright + Nuclei templates use memory)

### 1. Clone

```bash
git clone https://github.com/FN8-YT/attackflow.git
cd attackflow
```

### 2. Configure environment

```bash
cp .env.example .env
```

Open `.env` and set a real `DJANGO_SECRET_KEY`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

The defaults in `.env.example` work out of the box for local Docker use — no other changes needed to get started.

### 3. Build and migrate

```bash
docker-compose build
docker-compose run --rm migrate
```

> The `migrate` service runs `manage.py migrate` and exits cleanly before the web server starts.

### 4. Launch

```bash
docker-compose up -d
```

Services started:

| Service | URL / port |
|---|---|
| AttackFlow web | http://localhost:8000 |
| Mailpit (email capture) | http://localhost:8025 |

### 5. Create your first user

```bash
docker-compose exec web python manage.py createsuperuser
```

Or register directly at http://localhost:8000/accounts/register.

---

## Local Development (without Docker)

For hacking on the Python code with hot-reload.

### Prerequisites

- Python 3.12
- PostgreSQL 16 running locally (or use the Docker `db` + `redis` services only)
- Redis running locally
- `nmap` installed on your system (`brew install nmap` / `apt install nmap`)

### Setup

```bash
git clone https://github.com/FN8-YT/attackflow.git
cd attackflow

# Virtual environment
python3.12 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Dependencies
pip install --upgrade pip
pip install -r requirements/dev.txt

# Playwright browser (for screenshot monitoring)
playwright install chromium
```

### Configure

```bash
cp .env.example .env
```

Edit `.env` — set `POSTGRES_HOST=localhost` and `REDIS_URL=redis://localhost:6379/0`.

### Run

```bash
# Terminal 1 — Django dev server (ASGI via Channels)
python manage.py migrate
python manage.py runserver

# Terminal 2 — Celery worker (audit + monitoring tasks)
celery -A config worker --pool=solo --loglevel=info

# Terminal 3 — Celery Beat (monitoring scheduler every 5s)
celery -A config beat --loglevel=info
```

App available at http://localhost:8000.

> **Tip:** In dev mode, Daphne replaces Django's WSGI server automatically because `daphne` is in `INSTALLED_APPS`. WebSockets work out of the box with `runserver`.

---

## Usage

### Running a Security Audit

1. Go to **Audits → New Scan**
2. Enter the target URL (e.g., `https://example.com`)
3. Choose scan mode:
   - **Passive** — safe, read-only (headers, DNS, TLS, ports, fingerprinting)
   - **Active** — sends payloads (XSS, SQLi, OWASP checks, Nuclei)
4. Select scanners (or leave all checked)
5. Click **Launch Scan** — the task runs in Celery, the page polls for status
6. View findings grouped by severity with evidence and remediation advice
7. Export to **PDF** for stakeholder reports

### Setting up Continuous Monitoring

1. Go to **Monitoring → Add Target**
2. Enter URL + display name
3. Choose check interval (5s for live, 30m for standard)
4. Enable **Scan sensitive paths** if you want attack surface tracking
5. The target starts monitoring immediately
6. **Detail page** shows:
   - Live check log (WebSocket — no page reload needed)
   - Response time chart (last 50/100/200 checks)
   - Security headers analysis
   - SSL certificate details
   - Technology stack + WAF detection
   - Attack surface panel (subdomains + exposed paths)
   - Visual monitoring (screenshot + pixel diff history)
   - Change timeline with severity indicators

### Email Alerts

Monitoring sends email alerts for `CRITICAL` and `HIGH` severity changes:
- Target goes offline
- SSL expiring within 7 days
- Security score drops significantly
- Defacement detected (visual diff > 30%)
- Sensitive path suddenly exposed

Configure your SMTP settings in `.env` (Mailpit captures all emails at http://localhost:8025 in dev).

---

## Project Structure

```
attackflow/
├── apps/
│   ├── core/                   # TimeStampedModel base, shared utilities
│   ├── users/                  # Custom User model (email-based auth)
│   ├── audits/                 # Security scanning engine
│   │   ├── scanners/           # 24 modular scanners (strategy pattern)
│   │   │   ├── dns.py
│   │   │   ├── tls.py
│   │   │   ├── headers.py
│   │   │   ├── ports.py
│   │   │   ├── nuclei_scanner.py
│   │   │   ├── js_analysis.py
│   │   │   ├── js_secrets.py
│   │   │   ├── js_endpoints.py
│   │   │   └── ...             # OWASP A01–A10 scanners
│   │   ├── models.py           # Audit, Finding
│   │   ├── tasks.py            # run_audit_task (Celery)
│   │   └── services.py         # Scanner orchestration engine
│   ├── monitoring/             # Continuous monitoring engine
│   │   ├── checks/             # 7 check modules (tech, WAF, paths, screenshots...)
│   │   ├── consumers.py        # WebSocket consumers (Channels)
│   │   ├── models.py           # Target, Check, Change, Subdomain, Screenshot
│   │   ├── tasks.py            # run_due_monitoring_checks (every 5s)
│   │   └── services.py         # Check orchestration + change detection
│   └── reports/                # PDF export (WeasyPrint)
├── config/
│   ├── settings/
│   │   ├── base.py             # Common settings
│   │   ├── dev.py              # Development overrides
│   │   └── prod.py             # Production hardening
│   ├── asgi.py                 # ASGI app (HTTP + WebSocket routing)
│   └── celery.py               # Celery app configuration
├── templates/                  # HTML templates
├── nginx/
│   ├── nginx.conf              # Production nginx config (WS + TLS)
│   └── generate_cert.sh        # Self-signed cert helper
├── requirements/
│   ├── base.txt                # Production dependencies
│   ├── dev.txt                 # Dev extras (pytest, ruff, debug-toolbar)
│   └── prod.txt                # Production extras
├── Dockerfile                  # Multi-stage build (Nuclei + Playwright included)
├── docker-compose.yml          # Development stack (7 services)
├── docker-compose.prod.yml     # Production stack (nginx + Daphne)
└── .env.example                # Environment variable template
```

---

## API

AttackFlow exposes a REST API via Django REST Framework. Authenticate with a token:

```bash
# Get token
curl -X POST http://localhost:8000/api/auth/token/ \
  -d '{"username": "you@example.com", "password": "yourpass"}' \
  -H 'Content-Type: application/json'

# Use token
curl http://localhost:8000/api/audits/ \
  -H 'Authorization: Token <your-token>'
```

### WebSocket (monitoring real-time)

```javascript
// Target detail — receives check_update, surface_update, screenshot_update
const ws = new WebSocket('ws://localhost:8000/ws/monitoring/<target_pk>/');

// Dashboard — receives check_update for all targets of the user
const ws = new WebSocket('ws://localhost:8000/ws/monitoring/dashboard/');
```

---

## Production Deployment

A full nginx + Daphne stack is ready to go with `docker-compose.prod.yml`.

```bash
# 1. Generate TLS certificate (or copy Let's Encrypt cert to nginx/certs/)
chmod +x nginx/generate_cert.sh && ./nginx/generate_cert.sh

# 2. Configure production environment
cp .env.example.prod .env.prod
# Edit .env.prod: set DJANGO_SECRET_KEY, DJANGO_ALLOWED_HOSTS, SMTP, etc.

# 3. Build production images
docker-compose -f docker-compose.prod.yml build

# 4. Migrate + collectstatic
docker-compose -f docker-compose.prod.yml run --rm migrate

# 5. Launch
docker-compose -f docker-compose.prod.yml up -d
```

Production hardening included:
- nginx terminates TLS 1.2/1.3 with modern cipher suites
- HSTS (1 year, includeSubDomains, preload)
- `ManifestStaticFilesStorage` for cache-busting
- Daphne with `--proxy-headers` (trusts `X-Forwarded-Proto` from nginx)
- Celery worker with prefork (4 concurrent workers)
- Redis AOF persistence
- All secrets via environment variables (never hardcoded)

---

## Configuration Reference

Key environment variables (full list in `.env.example`):

| Variable | Description | Default |
|---|---|---|
| `DJANGO_SECRET_KEY` | Django secret key — **must be unique per environment** | — |
| `DJANGO_DEBUG` | Enable debug mode | `False` |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated allowed hostnames | `localhost,127.0.0.1` |
| `POSTGRES_*` | Database connection | see `.env.example` |
| `REDIS_URL` | Redis for cache + Channels | `redis://redis:6379/0` |
| `CELERY_BROKER_URL` | Celery task broker | `redis://redis:6379/1` |
| `CELERY_RESULT_BACKEND` | Celery result store | `redis://redis:6379/2` |
| `DEFAULT_FROM_EMAIL` | Sender address for alerts | `AttackFlow <noreply@…>` |

---

## Security Considerations

- **Anti-SSRF:** All target URLs are resolved and validated against private IP ranges (RFC 1918, loopback, link-local) before any HTTP request is made. You cannot scan internal services.
- **Ownership isolation:** Users only access their own audits, targets, and reports — enforced at the query level (`filter(user=request.user)`).
- **Rate limiting:** Audit creation is rate-limited to 10 scans/hour per user.
- **Brute-force protection:** django-axes locks accounts after 10 failed login attempts for 1 hour.
- **Active scans:** OWASP and payload-based scanners only run when the user explicitly selects active mode. Never passive by default.
- **Nuclei safety:** Runs with `--no-interactsh` and excludes `intrusive,dos,fuzz,brute` tagged templates.

---

## Contributing

Contributions are welcome. To add a new scanner:

1. Create `apps/audits/scanners/your_scanner.py` inheriting `BaseScanner`
2. Implement `run(self, context: ScanContext) → ScanResult`
3. Register it in `apps/audits/scanners/__init__.py` via `SCANNER_REGISTRY`
4. Write tests in `tests/audits/scanners/test_your_scanner.py`

```python
from .base import BaseScanner, FindingData, ScanContext, ScanResult

class YourScanner(BaseScanner):
    name = "your_scanner"

    def run(self, context: ScanContext) -> ScanResult:
        findings = []
        # ... your logic ...
        findings.append(FindingData(
            category="MISCONFIG",
            severity="HIGH",
            title="Something bad found",
            description="...",
            recommendation="...",
        ))
        return ScanResult(findings=findings, raw={})
```

Please open an issue before submitting large PRs to discuss the approach.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built for the security community.

*If AttackFlow helped you find a bug or secure a system, consider leaving a ⭐*

</div>
