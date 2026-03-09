<div align="center">

# OffenSecOps

**Offensive Security Operations Platform**

![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square)
![React](https://img.shields.io/badge/react-18-61dafb?style=flat-square)
![Docker](https://img.shields.io/badge/docker-compose-2496ed?style=flat-square)

> A comprehensive web-based platform for managing offensive security operations, vulnerability assessments, and penetration testing workflows.

</div>

---

## ✨ Features

### 🗡️ SQLi Testing Module
Dual-mode SQL injection testing — automated and manual.

<img width="1867" height="826" alt="image" src="https://github.com/user-attachments/assets/7012213b-8c51-4111-8f3f-a467e2254983" />

**sqlmap Integration:**
- Import raw HTTP requests directly (paste from Burp Suite or browser DevTools)
- Auto-parse headers, cookies, body, and injection parameters
- Full sqlmap flag support: `--dbs`, `--tables`, `--columns`, `--dump` with `-D` and `-T` targeting
- Tamper script selection (20+ scripts) for WAF bypass
- Technique selector: Boolean, Error, Union, Stacked, Time-based, Inline
- Real-time output terminal with color-coded sqlmap logs
- Session history with status tracking (queued → running → completed)

**Manual Error-Based Extraction:**
- Step-by-step guided workflow: Configure → Test → Extract
- Support for JSON body, form-urlencoded, GET parameters
- Auto-flatten nested JSON to selectable parameter list
- Built-in vulnerability test payloads (Single Quote, CONVERT, WAITFOR DELAY)
- One-click extraction: DB Name, Current User, Version, Server Name
- Chained enumeration: Databases → Tables → Columns → Dump
- Custom SQL query execution
- Export results to JSON

---

### 🛡️ Vulnerability Management
Centralized vulnerability tracking with full lifecycle management.

<img width="1857" height="820" alt="image" src="https://github.com/user-attachments/assets/ef3c77e3-bc20-437f-a4ad-1e702f67cfe0" />

- **Filter & Search** — Filter findings by product, year, severity, and status
- **CVSS Scoring** — Record and display CVSS scores per finding
- **SLA Tracking** — Automatic SLA breach detection and alerting
- **Status Workflow** — Track findings from Open → In Progress → Resolved → Accepted Risk
- **Severity Classification** — Critical, High, Medium, Low, Informational
- **Multi-product Support** — Organize findings by product/application
- **Bulk Operations** — Update multiple findings at once
- **Audit Trail** — Full history of changes per finding

---

### 📋 POC Management
Professional proof-of-concept documentation with collaboration features.

<img width="1336" height="882" alt="image" src="https://github.com/user-attachments/assets/bbbcfc74-42f1-46e1-9a5a-8c26a003e142" />

- **Multi-tab Modal** — Organized tabs: Details, Evidence, Retesting
- **Evidence Upload** — Attach screenshots, files, and documents as proof
- **Evidence Gallery** — View and manage uploaded evidence inline
- **Retesting Workflow** — Log retesting attempts with date, tester, and result
- **Retest Status** — Track whether fixes have been verified (Fixed / Still Vulnerable / Partial)
- **Export to PDF** — Generate professional PDF report per POC
- **Export to Word** — Generate `.docx` report for client delivery
- **Linked to Findings** — Each POC is linked to its parent vulnerability

---

### ⚙️ Advanced Tools
Integrated offensive security toolkit accessible from a single interface.

<img width="1351" height="821" alt="image" src="https://github.com/user-attachments/assets/28e0b366-cb75-43de-b2c4-2e4f6b8b9220" />

- **Log4Shell Scanner (CVE-2021-44228)** — Automated header injection across User-Agent, Referer, X-Api-Version, X-Forwarded-For, and 10+ headers with OAST callback support
- **XSS Scanner (Dalfox)** — Reflected and stored XSS detection with custom payloads
- **Directory Bruteforce (ffuf/dirsearch)** — Fast content discovery with wordlist support
- **Subdomain Enumeration (subfinder/amass)** — Passive and active subdomain discovery
- **Port Scanner (nmap/masscan)** — Service and version detection
- **HTTP Probe (httpx)** — Live host detection with status codes and technology fingerprinting
- **Nuclei** — Template-based vulnerability scanning with 9000+ community templates
- **DNS Resolver (dnsx)** — Bulk DNS resolution and record enumeration

---

### 📡 Real-time Output
Live terminal output for all running scans.

- Color-coded terminal output (green for findings, red for errors, yellow for warnings)
- Polling-based live updates every 3 seconds
- Full output history preserved per session
- Line count indicator
- Status indicator (queued / running / completed / failed)

---

### 👥 Multi-user & Authentication
Secure multi-user access with role-based control.

- **JWT Authentication** — Stateless token-based auth with configurable expiry
- **Role-based Access Control** — Admin and Analyst roles with permission boundaries
- **User Management** — Create, update, and deactivate user accounts
- **Audit Logging** — All actions logged with timestamp and user identity
- **Session Management** — Automatic token refresh and logout on expiry

---

### 📄 Export & Reporting
Generate professional deliverables directly from the platform.

- **PDF Export** — Styled PDF reports with findings, evidence, and remediation
- **Word Export** — Editable `.docx` reports for client customization
- **JSON Export** — Raw data export for integration with other tools
- **Per-finding Reports** — Export individual POC documentation
- **Bulk Reports** — Export all findings for a product in one report

---

## 🏗️ Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Nginx     │────▶│   FastAPI   │────▶│  PostgreSQL │
│  (Reverse   │     │  (Backend)  │     │  (Database) │
│   Proxy)    │     └─────────────┘     └─────────────┘
└─────────────┘            │
       │             ┌─────────────┐     ┌─────────────┐
       │             │   Celery    │────▶│    Redis    │
┌─────────────┐      │  (Worker)   │     │   (Queue)   │
│  React +    │      └─────────────┘     └─────────────┘
│   Vite      │
│ (Frontend)  │
└─────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Git

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/opsecramdan/offensecops.git
cd offensecops
```

**2. Configure environment**
```bash
cp .env.example .env
nano .env   # Set your own passwords and secrets
```

**3. Build and start**
```bash
docker compose up -d --build
```

**4. Access the platform**
```
http://localhost
```

---

## 📁 Project Structure
```
offensecops/
├── backend/                # FastAPI application
│   ├── app/
│   │   ├── api/routes/     # API endpoints
│   │   ├── db/             # Database models & migrations
│   │   ├── services/       # Business logic
│   │   └── tasks/          # Celery async tasks
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/               # React + Vite application
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── pages/          # Page components
│   │   └── lib/            # Utilities & API client
│   └── Dockerfile
├── docker/
│   └── nginx/              # Nginx configuration
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Backend | FastAPI, Python 3.12, SQLAlchemy |
| Database | PostgreSQL 15 |
| Queue | Celery + Redis |
| Proxy | Nginx |
| Container | Docker Compose |
| Security Tools | sqlmap, nuclei, nmap, subfinder, dalfox, ffuf, httpx, dnsx |

---

## ⚙️ Configuration

All configuration is managed via environment variables in `.env`:

| Variable | Description | Required | Where to Get |
|----------|-------------|----------|--------------|
| `POSTGRES_PASSWORD` | PostgreSQL password | ✅ Yes | Set your own |
| `REDIS_PASSWORD` | Redis password | ✅ Yes | Set your own |
| `JWT_SECRET_KEY` | JWT signing key (min 32 chars) | ✅ Yes | Set your own |
| `DEFAULT_ADMIN_PASSWORD` | Auto-created admin password | ✅ Yes | Default: `Admin123!` |
| `GF_SECURITY_ADMIN_PASSWORD` | Grafana admin password | ❌ Optional | Set your own |
| `VIRUSTOTAL_API_KEY` | VirusTotal subdomain enumeration | ❌ Optional | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails subdomain data | ❌ Optional | [securitytrails.com/app/account/credentials](https://securitytrails.com/app/account/credentials) |
| `CENSYS_API_TOKEN` | Censys host & subdomain search | ❌ Optional | [search.censys.io/account/api](https://search.censys.io/account/api) |
| `NVD_API_KEY` | NVD CVE database (faster rate limit) | ❌ Optional | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |

> **Note:** Without OSINT API keys, subdomain enumeration will still work via passive tools (subfinder, amass) but will skip VirusTotal, SecurityTrails, and Censys sources.

---

## 🔒 Security Notice

This tool is intended for **authorized penetration testing and security research only**. Users are responsible for complying with applicable laws and obtaining proper authorization before testing any systems. The developers assume no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built for offensive security professionals
</div>
