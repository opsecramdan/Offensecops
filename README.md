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

- **SQLi Testing Module** — Automated sqlmap integration + Manual error-based extraction
- **Vulnerability Management** — Track, filter, and manage findings by product and year
- **POC Management** — Document proof-of-concept with evidence upload and retesting
- **Advanced Tools** — Log4Shell scanner, XSS, directory brute-force, and more
- **Real-time Output** — Live terminal output for all running scans
- **Multi-user** — Role-based access control with JWT authentication
- **Export** — PDF and Word report generation

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
git clone https://github.com/YOUR_USERNAME/offensecops.git
cd offensecops
```

**2. Configure environment**
```bash
cp .env.example .env
# Edit .env with your own passwords and secrets
nano .env
```

**3. Build and start**
```bash
docker compose up -d --build
```

**4. Access the platform**
```
http://localhost
```

Default credentials:
```
Username: admin
Password: (set during first run)
```

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

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Backend | FastAPI, Python 3.12, SQLAlchemy |
| Database | PostgreSQL 15 |
| Queue | Celery + Redis |
| Proxy | Nginx |
| Container | Docker Compose |
| Security Tools | sqlmap, nuclei, nmap, subfinder, dalfox |

## 📖 Modules

### SQLi Testing
- Import raw HTTP requests
- Automated sqlmap with real-time output
- Manual error-based extraction (MSSQL, MySQL, PostgreSQL, Oracle)
- Database enumeration: `--dbs`, `--tables`, `--columns`, `--dump`

### Vulnerability Management
- Filter by product, year, and severity
- CVSS scoring
- SLA tracking

### POC Management
- Evidence upload (images, files)
- Retesting workflow
- Export to PDF/Word

## ⚙️ Configuration

All configuration is managed via environment variables in `.env`:

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `REDIS_PASSWORD` | Redis password |
| `JWT_SECRET_KEY` | JWT signing key (min 32 chars) |

## 🔒 Security Notice

This tool is intended for **authorized penetration testing and security research only**. Users are responsible for complying with applicable laws. The developers assume no liability for misuse.

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built for offensive security professionals
</div>
