#!/bin/bash
# ============================================================
# OffenSecOps - FASE 1 SETUP SCRIPT (v3 - VERBOSE)
# Cara pakai: cd /tmp/offensecops && bash scripts/setup_fase1.sh
# ============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-] ERROR: $1${NC}"; exit 1; }
step() { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════${NC}"; \
         echo -e "${CYAN}${BOLD}  $1${NC}"; \
         echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}"; }

SERVER_IP="10.16.91.126"

# ── Resolve project root ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

step "STEP 0: Verify project structure"
echo "  Script dir  : $SCRIPT_DIR"
echo "  Project root: $PROJECT_ROOT"

[ -f "$PROJECT_ROOT/docker-compose.yml" ] || err "docker-compose.yml tidak ditemukan di $PROJECT_ROOT"
[ -f "$PROJECT_ROOT/backend/Dockerfile" ] || err "backend/Dockerfile tidak ditemukan"
[ -f "$PROJECT_ROOT/frontend/Dockerfile" ] || err "frontend/Dockerfile tidak ditemukan"
log "Struktur project OK"

cd "$PROJECT_ROOT"
log "Working directory: $(pwd)"

# ── STEP 1: Docker check ─────────────────────────────────────
step "STEP 1: Verify Docker"
docker --version       || err "Docker tidak ditemukan"
docker compose version || err "Docker Compose v2 tidak ditemukan"
log "Docker OK"

# ── STEP 2: Direktori ────────────────────────────────────────
step "STEP 2: Buat direktori yang dibutuhkan"
mkdir -p docker/nginx infra scripts
log "Direktori OK"

# ── STEP 3: Pull images ──────────────────────────────────────
step "STEP 3: Pull infrastructure images"
echo ""
echo -e "${YELLOW}Menarik image berikut (progress terlihat di bawah):${NC}"
echo "  - postgres:16-alpine"
echo "  - redis:7-alpine"
echo "  - nginx:1.25-alpine"
echo "  - prom/prometheus:latest"
echo "  - grafana/grafana:latest"
echo ""
echo -e "${YELLOW}[Jika baru pertama kali, proses ini bisa 5-10 menit tergantung koneksi]${NC}"
echo ""

# Pull satu per satu agar progress masing-masing terlihat
for IMAGE in "postgres:16-alpine" "redis:7-alpine" "nginx:1.25-alpine" "prom/prometheus:latest" "grafana/grafana:latest"; do
    echo -e "\n${CYAN}>>> Pulling: ${IMAGE}${NC}"
    docker pull "$IMAGE" && echo -e "${GREEN}    ✓ $IMAGE selesai${NC}" || {
        warn "Gagal pull $IMAGE - akan dicoba saat docker compose up"
    }
done

log "Pull images selesai"

# ── STEP 4: Build backend ────────────────────────────────────
step "STEP 4: Build Backend image (FastAPI + Python)"
echo ""
echo -e "${YELLOW}Membangun backend Docker image...${NC}"
echo -e "${YELLOW}[Proses ini install Python packages, bisa 3-5 menit]${NC}"
echo ""

# Build dengan progress output penuh (tanpa --quiet)
docker compose build --no-cache --progress=plain backend
log "Backend image selesai dibangun"

# ── STEP 5: Build frontend ───────────────────────────────────
step "STEP 5: Build Frontend image (React + Vite)"
echo ""
echo -e "${YELLOW}Membangun frontend Docker image...${NC}"
echo -e "${YELLOW}[Proses ini install npm packages, bisa 3-5 menit]${NC}"
echo ""

docker compose build --no-cache --progress=plain frontend
log "Frontend image selesai dibangun"

# ── STEP 6: Start semua service ──────────────────────────────
step "STEP 6: Start semua service"
echo ""
echo -e "${YELLOW}Menjalankan semua container...${NC}"
echo ""
docker compose up -d
echo ""
log "Semua container dijalankan"

# Tampilkan status awal
echo ""
echo -e "${CYAN}Status container:${NC}"
docker compose ps

# ── STEP 7: Health checks ────────────────────────────────────
step "STEP 7: Tunggu semua service siap"

# PostgreSQL
echo ""
echo -e "${CYAN}[1/4] Menunggu PostgreSQL...${NC}"
COUNT=0
until docker compose exec -T postgres pg_isready -U offensecops_user -d offensecops -q 2>/dev/null; do
    COUNT=$((COUNT+1))
    if [ $COUNT -ge 30 ]; then
        err "PostgreSQL tidak siap dalam 60 detik. Cek: docker compose logs postgres"
    fi
    echo -n "."
    sleep 2
done
echo -e " ${GREEN}✓ PostgreSQL siap${NC}"

# Redis
echo ""
echo -e "${CYAN}[2/4] Menunggu Redis...${NC}"
COUNT=0
until docker compose exec -T redis redis-cli -a "changeme" ping 2>/dev/null | grep -q PONG; do
    COUNT=$((COUNT+1))
    if [ $COUNT -ge 15 ]; then
        err "Redis tidak siap dalam 30 detik. Cek: docker compose logs redis"
    fi
    echo -n "."
    sleep 2
done
echo -e " ${GREEN}✓ Redis siap${NC}"

# Backend
echo ""
echo -e "${CYAN}[3/4] Menunggu Backend API...${NC}"
COUNT=0
until curl -sf http://localhost:8000/api/health > /dev/null 2>&1; do
    COUNT=$((COUNT+1))
    if [ $COUNT -ge 30 ]; then
        echo ""
        err "Backend tidak siap dalam 90 detik. Cek: docker compose logs backend"
    fi
    echo -n "."
    sleep 3
done
echo -e " ${GREEN}✓ Backend API siap${NC}"

# Nginx/Frontend
echo ""
echo -e "${CYAN}[4/4] Menunggu Nginx + Frontend...${NC}"
COUNT=0
until curl -sf http://localhost > /dev/null 2>&1; do
    COUNT=$((COUNT+1))
    if [ $COUNT -ge 20 ]; then
        err "Nginx tidak siap dalam 60 detik. Cek: docker compose logs nginx"
    fi
    echo -n "."
    sleep 3
done
echo -e " ${GREEN}✓ Nginx siap${NC}"

# ── STEP 8: Buat users ───────────────────────────────────────
step "STEP 8: Buat initial users"

echo ""
echo -n "  Membuat admin user... "
RESP=$(curl -s -o /tmp/register_resp.txt -w "%{http_code}" -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@offensecops.local","full_name":"System Administrator","password":"changeme","role":"admin"}')
if [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
    echo -e "${GREEN}✓ berhasil${NC}"
else
    echo -e "${YELLOW}HTTP $RESP (mungkin sudah ada - OK)${NC}"
fi

echo -n "  Membuat operator1 user... "
RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"operator1","email":"operator1@offensecops.local","full_name":"Red Team Operator","password":"changeme","role":"pentester"}')
if [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
    echo -e "${GREEN}✓ berhasil${NC}"
else
    echo -e "${YELLOW}HTTP $RESP (mungkin sudah ada - OK)${NC}"
fi

# ── STEP 9: Final status ─────────────────────────────────────
step "STEP 9: Status akhir semua service"
echo ""
docker compose ps
echo ""

# ── STEP 10: Ringkasan ───────────────────────────────────────
step "SETUP SELESAI"
echo ""
echo -e "  ${GREEN}${BOLD}🌐 Dashboard${NC}  → ${CYAN}http://${SERVER_IP}${NC}"
echo -e "  ${GREEN}${BOLD}📡 API Docs${NC}   → ${CYAN}http://${SERVER_IP}/docs${NC}"
echo -e "  ${GREEN}${BOLD}📊 Grafana${NC}    → ${CYAN}http://${SERVER_IP}:3001${NC}"
echo -e "  ${GREEN}${BOLD}🔥 Prometheus${NC} → ${CYAN}http://${SERVER_IP}:9090${NC}"
echo ""
echo -e "  ┌─────────────────────────────────────┐"
echo -e "  │  Login: ${YELLOW}admin${NC}     / ${YELLOW}changeme${NC}      │"
echo -e "  │  Login: ${YELLOW}operator1${NC} / ${YELLOW}changeme${NC}      │"
echo -e "  └─────────────────────────────────────┘"
echo ""
echo -e "${GREEN}Fase 1 COMPLETE! ✅${NC}"
echo ""
echo -e "${CYAN}Perintah berguna:${NC}"
echo ""
echo "  Lihat log realtime:"
echo "    docker compose logs -f backend"
echo "    docker compose logs -f frontend"
echo "    docker compose logs -f        # semua sekaligus"
echo ""
echo "  Status service:"
echo "    docker compose ps"
echo ""
echo "  Restart satu service:"
echo "    docker compose restart backend"
echo ""
echo "  Stop semua:"
echo "    docker compose down"
echo ""
echo "  Stop + hapus data:"
echo "    docker compose down -v"
echo ""
