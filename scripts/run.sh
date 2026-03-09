#!/bin/bash
# OffenSecOps - Script Setup Lengkap
# Jalankan di /tmp/offensecops sebagai root
# IP: 192.168.1.10 | Password: changeme

set -e
cd /tmp/offensecops

echo "=========================================="
echo " OffenSecOps Setup Script"
echo "=========================================="

# ─── STEP 1: Update .env ───────────────────────
echo "[1/8] Writing .env..."
cat > .env << 'ENVEOF'
DATABASE_URL=postgresql+asyncpg://offensecops_user:changeme@postgres:5432/offensecops
SYNC_DATABASE_URL=postgresql://offensecops_user:changeme@postgres:5432/offensecops
REDIS_URL=redis://:changeme@redis:6379/0
CELERY_BROKER_URL=redis://:changeme@redis:6379/1
CELERY_RESULT_BACKEND=redis://:changeme@redis:6379/2
SECRET_KEY=offensecops-super-secret-jwt-2024-xK9mP3qR7nL2wZ8
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7
DEBUG=false
ENVEOF

# ─── STEP 2: Fix core files ───────────────────
echo "[2/8] Fixing config.py..."
mkdir -p backend/app/core backend/app/db backend/app/api

cat > backend/app/core/config.py << 'PYEOF'
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://offensecops_user:changeme@postgres:5432/offensecops"
    SYNC_DATABASE_URL: str = "postgresql://offensecops_user:changeme@postgres:5432/offensecops"
    REDIS_URL: str = "redis://:changeme@redis:6379/0"
    CELERY_BROKER_URL: str = "redis://:changeme@redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://:changeme@redis:6379/2"
    SECRET_KEY: str = "offensecops-super-secret-jwt-2024-xK9mP3qR7nL2wZ8"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    DEBUG: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
PYEOF

cat > backend/app/core/security.py << 'PYEOF'
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta=None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return {}
PYEOF

cat > backend/app/db/session.py << 'PYEOF'
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.config import settings

class Base(DeclarativeBase):
    pass

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
PYEOF

cat > backend/app/api/deps.py << 'PYEOF'
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.db.models import User
from app.core.security import decode_token

security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    return user
PYEOF

# ─── STEP 3: Fix nginx config ─────────────────
echo "[3/8] Fixing nginx config..."
mkdir -p docker/nginx
cat > docker/nginx/nginx.conf << 'NGINXEOF'
events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    
    upstream backend { server backend:8000; }
    upstream frontend { server frontend:3000; }

    server {
        listen 80;
        server_name _;
        client_max_body_size 50M;

        location /api/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_read_timeout 300s;
        }

        location /api/scans/ws/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_read_timeout 3600s;
        }

        location / {
            proxy_pass http://frontend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
        }
    }
}
NGINXEOF

# ─── STEP 4: Restart containers ───────────────
echo "[4/8] Restarting containers..."
docker compose restart nginx backend celery_worker celery_beat
sleep 10

# ─── STEP 5: Wait for backend ─────────────────
echo "[5/8] Waiting for backend to be ready..."
for i in {1..30}; do
    if curl -sf http://localhost:8000/api/health > /dev/null 2>&1; then
        echo "Backend is ready!"
        break
    fi
    echo "Waiting... ($i/30)"
    sleep 3
done

# ─── STEP 6: Init database ────────────────────
echo "[6/8] Initializing database..."
docker exec offensecops_backend python3 -c "
import asyncio, uuid
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

async def init():
    from app.db.session import Base, engine
    from app.db.models import User, ToolRegistry
    from app.core.security import get_password_hash

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print('Tables created')

    s = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with s() as db:
        r = await db.execute(select(User).where(User.username == 'admin'))
        if not r.scalar_one_or_none():
            db.add(User(
                id=str(uuid.uuid4()),
                username='admin',
                email='admin@offensecops.local',
                hashed_password=get_password_hash('changeme'),
                full_name='Administrator',
                role='admin',
                is_active=True,
            ))
            await db.commit()
            print('Admin created: admin / changeme')
        else:
            print('Admin already exists')

    await engine.dispose()

asyncio.run(init())
"

# ─── STEP 7: Seed tools ───────────────────────
echo "[7/8] Seeding tools..."
docker exec offensecops_backend python3 -c "
import asyncio, uuid
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from app.db.models import ToolRegistry
from app.core.config import settings

TOOLS = [
    {'name': 'subfinder', 'display_name': 'Subfinder', 'category': 'recon',
     'description': 'Fast passive subdomain enumeration',
     'docker_image': 'projectdiscovery/subfinder:latest', 'version': '2.6.x',
     'safe_args': ['-d', '-silent', '-o', '-r', '-t']},
    {'name': 'httpx', 'display_name': 'HTTPX', 'category': 'recon',
     'description': 'Fast HTTP probing tool',
     'docker_image': 'projectdiscovery/httpx:latest', 'version': '1.3.x',
     'safe_args': ['-l', '-silent', '-o', '-threads', '-title', '-status-code']},
    {'name': 'nuclei', 'display_name': 'Nuclei', 'category': 'web',
     'description': 'Fast vulnerability scanner',
     'docker_image': 'projectdiscovery/nuclei:latest', 'version': '3.x',
     'safe_args': ['-l', '-u', '-t', '-severity', '-o', '-silent']},
    {'name': 'nmap', 'display_name': 'Nmap', 'category': 'network',
     'description': 'Network port scanner',
     'docker_image': 'instrumentisto/nmap:latest', 'version': '7.x',
     'safe_args': ['-sV', '-sC', '-p', '--top-ports', '-oN', '-T']},
    {'name': 'sqlmap', 'display_name': 'SQLMap', 'category': 'web',
     'description': 'SQL injection tool',
     'docker_image': 'paoloo/sqlmap:latest', 'version': '1.7.x',
     'safe_args': ['-u', '--data', '--cookie', '--level', '--risk', '--technique', '--dbms', '--tamper', '--threads', '--batch']},
    {'name': 'ffuf', 'display_name': 'FFUF', 'category': 'web',
     'description': 'Fast web fuzzer',
     'docker_image': 'ghcr.io/ffuf/ffuf:latest', 'version': '2.x',
     'safe_args': ['-u', '-w', '-o', '-mc', '-fc', '-t']},
    {'name': 'dnsx', 'display_name': 'DNSX', 'category': 'recon',
     'description': 'DNS toolkit',
     'docker_image': 'projectdiscovery/dnsx:latest', 'version': '1.x',
     'safe_args': ['-d', '-l', '-resp', '-silent', '-o']},
    {'name': 'amass', 'display_name': 'Amass', 'category': 'recon',
     'description': 'Attack surface mapping',
     'docker_image': 'caffix/amass:latest', 'version': '4.x',
     'safe_args': ['enum', '-passive', '-d', '-o']},
    {'name': 'dalfox', 'display_name': 'Dalfox', 'category': 'web',
     'description': 'XSS hunter',
     'docker_image': 'hahwul/dalfox:latest', 'version': '2.x',
     'safe_args': ['url', '--no-spinner', '--output']},
    {'name': 'katana', 'display_name': 'Katana', 'category': 'recon',
     'description': 'Web crawler',
     'docker_image': 'projectdiscovery/katana:latest', 'version': '1.x',
     'safe_args': ['-u', '-silent', '-o', '-d']},
]

async def seed():
    engine = create_async_engine(settings.DATABASE_URL)
    s = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with s() as db:
        for td in TOOLS:
            r = await db.execute(select(ToolRegistry).where(ToolRegistry.name == td['name']))
            if not r.scalar_one_or_none():
                db.add(ToolRegistry(
                    id=str(uuid.uuid4()),
                    name=td['name'],
                    display_name=td['display_name'],
                    category=td['category'],
                    description=td.get('description'),
                    version=td.get('version'),
                    docker_image=td['docker_image'],
                    safe_args=td.get('safe_args', []),
                    allowed_roles=['admin', 'manager', 'pentester'],
                    health_status='unknown',
                    install_method='docker_image',
                    resource_limits={'cpu': 1.0, 'memory': '512m', 'timeout': 3600},
                ))
                print(f'Added: {td[\"name\"]}')
        await db.commit()
    await engine.dispose()
    print('Tools seeded!')

asyncio.run(seed())
"

# ─── STEP 8: Test API ─────────────────────────
echo "[8/8] Testing API..."
sleep 3

echo ""
echo "Testing health endpoint..."
curl -sf http://localhost/api/health && echo " OK" || echo " FAILED"

echo "Testing login..."
RESPONSE=$(curl -sf -X POST http://localhost/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"changeme"}' 2>&1)

if echo "$RESPONSE" | grep -q "access_token"; then
    echo " Login OK"
else
    echo " Login might have issues: $RESPONSE"
fi

echo ""
echo "=========================================="
echo " SETUP COMPLETE!"
echo "=========================================="
echo ""
echo "  Dashboard: http://192.168.1.10"
echo "  Login:     admin / changeme"
echo "  Grafana:   http://192.168.1.10:3001"
echo "  Prometheus:http://192.168.1.10:9090"
echo ""
echo "Jika login gagal, cek log:"
echo "  docker logs offensecops_backend --tail=30"
echo "=========================================="
