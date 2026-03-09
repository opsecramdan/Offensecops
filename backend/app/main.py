from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import os
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.config import settings
from app.db.session import init_db
from app.api.routes import auth, targets, scans, sqli, vulns, tools, reports, audit, dashboard, users, advanced_tools, scan_engine, vuln_mgmt, poc


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    print("✅ OffenSecOps Backend started")
    yield
    # Shutdown
    print("🛑 OffenSecOps Backend shutting down")


app = FastAPI(
    title="OffenSecOps API",
    description="Enterprise Offensive Security Operations Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Metrics
Instrumentator().instrument(app).expose(app)

# Routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(sqli.router, prefix="/api/sqli", tags=["sqli"])
app.include_router(vulns.router, prefix="/api/vulns", tags=["vulns"])
app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(advanced_tools.router, prefix="/api/advanced-tools", tags=["advanced-tools"])
app.include_router(scan_engine.router, prefix="/api/scan-engine", tags=["scan-engine"])
# Ensure upload dirs exist
os.makedirs("/app/uploads/poc_evidence", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="/app/uploads"), name="uploads")

app.include_router(vuln_mgmt.router, prefix="/api/vuln-mgmt", tags=["vuln-mgmt"])
app.include_router(poc.router, prefix="/api", tags=["poc"])


@app.get("/api/health")
async def health():
    return {"status": "operational", "version": "1.0.0"}
