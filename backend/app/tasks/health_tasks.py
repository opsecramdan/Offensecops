"""
Tool health check tasks — jalankan setiap 15 menit via Celery Beat
"""
from celery_worker import celery_app
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import os

SYNC_DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://offensecops_user:changeme@postgres:5432/offensecops"
).replace("postgresql+asyncpg://", "postgresql+psycopg2://")

sync_engine = create_engine(SYNC_DB_URL, pool_pre_ping=True)


@celery_app.task(queue="scan_queue")
def check_all_tools():
    """Check health status semua tool di registry"""
    from app.db.models import ToolRegistry
    try:
        from app.services.docker_executor import get_docker_client
    except Exception:
        get_docker_client = None

    with Session(sync_engine) as db:
        tools = db.query(ToolRegistry).filter(ToolRegistry.is_enabled == True).all()
        results = {}

        for tool in tools:
            try:
                client = get_docker_client()
                is_healthy = bool(client.images.list(tool.docker_image))
            except Exception:
                is_healthy = False
            tool.health_status = "healthy" if is_healthy else "unknown"
            tool.last_health_check = datetime.now(timezone.utc)
            if not is_healthy:
                tool.health_fail_count = (tool.health_fail_count or 0) + 1
            else:
                tool.health_fail_count = 0
            results[tool.name] = tool.health_status

        db.commit()

    return results


@celery_app.task(queue="scan_queue")
def cleanup_stale_scans():
    """Mark scans yang stuck di 'running' lebih dari 2 jam sebagai failed"""
    from app.db.models import ScanJob
    from datetime import timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
    with Session(sync_engine) as db:
        stale = db.query(ScanJob).filter(
            ScanJob.status == "running",
            ScanJob.started_at < cutoff
        ).all()

        for scan in stale:
            scan.status = "failed"
            scan.error_message = "Scan timed out (2 hour limit)"
            scan.completed_at = datetime.now(timezone.utc)

        db.commit()
        return {"cleaned": len(stale)}
