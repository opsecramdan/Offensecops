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
def check_sla_breaches():
    from app.db.models import Vulnerability

    now = datetime.now(timezone.utc)
    with Session(sync_engine) as db:
        open_vulns = db.query(Vulnerability).filter(
            Vulnerability.status == "open",
            Vulnerability.sla_due_date != None,
            Vulnerability.sla_due_date < now,
        ).all()

        breached = len(open_vulns)
        return {"sla_breached": breached}
