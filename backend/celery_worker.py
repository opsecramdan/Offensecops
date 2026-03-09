from celery import Celery
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")

celery_app = Celery(
    "offensecops",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.health_tasks",
        "app.tasks.sla_tasks",
        "app.tasks.scan_engine_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.tasks.scan_tasks.*": {"queue": "scan_queue"},
        "app.tasks.health_tasks.*": {"queue": "scan_queue"},
        "app.tasks.sla_tasks.*": {"queue": "scan_queue"},
        "app.tasks.scan_engine_tasks.*": {"queue": "scan_queue"},
    },
)

celery_app.conf.beat_schedule = {
    "tool-health-check": {
        "task": "app.tasks.health_tasks.check_all_tools",
        "schedule": 900.0,
    },
    "sla-breach-check": {
        "task": "app.tasks.sla_tasks.check_sla_breaches",
        "schedule": 3600.0,
    },
    "cleanup-stale-scans": {
        "task": "app.tasks.health_tasks.cleanup_stale_scans",
        "schedule": 3600.0,
    },
}

celery_app.conf.redbeat_redis_url = REDIS_URL
