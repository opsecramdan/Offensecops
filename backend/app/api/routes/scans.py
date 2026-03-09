from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
import asyncio, json
from datetime import datetime, timezone

from app.db.session import get_db
from app.db.models import ScanJob, User
from app.api.deps import get_current_user

router = APIRouter()


class ScanCreate(BaseModel):
    target_value: str
    target_id: Optional[str] = None
    scan_mode: str = "custom"
    tools: List[str] = []
    parameters: dict = {}


def scan_to_dict(s: ScanJob) -> dict:
    return {
        "id": s.id, "celery_task_id": s.celery_task_id,
        "target_id": s.target_id, "target_value": s.target_value,
        "scan_mode": s.scan_mode, "status": s.status,
        "progress": s.progress, "tools": s.tools or [],
        "parameters": s.parameters or {},
        "error_message": s.error_message,
        "raw_output": s.raw_output,
        "created_by": s.created_by,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("/")
async def list_scans(
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(ScanJob)
    if status:
        query = query.where(ScanJob.status == status)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()

    query = query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()
    return {"total": total, "items": [scan_to_dict(s) for s in scans]}


@router.post("/", status_code=201)
async def create_scan(
    data: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not data.tools:
        raise HTTPException(status_code=400, detail="Pilih minimal satu tool")

    scan = ScanJob(
        target_value=data.target_value,
        target_id=data.target_id,
        scan_mode=data.scan_mode,
        tools=data.tools,
        parameters=data.parameters,
        status="queued",
        progress=0,
        created_by=current_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Submit ke Celery
    try:
        from app.tasks.scan_tasks import run_scan
        task = run_scan.apply_async(args=[scan.id], queue="scan_queue")
        scan.celery_task_id = task.id
        await db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.error_message = f"Failed to queue: {str(e)}"
        await db.commit()

    return scan_to_dict(scan)


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_to_dict(scan)


@router.delete("/{scan_id}")
async def delete_or_cancel_scan(
    scan_id: str,
    force: bool = Query(False, description="Force delete (permanent) regardless of status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Scan masih running/queued -> cancel dulu, lalu delete jika force
    if scan.status in ("queued", "running"):
        try:
            from app.services.docker_executor import executor
            executor.stop_scan(scan_id)
        except Exception:
            pass
        if not force:
            scan.status = "cancelled"
            await db.commit()
            return {"message": "Scan cancelled", "id": scan_id}

    # Delete permanen (force atau sudah completed/failed/cancelled)
    await db.delete(scan)
    await db.commit()
    return {"message": "Scan deleted", "id": scan_id}


@router.websocket("/ws/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """
    Real-time scan output via WebSocket + Redis pub/sub.
    Client connect ke ws://host/api/scans/ws/{scan_id}
    """
    await websocket.accept()

    try:
        import redis.asyncio as aioredis
        import os

        REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")
        channel = f"scan:output:{scan_id}"

        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r.pubsub()
        await pubsub.subscribe(channel)

        # Kirim status awal
        await websocket.send_json({"type": "connected", "scan_id": scan_id})

        # Juga kirim current status dari DB
        from app.db.session import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                await websocket.send_json({
                    "type": "status",
                    "status": scan.status,
                    "progress": scan.progress,
                })
                # Kalau sudah done, kirim output history
                if scan.status in ("completed", "failed", "cancelled") and scan.raw_output:
                    for line in scan.raw_output.split("\n")[:100]:
                        await websocket.send_json({"type": "output", "line": line})
                    await websocket.send_json({"type": "done", "status": scan.status})
                    return

        # Stream real-time dari Redis pub/sub
        async def listen():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                    if data.get("type") == "done":
                        return

        # Timeout 35 menit
        try:
            await asyncio.wait_for(listen(), timeout=2100)
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "error", "message": "WebSocket timeout"})

        await pubsub.unsubscribe(channel)
        await r.aclose()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
