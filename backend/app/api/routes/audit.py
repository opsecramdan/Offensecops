from typing import Optional
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import csv, io
from fastapi.responses import StreamingResponse

from app.db.session import get_db
from app.db.models import AuditLog, User
from app.api.deps import get_current_user

router = APIRouter()


def audit_to_dict(a: AuditLog) -> dict:
    return {
        "id": a.id, "user_id": a.user_id, "username": a.username,
        "action": a.action, "resource_type": a.resource_type,
        "resource_id": a.resource_id, "ip_address": a.ip_address,
        "response_code": a.response_code,
        "ts": a.ts.isoformat() if a.ts else None,
    }


@router.get("/")
async def list_audit_logs(
    username: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(AuditLog)
    if username:
        query = query.where(AuditLog.username.ilike(f"%{username}%"))
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))

    # Pentesters can only see their own logs
    if current_user.role == "pentester":
        query = query.where(AuditLog.user_id == current_user.id)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()

    query = query.order_by(AuditLog.ts.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return {"total": total, "items": [audit_to_dict(a) for a in logs]}


@router.get("/export")
async def export_audit_csv(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "auditor"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Only admin/auditor can export audit logs")

    result = await db.execute(select(AuditLog).order_by(AuditLog.ts.desc()).limit(10000))
    logs = result.scalars().all()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["ts", "username", "action", "resource_type", "resource_id", "ip_address", "response_code"])
    writer.writeheader()
    for log in logs:
        writer.writerow(audit_to_dict(log))

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )
