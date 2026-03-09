from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from app.db.session import get_db
from app.db.models import Target, ScanJob, Vulnerability, ToolRegistry, AuditLog, User, ScanFinding, CVECache
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)

    # Basic counts
    total_targets = (await db.execute(select(func.count()).select_from(Target))).scalar()
    active_scans = (await db.execute(
        select(func.count()).select_from(ScanJob).where(ScanJob.status.in_(["running", "queued"]))
    )).scalar()
    total_scans = (await db.execute(select(func.count()).select_from(ScanJob))).scalar()
    completed_scans = (await db.execute(
        select(func.count()).select_from(ScanJob).where(ScanJob.status == "completed")
    )).scalar()

    # Vulnerability model stats
    vuln_result = await db.execute(select(Vulnerability))
    vulns = vuln_result.scalars().all()
    resolved_vulns = sum(1 for v in vulns if v.status == "resolved")
    sla_breached   = sum(1 for v in vulns if v.sla_due_date and v.sla_due_date < now and v.status not in ("resolved", "false_positive"))

    # Scan findings stats
    sf_result = await db.execute(
        select(ScanFinding.severity, func.count(ScanFinding.id).label("cnt"))
        .where(ScanFinding.false_positive == False)
        .group_by(ScanFinding.severity)
    )
    sf_counts = {row.severity: row.cnt for row in sf_result}
    sf_total     = sum(sf_counts.values())
    critical_vulns = sf_counts.get("critical", 0) + sum(1 for v in vulns if v.severity == "critical" and v.status != "resolved")
    high_vulns     = sf_counts.get("high", 0)     + sum(1 for v in vulns if v.severity == "high"     and v.status != "resolved")
    medium_vulns   = sf_counts.get("medium", 0)   + sum(1 for v in vulns if v.severity == "medium"   and v.status != "resolved")
    low_vulns      = sf_counts.get("low", 0)      + sum(1 for v in vulns if v.severity == "low"      and v.status != "resolved")
    total_vulns    = critical_vulns + high_vulns + medium_vulns + low_vulns + sf_counts.get("info", 0)

    risk_score = min(100, int(
        sf_counts.get("critical", 0) * 10 +
        sf_counts.get("high", 0) * 5 +
        sf_counts.get("medium", 0) * 2 +
        sf_counts.get("low", 0) * 0.5
    ))

    # CVE database count
    try:
        cve_count = (await db.execute(select(func.count()).select_from(CVECache))).scalar()
    except Exception:
        cve_count = 0

    # Tools
    tools_result = await db.execute(select(ToolRegistry))
    tools = tools_result.scalars().all()
    tools_healthy = sum(1 for t in tools if t.health_status == "healthy" and t.is_enabled)
    tools_total   = sum(1 for t in tools if t.is_enabled)

    # Recent scans
    recent_result = await db.execute(
        select(ScanJob).order_by(ScanJob.created_at.desc()).limit(10)
    )
    recent_scans = recent_result.scalars().all()

    return {
        "total_targets":   total_targets,
        "active_scans":    active_scans,
        "total_vulns":     total_vulns,
        "critical_vulns":  critical_vulns,
        "high_vulns":      high_vulns,
        "medium_vulns":    medium_vulns,
        "low_vulns":       low_vulns,
        "resolved_vulns":  resolved_vulns,
        "sla_breached":    sla_breached,
        "tools_healthy":   tools_healthy,
        "tools_total":     tools_total,
        "total_scans":     total_scans,
        "completed_scans": completed_scans,
        "risk_score":      risk_score,
        "cve_database":    cve_count or 0,
        "scan_findings": {
            "total":    sf_total,
            "critical": sf_counts.get("critical", 0),
            "high":     sf_counts.get("high", 0),
            "medium":   sf_counts.get("medium", 0),
            "low":      sf_counts.get("low", 0),
            "info":     sf_counts.get("info", 0),
        },
        "recent_scans": [
            {
                "id": s.id,
                "target": s.target_value,
                "status": s.status,
                "tools": s.tools or [],
                "progress": s.progress,
                "started": s.created_at.isoformat() if s.created_at else None,
            }
            for s in recent_scans
        ],
    }


@router.get("/vuln-trend")
async def vuln_trend(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Vulnerability discovery trend per hari (30 hari terakhir)"""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    result = await db.execute(
        select(Vulnerability).where(Vulnerability.created_at >= since)
    )
    vulns = result.scalars().all()

    # Group by date + severity
    daily: dict = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0})
    for v in vulns:
        if v.created_at:
            day = v.created_at.strftime("%b %d")
            sev = v.severity or "informational"
            if sev in daily[day]:
                daily[day][sev] += 1

    # Build ordered list for last N days
    trend = []
    for i in range(days - 1, -1, -1):
        day = (now - timedelta(days=i)).strftime("%b %d")
        entry = {"date": day, **daily[day]}
        # Only include days that have data OR last 14 days
        if any(daily[day][s] > 0 for s in ["critical", "high", "medium", "low"]) or i < 14:
            trend.append(entry)

    return trend


@router.get("/scan-activity")
async def scan_activity(
    days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan activity per hari (7 hari terakhir)"""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    result = await db.execute(
        select(ScanJob).where(ScanJob.created_at >= since)
    )
    scans = result.scalars().all()

    daily: dict = defaultdict(lambda: {"total": 0, "completed": 0, "failed": 0, "running": 0})
    for s in scans:
        if s.created_at:
            day = s.created_at.strftime("%a")
            daily[day]["total"] += 1
            if s.status in daily[day]:
                daily[day][s.status] += 1

    # Last 7 days in order
    activity = []
    for i in range(days - 1, -1, -1):
        day = (now - timedelta(days=i)).strftime("%a")
        date_label = (now - timedelta(days=i)).strftime("%b %d")
        activity.append({"day": day, "date": date_label, **daily[day]})

    return activity


@router.get("/recent-activity")
async def recent_activity(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Recent audit log events"""
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
    )
    logs = result.scalars().all()

    return [
        {
            "id": l.id,
            "username": l.username,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "ts": l.ts.isoformat() if l.ts else None,
        }
        for l in logs
    ]


@router.get("/tool-health")
async def tool_health(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Status kesehatan semua tools"""
    result = await db.execute(
        select(ToolRegistry).where(ToolRegistry.is_enabled == True).order_by(ToolRegistry.category, ToolRegistry.name)
    )
    tools = result.scalars().all()

    return [
        {
            "id": t.id,
            "name": t.name,
            "display_name": t.display_name or t.name,
            "category": t.category,
            "docker_image": t.docker_image,
            "health_status": t.health_status,
            "health_fail_count": t.health_fail_count or 0,
            "last_health_check": t.last_health_check.isoformat() if t.last_health_check else None,
        }
        for t in tools
    ]
