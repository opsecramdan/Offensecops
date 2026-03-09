from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
import csv, io, json

from app.db.session import get_db
from app.db.models import Vulnerability, ScanJob, User
from app.api.deps import get_current_user

router = APIRouter()

SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "informational": 365}


# ── Schemas ──────────────────────────────────────────────────
class VulnCreate(BaseModel):
    title: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: str = "medium"
    cve_ids: List[str] = []
    cwe_ids: List[str] = []
    mitre_techniques: List[str] = []
    affected_asset: Optional[str] = None
    scan_job_id: Optional[str] = None
    remediation_notes: Optional[str] = None
    references: List[str] = []
    evidence: dict = {}


class VulnUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    is_false_positive: Optional[bool] = None
    fp_reason: Optional[str] = None
    remediation_notes: Optional[str] = None
    assigned_to: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    references: Optional[List[str]] = None
    evidence: Optional[dict] = None


def sla_days_left(v: Vulnerability) -> Optional[int]:
    if not v.sla_due_date:
        return None
    now = datetime.now(timezone.utc)
    delta = v.sla_due_date - now
    return delta.days


def vuln_to_dict(v: Vulnerability) -> dict:
    now = datetime.now(timezone.utc)
    days_left = sla_days_left(v)
    return {
        "id": v.id,
        "title": v.title,
        "description": v.description,
        "cvss_score": v.cvss_score,
        "cvss_vector": v.cvss_vector,
        "severity": v.severity,
        "cve_ids": v.cve_ids or [],
        "cwe_ids": v.cwe_ids or [],
        "mitre_techniques": v.mitre_techniques or [],
        "affected_asset": v.affected_asset,
        "scan_job_id": v.scan_job_id,
        "status": v.status,
        "is_false_positive": v.is_false_positive,
        "fp_reason": v.fp_reason,
        "sla_due_date": v.sla_due_date.isoformat() if v.sla_due_date else None,
        "sla_days_left": days_left,
        "sla_breached": (days_left is not None and days_left < 0 and v.status != "resolved"),
        "remediation_notes": v.remediation_notes,
        "assigned_to": v.assigned_to,
        "resolved_at": v.resolved_at.isoformat() if v.resolved_at else None,
        "evidence": v.evidence or {},
        "references": v.references or [],
        "created_at": v.created_at.isoformat() if v.created_at else None,
        "updated_at": v.updated_at.isoformat() if v.updated_at else None,
    }


# ── Routes ───────────────────────────────────────────────────
@router.get("/stats")
async def vuln_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability))
    vulns = result.scalars().all()
    now = datetime.now(timezone.utc)

    stats = {
        "total": len(vulns),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
        "by_status": {"open": 0, "in_remediation": 0, "false_positive": 0, "resolved": 0},
        "sla_breached": 0,
        "sla_due_soon": 0,  # due dalam 7 hari
    }

    for v in vulns:
        if v.severity in stats["by_severity"]:
            stats["by_severity"][v.severity] += 1
        if v.status in stats["by_status"]:
            stats["by_status"][v.status] += 1
        if v.sla_due_date and v.status not in ("resolved", "false_positive"):
            days = (v.sla_due_date - now).days
            if days < 0:
                stats["sla_breached"] += 1
            elif days <= 7:
                stats["sla_due_soon"] += 1

    return stats


@router.get("/")
async def list_vulns(
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    asset: Optional[str] = Query(None),
    scan_job_id: Optional[str] = Query(None),
    sla_breached: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    sort_by: str = Query("created_at"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Vulnerability)

    if search:
        query = query.where(or_(
            Vulnerability.title.ilike(f"%{search}%"),
            Vulnerability.affected_asset.ilike(f"%{search}%"),
            Vulnerability.description.ilike(f"%{search}%"),
        ))
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    if asset:
        query = query.where(Vulnerability.affected_asset.ilike(f"%{asset}%"))
    if scan_job_id:
        query = query.where(Vulnerability.scan_job_id == scan_job_id)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()

    # Sort
    sort_col = {
        "cvss_score": Vulnerability.cvss_score.desc().nullslast(),
        "severity": Vulnerability.severity,
        "created_at": Vulnerability.created_at.desc(),
        "sla_due_date": Vulnerability.sla_due_date.asc().nullslast(),
    }.get(sort_by, Vulnerability.created_at.desc())

    query = query.order_by(sort_col).offset(skip).limit(limit)
    result = await db.execute(query)
    vulns = result.scalars().all()

    items = [vuln_to_dict(v) for v in vulns]

    # Filter sla_breached post-query
    if sla_breached is not None:
        items = [v for v in items if v["sla_breached"] == sla_breached]

    return {"total": total, "items": items, "skip": skip, "limit": limit}


@router.post("/", status_code=201)
async def create_vuln(
    data: VulnCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sla_days = SLA_DAYS.get(data.severity, 90)
    sla_due = datetime.now(timezone.utc) + timedelta(days=sla_days)

    vuln = Vulnerability(
        title=data.title,
        description=data.description,
        cvss_score=data.cvss_score,
        cvss_vector=data.cvss_vector,
        severity=data.severity,
        cve_ids=data.cve_ids,
        cwe_ids=data.cwe_ids,
        mitre_techniques=data.mitre_techniques,
        affected_asset=data.affected_asset,
        scan_job_id=data.scan_job_id,
        remediation_notes=data.remediation_notes,
        references=data.references,
        evidence=data.evidence,
        sla_due_date=sla_due,
        status="open",
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)
    return vuln_to_dict(vuln)


@router.post("/import/scan/{scan_job_id}", status_code=201)
async def import_from_scan(
    scan_job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Parse raw output dari scan job dan import sebagai vulnerabilities"""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if not scan.raw_output:
        raise HTTPException(status_code=400, detail="Scan job has no output to import")

    created = []
    lines = scan.raw_output.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Try parse JSON (nuclei output format)
        try:
            data = json.loads(line)
            if "info" in data and "name" in data.get("info", {}):
                info = data["info"]
                severity = info.get("severity", "informational").lower()
                if severity not in SLA_DAYS:
                    severity = "informational"

                sla_due = datetime.now(timezone.utc) + timedelta(days=SLA_DAYS[severity])
                vuln = Vulnerability(
                    title=info.get("name", "Unknown Finding"),
                    description=info.get("description", ""),
                    severity=severity,
                    affected_asset=data.get("host", scan.target_value),
                    scan_job_id=scan_job_id,
                    cve_ids=info.get("classification", {}).get("cve-id", []) or [],
                    cwe_ids=[str(c) for c in (info.get("classification", {}).get("cwe-id", []) or [])],
                    references=info.get("reference", []) or [],
                    evidence={"matched": data.get("matched-at", ""), "template": data.get("template-id", "")},
                    sla_due_date=sla_due,
                    status="open",
                )
                db.add(vuln)
                created.append(info.get("name", "Unknown"))
                continue
        except (json.JSONDecodeError, KeyError):
            pass

        # Heuristic: detect open ports dari nmap output
        if "open" in line and "/tcp" in line:
            parts = line.split()
            port_info = parts[0] if parts else ""
            service = parts[2] if len(parts) > 2 else "unknown"
            if port_info:
                sla_due = datetime.now(timezone.utc) + timedelta(days=SLA_DAYS["low"])
                vuln = Vulnerability(
                    title=f"Open Port: {port_info} ({service})",
                    description=f"Open port detected: {line}",
                    severity="low",
                    affected_asset=scan.target_value,
                    scan_job_id=scan_job_id,
                    sla_due_date=sla_due,
                    status="open",
                )
                db.add(vuln)
                created.append(f"Open Port: {port_info}")

    await db.commit()
    return {"imported": len(created), "findings": created}


@router.get("/{vuln_id}")
async def get_vuln(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln_to_dict(vuln)


@router.patch("/{vuln_id}")
async def update_vuln(
    vuln_id: str,
    data: VulnUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    for field, val in data.model_dump(exclude_none=True).items():
        setattr(vuln, field, val)

    # Auto-set resolved_at
    if data.status == "resolved" and not vuln.resolved_at:
        vuln.resolved_at = datetime.now(timezone.utc)
    elif data.status and data.status != "resolved":
        vuln.resolved_at = None

    # Recalculate SLA if severity changed
    if data.severity and data.severity in SLA_DAYS:
        sla_days = SLA_DAYS[data.severity]
        base = vuln.created_at or datetime.now(timezone.utc)
        vuln.sla_due_date = base + timedelta(days=sla_days)

    if data.is_false_positive:
        vuln.fp_marked_by = current_user.id
        vuln.status = "false_positive"

    await db.commit()
    await db.refresh(vuln)
    return vuln_to_dict(vuln)


@router.delete("/{vuln_id}", status_code=204)
async def delete_vuln(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    await db.delete(vuln)
    await db.commit()


@router.get("/export/csv")
async def export_csv(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(Vulnerability)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)

    result = await db.execute(query.order_by(Vulnerability.cvss_score.desc().nullslast()))
    vulns = result.scalars().all()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "title", "severity", "cvss_score", "affected_asset",
        "status", "sla_due_date", "cve_ids", "created_at"
    ])
    writer.writeheader()
    for v in vulns:
        writer.writerow({
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": v.cvss_score or "",
            "affected_asset": v.affected_asset or "",
            "status": v.status,
            "sla_due_date": v.sla_due_date.isoformat() if v.sla_due_date else "",
            "cve_ids": ",".join(v.cve_ids or []),
            "created_at": v.created_at.isoformat() if v.created_at else "",
        })

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )
