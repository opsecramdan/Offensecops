"""
Reports API — generate PDF pentest report dari scan findings + targets
"""
import uuid
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models import User, ScanJob, ScanFinding, Target, TargetGroup
from app.api.deps import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)


class ReportRequest(BaseModel):
    scan_job_ids: Optional[List[str]] = None   # specific scan jobs, or None = all
    target_ids: Optional[List[str]] = None      # specific targets, or None = all
    company: Optional[str] = "OffenSecOps"
    author: Optional[str] = "Red Team"
    title: Optional[str] = None
    include_info: bool = False                   # include info-severity findings


@router.post("/generate")
async def generate_report(
    req: ReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate PDF pentest report"""
    try:
        from app.services.report_generator import generate_pentest_report

        # ── Fetch findings ────────────────────────────────────
        findings_q = select(ScanFinding).where(
            ScanFinding.false_positive == False
        )
        if req.scan_job_ids:
            findings_q = findings_q.where(
                ScanFinding.scan_job_id.in_(req.scan_job_ids)
            )
        if not req.include_info:
            findings_q = findings_q.where(
                ScanFinding.severity.in_(['critical','high','medium','low'])
            )
        findings_q = findings_q.order_by(
            ScanFinding.scan_job_id, ScanFinding.created_at
        )
        findings_result = await db.execute(findings_q)
        db_findings = findings_result.scalars().all()

        findings = []
        for f in db_findings:
            findings.append({
                'id': str(f.id),
                'module': f.module or '',
                'severity': f.severity or 'info',
                'title': f.title or '',
                'description': f.description or '',
                'evidence': f.evidence or '',
                'host': f.host or '',
                'port': f.port,
                'protocol': f.protocol or '',
                'service': f.service or '',
                'cve_ids': f.cve_ids or [],
                'cvss_score': f.cvss_score,
                'cpe': f.cpe or '',
                'remediation': f.remediation or '',
                'owasp_category': f.owasp_category or '',
                'false_positive': f.false_positive,
                'created_at': str(f.created_at),
            })

        # ── Fetch targets ─────────────────────────────────────
        targets_q = select(Target).options(selectinload(Target.group))
        if req.target_ids:
            targets_q = targets_q.where(Target.id.in_(req.target_ids))
        else:
            targets_q = targets_q.limit(50)
        targets_result = await db.execute(targets_q)
        db_targets = targets_result.scalars().all()

        targets = []
        for t in db_targets:
            targets.append({
                'value': t.value or '',
                'ip_address': t.ip_address or 'N/A',
                'group': t.group.name if t.group else 'N/A',
                'status': t.status or 'active',
                'type': t.target_type or '',
            })

        # ── Fetch scan jobs ───────────────────────────────────
        jobs_q = select(ScanJob)
        if req.scan_job_ids:
            jobs_q = jobs_q.where(ScanJob.id.in_(req.scan_job_ids))
        else:
            jobs_q = jobs_q.order_by(ScanJob.created_at.desc()).limit(20)
        jobs_result = await db.execute(jobs_q)
        db_jobs = jobs_result.scalars().all()

        scan_jobs = [{'id': str(j.id), 'target': j.target,
                      'status': j.status, 'modules': j.modules or []}
                     for j in db_jobs]

        # ── Build primary target string ───────────────────────
        primary_target = 'Multiple Targets'
        if req.scan_job_ids and len(req.scan_job_ids) == 1 and scan_jobs:
            primary_target = scan_jobs[0]['target']
        elif targets and len(targets) == 1:
            primary_target = targets[0]['value']
        elif targets:
            primary_target = f'{targets[0]["value"]} (+{len(targets)-1} more)'

        meta = {
            'company': req.company or 'OffenSecOps',
            'author': req.author or 'Red Team',
            'target': primary_target,
            'title': req.title or 'Penetration Test Report',
        }

        logger.info(f"Generating report: {len(findings)} findings, {len(targets)} targets")

        pdf_bytes = generate_pentest_report(
            findings=findings,
            targets=targets,
            scan_jobs=scan_jobs,
            meta=meta,
        )

        filename = f"pentest_report_{primary_target.replace(' ','_').replace('/','_')[:30]}.pdf"

        return Response(
            content=pdf_bytes,
            media_type='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(pdf_bytes)),
                'X-Finding-Count': str(len(findings)),
                'X-Target-Count': str(len(targets)),
            }
        )

    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/preview")
async def report_preview(
    scan_job_ids: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Preview report stats before generating"""
    job_ids = scan_job_ids.split(',') if scan_job_ids else None

    findings_q = select(
        ScanFinding.severity,
        func.count(ScanFinding.id).label('count')
    ).where(ScanFinding.false_positive == False)
    if job_ids:
        findings_q = findings_q.where(ScanFinding.scan_job_id.in_(job_ids))
    findings_q = findings_q.group_by(ScanFinding.severity)
    result = await db.execute(findings_q)
    sev_counts = {row.severity: row.count for row in result}

    total = sum(sev_counts.values())
    rs = min(100, int(
        sev_counts.get('critical',0)*10 + sev_counts.get('high',0)*5 +
        sev_counts.get('medium',0)*2 + sev_counts.get('low',0)*0.5
    ))

    # OWASP coverage
    owasp_q = select(ScanFinding.owasp_category, func.count().label('c'))\
        .where(ScanFinding.false_positive == False)\
        .where(ScanFinding.owasp_category != None)\
        .where(ScanFinding.owasp_category != '')
    if job_ids:
        owasp_q = owasp_q.where(ScanFinding.scan_job_id.in_(job_ids))
    owasp_q = owasp_q.group_by(ScanFinding.owasp_category)
    owasp_result = await db.execute(owasp_q)
    owasp_coverage = {row.owasp_category: row.c for row in owasp_result}

    return {
        'total_findings': total,
        'severity_breakdown': sev_counts,
        'risk_score': rs,
        'owasp_categories_affected': len(owasp_coverage),
        'owasp_coverage': owasp_coverage,
    }
