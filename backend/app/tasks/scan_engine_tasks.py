"""
Scan Engine Tasks — orchestrate modular scans via Celery
"""
import asyncio
import logging
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from celery_worker import celery_app
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
import os

# scan_modules imported lazily inside tasks to avoid docker init at import time
from app.db.models import ScanJob, ScanFinding

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "").replace("+asyncpg", "+asyncpg")


def get_async_session():
    engine = create_async_engine(DATABASE_URL, echo=False)
    return sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def gen_id():
    return str(uuid.uuid4())


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="app.tasks.scan_engine_tasks.run_full_scan",
    queue="scan_queue",
    max_retries=0,
    time_limit=3600,
)
def run_full_scan(self, scan_job_id: str, target: str, modules: List[str], options: dict):
    """
    Orchestrate full modular scan.
    modules: list from [port_scan, web_scan, ssl_tls, headers, subdomain, dns, cve_match]
    """
    return run_async(_run_full_scan_async(self, scan_job_id, target, modules, options))


async def _run_full_scan_async(task, scan_job_id, target, modules, options):
    from app.services.scan_modules import (
        module_port_scan, module_web_scan, module_ssl_scan,
        module_security_headers, module_subdomain_recon,
        module_dns_check, module_cve_match, map_owasp_compliance,
    )
    SessionLocal = get_async_session()

    async with SessionLocal() as db:
        # Update scan job status
        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
        job = result.scalar_one_or_none()
        if not job:
            logger.error(f"ScanJob {scan_job_id} not found")
            return {"error": "Job not found"}

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await db.commit()

        all_findings = []
        total_modules = len(modules)
        completed = 0
        services_found = []  # for CVE matching

        try:
            for module_name in modules:
                logger.info(f"[{scan_job_id}] Running module: {module_name}")

                # Update progress
                job.progress = int((completed / total_modules) * 90)
                await db.commit()

                module_findings = []
                try:
                    if module_name == "port_scan":
                        module_findings = await module_port_scan(target, options)
                        # Extract services for CVE matching
                        for f in module_findings:
                            if f.get("service") and f.get("port"):
                                services_found.append({
                                    "service": f["service"],
                                    "version": "",
                                    "port": f["port"],
                                })

                    elif module_name == "web_scan":
                        module_findings = await module_web_scan(target, options)

                    elif module_name == "ssl_tls":
                        module_findings = await module_ssl_scan(target, options)

                    elif module_name == "headers":
                        module_findings = await module_security_headers(target, options)

                    elif module_name == "subdomain":
                        module_findings = await module_subdomain_recon(target, options)

                    elif module_name == "dns":
                        module_findings = await module_dns_check(target, options)

                    elif module_name == "cve_match" and services_found:
                        module_findings = await module_cve_match(target, services_found, db)

                except Exception as e:
                    logger.error(f"Module {module_name} failed: {e}", exc_info=True)
                    module_findings = [{
                        "module": module_name, "severity": "info",
                        "title": f"Module {module_name} error",
                        "target_value": target, "description": str(e)[:500],
                        "evidence": "", "host": target, "port": None,
                        "protocol": "", "service": "", "cve_ids": [],
                        "cvss_score": None, "cpe": "", "remediation": "",
                        "owasp_category": "", "false_positive": False,
                    }]

                # Save findings to DB
                for f in module_findings:
                    finding = ScanFinding(
                        id=gen_id(),
                        scan_job_id=scan_job_id,
                        target_value=f.get("target_value", target),
                        module=f.get("module", module_name),
                        severity=f.get("severity", "info"),
                        title=f.get("title", "Finding"),
                        description=f.get("description", ""),
                        evidence=f.get("evidence", ""),
                        host=f.get("host", target),
                        port=f.get("port"),
                        protocol=f.get("protocol", ""),
                        service=f.get("service", ""),
                        cve_ids=f.get("cve_ids", []),
                        cvss_score=f.get("cvss_score"),
                        cpe=f.get("cpe", ""),
                        remediation=f.get("remediation", ""),
                        owasp_category=f.get("owasp_category", ""),
                        false_positive=f.get("false_positive", False),
                    )
                    db.add(finding)
                    all_findings.append(f)

                await db.commit()
                completed += 1

            # Calculate risk score
            sev_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
            risk_score = sum(sev_weights.get(f.get("severity", "info"), 0) for f in all_findings)
            risk_score = min(round(risk_score, 1), 100)

            # OWASP mapping
            owasp = map_owasp_compliance(all_findings)

            # Summary
            summary = {
                "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
                "high":     sum(1 for f in all_findings if f.get("severity") == "high"),
                "medium":   sum(1 for f in all_findings if f.get("severity") == "medium"),
                "low":      sum(1 for f in all_findings if f.get("severity") == "low"),
                "info":     sum(1 for f in all_findings if f.get("severity") == "info"),
                "total":    len(all_findings),
                "risk_score": risk_score,
                "modules_run": modules,
                "owasp_coverage": {k: v["count"] for k, v in owasp.items() if v["count"] > 0},
            }

            # Update job
            job.status = "completed"
            job.progress = 100
            job.finished_at = datetime.now(timezone.utc)
            job.result_summary = summary
            await db.commit()

            logger.info(f"[{scan_job_id}] Scan complete — {len(all_findings)} findings, risk={risk_score}")
            return summary

        except Exception as e:
            logger.error(f"Scan engine error: {e}", exc_info=True)
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return {"error": str(e)}


@celery_app.task(
    name="app.tasks.scan_engine_tasks.ingest_nvd_feed",
    queue="scan_queue",
    max_retries=1,
    time_limit=3600,
)
def ingest_nvd_feed(years: List[int] = None):
    """Ingest NVD CVE feeds for given years"""
    if years is None:
        from datetime import datetime
        current_year = datetime.now().year
        years = list(range(current_year - 2, current_year + 1))
    return run_async(_ingest_nvd_async(years))


async def _ingest_nvd_async(years: List[int]):
    from app.services.cve_service import fetch_nvd_feed_year, fetch_kev_list, parse_nvd_item
    from app.db.models import CVECache, NVDIngestionLog

    SessionLocal = get_async_session()
    total_inserted = 0

    # Fetch KEV list once
    kev_set = await fetch_kev_list()
    logger.info(f"KEV list loaded: {len(kev_set)} entries")

    async with SessionLocal() as db:
        for year in years:
            log = NVDIngestionLog(
                id=gen_id(), feed_year=year, status="running",
                started_at=datetime.now(timezone.utc)
            )
            db.add(log)
            await db.commit()

            try:
                items = await fetch_nvd_feed_year(year)
                inserted = 0

                for item in items:
                    try:
                        parsed = parse_nvd_item(item, kev_set)
                        if not parsed["cve_id"]:
                            continue

                        # Check if exists
                        existing = await db.execute(
                            select(CVECache).where(CVECache.cve_id == parsed["cve_id"])
                        )
                        if existing.scalar_one_or_none():
                            continue

                        cve = CVECache(
                            id=gen_id(),
                            **{k: v for k, v in parsed.items()
                               if k not in ("raw_data",)},
                            raw_data={},
                        )
                        db.add(cve)
                        inserted += 1

                        # Batch commit every 500
                        if inserted % 500 == 0:
                            await db.commit()
                            logger.info(f"Year {year}: {inserted}/{len(items)} inserted")

                    except Exception as e:
                        logger.warning(f"CVE parse error: {e}")
                        continue

                await db.commit()
                total_inserted += inserted

                log.status = "done"
                log.cve_count = inserted
                log.finished_at = datetime.now(timezone.utc)
                await db.commit()
                logger.info(f"NVD {year}: {inserted} CVEs ingested")

            except Exception as e:
                logger.error(f"NVD feed {year} failed: {e}")
                log.status = "failed"
                log.error_msg = str(e)[:500]
                log.finished_at = datetime.now(timezone.utc)
                await db.commit()

    return {"total_inserted": total_inserted, "years": years}
