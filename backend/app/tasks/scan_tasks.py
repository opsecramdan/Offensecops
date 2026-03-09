"""
Celery scan tasks — jalankan tools via DockerExecutor
"""
import asyncio
import json
import redis
import os
from datetime import datetime, timezone
from celery_worker import celery_app
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

# Sync DB untuk Celery (bukan async)
SYNC_DB_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://offensecops_user:changeme@postgres:5432/offensecops"
).replace("postgresql+asyncpg://", "postgresql+psycopg2://")

REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")

sync_engine = create_engine(SYNC_DB_URL, pool_pre_ping=True)


def get_sync_db():
    return Session(sync_engine)


def redis_publish(scan_job_id: str, data: dict):
    """Publish ke Redis pub/sub (sync versi untuk Celery)"""
    try:
        r = redis.from_url(REDIS_URL)
        r.publish(f"scan:output:{scan_job_id}", json.dumps(data))
        r.close()
    except Exception:
        pass


def update_scan_status(scan_job_id: str, status: str, progress: int = None,
                       error: str = None, raw_output: str = None):
    """Update status scan job di database (sync)"""
    from app.db.models import ScanJob
    with get_sync_db() as db:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if scan:
            scan.status = status
            if progress is not None:
                scan.progress = progress
            if error:
                scan.error_message = error
            if raw_output:
                scan.raw_output = raw_output
            if status == "running" and not scan.started_at:
                scan.started_at = datetime.now(timezone.utc)
            if status in ("completed", "failed", "cancelled"):
                scan.completed_at = datetime.now(timezone.utc)
            db.commit()


@celery_app.task(bind=True, queue="scan_queue", max_retries=0)
def run_scan(self, scan_job_id: str):
    """
    Main scan task — dijalankan oleh Celery worker.
    Fetches scan job dari DB, runs tools via DockerExecutor,
    streams output ke Redis pub/sub.
    """
    from app.db.models import ScanJob, ToolRegistry
    import subprocess, threading, time as _time

    class executor:
        @staticmethod
        def run_tool(tool_name, docker_image, cmd_args, scan_job_id,
                     output_callback, timeout=300):
            import shutil, time as t
            start = t.time()
            # Find binary
            binary = shutil.which(tool_name) or shutil.which(tool_name.replace('_','-'))
            if not binary:
                output_callback(f"[ERROR] {tool_name} not found in PATH")
                return {"exit_code": 1, "duration": 0, "success": False}
            cmd = [binary] + [str(a) for a in cmd_args]
            output_callback(f"[CMD] {' '.join(cmd)}")
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1
                )
                def read_output():
                    for line in proc.stdout:
                        output_callback(line.rstrip())
                thread = threading.Thread(target=read_output, daemon=True)
                thread.start()
                proc.wait(timeout=timeout)
                thread.join(timeout=5)
                duration = t.time() - start
                return {"exit_code": proc.returncode, "duration": duration, "success": proc.returncode == 0}
            except subprocess.TimeoutExpired:
                proc.kill()
                output_callback(f"[TIMEOUT] {tool_name} exceeded {timeout}s")
                return {"exit_code": -1, "duration": timeout, "success": False}
            except Exception as e:
                output_callback(f"[ERROR] {e}")
                return {"exit_code": 1, "duration": t.time()-start, "success": False}

    def validate_args(args): return args

    # ── Load scan job dari DB ──────────────────────────────────
    with get_sync_db() as db:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
        if not scan:
            return {"error": "Scan job not found"}

        # Cek apakah sudah di-cancel sebelum start
        if scan.status == "cancelled":
            return {"status": "cancelled"}

        tools_to_run = list(scan.tools or [])
        target = scan.target_value
        parameters = dict(scan.parameters or {})

    if not tools_to_run:
        update_scan_status(scan_job_id, "failed", error="No tools specified")
        return {"error": "No tools"}

    update_scan_status(scan_job_id, "running", progress=0)
    redis_publish(scan_job_id, {"type": "status", "status": "running", "progress": 0})

    all_output = []
    total_tools = len(tools_to_run)

    for idx, tool_name in enumerate(tools_to_run):
        # Cek apakah di-cancel
        with get_sync_db() as db:
            scan = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if scan and scan.status == "cancelled":
                redis_publish(scan_job_id, {"type": "status", "status": "cancelled"})
                return {"status": "cancelled"}

        # Ambil tool config dari registry
        with get_sync_db() as db:
            tool = db.query(ToolRegistry).filter(ToolRegistry.name == tool_name).first()

        if not tool or not tool.is_enabled:
            msg = f"[SKIP] Tool '{tool_name}' tidak ditemukan atau disabled"
            redis_publish(scan_job_id, {"type": "output", "tool": tool_name, "line": msg})
            all_output.append(msg)
            continue

        docker_image = tool.docker_image

        # ── Build command args ─────────────────────────────────
        # Jika cmd_args sudah ada di parameters (dari sqli module), pakai langsung
        if parameters.get("cmd_args"):
            cmd_args = parameters["cmd_args"]
        else:
            try:
                cmd_args = build_tool_args(tool_name, target, parameters)
            except ValueError as e:
                msg = f"[ERROR] Args validation failed untuk {tool_name}: {e}"
                redis_publish(scan_job_id, {"type": "output", "tool": tool_name, "line": msg})
                all_output.append(msg)
                continue

        # Progress update
        progress = int((idx / total_tools) * 90)
        update_scan_status(scan_job_id, "running", progress=progress)
        redis_publish(scan_job_id, {
            "type": "tool_start",
            "tool": tool_name,
            "progress": progress,
            "message": f"Starting {tool_name} against {target}",
        })

        tool_output = []

        def on_output(line: str):
            tool_output.append(line)
            all_output.append(line)
            redis_publish(scan_job_id, {
                "type": "output",
                "tool": tool_name,
                "line": line,
            })

        # ── Execute tool ──────────────────────────────────────
        result = executor.run_tool(
            tool_name=tool_name,
            docker_image=docker_image,
            cmd_args=cmd_args,
            scan_job_id=scan_job_id,
            output_callback=on_output,
            timeout=parameters.get("timeout", 300),
        )

        redis_publish(scan_job_id, {
            "type": "tool_done",
            "tool": tool_name,
            "exit_code": result["exit_code"],
            "duration": result["duration"],
            "success": result["success"],
        })

    # ── Selesai ───────────────────────────────────────────────
    full_output = "\n".join(all_output)
    update_scan_status(scan_job_id, "completed", progress=100, raw_output=full_output)
    redis_publish(scan_job_id, {"type": "done", "status": "completed", "progress": 100})

    return {"status": "completed", "scan_job_id": scan_job_id}


def build_tool_args(tool_name: str, target: str, params: dict) -> list:
    """
    Build command args list untuk setiap tool.
    TIDAK menggunakan shell string — selalu return list.
    """
    t = target

    if tool_name == "nmap":
        args = []
        flags = params.get("flags", ["-sV", "--open", "-T3"])
        ports = params.get("ports", "")
        args.extend(flags)
        if ports:
            args.extend(["-p", ports])
        args.append(t)
        return args

    elif tool_name == "masscan":
        ports = params.get("ports", "0-65535")
        rate = params.get("rate", "1000")
        return [t, "-p", ports, "--rate", rate]

    elif tool_name == "subfinder":
        args = ["-d", t, "-silent"]
        if params.get("recursive"):
            args.append("-recursive")
        if params.get("all_sources"):
            args.append("-all")
        return args

    elif tool_name == "httpx":
        args = ["-u", t, "-title", "-status-code", "-tech-detect", "-silent"]
        if params.get("follow_redirects"):
            args.append("-follow-redirects")
        return args

    elif tool_name == "nuclei":
        args = ["-u", t, "-silent"]
        severity = params.get("severity", "")
        if severity:
            args.extend(["-severity", severity])
        tags = params.get("tags", "")
        if tags:
            args.extend(["-tags", tags])
        return args

    elif tool_name == "sqlmap":
        url = params.get("url", t)
        args = ["-u", url, "--batch", "--output-dir", "/tmp/sqlmap"]
        level = params.get("level", "1")
        risk = params.get("risk", "1")
        technique = params.get("technique", "BEUSTQ")
        args.extend(["--level", str(level), "--risk", str(risk)])
        args.extend(["--technique", technique])
        if params.get("data"):
            args.extend(["--data", params["data"]])
        if params.get("cookie"):
            args.extend(["--cookie", params["cookie"]])
        if params.get("dbs"):
            args.append("--dbs")
        tamper = params.get("tamper", "")
        if tamper:
            args.extend(["--tamper", tamper])
        threads = params.get("threads", 1)
        args.extend(["--threads", str(threads)])
        return args

    elif tool_name == "ghauri":
        url = params.get("url", t)
        args = ["-u", url, "--batch"]
        level = params.get("level", "1")
        technique = params.get("technique", "BEUSTQ")
        args.extend(["--level", str(level), "--technique", technique])
        if params.get("data"):
            args.extend(["--data", params["data"]])
        if params.get("dbs"):
            args.append("--dbs")
        return args

    elif tool_name == "dalfox":
        url = params.get("url", t)
        args = ["url", url]
        if params.get("blind_xss"):
            args.extend(["-b", params["blind_xss"]])
        return args

    elif tool_name == "ffuf":
        url = params.get("url", t)
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        args = ["-u", url, "-w", wordlist, "-s"]
        threads = params.get("threads", 40)
        args.extend(["-t", str(threads)])
        extensions = params.get("extensions", "")
        if extensions:
            args.extend(["-e", extensions])
        return args

    elif tool_name == "dirsearch":
        args = ["-u", t, "--format", "plain", "-q"]
        extensions = params.get("extensions", "php,html,js,txt")
        args.extend(["-e", extensions])
        threads = params.get("threads", 20)
        args.extend(["-t", str(threads)])
        return args

    elif tool_name == "amass":
        return ["enum", "-d", t, "-passive", "-silent"]

    elif tool_name == "dnsx":
        return ["-d", t, "-a", "-resp", "-silent"]

    else:
        raise ValueError(f"No arg builder for tool: {tool_name}")
