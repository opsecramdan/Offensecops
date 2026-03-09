"""
Scan Modules — each module runs a tool and returns normalized findings
"""
import re
import json
import logging
import asyncio
import httpx
import ssl
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.services.docker_executor import run_container as _run_container

async def run_container(**kwargs):
    """Wrapper: convert tuple return to dict for backward compat"""
    exit_code, stdout, stderr = await _run_container(**kwargs)
    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }

logger = logging.getLogger(__name__)


def make_finding(module, severity, title, target, description="", evidence="",
                 host="", port=None, protocol="", service="", cve_ids=None,
                 cvss_score=None, cpe="", remediation="", owasp=None) -> dict:
    return {
        "module": module, "severity": severity, "title": title,
        "target_value": target, "description": description, "evidence": evidence,
        "host": host or target, "port": port, "protocol": protocol,
        "service": service, "cve_ids": cve_ids or [], "cvss_score": cvss_score,
        "cpe": cpe, "remediation": remediation, "owasp_category": owasp or "",
        "false_positive": False,
    }


# ── MODULE 1: Port Scan (nmap) ────────────────────────────────
async def module_port_scan(target: str, options: dict) -> List[dict]:
    findings = []
    ports = options.get("ports", "1-1000,8080,8443,8888")
    cmd = f"-sV -sC --open -T4 -p {ports} {target} -oX -"

    result = await run_container(
        image="instrumentisto/nmap:latest",
        cmd=["nmap"] + cmd.split(),
        timeout=int(options.get("timeout", 180)),
        mem_limit="256m",
    )

    if not result["success"] and not result["stdout"]:
        return [make_finding("port_scan", "info", "Port scan failed", target,
                             description=result["stderr"][:500])]

    output = result["stdout"]

    # Parse nmap XML-like output — extract open ports
    port_pattern = re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)".*?'
        r'<state state="open".*?'
        r'<service name="([^"]*)"[^/]*/?>(?:.*?<product>([^<]*)</product>)?(?:.*?<version>([^<]*)</version>)?',
        output, re.DOTALL
    )

    open_ports = []
    for m in port_pattern:
        protocol, port, service, product, version = m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5) or ""
        full_service = f"{product} {version}".strip() or service
        open_ports.append((protocol, int(port), service, full_service))

        sev = "info"
        if int(port) in [21, 23, 25, 110, 143, 3389, 445, 139]:
            sev = "medium"
        if service in ["ssh", "ftp", "telnet"]:
            sev = "low" if int(port) == 22 else "medium"

        findings.append(make_finding(
            "port_scan", sev,
            f"Open port {port}/{protocol} — {full_service or service}",
            target,
            description=f"Port {port}/{protocol} is open running {full_service or service}",
            evidence=f"{target}:{port}/{protocol} [{full_service or service}]",
            host=target, port=int(port), protocol=protocol, service=full_service or service,
            remediation=f"Review if port {port} needs to be exposed. Restrict with firewall rules if not required.",
        ))

    # Summary finding if no open ports found
    if not open_ports:
        findings.append(make_finding(
            "port_scan", "info", "No open ports found in range",
            target, evidence=output[:500]
        ))

    return findings


# ── MODULE 2: Service Version + CVE Match ────────────────────
async def module_cve_match(target: str, services: List[dict], db_session) -> List[dict]:
    """Match discovered services against CVE cache"""
    findings = []
    if not services:
        return findings

    from sqlalchemy import select, or_
    from app.db.models import CVECache

    for svc in services:
        service_name = svc.get("service", "")
        version = svc.get("version", "")
        port = svc.get("port")
        if not service_name:
            continue

        # Query CVE cache for matching CPE
        terms = [service_name.lower()]
        if version:
            terms.append(version.lower())

        # Build search conditions
        conditions = [CVECache.cpe_matches.any(service_name.lower())]
        result = await db_session.execute(
            select(CVECache)
            .where(CVECache.severity.in_(["critical", "high", "medium"]))
            .limit(5)
        )
        # Simple heuristic match
        cves = result.scalars().all()
        for cve in cves:
            for cpe in (cve.cpe_matches or []):
                if service_name.lower() in cpe.lower():
                    if not version or version.split(".")[0] in cpe:
                        findings.append(make_finding(
                            "cve_match",
                            cve.severity or "medium",
                            f"{cve.cve_id} — {service_name} {version}",
                            target,
                            description=cve.description or "",
                            host=target, port=port, service=service_name,
                            cve_ids=[cve.cve_id],
                            cvss_score=cve.cvss_v3_score or cve.cvss_v2_score,
                            cpe=cpe,
                            remediation=f"Update {service_name} to latest version. Check vendor advisory for {cve.cve_id}.",
                        ))
                        break

    return findings


# ── MODULE 3: HTTP Template Scan (nuclei) ────────────────────
async def module_web_scan(target: str, options: dict) -> List[dict]:
    """Run nuclei via host binary (mounted at /usr/local/bin/nuclei)"""
    import asyncio as _asyncio
    findings = []

    if not target.startswith("http"):
        target_url = f"http://{target}"
    else:
        target_url = target

    # Build nuclei command using host binary
    # Templates path — use host templates dir
    template_dir = options.get("template_dir", "/home/appuser/nuclei-templates")
    severity_filter = options.get("severity", "low,medium,high,critical")
    extra_tags = options.get("tags", "")
    timeout = int(options.get("timeout", 120))

    cmd = [
        "/usr/local/bin/nuclei",
        "-u", target_url,
        "-jsonl", "-no-color",
        "-timeout", "30",
        "-disable-update-check",
        "-silent",
    ]

    # Add template path if specified, else use automatic scan
    if options.get("templates"):
        for t in options["templates"].split(","):
            cmd += ["-t", f"{template_dir}/http/{t.strip()}"]
    else:
        cmd += ["-t", f"{template_dir}/http/technologies",
                "-t", f"{template_dir}/http/exposures",
                "-t", f"{template_dir}/http/misconfiguration",
                "-t", f"{template_dir}/http/vulnerabilities"]

    if extra_tags:
        cmd += ["-tags", extra_tags]

    try:
        proc = await _asyncio.create_subprocess_exec(
            *cmd,
            stdout=_asyncio.subprocess.PIPE,
            stderr=_asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await _asyncio.wait_for(
                proc.communicate(), timeout=timeout + 60
            )
        except _asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            stdout_b, stderr_b = b"", b"Timeout"

        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        logger.info(f"nuclei stdout lines: {len(stdout.splitlines())}")
        logger.info(f"nuclei cmd: {' '.join(cmd)}")
        if stderr:
            logger.warning(f"nuclei stderr: {stderr[:500]}")

    except Exception as e:
        logger.error(f"nuclei exec error: {e}")
        return [make_finding("web_scan", "info",
                             "Web scan failed", target,
                             description=str(e))]

    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "info": "info", "unknown": "info"}

    # Remap certain info findings to proper severity
    SEVERITY_REMAP = {
        "end-of-life": "high",
        "eol": "high",
        "sql injection": "critical",
        "sqli": "critical",
        "xss": "high",
        "cross-site scripting": "high",
        "rce": "critical",
        "remote code execution": "critical",
        "lfi": "high",
        "local file inclusion": "high",
        "open redirect": "medium",
        "ssrf": "high",
        "xxe": "high",
        "insecure deserialization": "high",
        "default credentials": "high",
        "default login": "high",
        "exposed panel": "medium",
        "exposed .git": "high",
        "exposed .env": "critical",
        "directory listing": "medium",
        "missing security header": "low",
        "clickjacking": "medium",
    }

    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            info = item.get("info", {})
            sev = sev_map.get(info.get("severity", "info").lower(), "info")
            # Remap based on finding name
            name_lower = (info.get("name") or "").lower()
            for keyword, remapped_sev in SEVERITY_REMAP.items():
                if keyword in name_lower:
                    # Only upgrade severity, never downgrade
                    sev_order = ["info", "low", "medium", "high", "critical"]
                    if sev_order.index(remapped_sev) > sev_order.index(sev):
                        sev = remapped_sev
                    break
            matched = item.get("matched-at") or item.get("matched") or ""
            template_id = item.get("template-id") or item.get("templateID", "")
            cve_ids = []
            cvss = None
            owasp_cat = ""
            classification = info.get("classification", {})
            if classification:
                cve_ids = classification.get("cve-id", []) or []
                cvss = classification.get("cvss-score")
                owasp_list = classification.get("owasp-top10", [])
                owasp_cat = str(owasp_list[0]) if owasp_list else ""

            findings.append(make_finding(
                "web_scan", sev,
                info.get("name") or template_id or "Finding",
                target,
                description=info.get("description", ""),
                evidence=f"[{template_id}] Matched: {matched}",
                host=item.get("host", target),
                cve_ids=cve_ids,
                cvss_score=float(cvss) if cvss else None,
                remediation=info.get("remediation", ""),
                owasp=owasp_cat,
            ))
        except (json.JSONDecodeError, Exception):
            continue

    if not findings:
        findings.append(make_finding(
            "web_scan", "info", "Web scan completed — no findings",
            target, evidence=stderr[:300] if stderr else ""
        ))
    return findings

# ── MODULE 4: SSL/TLS Scan ────────────────────────────────────
async def module_ssl_scan(target: str, options: dict) -> List[dict]:
    findings = []
    port = options.get("port", 443)

    result = await run_container(
        image="drwetter/testssl.sh:latest",
        cmd=["bash", "/usr/bin/testssl.sh", "--jsonfile", "/dev/stdout",
             "--severity", "LOW", "--quiet", f"{target}:{port}"],
        timeout=int(options.get("timeout", 180)),
        mem_limit="256m",
    )

    # Parse testssl JSON
    try:
        for line in result["stdout"].splitlines():
            if not line.strip().startswith("{"):
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    continue
                sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                           "LOW": "low", "INFO": "info", "OK": "info", "WARN": "low"}
                raw_sev = item.get("severity", "INFO")
                sev = sev_map.get(raw_sev.upper(), "info")
                if sev == "info":
                    continue  # skip OK findings
                findings.append(make_finding(
                    "ssl_tls", sev,
                    item.get("id", "SSL/TLS Issue"),
                    target,
                    description=item.get("finding", ""),
                    host=target, port=int(port), protocol="tcp", service="https",
                    remediation="Update TLS configuration. Disable weak ciphers and old protocol versions.",
                ))
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"SSL parse error: {e}")

    # Fallback — do quick inline SSL check
    if not findings:
        findings.extend(await _inline_ssl_check(target, int(port)))

    return findings


async def _inline_ssl_check(host: str, port: int) -> List[dict]:
    """Quick Python SSL check as fallback"""
    findings = []
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def check():
            import socket
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    cipher = ssock.cipher()
                    return cert, proto, cipher

        cert, proto, cipher = await loop.run_in_executor(None, check)

        # Check TLS version
        if proto in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(make_finding(
                "ssl_tls", "high",
                f"Weak TLS version: {proto}",
                host, host=host, port=port, protocol="tcp", service="https",
                description=f"Server supports deprecated protocol {proto}",
                remediation="Disable TLS 1.0 and 1.1. Only allow TLS 1.2+ with strong ciphers.",
                owasp="A02:2021"
            ))

        # Check cert expiry
        if cert:
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp - datetime.now(timezone.utc)).days
                    if days_left < 30:
                        findings.append(make_finding(
                            "ssl_tls", "high" if days_left < 7 else "medium",
                            f"SSL certificate expires in {days_left} day(s)",
                            host, host=host, port=port,
                            description=f"Certificate expires on {not_after}",
                            remediation="Renew SSL certificate before expiration.",
                        ))
                except Exception:
                    pass

    except ssl.SSLError as e:
        findings.append(make_finding(
            "ssl_tls", "high", f"SSL Error: {str(e)[:100]}",
            host, host=host, port=port,
            remediation="Fix SSL/TLS configuration on the server."
        ))
    except Exception:
        pass

    return findings


# ── MODULE 5: Security Headers ────────────────────────────────
async def module_security_headers(target: str, options: dict) -> List[dict]:
    findings = []
    if not target.startswith("http"):
        urls = [f"https://{target}", f"http://{target}"]
    else:
        urls = [target]

    REQUIRED_HEADERS = {
        "strict-transport-security": ("high", "Missing HSTS header", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", "A05:2021"),
        "x-frame-options": ("medium", "Missing X-Frame-Options (Clickjacking)", "Add: X-Frame-Options: DENY or SAMEORIGIN", "A04:2021"),
        "x-content-type-options": ("low", "Missing X-Content-Type-Options", "Add: X-Content-Type-Options: nosniff", "A04:2021"),
        "content-security-policy": ("medium", "Missing Content-Security-Policy", "Implement a strict CSP policy", "A04:2021"),
        "referrer-policy": ("low", "Missing Referrer-Policy", "Add: Referrer-Policy: no-referrer-when-downgrade", "A04:2021"),
        "permissions-policy": ("low", "Missing Permissions-Policy", "Add appropriate Permissions-Policy header", "A04:2021"),
    }

    BAD_HEADERS = {
        "x-powered-by": ("info", "Server technology disclosure via X-Powered-By", "Remove X-Powered-By header"),
        "server": ("info", "Server version disclosure", "Suppress Server header or remove version info"),
        "x-aspnet-version": ("low", "ASP.NET version disclosure", "Remove X-AspNet-Version header"),
    }

    response = None
    for url in urls:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                response = await client.get(url)
                break
        except Exception:
            continue

    if not response:
        return [make_finding("security_headers", "info", "Could not reach target for header check", target)]

    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header, (sev, title, rem, owasp) in REQUIRED_HEADERS.items():
        if header not in headers_lower:
            findings.append(make_finding(
                "security_headers", sev, title, target,
                description=f"The {header} security header is not set.",
                evidence=f"GET {response.url} HTTP/{response.http_version}\nStatus: {response.status_code}",
                host=target, remediation=rem, owasp=owasp,
            ))

    for header, (sev, title, rem) in BAD_HEADERS.items():
        if header in headers_lower:
            findings.append(make_finding(
                "security_headers", sev, title, target,
                description=f"Header {header}: {headers_lower[header]}",
                evidence=f"{header}: {headers_lower[header]}",
                host=target, remediation=rem, owasp="A05:2021",
            ))

    if not findings:
        findings.append(make_finding(
            "security_headers", "info", "Security headers look good",
            target, description="All required security headers are present."
        ))

    return findings


# ── MODULE 6: Subdomain Recon (subfinder + dnsx) ─────────────
async def module_subdomain_recon(target: str, options: dict) -> List[dict]:
    findings = []
    # Remove scheme if present
    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]

    result = await run_container(
        image="projectdiscovery/subfinder:latest",
        cmd=["subfinder", "-d", domain, "-silent", "-all"],
        timeout=int(options.get("timeout", 120)),
        mem_limit="256m",
    )

    subdomains = [s.strip() for s in result["stdout"].splitlines() if s.strip()]

    # DNS verify with dnsx
    if subdomains:
        subs_input = "\n".join(subdomains)
        dnsx_result = await run_container(
            image="projectdiscovery/dnsx:latest",
            cmd=["dnsx", "-resp", "-a", "-silent"],
            timeout=60,
            mem_limit="128m",
        )
        # Parse dnsx output: subdomain [IP]
        verified = {}
        for line in dnsx_result["stdout"].splitlines():
            m = re.match(r"([\w\-\.]+)\s+\[([^\]]+)\]", line)
            if m:
                verified[m.group(1)] = m.group(2)

    for sub in subdomains[:100]:
        ip = verified.get(sub, "") if subdomains else ""
        findings.append(make_finding(
            "subdomain_recon", "info",
            f"Subdomain discovered: {sub}",
            target,
            description=f"Subdomain {sub} found via passive recon",
            evidence=f"{sub} → {ip}" if ip else sub,
            host=sub,
        ))

    if not findings:
        findings.append(make_finding(
            "subdomain_recon", "info", "No subdomains found via passive recon",
            target, evidence=result["stderr"][:300]
        ))

    return findings


# ── MODULE 7: DNS Misconfiguration ───────────────────────────
async def module_dns_check(target: str, options: dict) -> List[dict]:
    findings = []
    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]

    result = await run_container(
        image="projectdiscovery/dnsx:latest",
        cmd=["dnsx", "-d", domain, "-resp", "-a", "-aaaa",
             "-mx", "-ns", "-txt", "-cname", "-silent", "-json"],
        timeout=60,
        mem_limit="128m",
    )

    has_spf = False
    has_dmarc = False
    has_dnssec = False

    for line in result["stdout"].splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            # Check TXT records for SPF/DMARC
            for txt in item.get("txt", []):
                if "v=spf1" in txt.lower():
                    has_spf = True
                if "v=dmarc1" in txt.lower():
                    has_dmarc = True
            # Check for DNSSEC
            if item.get("dnssec"):
                has_dnssec = True
        except Exception:
            # Try simple text parsing
            if "v=spf1" in line.lower():
                has_spf = True
            if "v=dmarc1" in line.lower():
                has_dmarc = True

    if not has_spf:
        findings.append(make_finding(
            "dns_check", "medium", "Missing SPF record",
            target, host=domain,
            description="No SPF record found. Domain is vulnerable to email spoofing.",
            remediation='Add TXT record: v=spf1 include:_spf.google.com ~all',
            owasp="A05:2021",
        ))

    if not has_dmarc:
        findings.append(make_finding(
            "dns_check", "medium", "Missing DMARC record",
            target, host=f"_dmarc.{domain}",
            description="No DMARC policy found. Email spoofing protection is incomplete.",
            remediation='Add TXT record on _dmarc.domain: v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com',
            owasp="A05:2021",
        ))

    if not has_dnssec:
        findings.append(make_finding(
            "dns_check", "low", "DNSSEC not enabled",
            target, host=domain,
            description="DNSSEC is not configured. DNS responses cannot be cryptographically verified.",
            remediation="Enable DNSSEC through your DNS provider or registrar.",
        ))

    if not findings:
        findings.append(make_finding(
            "dns_check", "info", "DNS configuration looks acceptable",
            target, host=domain,
        ))

    return findings


# ── MODULE 8: OWASP Compliance Mapper ────────────────────────
def map_owasp_compliance(findings: List[dict]) -> dict:
    """Map findings to OWASP Top 10 categories"""
    owasp_map = {
        "A01:2021": "Broken Access Control",
        "A02:2021": "Cryptographic Failures",
        "A03:2021": "Injection",
        "A04:2021": "Insecure Design",
        "A05:2021": "Security Misconfiguration",
        "A06:2021": "Vulnerable and Outdated Components",
        "A07:2021": "Identification and Authentication Failures",
        "A08:2021": "Software and Data Integrity Failures",
        "A09:2021": "Security Logging and Monitoring Failures",
        "A10:2021": "Server-Side Request Forgery",
    }
    result = {cat: {"name": name, "findings": [], "count": 0}
              for cat, name in owasp_map.items()}

    for f in findings:
        cat = f.get("owasp_category", "")
        if cat in result:
            result[cat]["findings"].append(f["title"])
            result[cat]["count"] += 1

    return result
