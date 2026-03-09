"""
CVE Service — NVD API v2, chunked by month to avoid 404 on large results
"""
import httpx
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional, List

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OffenSecOps/1.0)", "Accept": "application/json"}
MONTH_ENDS = [31,28,31,30,31,30,31,31,30,31,30,31]

def score_to_severity(score: Optional[float]) -> str:
    if not score: return "info"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"

async def fetch_nvd_feed_year(year: int) -> List[dict]:
    import os
    api_key = os.getenv("NVD_API_KEY", "")
    delay = 2 if api_key else 7
    hdrs = dict(HEADERS)
    if api_key:
        hdrs["apiKey"] = api_key

    is_leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
    ends = MONTH_ENDS.copy()
    if is_leap: ends[1] = 29

    all_cves = []
    logger.info(f"NVD ingest year {year} — chunked by month")

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        for month in range(1, 13):
            s = f"{year}-{month:02d}-01T00:00:00.000Z"
            e = f"{year}-{month:02d}-{ends[month-1]:02d}T23:59:59.999Z"
            idx = 0
            mtotal = None

            while True:
                await asyncio.sleep(delay)
                url = f"{NVD_API_BASE}?pubStartDate={s}&pubEndDate={e}&startIndex={idx}&resultsPerPage=500"
                try:
                    r = await client.get(url, headers=hdrs)
                    if r.status_code != 200:
                        logger.error(f"Year {year} month {month}: HTTP {r.status_code}")
                        break
                    data = r.json()
                except Exception as ex:
                    logger.error(f"Year {year} month {month} idx {idx}: {ex}")
                    break

                vulns = data.get("vulnerabilities", [])
                if mtotal is None:
                    mtotal = data.get("totalResults", 0)
                all_cves.extend(vulns)
                idx += 500
                if idx >= (mtotal or 0):
                    break

            logger.info(f"Year {year} month {month:02d} done — total so far: {len(all_cves)}")

    logger.info(f"Year {year} complete — {len(all_cves)} CVEs")
    return all_cves

async def fetch_kev_list() -> set:
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
            r = await c.get(KEV_URL, headers=HEADERS)
            r.raise_for_status()
            kev = {v["cveID"] for v in r.json().get("vulnerabilities", [])}
            logger.info(f"KEV: {len(kev)} entries")
            return kev
    except Exception as e:
        logger.warning(f"KEV failed: {e}")
        return set()

def parse_nvd_item(item: dict, kev_set: set) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
    metrics = cve.get("metrics", {})
    cvss_v3 = None
    cvss_v2 = None
    for key in ["cvssMetricV31","cvssMetricV30"]:
        if key in metrics and metrics[key]:
            cvss_v3 = metrics[key][0].get("cvssData",{}).get("baseScore")
            break
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss_v2 = metrics["cvssMetricV2"][0].get("cvssData",{}).get("baseScore")
    score = cvss_v3 or cvss_v2
    cpe_list = []
    for cfg in cve.get("configurations",[]):
        for node in cfg.get("nodes",[]):
            for m in node.get("cpeMatch",[]):
                if m.get("criteria"): cpe_list.append(m["criteria"])
    refs = [r.get("url","") for r in cve.get("references",[])[:5]]
    def dt(s):
        if not s: return None
        try: return datetime.fromisoformat(s.replace("Z","+00:00"))
        except: return None
    return {
        "cve_id": cve_id,
        "description": desc[:2000],
        "cvss_v3_score": cvss_v3,
        "cvss_v2_score": cvss_v2,
        "severity": score_to_severity(score),
        "cpe_matches": cpe_list[:20],
        "published": dt(cve.get("published")),
        "modified": dt(cve.get("lastModified")),
        "is_kev": cve_id in kev_set,
        "references": [r for r in refs if r],
        "raw_data": {},
    }

async def lookup_cve(cve_id: str, db_session) -> Optional[dict]:
    from sqlalchemy import select
    from app.db.models import CVECache
    r = await db_session.execute(select(CVECache).where(CVECache.cve_id == cve_id))
    cve = r.scalar_one_or_none()
    if cve:
        return {"cve_id": cve.cve_id, "description": cve.description,
                "cvss_v3_score": cve.cvss_v3_score, "severity": cve.severity,
                "is_kev": cve.is_kev, "references": cve.references or []}
    return None
