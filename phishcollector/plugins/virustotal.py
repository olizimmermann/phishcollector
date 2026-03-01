"""
VirusTotal plugin — URL reputation via VT API v3.

Submits the URL to VirusTotal for analysis.  On the first run the URL may not
yet have results; in that case we submit it for scanning and return "unknown".
Docs: https://developers.virustotal.com/reference/urls
"""

import base64
from typing import Optional

import httpx

from . import CheckResult

_VT_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    """VT URL identifier: url-safe base64 of the URL, no padding."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


async def check(url: str, api_key: str, proxy_url: Optional[str] = None, ssl_verify: bool = True) -> CheckResult:
    """Query VirusTotal for the given URL."""
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(
            timeout=20,
            proxy=proxy_url or None,
            headers=headers,
            verify=ssl_verify,
        ) as client:
            # Try a GET first (uses cached result if available)
            uid = _url_id(url)
            r = await client.get(f"{_VT_BASE}/urls/{uid}")

            if r.status_code == 404:
                # Not in cache — submit for scanning and store the analysis ID
                submit = await client.post(f"{_VT_BASE}/urls", data={"url": url})
                submit.raise_for_status()
                analysis_id = submit.json().get("data", {}).get("id")
                return CheckResult(
                    plugin_name="virustotal",
                    status="unknown",
                    score=None,
                    result={
                        "info": "URL submitted for analysis; will be fetched automatically",
                        "analysis_id": analysis_id,
                    },
                )

            r.raise_for_status()
            data = r.json()

    except Exception as exc:
        return CheckResult(
            plugin_name="virustotal",
            status="error",
            score=None,
            result={"error": str(exc)},
        )

    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        # If total is 0 the scan is still queued / in progress — stay unknown
        if total == 0:
            return CheckResult(
                plugin_name="virustotal",
                status="unknown",
                score=None,
                result={"info": "Analysis queued, not yet available"},
            )

        score = round(malicious / total, 3)

        if malicious > 0:
            status = "malicious"
        elif suspicious > 0:
            status = "suspicious"
        else:
            status = "clean"

        return CheckResult(
            plugin_name="virustotal",
            status=status,
            score=score,
            result={
                "stats": stats,
                "permalink": data["data"].get("links", {}).get("self"),
            },
        )
    except (KeyError, TypeError) as exc:
        return CheckResult(
            plugin_name="virustotal",
            status="error",
            score=None,
            result={"error": f"Unexpected response shape: {exc}", "raw": data},
        )
