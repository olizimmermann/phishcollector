"""
URLhaus plugin — abuse.ch threat feed.

Requires a free Auth-Key from https://auth.abuse.ch/
Docs: https://urlhaus-api.abuse.ch/
"""

from typing import Optional

import httpx

from . import CheckResult

_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


async def check(url: str, api_key: Optional[str] = None, proxy_url: Optional[str] = None, ssl_verify: bool = True) -> CheckResult:
    """Query URLhaus for the given URL."""
    if not api_key:
        return CheckResult(
            plugin_name="urlhaus",
            status="error",
            score=None,
            result={"error": "No URLhaus Auth-Key configured. Get one free at https://auth.abuse.ch/"},
        )
    try:
        async with httpx.AsyncClient(
            timeout=15,
            proxy=proxy_url or None,
            verify=ssl_verify,
        ) as client:
            r = await client.post(_API_URL, data={"url": url}, headers={"Auth-Key": api_key})
            r.raise_for_status()
            data = r.json()
    except Exception as exc:
        return CheckResult(
            plugin_name="urlhaus",
            status="error",
            score=None,
            result={"error": str(exc)},
        )

    query_status = data.get("query_status", "")

    if query_status == "no_results":
        return CheckResult(plugin_name="urlhaus", status="clean", score=0.0, result=data)

    if query_status in ("is_host", "blacklisted"):
        # URL is listed in URLhaus
        threat = (data.get("threat") or "").lower()
        url_status = (data.get("url_status") or "").lower()
        # Still-online malicious URL is highest confidence
        if url_status == "online":
            return CheckResult(plugin_name="urlhaus", status="malicious", score=1.0, result=data)
        return CheckResult(plugin_name="urlhaus", status="malicious", score=0.85, result=data)

    return CheckResult(plugin_name="urlhaus", status="unknown", score=None, result=data)
