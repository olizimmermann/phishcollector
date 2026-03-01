"""
Plugin runner — calls enabled plugins concurrently and collects results.
"""

import asyncio
from typing import Optional

from ..config import settings
from . import CheckResult


async def run_plugins(url: str) -> list[CheckResult]:
    """Run all enabled threat-intelligence plugins against *url*."""
    tasks = []

    if settings.urlhaus_enabled:
        from .urlhaus import check as urlhaus_check
        tasks.append(urlhaus_check(
            url,
            api_key=settings.urlhaus_api_key,
            proxy_url=settings.proxy_url,
            ssl_verify=settings.proxy_ssl_verify,
        ))

    if settings.virustotal_api_key:
        from .virustotal import check as vt_check
        tasks.append(vt_check(
            url,
            api_key=settings.virustotal_api_key,
            proxy_url=settings.proxy_url,
            ssl_verify=settings.proxy_ssl_verify,
        ))

    if not tasks:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)

    out: list[CheckResult] = []
    for r in results:
        if isinstance(r, CheckResult):
            out.append(r)
        elif isinstance(r, Exception):
            out.append(CheckResult(
                plugin_name="unknown",
                status="error",
                score=None,
                result={"error": str(r)},
            ))
    return out
