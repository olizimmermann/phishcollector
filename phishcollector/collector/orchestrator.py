"""
Collection orchestrator.

Ties together the browser, fingerprinting, and spider modules, persists
every artifact to the database and to disk, and manages the collection
job's lifecycle (pending → running → completed | failed).
"""

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiofiles
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import Asset, Collection, Fingerprint, HttpRequest, PluginResult, SpiderResult
from .browser import PageCapture, capture_page, random_user_agent
from .fingerprint import fingerprint_page
from .spider import SpiderResult as SpiderData
from .spider import spider_site


# ─────────────────────────────────────────────────────────────────────────────
# Entry point (runs as a FastAPI BackgroundTask)
# ─────────────────────────────────────────────────────────────────────────────


async def run_collection(
    collection_id: uuid.UUID,
    url: str,
    options: dict,
    session_factory,  # AsyncSessionLocal callable
) -> None:
    """
    Main orchestrator.  Must be called with *session_factory* so that it
    can open its own database session (background tasks outlive the
    request-scoped session).
    """
    async with session_factory() as session:
        try:
            await _run(collection_id, url, options, session)
        except Exception as exc:
            await _fail(collection_id, str(exc), session)
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────


async def _run(
    collection_id: uuid.UUID,
    url: str,
    options: dict,
    session: AsyncSession,
) -> None:
    # ── Mark running ──────────────────────────────────────────────────────────
    collection: Collection = await session.get(Collection, collection_id)
    user_agent = random_user_agent()
    collection.status = "running"
    collection.user_agent = user_agent
    await session.commit()

    # ── 1. Browser capture ───────────────────────────────────────────────────
    page: PageCapture = await capture_page(
        url, user_agent, timeout=settings.browser_timeout,
        proxy_url=settings.proxy_url,
    )

    # ── 2. Persist HTML ──────────────────────────────────────────────────────
    html_path = await _save_text(
        settings.html_dir, collection_id, "html", page.html.encode("utf-8", errors="replace")
    )

    # ── 3. Persist screenshot ────────────────────────────────────────────────
    screenshot_path = await _save_binary(
        settings.screenshots_dir, collection_id, "png", page.screenshot
    )

    # ── 4. Persist HTTP request log ──────────────────────────────────────────
    for req in page.requests:
        session.add(
            HttpRequest(
                collection_id=collection_id,
                url=req.url,
                method=req.method,
                request_headers=req.request_headers,
                response_status=req.response_status,
                response_headers=req.response_headers,
                response_body_sha256=req.response_body_sha256,
                resource_type=req.resource_type,
            )
        )

    # ── 5. Download and persist assets (JS / CSS) ────────────────────────────
    await _save_assets(collection_id, page, session)

    # ── 6. Fingerprint ───────────────────────────────────────────────────────
    fp_data = await fingerprint_page(
        url, page, options, request_timeout=settings.request_timeout,
        proxy_url=settings.proxy_url,
    )

    session.add(
        Fingerprint(
            collection_id=collection_id,
            ip_address=fp_data.get("ip_address"),
            asn=fp_data.get("asn"),
            org=fp_data.get("org"),
            country=fp_data.get("country"),
            city=fp_data.get("city"),
            ssl_cert=fp_data.get("ssl_cert"),
            ssl_valid=fp_data.get("ssl_valid"),
            final_url=page.final_url,
            redirect_chain=page.redirect_chain,
            response_headers=page.response_headers,
            status_code=page.response_status,
            title=page.title,
            favicon_hash_mmh3=fp_data.get("favicon_hash"),
            favicon_sha256=fp_data.get("favicon_sha256"),
            page_sha256=hashlib.sha256(page.html.encode("utf-8", errors="replace")).hexdigest(),
            technologies=fp_data.get("technologies"),
            forms=fp_data.get("forms"),
            external_domains=fp_data.get("external_domains"),
            phishing_indicators=fp_data.get("phishing_indicators"),
            whois=fp_data.get("whois"),
            cookies=page.cookies,
            screenshot_path=str(screenshot_path),
            html_path=str(html_path),
        )
    )

    # ── 7. Spider ────────────────────────────────────────────────────────────
    wordlist: Optional[list[str]] = None
    if options.get("use_wordlist"):
        wordlist_path = options.get("wordlist_path") or settings.default_wordlist
        wordlist = _load_wordlist(wordlist_path)

    spider_data: list[SpiderData] = await spider_site(
        base_url=page.final_url or url,
        html=page.html,
        user_agent=user_agent,
        wordlist=wordlist,
        max_pages=settings.max_spider_pages,
        timeout=settings.request_timeout,
        proxy_url=settings.proxy_url,
    )

    for sr in spider_data:
        session.add(
            SpiderResult(
                collection_id=collection_id,
                url=sr.url,
                status_code=sr.status_code,
                found_via=sr.found_via,
                title=sr.title,
                content_type=sr.content_type,
                size_bytes=sr.size_bytes,
            )
        )

    # ── 8. Threat-intelligence plugins ───────────────────────────────────────
    from ..plugins.runner import run_plugins
    plugin_results = await run_plugins(url)
    for pr in plugin_results:
        session.add(
            PluginResult(
                collection_id=collection_id,
                plugin_name=pr.plugin_name,
                status=pr.status,
                score=pr.score,
                result=pr.result,
            )
        )

    # ── 9. Mark completed ────────────────────────────────────────────────────
    collection = await session.get(Collection, collection_id)
    collection.status = "completed"
    collection.completed_at = datetime.now(timezone.utc)
    await session.commit()


async def _fail(
    collection_id: uuid.UUID, error: str, session: AsyncSession
) -> None:
    collection: Collection = await session.get(Collection, collection_id)
    if collection:
        collection.status = "failed"
        collection.error = error[:4096]
        collection.completed_at = datetime.now(timezone.utc)
        await session.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Disk I/O helpers
# ─────────────────────────────────────────────────────────────────────────────


async def _save_binary(directory: Path, cid: uuid.UUID, ext: str, data: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{cid}.{ext}"
    async with aiofiles.open(path, "wb") as f:
        await f.write(data)
    return path


async def _save_text(directory: Path, cid: uuid.UUID, ext: str, data: bytes) -> Path:
    return await _save_binary(directory, cid, ext, data)


async def _save_assets(
    collection_id: uuid.UUID,
    page: PageCapture,
    session: AsyncSession,
) -> None:
    """Save JS and CSS response bodies captured by the browser."""
    assets_dir = settings.assets_dir / str(collection_id)
    assets_dir.mkdir(parents=True, exist_ok=True)

    seen_urls: set[str] = set()

    for req in page.requests:
        if req.url in seen_urls:
            continue

        content_type = (req.response_headers or {}).get("content-type", "")
        asset_type = _classify_asset(req.resource_type, content_type, req.url)

        if asset_type not in ("javascript", "css"):
            # Only persist JS and CSS (HTML is already saved separately)
            continue

        if not req.response_body:
            continue

        if len(req.response_body) > settings.max_asset_size:
            continue

        seen_urls.add(req.url)
        sha256 = req.response_body_sha256 or hashlib.sha256(req.response_body).hexdigest()
        ext = "js" if asset_type == "javascript" else "css"
        filename = f"{sha256[:16]}.{ext}"
        file_path = assets_dir / filename

        if not file_path.exists():
            async with aiofiles.open(file_path, "wb") as f:
                await f.write(req.response_body)

        session.add(
            Asset(
                collection_id=collection_id,
                url=req.url,
                asset_type=asset_type,
                sha256=sha256,
                file_path=str(file_path),
                size_bytes=len(req.response_body),
                content_type=content_type,
            )
        )


def _classify_asset(resource_type: str, content_type: str, url: str) -> str:
    if resource_type == "script" or "javascript" in content_type or url.endswith(".js"):
        return "javascript"
    if resource_type == "stylesheet" or "css" in content_type or url.endswith(".css"):
        return "css"
    if resource_type == "image" or content_type.startswith("image/"):
        return "image"
    if "font" in content_type or resource_type == "font":
        return "font"
    return "other"


def _load_wordlist(path: Optional[str]) -> list[str]:
    """Load a wordlist from a trusted path inside the allowed wordlist directory."""
    if not path:
        return []
    try:
        safe = (settings.wordlist_dir / Path(path).name).resolve()
        allowed = settings.wordlist_dir.resolve()
        # Ensure the resolved path is still inside the wordlist directory
        safe.relative_to(allowed)
        with open(safe) as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except (FileNotFoundError, ValueError):
        return []
