"""
FastAPI route definitions.

Endpoints:
  POST /collections          – submit a URL for collection
  GET  /collections          – list all collections (paginated)
  GET  /collections/{id}     – full detail for one collection
  GET  /collections/{id}/screenshot  – serve the PNG screenshot
  GET  /collections/{id}/html        – serve the rendered HTML
  GET  /search               – search by favicon hash, IP, technology, …
  DELETE /collections/{id}   – delete a collection and its artifacts
"""

import csv
import io
import json
import shutil
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..collector.orchestrator import run_collection
from ..config import settings
from ..database import AsyncSessionLocal, get_db
from ..models import Collection, Fingerprint, PluginResult, SpiderResult

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────


class CollectionRequest(BaseModel):
    url: str                            # target URL — http/https only
    use_wordlist: bool = False          # probe common phishing paths
    wordlist_path: Optional[str] = None # name of wordlist file (basename only)

    @field_validator("url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("Only http:// and https:// URLs are accepted")
        return v

    @field_validator("wordlist_path")
    @classmethod
    def wordlist_basename_only(cls, v: Optional[str]) -> Optional[str]:
        """Accept only a plain filename — no directory traversal."""
        if v is None:
            return v
        # Strip path components: only allow the bare filename
        name = Path(v).name
        if not name or name != v:
            raise ValueError("wordlist_path must be a plain filename with no path separators")
        return name


class CollectionSummary(BaseModel):
    id: str
    url: str
    status: str
    submitted_at: str
    completed_at: Optional[str]
    user_agent: Optional[str]

    model_config = {"from_attributes": True}


class FingerprintOut(BaseModel):
    ip_address: Optional[str]
    asn: Optional[str]
    org: Optional[str]
    country: Optional[str]
    city: Optional[str]
    ssl_cert: Optional[dict]
    ssl_valid: Optional[bool]
    final_url: Optional[str]
    redirect_chain: Optional[list]
    status_code: Optional[int]
    title: Optional[str]
    favicon_hash_mmh3: Optional[str]
    favicon_sha256: Optional[str]
    page_sha256: Optional[str]
    technologies: Optional[list]
    forms: Optional[list]
    external_domains: Optional[list]
    phishing_indicators: Optional[dict]
    whois: Optional[dict]
    cookies: Optional[list]

    model_config = {"from_attributes": True}


class CollectionDetail(CollectionSummary):
    error: Optional[str]
    options: dict
    fingerprint: Optional[FingerprintOut]
    spider_count: int
    asset_count: int
    request_count: int


class CollectionPatch(BaseModel):
    """Fields that analysts can update after collection."""
    tags: Optional[list[str]] = None
    notes: Optional[str] = None

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: Optional[list]) -> Optional[list]:
        if v is None:
            return v
        if len(v) > 20:
            raise ValueError("Maximum 20 tags per collection")
        return [str(t).strip()[:50] for t in v if str(t).strip()]

    @field_validator("notes")
    @classmethod
    def validate_notes(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 10_000:
            raise ValueError("Notes cannot exceed 10,000 characters")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/collections", status_code=202)
async def submit_collection(
    body: CollectionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Submit a URL for collection.  Returns immediately with a job ID."""
    options = {
        "use_wordlist": body.use_wordlist,
        "wordlist_path": body.wordlist_path,
    }

    collection = Collection(url=body.url, options=options)
    db.add(collection)
    await db.commit()
    await db.refresh(collection)

    background_tasks.add_task(
        run_collection,
        collection.id,
        body.url,
        options,
        AsyncSessionLocal,
    )

    return {"id": str(collection.id), "status": "pending"}


@router.get("/collections")
async def list_collections(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List collections, most-recent first."""
    stmt = select(Collection).order_by(Collection.submitted_at.desc()).offset(skip).limit(limit)
    if status:
        stmt = stmt.filter(Collection.status == status)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [_summary(c) for c in rows]


@router.get("/collections/{cid}")
async def get_collection(cid: str, db: AsyncSession = Depends(get_db)):
    """Retrieve full detail for a collection including the fingerprint."""
    collection = await _get_or_404(cid, db)

    stmt = (
        select(Collection)
        .where(Collection.id == collection.id)
        .options(
            selectinload(Collection.fingerprint),
            selectinload(Collection.spider_results),
            selectinload(Collection.assets),
            selectinload(Collection.http_requests),
        )
    )
    result = await db.execute(stmt)
    c = result.scalar_one()

    fp = FingerprintOut.model_validate(c.fingerprint) if c.fingerprint else None

    return {
        **_summary(c),
        "error": c.error,
        "options": c.options,
        "fingerprint": fp,
        "spider_count": len(c.spider_results),
        "asset_count": len(c.assets),
        "request_count": len(c.http_requests),
    }


@router.get("/collections/{cid}/screenshot")
async def get_screenshot(cid: str, db: AsyncSession = Depends(get_db)):
    """Stream the full-page PNG screenshot."""
    collection = await _get_or_404(cid, db)
    fp = await _fingerprint_or_404(collection.id, db)
    if not fp.screenshot_path or not Path(fp.screenshot_path).exists():
        raise HTTPException(404, "Screenshot not available")
    return FileResponse(fp.screenshot_path, media_type="image/png")


@router.get("/collections/{cid}/html")
async def get_html(cid: str, db: AsyncSession = Depends(get_db)):
    """Serve the rendered HTML dump."""
    collection = await _get_or_404(cid, db)
    fp = await _fingerprint_or_404(collection.id, db)
    if not fp.html_path or not Path(fp.html_path).exists():
        raise HTTPException(404, "HTML not available")
    # Serve as plain-text download — never execute the captured malicious HTML
    return FileResponse(
        fp.html_path,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="captured_page.html"'},
    )


@router.get("/collections/{cid}/requests")
async def get_requests(
    cid: str,
    resource_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Return the full HTTP request/response log for a collection."""
    from ..models import HttpRequest

    collection = await _get_or_404(cid, db)
    stmt = select(HttpRequest).where(HttpRequest.collection_id == collection.id)
    if resource_type:
        stmt = stmt.where(HttpRequest.resource_type == resource_type)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "url": r.url,
            "method": r.method,
            "status": r.response_status,
            "resource_type": r.resource_type,
            "response_body_sha256": r.response_body_sha256,
            "request_headers": r.request_headers,
            "response_headers": r.response_headers,
        }
        for r in rows
    ]


@router.get("/collections/{cid}/spider")
async def get_spider_results(cid: str, db: AsyncSession = Depends(get_db)):
    """Return all URLs discovered by the spider."""
    collection = await _get_or_404(cid, db)
    stmt = select(SpiderResult).where(SpiderResult.collection_id == collection.id)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "url": r.url,
            "status_code": r.status_code,
            "found_via": r.found_via,
            "title": r.title,
            "content_type": r.content_type,
            "size_bytes": r.size_bytes,
        }
        for r in rows
    ]


@router.post("/collections/{cid}/rescan", status_code=202)
async def rescan_collection(
    cid: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create a new collection job for the same URL, preserving the original."""
    original = await _get_or_404(cid, db)
    new_collection = Collection(
        url=original.url,
        options=original.options,
        parent_id=original.id,
    )
    db.add(new_collection)
    await db.commit()
    await db.refresh(new_collection)

    background_tasks.add_task(
        run_collection,
        new_collection.id,
        new_collection.url,
        new_collection.options,
        AsyncSessionLocal,
    )
    return {"id": str(new_collection.id), "status": "pending", "parent_id": str(original.id)}


@router.get("/collections/{cid}/plugins")
async def get_plugin_results(cid: str, db: AsyncSession = Depends(get_db)):
    """Return threat-intelligence plugin results for a collection."""
    collection = await _get_or_404(cid, db)
    stmt = select(PluginResult).where(PluginResult.collection_id == collection.id)
    result = await db.execute(stmt)
    rows = result.scalars().all()
    return [
        {
            "plugin_name": r.plugin_name,
            "status": r.status,
            "score": r.score,
            "result": r.result,
            "queried_at": r.queried_at.isoformat() if r.queried_at else None,
        }
        for r in rows
    ]


@router.post("/collections/{cid}/plugins/refresh", status_code=202)
async def refresh_plugins(
    cid: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Re-run all enabled plugins and upsert results (e.g. fetch a pending VT analysis)."""
    collection = await _get_or_404(cid, db)
    background_tasks.add_task(
        _refresh_plugins_bg,
        collection.id,
        collection.url,
        AsyncSessionLocal,
    )
    return {"status": "refreshing"}


async def _refresh_plugins_bg(
    collection_id: uuid.UUID,
    url: str,
    session_factory,
) -> None:
    """Re-query all enabled plugins and upsert into plugin_results."""
    from datetime import datetime, timezone

    from ..plugins.runner import run_plugins

    results = await run_plugins(url)
    if not results:
        return

    async with session_factory() as session:
        for pr in results:
            stmt = select(PluginResult).where(
                PluginResult.collection_id == collection_id,
                PluginResult.plugin_name == pr.plugin_name,
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if existing:
                existing.status = pr.status
                existing.score = pr.score
                existing.result = pr.result
                existing.queried_at = datetime.now(timezone.utc)
            else:
                session.add(PluginResult(
                    collection_id=collection_id,
                    plugin_name=pr.plugin_name,
                    status=pr.status,
                    score=pr.score,
                    result=pr.result,
                ))
        await session.commit()


@router.get("/collections/{cid}/export")
async def export_collection(
    cid: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export all collection data as JSON or CSV."""
    stmt = (
        select(Collection)
        .where(Collection.id == (await _get_or_404(cid, db)).id)
        .options(
            selectinload(Collection.fingerprint),
            selectinload(Collection.spider_results),
            selectinload(Collection.assets),
            selectinload(Collection.http_requests),
            selectinload(Collection.plugin_results),
        )
    )
    result = await db.execute(stmt)
    c = result.scalar_one()

    fp = c.fingerprint

    if format == "json":
        data = {
            "id": str(c.id),
            "url": c.url,
            "status": c.status,
            "submitted_at": c.submitted_at.isoformat() if c.submitted_at else None,
            "completed_at": c.completed_at.isoformat() if c.completed_at else None,
            "user_agent": c.user_agent,
            "options": c.options,
            "parent_id": str(c.parent_id) if c.parent_id else None,
            "fingerprint": {
                "ip_address": fp.ip_address,
                "asn": fp.asn,
                "org": fp.org,
                "country": fp.country,
                "city": fp.city,
                "ssl_valid": fp.ssl_valid,
                "final_url": fp.final_url,
                "redirect_chain": fp.redirect_chain,
                "status_code": fp.status_code,
                "title": fp.title,
                "favicon_hash_mmh3": fp.favicon_hash_mmh3,
                "favicon_sha256": fp.favicon_sha256,
                "page_sha256": fp.page_sha256,
                "technologies": fp.technologies,
                "forms": fp.forms,
                "external_domains": fp.external_domains,
                "phishing_indicators": fp.phishing_indicators,
                "whois": fp.whois,
                "cookies": fp.cookies,
            } if fp else None,
            "plugin_results": [
                {"plugin_name": p.plugin_name, "status": p.status, "score": p.score, "result": p.result}
                for p in c.plugin_results
            ],
            "spider_results": [
                {"url": s.url, "status_code": s.status_code, "found_via": s.found_via,
                 "title": s.title, "content_type": s.content_type, "size_bytes": s.size_bytes}
                for s in c.spider_results
            ],
            "http_requests": [
                {"url": r.url, "method": r.method, "status": r.response_status,
                 "resource_type": r.resource_type, "body_sha256": r.response_body_sha256}
                for r in c.http_requests
            ],
        }
        content = json.dumps(data, indent=2, default=str)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="collection_{cid[:8]}.json"'},
        )

    # CSV — flat summary row
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "url", "status", "submitted_at", "completed_at",
        "ip_address", "country", "asn", "org", "title", "status_code",
        "ssl_valid", "final_url", "favicon_hash_mmh3", "page_sha256",
        "technologies", "phishing_indicator_count", "redirect_hops",
    ])
    indicator_count = sum(len(v) for v in (fp.phishing_indicators or {}).values()) if fp else 0
    writer.writerow([
        str(c.id), c.url, c.status,
        c.submitted_at.isoformat() if c.submitted_at else "",
        c.completed_at.isoformat() if c.completed_at else "",
        fp.ip_address if fp else "", fp.country if fp else "",
        fp.asn if fp else "", fp.org if fp else "",
        fp.title if fp else "", fp.status_code if fp else "",
        fp.ssl_valid if fp else "", fp.final_url if fp else "",
        fp.favicon_hash_mmh3 if fp else "", fp.page_sha256 if fp else "",
        "|".join(fp.technologies or []) if fp else "",
        indicator_count,
        len(fp.redirect_chain or []) if fp else 0,
    ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="collection_{cid[:8]}.csv"'},
    )


@router.patch("/collections/{cid}")
async def patch_collection(
    cid: str,
    body: CollectionPatch,
    db: AsyncSession = Depends(get_db),
):
    """Update analyst-controlled fields: tags and notes."""
    collection = await _get_or_404(cid, db)
    if body.tags is not None:
        collection.tags = body.tags
    if body.notes is not None:
        collection.notes = body.notes if body.notes.strip() else None
    await db.commit()
    return {"id": str(collection.id), "tags": collection.tags or [], "notes": collection.notes}


@router.delete("/collections/{cid}", status_code=204)
async def delete_collection(cid: str, db: AsyncSession = Depends(get_db)):
    """Delete a collection, all related DB records, and all on-disk artifacts."""
    collection = await _get_or_404(cid, db)
    _delete_artifacts(collection.id)
    await db.delete(collection)
    await db.commit()


@router.get("/search")
async def search(
    favicon_hash: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    technology: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    title: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """
    Search fingerprints.  All filters are ANDed together.

    Examples:
      /search?favicon_hash=-1234567890
      /search?technology=WordPress&country=RU
      /search?ip=185.220.101.1
    """
    stmt = (
        select(Fingerprint)
        .join(Collection)
        .where(Collection.status == "completed")
        .limit(limit)
    )

    if favicon_hash:
        stmt = stmt.where(Fingerprint.favicon_hash_mmh3 == favicon_hash)
    if ip:
        stmt = stmt.where(Fingerprint.ip_address == ip)
    if technology:
        # JSONB array contains operator
        stmt = stmt.where(Fingerprint.technologies.contains([technology]))
    if country:
        stmt = stmt.where(Fingerprint.country == country.upper())
    if title:
        stmt = stmt.where(Fingerprint.title.ilike(f"%{title}%"))

    result = await db.execute(stmt)
    rows = result.scalars().all()

    return [
        {
            "collection_id": str(fp.collection_id),
            "ip_address": fp.ip_address,
            "country": fp.country,
            "asn": fp.asn,
            "title": fp.title,
            "technologies": fp.technologies,
            "favicon_hash_mmh3": fp.favicon_hash_mmh3,
            "phishing_indicators": fp.phishing_indicators,
            "final_url": fp.final_url,
        }
        for fp in rows
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


async def _get_or_404(cid: str, db: AsyncSession) -> Collection:
    try:
        uid = uuid.UUID(cid)
    except ValueError:
        raise HTTPException(400, "Invalid collection ID")
    obj = await db.get(Collection, uid)
    if not obj:
        raise HTTPException(404, "Collection not found")
    return obj


async def _fingerprint_or_404(collection_id: uuid.UUID, db: AsyncSession) -> Fingerprint:
    stmt = select(Fingerprint).where(Fingerprint.collection_id == collection_id)
    result = await db.execute(stmt)
    fp = result.scalar_one_or_none()
    if not fp:
        raise HTTPException(404, "Fingerprint not available (collection may still be running)")
    return fp


def _summary(c: Collection) -> dict:
    return {
        "id": str(c.id),
        "url": c.url,
        "status": c.status,
        "submitted_at": c.submitted_at.isoformat() if c.submitted_at else None,
        "completed_at": c.completed_at.isoformat() if c.completed_at else None,
        "user_agent": c.user_agent,
        "tags": c.tags or [],
        "notes": c.notes,
        "parent_id": str(c.parent_id) if c.parent_id else None,
    }


def _delete_artifacts(collection_id: uuid.UUID) -> None:
    """Remove all on-disk files created for a collection."""
    # Screenshot
    p = settings.screenshots_dir / f"{collection_id}.png"
    p.unlink(missing_ok=True)
    # HTML dump
    p = settings.html_dir / f"{collection_id}.html"
    p.unlink(missing_ok=True)
    # JS / CSS asset directory
    d = settings.assets_dir / str(collection_id)
    if d.exists():
        shutil.rmtree(d)
