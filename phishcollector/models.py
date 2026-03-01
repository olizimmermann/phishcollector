import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Collection(Base):
    """Top-level record for a single collection job."""

    __tablename__ = "collections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # pending | running | completed | failed
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[Optional[str]] = mapped_column(String(4096), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Rescan chain: points to the collection this was rescanned from
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )

    # Analyst annotations
    tags: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True, default=list)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    fingerprint: Mapped[Optional["Fingerprint"]] = relationship(
        back_populates="collection", uselist=False, cascade="all, delete-orphan"
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="collection", cascade="all, delete-orphan"
    )
    http_requests: Mapped[list["HttpRequest"]] = relationship(
        back_populates="collection", cascade="all, delete-orphan"
    )
    spider_results: Mapped[list["SpiderResult"]] = relationship(
        back_populates="collection", cascade="all, delete-orphan"
    )
    plugin_results: Mapped[list["PluginResult"]] = relationship(
        back_populates="collection", cascade="all, delete-orphan"
    )


# Index for fast "all scans of this URL" lookups
Index("ix_collections_url", Collection.url)


class Fingerprint(Base):
    """Rich fingerprint record produced for each completed collection."""

    __tablename__ = "fingerprints"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    # ── Network ──────────────────────────────────────────────────────────────
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    asn: Mapped[Optional[str]] = mapped_column(String(100))
    org: Mapped[Optional[str]] = mapped_column(String(512))
    country: Mapped[Optional[str]] = mapped_column(String(2))
    city: Mapped[Optional[str]] = mapped_column(String(256))

    # ── TLS ──────────────────────────────────────────────────────────────────
    ssl_cert: Mapped[Optional[dict]] = mapped_column(JSONB)
    ssl_valid: Mapped[Optional[bool]] = mapped_column(Boolean)

    # ── HTTP ─────────────────────────────────────────────────────────────────
    final_url: Mapped[Optional[str]] = mapped_column(String(2048))
    redirect_chain: Mapped[Optional[list]] = mapped_column(JSONB)
    response_headers: Mapped[Optional[dict]] = mapped_column(JSONB)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)

    # ── Page ─────────────────────────────────────────────────────────────────
    title: Mapped[Optional[str]] = mapped_column(String(2048))
    favicon_hash_mmh3: Mapped[Optional[str]] = mapped_column(String(20))  # Shodan-compatible
    favicon_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    page_sha256: Mapped[Optional[str]] = mapped_column(String(64))  # SHA256(rendered HTML)

    # ── Analysis ─────────────────────────────────────────────────────────────
    technologies: Mapped[Optional[list]] = mapped_column(JSONB)
    forms: Mapped[Optional[list]] = mapped_column(JSONB)
    external_domains: Mapped[Optional[list]] = mapped_column(JSONB)
    phishing_indicators: Mapped[Optional[dict]] = mapped_column(JSONB)
    whois: Mapped[Optional[dict]] = mapped_column(JSONB)
    cookies: Mapped[Optional[list]] = mapped_column(JSONB)

    # ── Artifacts ────────────────────────────────────────────────────────────
    screenshot_path: Mapped[Optional[str]] = mapped_column(Text)
    html_path: Mapped[Optional[str]] = mapped_column(Text)

    collection: Mapped["Collection"] = relationship(back_populates="fingerprint")


class PluginResult(Base):
    """Result from a threat-intelligence plugin (URLhaus, VirusTotal, …)."""

    __tablename__ = "plugin_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    plugin_name: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # malicious | suspicious | clean | unknown | error
    score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)  # 0.0–1.0
    result: Mapped[Optional[dict]] = mapped_column(JSONB)
    queried_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    collection: Mapped["Collection"] = relationship(back_populates="plugin_results")


class Asset(Base):
    """A downloaded resource (JS, CSS, …) associated with a collection."""

    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(20), nullable=False)
    sha256: Mapped[Optional[str]] = mapped_column(String(64))
    file_path: Mapped[Optional[str]] = mapped_column(Text)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    content_type: Mapped[Optional[str]] = mapped_column(String(256))

    collection: Mapped["Collection"] = relationship(back_populates="assets")


class HttpRequest(Base):
    """Every network request made by the browser during a collection."""

    __tablename__ = "http_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    request_headers: Mapped[Optional[dict]] = mapped_column(JSONB)
    response_status: Mapped[Optional[int]] = mapped_column(Integer)
    response_headers: Mapped[Optional[dict]] = mapped_column(JSONB)
    response_body_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    resource_type: Mapped[Optional[str]] = mapped_column(String(30))

    collection: Mapped["Collection"] = relationship(back_populates="http_requests")


class SpiderResult(Base):
    """Each URL visited or probed by the spider."""

    __tablename__ = "spider_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    collection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("collections.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    found_via: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # link | robots | sitemap | wordlist
    title: Mapped[Optional[str]] = mapped_column(String(2048))
    content_type: Mapped[Optional[str]] = mapped_column(String(256))
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer)

    collection: Mapped["Collection"] = relationship(back_populates="spider_results")
