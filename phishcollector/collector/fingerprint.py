"""
Fingerprinting engine.

Extracts every observable attribute of a phishing site:
  - IP address, ASN, organisation, country/city (ip-api.com, no key required)
  - TLS certificate details (subject, issuer, SANs, expiry)
  - Detected server-side / client-side technologies
  - All HTML forms (with credential-form detection)
  - Favicon hash (mmh3 / Shodan-compatible + SHA-256)
  - WHOIS record for the registrar domain
  - Phishing-specific indicator patterns (obfuscation, exfiltration, anti-bot…)
  - External third-party domains loaded by the page
"""

import asyncio
import base64
import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import mmh3
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ipwhois import IPWhois

from .browser import PageCapture

# ─────────────────────────────────────────────────────────────────────────────
# Technology signatures
# ─────────────────────────────────────────────────────────────────────────────

TECH_SIGNATURES: dict[str, dict] = {
    # ── CMS ──────────────────────────────────────────────────────────────────
    "WordPress": {
        "html": [r"wp-content", r"wp-includes", r'name="generator" content="WordPress'],
        "url": [r"/wp-login\.php", r"/wp-admin/"],
        "cookies": ["wordpress_", "wp-settings-"],
    },
    "Joomla": {
        "html": [r"/components/com_", r'name="generator" content="Joomla'],
    },
    "Drupal": {
        "headers": {"X-Generator": r"Drupal", "X-Drupal-Cache": r".+"},
        "html": [r"Drupal\.settings", r"drupal\.js"],
    },
    # ── Languages ────────────────────────────────────────────────────────────
    "PHP": {
        "headers": {"X-Powered-By": r"PHP"},
        "url": [r"\.php(\?|$|/)"],
        "cookies": ["PHPSESSID"],
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".+"},
        "cookies": ["ASP\.NET_SessionId", "ASPXAUTH"],
    },
    # ── Web servers ───────────────────────────────────────────────────────────
    "Apache": {"headers": {"Server": r"Apache"}},
    "Nginx": {"headers": {"Server": r"nginx"}},
    "IIS": {"headers": {"Server": r"IIS"}},
    # ── CDN / proxy ───────────────────────────────────────────────────────────
    "Cloudflare": {
        "headers": {"CF-Ray": r".+", "Server": r"cloudflare"},
    },
    "AWS": {
        "headers": {"Server": r"awselb|AmazonS3"},
    },
    # ── JS frameworks ────────────────────────────────────────────────────────
    "jQuery": {
        "html": [r"jquery[.\-][\d.]+\.min\.js", r"jquery[.\-][\d.]+\.js"],
    },
    "React": {
        "html": [r"react[.\-][\d.]+\.js", r"__NEXT_DATA__", r"data-reactroot"],
    },
    "Vue.js": {
        "html": [r"vue[.\-][\d.]+\.js", r"\bv-bind\b", r"\bv-model\b"],
    },
    "Angular": {
        "html": [r"angular[.\-][\d.]+\.js", r"\bng-app\b", r"\bng-controller\b"],
    },
    "Bootstrap": {
        "html": [
            r"bootstrap[.\-][\d.]+\.css",
            r"bootstrap[.\-][\d.]+\.js",
        ],
    },
    # ── Mailer / webmail ──────────────────────────────────────────────────────
    "PHPMailer": {"html": [r"PHPMailer"]},
    "Roundcube": {"html": [r"roundcube", r"rcmloginuser"]},
}

# ─────────────────────────────────────────────────────────────────────────────
# Phishing indicator patterns
# Each entry: (regex_pattern, human_readable_description)
# ─────────────────────────────────────────────────────────────────────────────

PHISHING_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "credential_harvest": [
        (r"document\.getElementById\(['\"]password['\"]", "JS reads password field by ID"),
        (r"\.value\s*\+.*password|password.*\.value\s*\+", "JS concatenates password value"),
        (r"btoa\s*\(.*password|password.*btoa\s*\(", "Base64-encoding a password"),
        (
            r"fetch\s*\([^)]*['\"]POST['\"]|XMLHttpRequest.*\.open\s*\(['\"]POST",
            "Async POST request (potential exfil)",
        ),
    ],
    "obfuscation": [
        (r"\beval\s*\(", "eval() usage"),
        (r"String\.fromCharCode\s*\(", "String.fromCharCode obfuscation"),
        (r"\\x[0-9a-fA-F]{2}", "Hex-encoded strings"),
        (r"\bunescape\s*\(", "unescape() call"),
        (r"atob\s*\(", "Base64 decoding at runtime"),
        (r"\.replace\s*\(\s*/[^/]+/g\s*,\s*['\"]", "Regex-based string replacement (deobfuscation)"),
    ],
    "exfiltration": [
        (r"api\.telegram\.org/bot", "Telegram bot exfiltration endpoint"),
        (r"https?://t\.me/", "Telegram link in code"),
        (r"@(?:gmail|yahoo|hotmail|outlook)\.com", "Freemail address in code"),
        (r"\.php\?.*(?:email|pass|user|token)=", "Credential query-string to PHP script"),
    ],
    "antibot": [
        (r"ipqualityscore|ipqs\.com", "IPQS anti-bot service"),
        (r"anti[_\-]?bot|antibot", "Generic anti-bot check"),
        (r"\bisBot\b|\bcheckBot\b|\bdetectBot\b", "Bot detection function"),
        (r"navigator\.webdriver", "WebDriver property check"),
        (r"navigator\.languages\.length\s*===?\s*0", "Empty languages array check"),
        (r"window\.__phantomas", "Phantomas headless detection"),
    ],
    "kit_indicators": [
        (r"scambaiter|scam.{0,5}baiter", "Anti-scambaiter logic"),
        (r"office365|microsoft365|ms365", "Office 365 phishing theme"),
        (r"unusual.*activity|suspicious.*sign.?in", "Security-alert phishing theme"),
        (r"verify.*account|account.*verif", "Account verification phishing theme"),
        (r"update.*(?:billing|payment|card)|(?:billing|payment).*update", "Payment-update theme"),
        (r"apple.?id.*suspend|suspend.*apple.?id", "Apple ID suspension theme"),
        (r"paypal.*limit|limit.*paypal", "PayPal limitation theme"),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


async def fingerprint_page(
    url: str,
    page: PageCapture,
    options: dict,
    request_timeout: int = 15,
    proxy_url: Optional[str] = None,
) -> dict:
    """
    Run all fingerprinting probes against *url* / *page* and return a
    flat dictionary suitable for storing in the :class:`Fingerprint` model.

    :param proxy_url: Routes favicon/direct HTTP probes to the phishing site
        through this proxy.  Geo/ASN/WHOIS probes use direct connections since
        they query our own intelligence sources, not the phishing server.
    """
    parsed = urlparse(page.final_url or url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Run independent probes concurrently.
    # Geo / TLS / WHOIS: always direct (querying our intel sources, not phisher).
    # Favicon: use proxy so phisher doesn't see analyst's real IP.
    (
        geo_info,
        ssl_info,
        whois_info,
        favicon_info,
    ) = await asyncio.gather(
        _geoip(hostname, request_timeout),
        _ssl_cert(hostname, port),
        _whois(hostname),
        _favicon(page.final_url or url, page.html, request_timeout, proxy_url),
        return_exceptions=True,
    )

    def _safe(result, default=None):
        return result if not isinstance(result, Exception) else default

    geo_info = _safe(geo_info, {})
    ssl_info = _safe(ssl_info, {})
    whois_info = _safe(whois_info, {})
    favicon_info = _safe(favicon_info, {})

    return {
        # Network
        "ip_address": geo_info.get("query"),
        "asn": geo_info.get("as"),
        "org": geo_info.get("org"),
        "country": geo_info.get("countryCode"),
        "city": geo_info.get("city"),
        # TLS
        "ssl_cert": ssl_info,
        "ssl_valid": ssl_info.get("valid") if ssl_info else None,
        # Favicon
        "favicon_hash": favicon_info.get("mmh3"),
        "favicon_sha256": favicon_info.get("sha256"),
        # Page
        "technologies": _detect_technologies(page),
        "forms": _extract_forms(page.html),
        "external_domains": _external_domains(page.final_url or url, page),
        "phishing_indicators": _detect_phishing_indicators(page.html),
        # WHOIS
        "whois": whois_info,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Internal probes
# ─────────────────────────────────────────────────────────────────────────────


async def _geoip(hostname: str, timeout: int) -> dict:
    """Resolve host → IP, then query ip-api.com for ASN/geo (free, no key)."""
    try:
        ip = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyname(hostname)
        )
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,query,country,countryCode,city,org,as"
            )
            data = r.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


async def _ssl_cert(hostname: str, port: int) -> dict:
    """Fetch and parse the TLS certificate for *hostname*:*port*."""
    if not hostname:
        return {}

    def _fetch():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True)

    try:
        der = await asyncio.get_event_loop().run_in_executor(None, _fetch)
        cert = x509.load_der_x509_certificate(der, default_backend())

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(n) for n in san_ext.value]
        except x509.ExtensionNotFound:
            sans = []

        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": (not_after - now).days,
            "serial": str(cert.serial_number),
            "sans": sans,
            "valid": not_before <= now <= not_after,
            "expired": now > not_after,
        }
    except Exception as exc:
        return {"error": str(exc)}


async def _whois(hostname: str) -> dict:
    """Run a WHOIS lookup. Returns a trimmed dict (no raw text blobs)."""
    if not hostname:
        return {}

    # Strip www. and subdomains — only look up the registrar domain
    parts = hostname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    def _lookup():
        import whois as pythonwhois  # python-whois

        try:
            w = pythonwhois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "country": w.country,
            }
        except Exception as exc:
            return {"error": str(exc)}

    return await asyncio.get_event_loop().run_in_executor(None, _lookup)


async def _favicon(
    base_url: str,
    html: str,
    timeout: int,
    proxy_url: Optional[str] = None,
) -> dict:
    """
    Locate, download, and hash the site favicon.
    Returns both the Shodan-compatible mmh3 hash and SHA-256.
    Routes through *proxy_url* when set to hide the analyst's IP.
    """
    favicon_url = _find_favicon_url(base_url, html)
    if not favicon_url:
        return {}

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
            proxy=proxy_url or None,
        ) as client:
            r = await client.get(favicon_url)
            if r.status_code == 200 and r.content:
                data = r.content
                # Shodan-compatible: mmh3 hash of base64-encoded favicon
                b64 = base64.encodebytes(data).decode("utf-8")
                mmh3_hash = str(mmh3.hash(b64))
                sha256 = hashlib.sha256(data).hexdigest()
                return {"url": favicon_url, "mmh3": mmh3_hash, "sha256": sha256}
    except Exception:
        pass
    return {}


def _find_favicon_url(base_url: str, html: str) -> Optional[str]:
    """Extract favicon URL from HTML <link> tags, fall back to /favicon.ico."""
    from urllib.parse import urljoin

    soup = BeautifulSoup(html, "lxml")
    for rel in ("icon", "shortcut icon", "apple-touch-icon"):
        tag = soup.find("link", rel=lambda v, r=rel: v and r in v.lower())
        if tag and tag.get("href"):
            return urljoin(base_url, tag["href"])

    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"


# ─────────────────────────────────────────────────────────────────────────────
# HTML analysis helpers
# ─────────────────────────────────────────────────────────────────────────────


def _detect_technologies(page: PageCapture) -> list[str]:
    """Match tech signatures against headers, HTML, cookies, and URL."""
    detected: list[str] = []
    html_lower = page.html.lower()
    headers = {k.lower(): v for k, v in page.response_headers.items()}
    cookie_names = [c.get("name", "") for c in page.cookies]
    final_url = page.final_url or ""

    for tech, sigs in TECH_SIGNATURES.items():
        matched = False

        for pattern in sigs.get("html", []):
            if re.search(pattern, page.html, re.IGNORECASE):
                matched = True
                break

        if not matched:
            for header_name, pattern in sigs.get("headers", {}).items():
                value = headers.get(header_name.lower(), "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    matched = True
                    break

        if not matched:
            for pattern in sigs.get("url", []):
                if re.search(pattern, final_url, re.IGNORECASE):
                    matched = True
                    break

        if not matched:
            for cookie_prefix in sigs.get("cookies", []):
                if any(re.search(cookie_prefix, c, re.IGNORECASE) for c in cookie_names):
                    matched = True
                    break

        if matched:
            detected.append(tech)

    return detected


def _extract_forms(html: str) -> list[dict]:
    """Parse all HTML forms and annotate credential forms."""
    soup = BeautifulSoup(html, "lxml")
    forms: list[dict] = []

    for form in soup.find_all("form"):
        fields = []
        for tag in form.find_all(["input", "select", "textarea"]):
            fields.append(
                {
                    "name": tag.get("name", ""),
                    "type": tag.get("type", "text").lower(),
                    "id": tag.get("id", ""),
                    "placeholder": tag.get("placeholder", ""),
                    "required": tag.has_attr("required"),
                    "hidden": tag.get("type", "").lower() == "hidden",
                    "value": tag.get("value") if tag.get("type", "").lower() == "hidden" else None,
                }
            )

        field_types = [f["type"] for f in fields]
        field_names = [f["name"].lower() for f in fields]

        has_password = "password" in field_types
        has_email_or_username = any(
            t in ("email",) or n in ("email", "username", "user", "login", "userid", "account")
            for t, n in zip(field_types, field_names)
        )

        forms.append(
            {
                "action": form.get("action", ""),
                "method": form.get("method", "get").upper(),
                "fields": fields,
                "has_password_field": has_password,
                "credential_form": has_password and has_email_or_username,
            }
        )

    return forms


def _external_domains(base_url: str, page: PageCapture) -> list[str]:
    """Return sorted list of unique third-party domains loaded by the page."""
    base_host = urlparse(base_url).netloc.lower()
    external: set[str] = set()

    for req in page.requests:
        parsed = urlparse(req.url)
        host = parsed.netloc.lower()
        if host and host != base_host:
            external.add(host)

    return sorted(external)


def _detect_phishing_indicators(html: str) -> dict[str, list[str]]:
    """
    Scan the HTML (including embedded JS) for phishing-specific patterns.
    Returns a mapping of category → list of matched descriptions.
    """
    findings: dict[str, list[str]] = {}

    for category, patterns in PHISHING_PATTERNS.items():
        matched: list[str] = []
        for pattern, description in patterns:
            if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
                matched.append(description)
        if matched:
            findings[category] = matched

    return findings
