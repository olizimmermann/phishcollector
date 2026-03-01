"""
Spider module.

Discovers URLs on a target site via:
  1. Link extraction from the already-captured HTML
  2. robots.txt (Disallow/Allow paths + Sitemap directives)
  3. sitemap.xml / sitemap index files
  4. Optional wordlist-based path probing

All discovered URLs are fetched concurrently (bounded semaphore) and the
responses are recorded as :class:`SpiderResult` objects.
"""

import asyncio
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class SpiderResult:
    url: str
    status_code: Optional[int]
    found_via: str          # link | robots | sitemap | wordlist
    title: Optional[str]
    content_type: Optional[str]
    size_bytes: Optional[int]


async def spider_site(
    base_url: str,
    html: str,
    user_agent: str,
    wordlist: Optional[list[str]] = None,
    max_pages: int = 50,
    timeout: int = 10,
    proxy_url: Optional[str] = None,
) -> list[SpiderResult]:
    """
    Crawl *base_url* and return a list of :class:`SpiderResult` records.

    :param base_url: Final URL of the page (after redirects).
    :param html: Already-rendered HTML of the main page.
    :param user_agent: UA string to use for spider requests.
    :param wordlist: Optional list of relative paths to probe.
    :param max_pages: Hard cap on total pages visited.
    :param timeout: Per-request timeout in seconds.
    """
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    results: list[SpiderResult] = []
    visited: set[str] = {base_url}
    pending: dict[str, str] = {}  # url → found_via

    # Seed with links from the initial page
    for link in _extract_links(base_url, html):
        if link not in visited:
            pending[link] = "link"

    async with httpx.AsyncClient(
        headers={"User-Agent": user_agent},
        follow_redirects=True,
        verify=False,
        timeout=timeout,
        proxy=proxy_url or None,
    ) as client:
        # ── robots.txt ───────────────────────────────────────────────────────
        robots_url = f"{origin}/robots.txt"
        robot_paths, sitemap_urls = await _fetch_robots(client, robots_url)
        for path in robot_paths:
            url = urljoin(origin, path)
            if url not in visited and url not in pending:
                pending[url] = "robots"

        # ── sitemap.xml ──────────────────────────────────────────────────────
        sitemap_urls.append(f"{origin}/sitemap.xml")
        sitemap_links = await _fetch_sitemaps(client, sitemap_urls)
        for url in sitemap_links:
            if url not in visited and url not in pending:
                pending[url] = "sitemap"

        # ── wordlist ─────────────────────────────────────────────────────────
        if wordlist:
            for path in wordlist:
                url = urljoin(origin + "/", path.lstrip("/"))
                if url not in visited and url not in pending:
                    pending[url] = "wordlist"

        # ── Fetch all pending URLs ────────────────────────────────────────────
        sem = asyncio.Semaphore(8)

        async def _fetch(url: str, found_via: str):
            if len(results) >= max_pages:
                return
            async with sem:
                visited.add(url)
                try:
                    r = await client.get(url)
                    content_type = r.headers.get("content-type", "")
                    title: Optional[str] = None

                    if "html" in content_type:
                        soup = BeautifulSoup(r.text, "lxml")
                        t = soup.find("title")
                        title = t.get_text(strip=True) if t else None

                        # Discover more links from same domain
                        if len(results) < max_pages:
                            for new_link in _extract_links(url, r.text):
                                if (
                                    new_link not in visited
                                    and new_link not in pending
                                    and _same_domain(new_link, origin)
                                ):
                                    pending[new_link] = "link"

                    results.append(
                        SpiderResult(
                            url=url,
                            status_code=r.status_code,
                            found_via=found_via,
                            title=title,
                            content_type=content_type,
                            size_bytes=len(r.content),
                        )
                    )
                except Exception:
                    results.append(
                        SpiderResult(
                            url=url,
                            status_code=None,
                            found_via=found_via,
                            title=None,
                            content_type=None,
                            size_bytes=None,
                        )
                    )

        # Process only same-domain URLs (wordlist paths are already relative to origin)
        tasks = [
            _fetch(url, via)
            for url, via in list(pending.items())
            if _same_domain(url, origin) or via == "wordlist"
        ]
        await asyncio.gather(*tasks[:max_pages], return_exceptions=True)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _extract_links(base_url: str, html: str) -> set[str]:
    """Extract absolute HTTP(S) links from HTML."""
    soup = BeautifulSoup(html, "lxml")
    links: set[str] = set()

    _BLOCKED_SCHEMES = (
        "javascript:", "vbscript:", "data:", "blob:", "mailto:", "tel:",
        "ftp:", "file:", "about:", "chrome:", "chrome-extension:",
    )
    for tag in soup.find_all(["a", "form", "link", "script", "iframe", "frame"]):
        ref = tag.get("href") or tag.get("src") or tag.get("action") or ""
        ref = ref.strip()
        if not ref or ref.startswith(("#",)):
            continue
        ref_lower = ref.lower()
        if any(ref_lower.startswith(s) for s in _BLOCKED_SCHEMES):
            continue
        full = urljoin(base_url, ref).split("#")[0]
        # Only follow http/https — strictly
        if full.startswith(("http://", "https://")):
            links.add(full)

    return links


def _same_domain(url: str, origin: str) -> bool:
    return urlparse(url).netloc == urlparse(origin).netloc


async def _fetch_robots(
    client: httpx.AsyncClient, robots_url: str
) -> tuple[list[str], list[str]]:
    """
    Parse robots.txt.
    Returns (list_of_paths, list_of_sitemap_urls).
    """
    paths: list[str] = []
    sitemaps: list[str] = []
    try:
        r = await client.get(robots_url, timeout=5)
        if r.status_code != 200:
            return paths, sitemaps
        for raw_line in r.text.splitlines():
            line = raw_line.strip()
            lower = line.lower()
            if lower.startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemaps.append(sm)
            elif lower.startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                # Skip wildcards and root
                if path and "*" not in path and path != "/":
                    paths.append(path)
    except Exception:
        pass
    return paths, sitemaps


async def _fetch_sitemaps(
    client: httpx.AsyncClient, sitemap_urls: list[str]
) -> list[str]:
    """Fetch one or more sitemap (or sitemap-index) URLs and return all <loc> values."""
    links: list[str] = []
    seen: set[str] = set()

    async def _fetch_one(url: str):
        if url in seen:
            return
        seen.add(url)
        try:
            r = await client.get(url, timeout=5)
            if r.status_code != 200:
                return
            soup = BeautifulSoup(r.text, "xml")
            # sitemap index → recurse into child sitemaps
            for sitemap_tag in soup.find_all("sitemap"):
                loc = sitemap_tag.find("loc")
                if loc:
                    await _fetch_one(loc.get_text(strip=True))
            # regular sitemap
            for loc in soup.find_all("loc"):
                links.append(loc.get_text(strip=True))
        except Exception:
            pass

    await asyncio.gather(*[_fetch_one(u) for u in sitemap_urls], return_exceptions=True)
    return links
