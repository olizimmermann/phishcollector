"""
Playwright-based page capture module.

Launches a headless Chromium browser, navigates to the target URL with
JavaScript enabled, intercepts every network response, captures the fully
rendered HTML, a full-page screenshot, cookies, and console output.
"""

import asyncio
import hashlib
import random
from dataclasses import dataclass
from typing import Optional

from fake_useragent import UserAgent
from playwright.async_api import async_playwright

_ua = UserAgent(browsers=["chrome", "firefox", "edge"])
_UA_GETTERS = [lambda: _ua.chrome, lambda: _ua.firefox, lambda: _ua.edge]

# Stealth init-script: hide automation signals so the phisher's anti-bot
# checks see a real browser.
_STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
window.chrome = {runtime: {}};
"""


def random_user_agent() -> str:
    """Return a random realistic user-agent string."""
    try:
        return random.choice(_UA_GETTERS)()
    except Exception:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )


@dataclass
class CapturedRequest:
    url: str
    method: str
    request_headers: dict
    response_status: Optional[int] = None
    response_headers: Optional[dict] = None
    response_body: Optional[bytes] = None
    response_body_sha256: Optional[str] = None
    resource_type: str = "other"


@dataclass
class PageCapture:
    url: str                    # original submitted URL
    final_url: str              # URL after all redirects
    redirect_chain: list[str]   # ordered list of URLs visited
    html: str                   # fully rendered DOM (post-JS)
    screenshot: bytes           # full-page PNG
    title: str
    cookies: list[dict]
    requests: list[CapturedRequest]
    console_messages: list[str]
    response_headers: dict      # main document response headers
    response_status: int        # main document HTTP status


async def capture_page(
    url: str,
    user_agent: str,
    timeout: int = 30_000,
    proxy_url: Optional[str] = None,
) -> PageCapture:
    """
    Load *url* in a headless Chromium browser and return a :class:`PageCapture`
    with everything collected during the session.

    :param url: Target URL (must be http:// or https://).
    :param user_agent: User-Agent string to present to the server.
    :param timeout: Navigation timeout in milliseconds.
    :param proxy_url: Optional proxy (http/https/socks5).  Routes all browser
        traffic through this proxy so the analyst's real IP is not exposed to
        the phishing server.
    """
    proxy_config: Optional[dict] = None
    if proxy_url:
        proxy_config = {"server": proxy_url}

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            proxy=proxy_config,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--disable-extensions",
                # Allow mixed content so we capture everything the phisher loads
                "--allow-running-insecure-content",
            ],
        )

        context = await browser.new_context(
            user_agent=user_agent,
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,  # capture even broken-cert sites
            java_script_enabled=True,
            accept_downloads=False,
        )
        await context.add_init_script(_STEALTH_JS)

        page = await context.new_page()

        # ── Intercept all responses ─────────────────────────────────────────
        captured_requests: list[CapturedRequest] = []
        _lock = asyncio.Lock()

        async def _on_response(response):
            try:
                body = await response.body()
                sha256 = hashlib.sha256(body).hexdigest() if body else None
            except Exception:
                body = None
                sha256 = None

            async with _lock:
                captured_requests.append(
                    CapturedRequest(
                        url=response.url,
                        method=response.request.method,
                        request_headers=dict(response.request.headers),
                        response_status=response.status,
                        response_headers=dict(response.headers),
                        response_body=body,
                        response_body_sha256=sha256,
                        resource_type=response.request.resource_type,
                    )
                )

        page.on("response", lambda r: asyncio.create_task(_on_response(r)))

        # ── Console capture ─────────────────────────────────────────────────
        console_messages: list[str] = []
        page.on(
            "console",
            lambda msg: console_messages.append(f"{msg.type}: {msg.text}"),
        )

        # ── Navigate ────────────────────────────────────────────────────────
        main_response = await page.goto(
            url, timeout=timeout, wait_until="networkidle"
        )

        # Give lazy-loaded content a little extra time to settle
        await asyncio.sleep(2)

        # ── Collect artifacts ───────────────────────────────────────────────
        html = await page.content()
        screenshot = await page.screenshot(full_page=True, type="png")
        title = await page.title()
        cookies = await context.cookies()
        final_url = page.url

        if main_response:
            main_headers = dict(main_response.headers)
            main_status = main_response.status
            # Build redirect chain from Playwright's request chain
            redirect_chain = _build_redirect_chain(main_response.request, url)
        else:
            main_headers = {}
            main_status = 0
            redirect_chain = [url]

        await browser.close()

    return PageCapture(
        url=url,
        final_url=final_url,
        redirect_chain=redirect_chain,
        html=html,
        screenshot=screenshot,
        title=title,
        cookies=[dict(c) for c in cookies],
        requests=captured_requests,
        console_messages=console_messages,
        response_headers=main_headers,
        response_status=main_status,
    )


def _build_redirect_chain(request, original_url: str) -> list[str]:
    """Walk the Playwright request chain backwards to build redirect list."""
    chain: list[str] = []
    current = request
    while current is not None:
        chain.append(current.url)
        current = current.redirected_from
    chain.reverse()
    # Always start from the user-supplied URL
    if not chain or chain[0] != original_url:
        chain.insert(0, original_url)
    return list(dict.fromkeys(chain))  # deduplicate while preserving order
