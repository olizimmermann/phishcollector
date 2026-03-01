#!/usr/bin/env python3
"""
submit_feed.py — bulk-submit URLs from urllist/*.txt to the PhishCollector API.

Usage:
    python scripts/submit_feed.py
    python scripts/submit_feed.py --api http://localhost:8000 --concurrency 3
    python scripts/submit_feed.py --wordlist --api-key mysecretkey
    python scripts/submit_feed.py --file scripts/urllist/phishing_feed_1.txt
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

import httpx

# ── Defaults (can be overridden via CLI args or env vars) ─────────────────────
DEFAULT_API     = os.getenv("PHISH_API_URL", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("PHISH_API_KEY", "")
DEFAULT_CONCURRENCY = 2
DEFAULT_DELAY = 5.0  # seconds between submissions


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_urls(paths: list[Path]) -> list[str]:
    """Read URLs from one or more text files, skipping blanks and # comments."""
    urls = []
    for path in paths:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


async def submit(client: httpx.AsyncClient, url: str, wordlist: bool) -> dict:
    """Submit a single URL and return a result dict."""
    try:
        resp = await client.post(
            "/api/v1/collections",
            json={"url": url, "use_wordlist": wordlist},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {"url": url, "ok": True, "id": data.get("id"), "status": data.get("status")}
        else:
            try:
                detail = resp.json().get("detail", resp.text)
                if isinstance(detail, list):
                    detail = detail[0].get("msg", str(detail[0]))
                detail = str(detail).removeprefix("Value error, ")
            except Exception:
                detail = resp.text
            return {"url": url, "ok": False, "error": f"HTTP {resp.status_code}: {detail}"}
    except httpx.RequestError as exc:
        return {"url": url, "ok": False, "error": str(exc)}


async def run(urls: list[str], api: str, api_key: str, concurrency: int, delay: float, wordlist: bool):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    ok_count = 0
    fail_count = 0
    sem = asyncio.Semaphore(concurrency)
    total = len(urls)

    async def bounded_submit(client, url, idx):
        async with sem:
            result = await submit(client, url, wordlist)
            if delay > 0:
                await asyncio.sleep(delay)
            return idx, result

    async with httpx.AsyncClient(base_url=api, headers=headers) as client:
        tasks = [bounded_submit(client, url, i) for i, url in enumerate(urls)]
        for coro in asyncio.as_completed(tasks):
            idx, result = await coro
            done = ok_count + fail_count + 1
            if result["ok"]:
                ok_count += 1
                print(f"[{done:>4}/{total}] ✓  {result['id'][:8]}…  {result['url'][:72]}")
            else:
                fail_count += 1
                print(f"[{done:>4}/{total}] ✗  {result['error'][:40]}  {result['url'][:60]}", file=sys.stderr)

    print(f"\nDone — {ok_count} submitted, {fail_count} failed out of {total} URLs.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bulk-submit URLs to PhishCollector.")
    parser.add_argument("--api", default=DEFAULT_API, help="API base URL (default: %(default)s)")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="X-API-Key header value")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help="Max simultaneous submissions (default: %(default)s)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY,
                        help="Seconds to wait after each submission (default: %(default)s)")
    parser.add_argument("--wordlist", action="store_true",
                        help="Enable wordlist fuzzing for each submission")
    parser.add_argument("--file", type=Path, metavar="PATH",
                        help="Single URL list file (default: all files in scripts/urllist/)")
    args = parser.parse_args()

    # Resolve URL list files
    if args.file:
        files = [args.file]
    else:
        urllist_dir = Path(__file__).parent / "urllist"
        files = sorted(urllist_dir.glob("*.txt"))
        if not files:
            print(f"No .txt files found in {urllist_dir}", file=sys.stderr)
            sys.exit(1)

    urls = load_urls(files)
    if not urls:
        print("No URLs found.", file=sys.stderr)
        sys.exit(1)

    print(f"Submitting {len(urls)} URLs → {args.api}  (concurrency={args.concurrency}, delay={args.delay}s, wordlist={args.wordlist})\n")
    asyncio.run(run(urls, args.api, args.api_key, args.concurrency, args.delay, args.wordlist))


if __name__ == "__main__":
    main()
