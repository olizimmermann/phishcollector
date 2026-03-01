#!/usr/bin/env python3
"""
cleanup.py — delete collections from PhishCollector.

Deletes via the API so all DB records AND on-disk artifacts are removed.

Usage:
    # Dry-run: show what would be deleted
    python scripts/cleanup.py --dry-run

    # Delete everything (asks for confirmation)
    python scripts/cleanup.py --all

    # Delete only failed collections
    python scripts/cleanup.py --status failed

    # Delete completed collections older than 30 days
    python scripts/cleanup.py --status completed --older-than 30

    # Delete anything whose URL contains a pattern
    python scripts/cleanup.py --url-contains vercel.app

    # Combine filters + skip confirmation prompt
    python scripts/cleanup.py --status failed --older-than 7 --yes
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

import httpx

DEFAULT_API     = os.getenv("PHISH_API_URL", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("PHISH_API_KEY", "")


def parse_date(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def matches(col: dict, status: str | None, older_than: int | None, url_contains: str | None) -> bool:
    if status and col["status"] != status:
        return False
    if older_than is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than)
        submitted = parse_date(col["submitted_at"]) if col.get("submitted_at") else None
        if not submitted or submitted > cutoff:
            return False
    if url_contains and url_contains.lower() not in col["url"].lower():
        return False
    return True


async def fetch_all(client: httpx.AsyncClient) -> list[dict]:
    """Fetch all collections (paginated in batches of 500)."""
    all_cols = []
    skip = 0
    while True:
        r = await client.get(f"/api/v1/collections?limit=500&skip={skip}")
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        all_cols.extend(batch)
        if len(batch) < 500:
            break
        skip += len(batch)
    return all_cols


async def delete_one(client: httpx.AsyncClient, col: dict) -> bool:
    try:
        r = await client.delete(f"/api/v1/collections/{col['id']}")
        return r.status_code == 204
    except httpx.RequestError:
        return False


async def run(
    api: str,
    api_key: str,
    status: str | None,
    older_than: int | None,
    url_contains: str | None,
    dry_run: bool,
    yes: bool,
):
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    async with httpx.AsyncClient(base_url=api, headers=headers, timeout=30) as client:
        print("Fetching collections…")
        try:
            all_cols = await fetch_all(client)
        except httpx.HTTPStatusError as e:
            print(f"Failed to fetch collections: {e}", file=sys.stderr)
            sys.exit(1)

        targets = [c for c in all_cols if matches(c, status, older_than, url_contains)]

        if not targets:
            print("No collections match the given filters.")
            return

        # Summary
        print(f"\n{'DRY RUN — ' if dry_run else ''}Found {len(targets)} collection(s) to delete:\n")
        for c in targets:
            age = ""
            if c.get("submitted_at"):
                delta = datetime.now(timezone.utc) - parse_date(c["submitted_at"])
                age = f"  ({delta.days}d ago)"
            print(f"  [{c['status']:<10}] {c['id'][:8]}…  {c['url'][:72]}{age}")

        if dry_run:
            print(f"\nDry run complete — {len(targets)} would be deleted. Pass --yes to confirm.")
            return

        # Confirm
        if not yes:
            print(f"\nThis will permanently delete {len(targets)} collection(s) and all their artifacts.")
            try:
                ans = input("Type 'yes' to continue: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                return
            if ans != "yes":
                print("Aborted.")
                return

        # Delete
        print()
        ok = fail = 0
        for c in targets:
            success = await delete_one(client, c)
            if success:
                ok += 1
                print(f"  ✓  deleted  {c['id'][:8]}…  {c['url'][:64]}")
            else:
                fail += 1
                print(f"  ✗  failed   {c['id'][:8]}…  {c['url'][:64]}", file=sys.stderr)

        print(f"\nDone — {ok} deleted, {fail} failed.")


def main():
    parser = argparse.ArgumentParser(description="Delete PhishCollector collections and their artifacts.")
    parser.add_argument("--api",     default=DEFAULT_API,     help="API base URL (default: %(default)s)")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="X-API-Key header value")

    # Filters
    filt = parser.add_argument_group("filters (combined with AND)")
    filt.add_argument("--all",          action="store_true",  help="Delete all collections (no filter)")
    filt.add_argument("--status",       choices=["pending", "running", "completed", "failed"],
                      help="Only delete collections with this status")
    filt.add_argument("--older-than",   type=int, metavar="DAYS",
                      help="Only delete collections submitted more than N days ago")
    filt.add_argument("--url-contains", metavar="PATTERN",
                      help="Only delete collections whose URL contains this string (case-insensitive)")

    # Behaviour
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without deleting")
    parser.add_argument("--yes",     action="store_true", help="Skip confirmation prompt")

    args = parser.parse_args()

    if not args.all and not args.status and args.older_than is None and not args.url_contains and not args.dry_run:
        parser.error("Specify at least one filter (--all, --status, --older-than, --url-contains) or --dry-run")

    asyncio.run(run(
        api=args.api,
        api_key=args.api_key,
        status=args.status,
        older_than=args.older_than,
        url_contains=args.url_contains,
        dry_run=args.dry_run,
        yes=args.yes,
    ))


if __name__ == "__main__":
    main()
