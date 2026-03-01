"""
PhishCollector CLI

Wraps the REST API for convenient command-line use.

Usage examples:
  phishcollector collect https://suspicious-site.example.com
  phishcollector collect https://suspicious.example.com --wordlist
  phishcollector status <job-id>
  phishcollector detail <job-id>
  phishcollector list --status completed
  phishcollector search --tech WordPress --country RU
  phishcollector screenshot <job-id> -o capture.png
"""

import sys
import time
from pathlib import Path
from typing import Optional

import click
import httpx
from rich.console import Console
from rich.json import JSON
from rich.table import Table

console = Console()
DEFAULT_API = "http://localhost:8000/api/v1"


def _api(ctx) -> str:
    return ctx.obj.get("api", DEFAULT_API)


def _key(ctx) -> Optional[str]:
    return ctx.obj.get("key")


def _headers(ctx) -> dict:
    h = {}
    k = _key(ctx)
    if k:
        h["X-API-Key"] = k
    return h


def _get(ctx, path: str) -> dict:
    r = httpx.get(f"{_api(ctx)}{path}", headers=_headers(ctx), timeout=30)
    r.raise_for_status()
    return r.json()


def _post(ctx, path: str, body: dict) -> dict:
    r = httpx.post(f"{_api(ctx)}{path}", json=body, headers=_headers(ctx), timeout=30)
    r.raise_for_status()
    return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# Main group
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.option("--api", default=DEFAULT_API, show_default=True, help="API base URL")
@click.option("--key", default=None, envvar="PHISH_API_KEY", help="API key (or set PHISH_API_KEY)")
@click.pass_context
def cli(ctx, api, key):
    """PhishCollector — capture and fingerprint phishing websites."""
    ctx.ensure_object(dict)
    ctx.obj["api"] = api
    ctx.obj["key"] = key


# ─────────────────────────────────────────────────────────────────────────────
# collect
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("url")
@click.option("--wordlist", is_flag=True, default=False, help="Enable wordlist path fuzzing")
@click.option("--wordlist-path", default=None, help="Path to a custom wordlist inside the container")
@click.option("--wait", is_flag=True, default=False, help="Block until the job completes")
@click.option("--poll", default=5, show_default=True, help="Polling interval in seconds (with --wait)")
@click.pass_context
def collect(ctx, url, wordlist, wordlist_path, wait, poll):
    """Submit URL for collection and fingerprinting."""
    body = {
        "url": url,
        "use_wordlist": wordlist,
    }
    if wordlist_path:
        body["wordlist_path"] = wordlist_path

    try:
        result = _post(ctx, "/collections", body)
    except httpx.HTTPError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    job_id = result["id"]
    console.print(f"[green]Submitted[/green] job [bold]{job_id}[/bold]")

    if wait:
        console.print(f"Waiting for completion (polling every {poll}s)…")
        while True:
            time.sleep(poll)
            try:
                detail = _get(ctx, f"/collections/{job_id}")
            except httpx.HTTPError:
                continue
            status = detail["status"]
            if status == "completed":
                console.print(f"[green]Completed.[/green]")
                _print_summary(detail)
                break
            elif status == "failed":
                console.print(f"[red]Failed:[/red] {detail.get('error')}")
                sys.exit(1)
            else:
                console.print(f"  status: {status}")


# ─────────────────────────────────────────────────────────────────────────────
# status
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("job_id")
@click.pass_context
def status(ctx, job_id):
    """Show the current status of a collection job."""
    try:
        detail = _get(ctx, f"/collections/{job_id}")
    except httpx.HTTPError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    console.print(f"Status: [bold]{detail['status']}[/bold]")
    if detail.get("error"):
        console.print(f"Error:  {detail['error']}")


# ─────────────────────────────────────────────────────────────────────────────
# detail
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("job_id")
@click.option("--json", "as_json", is_flag=True, help="Print raw JSON")
@click.pass_context
def detail(ctx, job_id, as_json):
    """Print full fingerprint detail for a completed collection."""
    try:
        data = _get(ctx, f"/collections/{job_id}")
    except httpx.HTTPError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if as_json:
        console.print(JSON.from_data(data))
        return

    _print_summary(data)


# ─────────────────────────────────────────────────────────────────────────────
# list
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("list")
@click.option("--status", "status_filter", default=None)
@click.option("--limit", default=20, show_default=True)
@click.pass_context
def list_cmd(ctx, status_filter, limit):
    """List recent collections."""
    path = f"/collections?limit={limit}"
    if status_filter:
        path += f"&status={status_filter}"
    try:
        rows = _get(ctx, path)
    except httpx.HTTPError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    t = Table(title="Collections")
    t.add_column("ID", style="cyan", no_wrap=True)
    t.add_column("URL")
    t.add_column("Status")
    t.add_column("Submitted")

    for r in rows:
        color = {"completed": "green", "failed": "red", "running": "yellow"}.get(r["status"], "white")
        t.add_row(r["id"][:8] + "…", r["url"], f"[{color}]{r['status']}[/{color}]", r["submitted_at"])

    console.print(t)


# ─────────────────────────────────────────────────────────────────────────────
# search
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--favicon-hash", default=None, help="Shodan-style mmh3 favicon hash")
@click.option("--ip", default=None)
@click.option("--tech", default=None, help="Detected technology (e.g. WordPress)")
@click.option("--country", default=None, help="Two-letter country code")
@click.option("--title", default=None, help="Partial page title match")
@click.option("--limit", default=20, show_default=True)
@click.pass_context
def search(ctx, favicon_hash, ip, tech, country, title, limit):
    """Search fingerprints across all completed collections."""
    params = []
    if favicon_hash:
        params.append(f"favicon_hash={favicon_hash}")
    if ip:
        params.append(f"ip={ip}")
    if tech:
        params.append(f"technology={tech}")
    if country:
        params.append(f"country={country}")
    if title:
        params.append(f"title={title}")
    params.append(f"limit={limit}")

    try:
        rows = _get(ctx, f"/search?{'&'.join(params)}")
    except httpx.HTTPError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if not rows:
        console.print("No results.")
        return

    t = Table(title="Search results")
    t.add_column("Collection ID", style="cyan")
    t.add_column("IP")
    t.add_column("Country")
    t.add_column("Title")
    t.add_column("Technologies")
    t.add_column("Favicon hash (mmh3)")

    for r in rows:
        t.add_row(
            str(r["collection_id"])[:8] + "…",
            r.get("ip_address", ""),
            r.get("country", ""),
            (r.get("title") or "")[:50],
            ", ".join(r.get("technologies") or []),
            r.get("favicon_hash_mmh3", ""),
        )

    console.print(t)


# ─────────────────────────────────────────────────────────────────────────────
# screenshot
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("job_id")
@click.option("-o", "--output", default="screenshot.png", show_default=True)
@click.pass_context
def screenshot(ctx, job_id, output):
    """Download the screenshot for a collection."""
    url = f"{_api(ctx)}/collections/{job_id}/screenshot"
    r = httpx.get(url, headers=_headers(ctx), timeout=30)
    if r.status_code != 200:
        console.print(f"[red]Error {r.status_code}:[/red] {r.text}")
        sys.exit(1)
    Path(output).write_bytes(r.content)
    console.print(f"[green]Saved[/green] → {output}")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: pretty-print collection detail
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(data: dict):
    console.rule(f"[bold]{data['url']}[/bold]")
    console.print(f"  ID:        {data['id']}")
    console.print(f"  Status:    {data['status']}")
    console.print(f"  Submitted: {data.get('submitted_at', '')}")
    console.print(f"  Completed: {data.get('completed_at', '')}")

    fp = data.get("fingerprint")
    if not fp:
        return

    console.print()
    console.rule("[bold]Fingerprint[/bold]")
    console.print(f"  IP/ASN:    {fp.get('ip_address')} / {fp.get('asn')}")
    console.print(f"  Country:   {fp.get('country')} / {fp.get('city')}")
    console.print(f"  Title:     {fp.get('title')}")
    console.print(f"  Final URL: {fp.get('final_url')}")
    console.print(f"  Status:    {fp.get('status_code')}")
    console.print(f"  Page SHA256:  {fp.get('page_sha256')}")
    console.print(f"  Favicon mmh3: {fp.get('favicon_hash_mmh3')}")
    console.print(f"  Technologies: {', '.join(fp.get('technologies') or [])}")

    cred_forms = [f for f in (fp.get("forms") or []) if f.get("credential_form")]
    if cred_forms:
        console.print(f"  [yellow]Credential forms: {len(cred_forms)}[/yellow]")

    indicators = fp.get("phishing_indicators") or {}
    if indicators:
        console.print()
        console.rule("[bold yellow]Phishing Indicators[/bold yellow]")
        for category, matches in indicators.items():
            console.print(f"  [yellow]{category}[/yellow]")
            for m in matches:
                console.print(f"    • {m}")

    tls = fp.get("ssl_cert") or {}
    if tls and not tls.get("error"):
        console.print()
        console.rule("[bold]TLS Certificate[/bold]")
        console.print(f"  Issuer:  {tls.get('issuer')}")
        console.print(f"  Subject: {tls.get('subject')}")
        console.print(f"  Valid:   {tls.get('not_before')} → {tls.get('not_after')}")
        console.print(f"  Expired: {tls.get('expired')}")
        sans = tls.get("sans", [])
        if sans:
            console.print(f"  SANs:    {', '.join(sans[:5])}" + (" …" if len(sans) > 5 else ""))

    console.print()
    console.print(f"  Spider pages: {data.get('spider_count', 0)}")
    console.print(f"  Assets saved: {data.get('asset_count', 0)}")
    console.print(f"  HTTP requests logged: {data.get('request_count', 0)}")


if __name__ == "__main__":
    cli()
