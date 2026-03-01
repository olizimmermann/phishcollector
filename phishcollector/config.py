from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "PHISH_", "env_file": ".env"}

    # Database
    database_url: str = "postgresql+asyncpg://phish:phish@db:5432/phishcollector"

    # Optional API authentication (if set, all API requests require X-API-Key header)
    api_key: Optional[str] = None

    # Storage
    data_dir: str = "/data"

    # Browser
    browser_timeout: int = 30000  # ms
    request_timeout: int = 15  # seconds

    # Spider
    max_spider_pages: int = 50

    # Asset download
    max_asset_size: int = 10 * 1024 * 1024  # 10 MB

    # Default wordlist (inside container)
    default_wordlist: str = "/app/wordlists/phishing_paths.txt"

    # ── Proxy ─────────────────────────────────────────────────────────────────
    # Routes all browser and HTTP requests to phishing sites through this proxy.
    # Supports: http://host:port  https://host:port  socks5://host:port
    # With auth: http://user:pass@host:port
    # Leave empty to connect directly (analyst IP will be visible to the phisher).
    proxy_url: Optional[str] = None

    # Set to false when using an intercepting proxy such as Burp Suite.
    # Burp presents its own CA certificate for every TLS connection; without
    # disabling verification all HTTPS requests through the proxy will fail.
    # Never set to false in production / non-proxied environments.
    proxy_ssl_verify: bool = True

    # ── Threat intelligence plugins ───────────────────────────────────────────
    urlhaus_enabled: bool = False          # abuse.ch URLhaus
    urlhaus_api_key: Optional[str] = None  # abuse.ch Auth-Key — get free at https://auth.abuse.ch/
    virustotal_api_key: Optional[str] = None  # VirusTotal v3 API key

    @property
    def screenshots_dir(self) -> Path:
        return Path(self.data_dir) / "screenshots"

    @property
    def html_dir(self) -> Path:
        return Path(self.data_dir) / "html"

    @property
    def assets_dir(self) -> Path:
        return Path(self.data_dir) / "assets"

    @property
    def wordlist_dir(self) -> Path:
        """Trusted directory for wordlists — used to validate user-supplied paths."""
        return Path("/app/wordlists")


settings = Settings()
