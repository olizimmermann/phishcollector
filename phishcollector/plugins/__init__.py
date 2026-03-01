"""Threat-intelligence plugins for PhishCollector."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class CheckResult:
    plugin_name: str
    status: str              # malicious | suspicious | clean | unknown | error
    score: Optional[float]   # 0.0 – 1.0, or None if unavailable
    result: Optional[dict]   # raw API response for storage
