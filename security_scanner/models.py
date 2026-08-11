"""Structured findings and risk levels for scan output."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class HttpLogEntry:
    """One logged HTTP exchange (request + response summary)."""

    method: str
    url: str
    status_code: int | None
    response_snippet: str
    error: str | None = None


@dataclass
class Finding:
    """A single vulnerability or misconfiguration finding."""

    module: str
    title: str
    risk: RiskLevel
    description: str
    remediation: str
    evidence: str
    request_url: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Full scan result for JSON / dashboard export."""

    target_url: str
    disclaimer: str
    findings: list[Finding]
    http_log: list[HttpLogEntry]
    total_requests: int
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "disclaimer": self.disclaimer,
            "total_requests": self.total_requests,
            "findings": [
                {
                    "module": f.module,
                    "title": f.title,
                    "risk": f.risk.value,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                    "request_url": f.request_url,
                    "metadata": f.metadata,
                }
                for f in self.findings
            ],
            "http_log": [
                {
                    "method": e.method,
                    "url": e.url,
                    "status_code": e.status_code,
                    "response_snippet": e.response_snippet,
                    "error": e.error,
                }
                for e in self.http_log
            ],
            "errors": self.errors,
        }

    def risk_counts(self) -> dict[str, int]:
        counts = {level.value: 0 for level in RiskLevel}
        for finding in self.findings:
            counts[finding.risk.value] += 1
        return counts

    @property
    def failed_request_count(self) -> int:
        return sum(1 for entry in self.http_log if entry.error)
