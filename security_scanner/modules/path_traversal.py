"""
Path traversal *detection* using benign traversal sequences.

We request URLs that include ../-style segments and look for patterns that
might indicate unintended file read (e.g. Unix passwd file markers). This is
read-oriented detection only — we do not attempt to write or overwrite files.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

from security_scanner.config import PATH_TRAVERSAL_SEGMENTS
from security_scanner.http_client import LoggingHttpClient, ScannerNetworkError
from security_scanner.models import Finding, RiskLevel

# Heuristic markers (may indicate file disclosure; can false-positive).
TRAVERSAL_MARKERS = (
    "root:x:0:0:",
    "[boot loader]",
    "for 16-bit app support",
    "daemon:x:",
    "[extensions]",
)


def _with_extra_path(base_url: str, suffix: str) -> str:
    """Append traversal suffix to the path component."""
    parsed = urlparse(base_url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path + "/"
    new_path = path + suffix
    return urlunparse(
        (parsed.scheme, parsed.netloc, new_path, "", "", "")
    )


def run_path_traversal_tests(client: LoggingHttpClient, target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for seg in PATH_TRAVERSAL_SEGMENTS:
        test_url = _with_extra_path(target_url, seg)
        try:
            resp = client.request("GET", test_url)
        except ScannerNetworkError:
            continue
        lower = resp.text.lower()
        hits = [m for m in TRAVERSAL_MARKERS if m.lower() in lower]
        if hits:
            findings.append(
                Finding(
                    module="PathTraversal",
                    title="Possible path traversal / file disclosure indicator",
                    risk=RiskLevel.HIGH,
                    description=(
                        "A response to a URL containing directory traversal segments "
                        "included content that resembles system configuration or "
                        "passwd-style data. This may indicate unsafe file path handling."
                    ),
                    remediation=(
                        "Do not pass user input to file APIs without validation. Use "
                        "allowlists for filenames, chroot or sandboxed storage, and "
                        "reject path segments like '..'. Serve files from a dedicated "
                        "directory with no traversal."
                    ),
                    evidence=f"Matched: {hits[:3]}; segment={seg!r}",
                    request_url=test_url,
                    metadata={"segment": seg},
                )
            )
            break

    # Secondary check: traversal in query param (common vulnerable pattern).
    test_url2 = target_url + ("&" if "?" in target_url else "?") + "file=../../etc/passwd"
    try:
        resp2 = client.request("GET", test_url2)
    except ScannerNetworkError:
        return findings
    lower2 = resp2.text.lower()
    if re.search(r"root:[^:]*:0:0:", lower2):
        findings.append(
            Finding(
                module="PathTraversal",
                title="Suspicious file path pattern in query parameter response",
                risk=RiskLevel.HIGH,
                description=(
                    "Response to a benign traversal-style query parameter resembled "
                    "Unix passwd format. Verify that file read endpoints cannot access "
                    "arbitrary paths."
                ),
                remediation=(
                    "Same as directory traversal: validate and sandbox file access; "
                    "never use user input to build filesystem paths directly."
                ),
                evidence="passwd-like line pattern in response.",
                request_url=test_url2,
                metadata={},
            )
        )
    return findings
