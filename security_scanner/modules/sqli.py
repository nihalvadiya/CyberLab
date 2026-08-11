"""
SQL injection *detection* using safe, non-destructive probe payloads.

We send typical test strings as query parameters and look for database error
messages in the response body. This identifies error-based leakage without
attempting data exfiltration or destructive statements.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from security_scanner.config import SQL_ERROR_MARKERS
from security_scanner.http_client import LoggingHttpClient, ScannerNetworkError
from security_scanner.models import Finding, RiskLevel

# Benign probe strings (no DROP/DELETE/etc.) used only to trigger parser errors
# or observable differences when mishandled by vulnerable string concatenation.
SQLI_SAFE_PROBES = (
    "'",
    "\"",
    "' OR '1'='1",
    "1' AND '1'='1",
    "1; SELECT 1",
    "1 UNION SELECT NULL--",
)


def _merge_query(base_url: str, extra: dict[str, str]) -> str:
    parsed = urlparse(base_url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q.update(extra)
    new_query = urlencode(q)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def run_sqli_tests(client: LoggingHttpClient, target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(target_url)
    base = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", "", "")
    )

    # ponytail: same param-name guess as xss.py — pass the real ?param=value in
    # target_url so this reuses it, rather than crawling for form fields.
    param_name = "q"
    # If URL already has query params, reuse first key for injection context.
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if pairs:
            param_name = pairs[0][0]

    for probe in SQLI_SAFE_PROBES:
        test_url = _merge_query(base, {param_name: probe})
        try:
            resp = client.request("GET", test_url)
        except ScannerNetworkError:
            continue
        lower = resp.text.lower()
        matched = [m for m in SQL_ERROR_MARKERS if m in lower]
        if matched:
            findings.append(
                Finding(
                    module="SQLi",
                    title="Possible SQL error message in response (injection probe)",
                    risk=RiskLevel.HIGH,
                    description=(
                        "The application responded with text that resembles a database "
                        "error after a benign SQL probe was sent in a query parameter. "
                        "This often indicates unsanitized input reaching a SQL query."
                    ),
                    remediation=(
                        "Use parameterized queries (prepared statements) for all "
                        "database access; never concatenate user input into SQL. "
                        "Apply least-privilege DB accounts and disable verbose errors "
                        "in production."
                    ),
                    evidence=f"Matched markers: {matched[:5]}; probe={probe!r}",
                    request_url=test_url,
                    metadata={"probe": probe, "markers": matched},
                )
            )
            break

    return findings
