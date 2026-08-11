"""
Cross-Site Scripting (XSS) *detection* via reflection checks.

We inject a unique probe token into a query parameter. If the raw token appears
in the HTML response, the page may reflect user input without proper encoding —
a prerequisite for reflected XSS. This does not execute scripts on victims; it
only observes the target's response to our own request.
"""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from security_scanner.config import XSS_PROBE_TOKEN
from security_scanner.http_client import LoggingHttpClient, ScannerNetworkError
from security_scanner.models import Finding, RiskLevel


def _merge_query(base_url: str, extra: dict[str, str]) -> str:
    parsed = urlparse(base_url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q.update(extra)
    new_query = urlencode(q, safe="<>")
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


def run_xss_tests(client: LoggingHttpClient, target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(target_url)
    base = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", "", "")
    )
    # ponytail: guesses a param name instead of crawling forms/links to discover
    # real ones. Pass the target URL with its real query string (e.g. ?q=x) so
    # this reuses that key; a bare path may probe the wrong parameter and miss
    # a real vulnerability. Upgrade path: parse <form>/<a> from the response.
    param_name = "xss"
    if parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if pairs:
            param_name = pairs[0][0]

    token = XSS_PROBE_TOKEN
    test_url = _merge_query(base, {param_name: token})

    try:
        resp = client.request("GET", test_url)
    except ScannerNetworkError:
        return findings

    body = resp.text
    escaped = html.escape(token)

    # Escaped in body only (not raw) — lower risk than full reflection.
    if escaped in body and token not in body:
        findings.append(
            Finding(
                module="XSS",
                title="Probe appears HTML-escaped in response",
                risk=RiskLevel.LOW,
                description=(
                    "The probe was present in the response as HTML entities, which "
                    "often prevents classic HTML injection in that context. "
                    "Verify attribute and JavaScript contexts separately."
                ),
                remediation=(
                    "Continue using context-appropriate encoding and CSP. "
                    "Test URL, JS, and CSS contexts if user input reaches them."
                ),
                evidence="Probe matched as escaped entities, not raw markup.",
                request_url=test_url,
                metadata={"param": param_name},
            )
        )
        return findings

    if token not in body:
        return findings

    # Raw token present: possible reflection.
    in_script = bool(re.search(r"<script[^>]*>[\s\S]*?" + re.escape(token), body, re.I))
    risk = RiskLevel.HIGH if in_script else RiskLevel.MEDIUM

    findings.append(
        Finding(
            module="XSS",
            title="User-controlled input reflected in response (reflected XSS risk)",
            risk=risk,
            description=(
                "A unique probe string sent in a query parameter was found verbatim "
                "in the response body. If this data is attacker-controlled in "
                "production, reflected XSS may be possible depending on HTML context."
            ),
            remediation=(
                "Encode output for the correct context (HTML entity, attribute, JS). "
                "Validate input with allowlists where possible. Add a strict CSP and "
                "avoid inline scripts."
            ),
            evidence=f"Probe {token!r} reflected in body (in_script_hint={in_script}).",
            request_url=test_url,
            metadata={"param": param_name, "in_script_context_hint": in_script},
        )
    )
    return findings
