"""
Authentication and authorization *misconfiguration* checks (non-intrusive).

We perform passive analysis: security headers on the base URL, cookie flags
if Set-Cookie is present, and light probing of common admin paths with GET
only — interpreting status codes without credential stuffing or bypass attempts.
"""

from __future__ import annotations

from urllib.parse import urljoin

from security_scanner.config import SECURITY_HEADERS_TO_CHECK
from security_scanner.http_client import LoggingHttpClient, ScannerNetworkError
from security_scanner.models import Finding, RiskLevel

# Common paths that sometimes expose panels without proper auth (informational).
ADMIN_PATHS = ("/admin", "/administrator", "/wp-admin", "/.env")


def run_auth_misconfig_tests(client: LoggingHttpClient, target_url: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        resp = client.request("GET", target_url)
    except ScannerNetworkError:
        return findings

    # --- Security headers ---
    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = [h for h in SECURITY_HEADERS_TO_CHECK if h.lower() not in headers]
    if missing:
        findings.append(
            Finding(
                module="AuthMisconfig",
                title="Missing recommended HTTP security headers",
                risk=RiskLevel.MEDIUM,
                description=(
                    "The response did not include some standard security headers "
                    f"(missing: {', '.join(missing)}). This weakens browser-side "
                    "defenses (clickjacking, MIME sniffing, XSS mitigation via CSP)."
                ),
                remediation=(
                    "Add X-Frame-Options or frame-ancestors in CSP, "
                    "X-Content-Type-Options: nosniff, a strict Content-Security-Policy, "
                    "Referrer-Policy, and Permissions-Policy as appropriate."
                ),
                evidence=f"Present headers (sample): {list(resp.headers.keys())[:12]}",
                request_url=target_url,
                metadata={"missing_headers": missing},
            )
        )

    # Strict-Transport-Security only meaningful on HTTPS
    if target_url.lower().startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                module="AuthMisconfig",
                title="HTTPS site without Strict-Transport-Security (HSTS)",
                risk=RiskLevel.MEDIUM,
                description=(
                    "The HTTPS response did not set Strict-Transport-Security. "
                    "Users may be more exposed to downgrade or SSL stripping attacks."
                ),
                remediation=(
                    "Enable HSTS with an appropriate max-age, includeSubDomains "
                    "and preload only after careful testing."
                ),
                evidence="No Strict-Transport-Security header on HTTPS response.",
                request_url=target_url,
                metadata={},
            )
        )

    # --- Cookie flags (if any Set-Cookie) ---
    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        issues = []
        if "httponly" not in set_cookie.lower():
            issues.append("HttpOnly")
        if "secure" not in set_cookie.lower() and target_url.lower().startswith("https://"):
            issues.append("Secure")
        if "samesite" not in set_cookie.lower():
            issues.append("SameSite")
        if issues:
            findings.append(
                Finding(
                    module="AuthMisconfig",
                    title="Session cookie may lack hardening flags",
                    risk=RiskLevel.MEDIUM,
                    description=(
                        "Set-Cookie appeared without recommended flags: "
                        f"{', '.join(issues)}. This can increase XSS/session theft risk."
                    ),
                    remediation=(
                        "Set HttpOnly on session cookies, Secure on HTTPS, and "
                        "SameSite=Lax or Strict unless cross-site flows require otherwise."
                    ),
                    evidence="Analyzed Set-Cookie header from base URL response.",
                    request_url=target_url,
                    metadata={"missing_cookie_flags": issues},
                )
            )

    # --- Light path probes (GET, no credentials) ---
    for path in ADMIN_PATHS:
        url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = client.request("GET", url, allow_redirects=False)
        except ScannerNetworkError:
            continue
        if r.status_code in (200, 301, 302, 307, 308):
            # 200 on sensitive paths may warrant review; redirects are informational.
            risk = RiskLevel.MEDIUM if r.status_code == 200 else RiskLevel.LOW
            findings.append(
                Finding(
                    module="AuthMisconfig",
                    title=f"Sensitive path reachable: {path} (HTTP {r.status_code})",
                    risk=risk,
                    description=(
                        "A common administrative or sensitive path responded with "
                        "a success or redirect status. This does not prove a vulnerability "
                        "but should be verified: access should require strong authentication."
                    ),
                    remediation=(
                        "Restrict admin interfaces by network and authentication; "
                        "return 404 for unauthenticated users where appropriate; "
                        "avoid exposing /.env in web roots."
                    ),
                    evidence=f"URL {url} returned status {r.status_code}.",
                    request_url=url,
                    metadata={"status_code": r.status_code},
                )
            )

    return findings
