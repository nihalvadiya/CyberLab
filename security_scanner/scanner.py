"""Orchestrates the detection modules into one scan and one report."""

from __future__ import annotations

from security_scanner.config import DEFAULT_MIN_INTERVAL_SEC
from security_scanner.http_client import (
    LoggingHttpClient,
    RequestBudgetExceeded,
    ScannerNetworkError,
)
from security_scanner.models import Finding, ScanResult
from security_scanner.modules.auth_misconfig import run_auth_misconfig_tests
from security_scanner.modules.path_traversal import run_path_traversal_tests
from security_scanner.modules.sqli import run_sqli_tests
from security_scanner.modules.xss import run_xss_tests
from security_scanner.rate_limiter import RateLimiter
from security_scanner.validators import (
    validate_authorization,
    validate_target_url,
)

DISCLAIMER = (
    "Educational, detection-only scan. Run this only against systems you own or "
    "are explicitly authorized to test. No exploitation or destructive requests "
    "are sent; findings are heuristic and require manual confirmation."
)

_MODULES = (
    ("AuthMisconfig", run_auth_misconfig_tests),
    ("SQLi", run_sqli_tests),
    ("XSS", run_xss_tests),
    ("PathTraversal", run_path_traversal_tests),
)


def run_scan(
    target_url: str,
    *,
    authorize: bool,
    authorize_text: str | None,
    allow_internal: bool = False,
    min_interval_sec: float = DEFAULT_MIN_INTERVAL_SEC,
) -> ScanResult:
    """
    Validate authorization and the target, then run every detection module.

    A module raising an unexpected error does not abort the scan: it is
    recorded in ``ScanResult.errors`` and the remaining modules still run, so
    one flaky check can't hide findings from the others.
    """
    validate_authorization(authorize, authorize_text)
    target_url = validate_target_url(target_url, allow_internal=allow_internal)

    client = LoggingHttpClient(
        RateLimiter(min_interval_sec), allow_internal=allow_internal
    )
    findings: list[Finding] = []
    errors: list[str] = []

    for name, run in _MODULES:
        try:
            findings.extend(run(client, target_url))
        except RequestBudgetExceeded as exc:
            errors.append(f"{name}: {exc}")
            break
        except ScannerNetworkError as exc:
            errors.append(f"{name}: network error: {exc}")
        except Exception as exc:  # noqa: BLE001 - one module's bug shouldn't sink the scan
            errors.append(f"{name}: unexpected error: {exc}")

    # Modules swallow individual failed probes so one bad request doesn't stop a
    # module, but that must not read as "scanned clean" when every request
    # failed outright — e.g. the target was unreachable for the whole run.
    if client.log and all(entry.error for entry in client.log):
        first_error = client.log[0].error
        errors.insert(
            0,
            f"All {len(client.log)} requests failed; findings below are incomplete. "
            f"First error: {first_error}",
        )

    return ScanResult(
        target_url=target_url,
        disclaimer=DISCLAIMER,
        findings=findings,
        http_log=client.log,
        total_requests=client.request_count,
        errors=errors,
    )
