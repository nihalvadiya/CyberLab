"""
End-to-end checks for the scanner package, against a tiny local HTTP stub.

Run with:  python -m security_scanner.test_scanner
"""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from security_scanner.config import MAX_REQUESTS_PER_SCAN
from security_scanner.http_client import LoggingHttpClient, RequestBudgetExceeded
from security_scanner.rate_limiter import RateLimiter
from security_scanner.scanner import run_scan
from security_scanner.validators import ValidationError, validate_authorization, validate_target_url

AUTH = dict(authorize=True, authorize_text="I_AUTHORIZE_TESTING")


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/reflect":
            q = qs.get("q", [""])[0]
            body = f"<html><body>Results: {q}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/sqlerror":
            body = b"You have an error in your SQL syntax; check the manual"
            self.send_response(500)
            self.end_headers()
            self.wfile.write(body)
            return

        # Default: minimal, no security headers (so AuthMisconfig has something
        # to flag) and no reflection (so XSS/SQLi stay quiet here).
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html><body>ok</body></html>")


def _start_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_ssrf_guard_blocks_internal_targets():
    try:
        validate_target_url("http://127.0.0.1:9/")
    except ValidationError:
        pass
    else:
        raise AssertionError("internal target should be rejected without --allow-internal")

    # Explicit opt-in accepts it.
    validate_target_url("http://127.0.0.1:9/", allow_internal=True)


def test_authorization_gate():
    try:
        validate_authorization(False, None)
    except ValidationError:
        pass
    else:
        raise AssertionError("missing --authorize should be rejected")

    try:
        validate_authorization(True, "wrong phrase")
    except ValidationError:
        pass
    else:
        raise AssertionError("wrong phrase should be rejected")

    validate_authorization(True, "I_AUTHORIZE_TESTING")  # must not raise


def test_request_budget_is_enforced():
    client = LoggingHttpClient(RateLimiter(0.0), allow_internal=True)
    client._count = MAX_REQUESTS_PER_SCAN  # simulate budget already spent
    try:
        client.request("GET", "http://127.0.0.1:1/")
    except RequestBudgetExceeded:
        pass
    else:
        raise AssertionError("request over budget should raise")


def test_reflected_xss_detected_on_vulnerable_stub():
    server = _start_stub()
    try:
        port = server.server_address[1]
        # The XSS/SQLi modules reuse an existing query-key name rather than
        # guessing one; without a seed key here they'd probe "?xss=" against a
        # handler that only reads "q" and find nothing. This is a real limit of
        # a lightweight, non-crawling scanner, not something to paper over.
        result = run_scan(f"http://127.0.0.1:{port}/reflect?q=seed", allow_internal=True,
                           min_interval_sec=0.0, **AUTH)
        titles = [f.title for f in result.findings]
        assert any("reflected" in t.lower() for t in titles), titles
    finally:
        server.shutdown()


def test_sql_error_marker_detected_on_vulnerable_stub():
    server = _start_stub()
    try:
        port = server.server_address[1]
        result = run_scan(f"http://127.0.0.1:{port}/sqlerror", allow_internal=True,
                           min_interval_sec=0.0, **AUTH)
        assert any(f.module == "SQLi" for f in result.findings), result.findings
    finally:
        server.shutdown()


def test_missing_headers_detected_on_default_stub():
    server = _start_stub()
    try:
        port = server.server_address[1]
        result = run_scan(f"http://127.0.0.1:{port}/plain", allow_internal=True,
                           min_interval_sec=0.0, **AUTH)
        assert any(f.module == "AuthMisconfig" for f in result.findings), result.findings
    finally:
        server.shutdown()


def test_all_requests_failing_is_surfaced_not_hidden():
    # Nothing is listening on this port, so every request fails to connect.
    result = run_scan("http://127.0.0.1:1/", allow_internal=True, min_interval_sec=0.0, **AUTH)
    assert not result.findings
    assert result.errors, "a fully-failed scan must say so, not just report 0 findings"
    assert "all" in result.errors[0].lower()


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok    {test.__name__}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
