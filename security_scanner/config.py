"""Default limits and scanner constants (non-destructive, detection-focused)."""

# Minimum seconds between outbound HTTP requests (rate limiting).
DEFAULT_MIN_INTERVAL_SEC = 0.75

# Hard cap on total HTTP requests per full scan (safety).
MAX_REQUESTS_PER_SCAN = 80

# Largest response body read into memory, per request. Anything beyond this is
# truncated, so a huge or endlessly streaming response cannot exhaust the
# scanner's memory.
MAX_RESPONSE_BYTES = 512 * 1024

# User-agent identifying the tool (transparency).
SCANNER_USER_AGENT = "CyberLab-SecurityScanner/1.0 (Educational; +https://example.invalid)"

# Short SQL error substrings used only to *detect* error-based leakage in responses.
SQL_ERROR_MARKERS = (
    "sql syntax",
    "sqlite3.operationalerror",
    "sqlite error",
    "postgresql error",
    "warning: mysql",
    "mysql server version",
    "microsoft ole db provider",
    "odbc sql server driver",
    "ora-00933",  # Oracle
    "unclosed quotation mark",
)

# XSS probe: unique token with angle brackets to detect HTML escaping vs raw reflection.
XSS_PROBE_TOKEN = "<CyberLabXSSProbe_7f3a9c2e>"

# Path traversal probes (read-only style; detection via suspicious response body).
PATH_TRAVERSAL_SEGMENTS = (
    "../",
    "..\\",
    "....//....//",
)

# Auth / header checks: header names and severity hints.
SECURITY_HEADERS_TO_CHECK = (
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
)
