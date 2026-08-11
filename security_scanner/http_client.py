"""HTTP client with request logging, a global request budget, and body caps."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlparse

import requests

from security_scanner.config import (
    MAX_REQUESTS_PER_SCAN,
    MAX_RESPONSE_BYTES,
    SCANNER_USER_AGENT,
)
from security_scanner.models import HttpLogEntry
from security_scanner.rate_limiter import RateLimiter
from security_scanner.validators import is_internal_address


class RequestBudgetExceeded(RuntimeError):
    """
    Raised when the scan would exceed MAX_REQUESTS_PER_SCAN.

    Deliberately not a subclass of the network error type below, so a module's
    per-request error handling cannot swallow it and keep hammering the target.
    """


class ScannerNetworkError(Exception):
    """A request failed at the network or protocol level."""


class UnsafeRedirect(ScannerNetworkError):
    """A redirect pointed at an internal address the scan is not allowed to reach."""


@dataclass
class ScanResponse:
    """The subset of a response the detection modules use."""

    url: str
    status_code: int
    headers: Mapping[str, str] = field(default_factory=dict)
    text: str = ""
    truncated: bool = False


def _snippet(text: str, max_len: int = 400) -> str:
    text = text.replace("\r\n", "\n").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


class LoggingHttpClient:
    """
    Wrapper around requests.Session that:

    - rate limits before each request,
    - caps total requests per scan,
    - caps how much of each response body is read into memory,
    - refuses redirects into internal address space,
    - records a bounded log of every exchange for the report.
    """

    def __init__(
        self,
        rate_limiter: RateLimiter,
        timeout_sec: float = 12.0,
        *,
        allow_internal: bool = False,
    ) -> None:
        self._limiter = rate_limiter
        self._timeout = timeout_sec
        self._allow_internal = allow_internal
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": SCANNER_USER_AGENT})
        # TLS verification stays on: a scanner that ignores certificate errors
        # would report on a connection it cannot prove reached the real target.
        self._session.verify = True
        self.log: list[HttpLogEntry] = []
        self._count = 0

    @property
    def request_count(self) -> int:
        return self._count

    @property
    def budget_remaining(self) -> int:
        return max(0, MAX_REQUESTS_PER_SCAN - self._count)

    def _check_hop(self, url: str) -> None:
        if self._allow_internal:
            return
        host = urlparse(url).hostname or ""
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return  # A name, not a literal; the initial target check covered it.
        if is_internal_address(addr):
            raise UnsafeRedirect(f"Refusing to follow redirect to internal host {host}")

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> ScanResponse:
        if self._count >= MAX_REQUESTS_PER_SCAN:
            raise RequestBudgetExceeded(
                f"Scan stopped: reached the maximum of {MAX_REQUESTS_PER_SCAN} HTTP requests."
            )
        self._count += 1
        self._limiter.acquire()

        logged_url = url if not params else f"{url} (params={params!r})"

        try:
            resp = self._session.request(
                method=method.upper(),
                url=url,
                params=params,
                timeout=self._timeout,
                allow_redirects=allow_redirects,
                stream=True,
                **kwargs,
            )
        except requests.RequestException as exc:
            self.log.append(
                HttpLogEntry(
                    method=method.upper(),
                    url=logged_url,
                    status_code=None,
                    response_snippet="",
                    error=str(exc),
                )
            )
            raise ScannerNetworkError(str(exc)) from exc

        with resp:
            for hop in list(resp.history) + [resp]:
                self._check_hop(hop.url)

            # Read a bounded prefix rather than the whole body: an oversized or
            # endlessly streaming response would otherwise exhaust our memory.
            try:
                raw = resp.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True) or b""
            except (requests.RequestException, OSError) as exc:
                self.log.append(
                    HttpLogEntry(
                        method=method.upper(),
                        url=logged_url,
                        status_code=resp.status_code,
                        response_snippet="",
                        error=str(exc),
                    )
                )
                raise ScannerNetworkError(str(exc)) from exc

            truncated = len(raw) > MAX_RESPONSE_BYTES
            body = raw[:MAX_RESPONSE_BYTES].decode(
                resp.encoding or "utf-8", errors="replace"
            )
            scan_response = ScanResponse(
                url=resp.url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=body,
                truncated=truncated,
            )

        self.log.append(
            HttpLogEntry(
                method=method.upper(),
                url=logged_url,
                status_code=scan_response.status_code,
                response_snippet=_snippet(body),
                error=None,
            )
        )
        return scan_response
