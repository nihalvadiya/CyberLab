"""Input validation for target URLs and authorization flags."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# User must pass this exact phrase to prove intent (authorized testing only).
AUTHORIZATION_PHRASE = "I_AUTHORIZE_TESTING"

_ALLOWED_SCHEMES = frozenset(("http", "https"))


class ValidationError(ValueError):
    """Raised when CLI input fails validation."""


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname to every address it maps to."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValidationError(f"Could not resolve host {host!r}: {exc}") from exc
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def is_internal_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def validate_target_url(raw: str, *, allow_internal: bool = False) -> str:
    """
    Accept only absolute http(s) URLs with a network location.

    Rejects javascript:, file: and other schemes. Unless ``allow_internal`` is
    set, also rejects hosts resolving to loopback, private, link-local or
    reserved ranges: without that check a hostname under someone else's control
    can point at 127.0.0.1 or 169.254.169.254 and turn the scanner into an SSRF
    proxy into whatever network it runs on.
    """
    if not raw or not isinstance(raw, str):
        raise ValidationError("Target URL must be a non-empty string.")
    raw = raw.strip()
    if len(raw) > 2048:
        raise ValidationError("Target URL is too long (max 2048 characters).")

    parsed = urlparse(raw)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValidationError("Only http and https URLs are allowed.")
    if not parsed.netloc:
        raise ValidationError("URL must include a host (e.g. https://example.com).")

    host = parsed.hostname or ""
    if not host:
        raise ValidationError("URL must include a valid hostname.")

    if not allow_internal:
        for addr in _resolve(host):
            if is_internal_address(addr):
                raise ValidationError(
                    f"Host {host!r} resolves to internal address {addr}. "
                    "Pass --allow-internal to scan a local lab target you control."
                )

    return raw


def validate_authorization(authorize_flag: bool, authorize_text: str | None) -> None:
    """
    Require explicit --authorize and matching phrase so the tool never runs
    against a URL without clear user consent.
    """
    if not authorize_flag:
        raise ValidationError(
            "You must pass --authorize and confirm with the required phrase. "
            "This tool only runs when you explicitly authorize testing."
        )
    if (authorize_text or "").strip() != AUTHORIZATION_PHRASE:
        raise ValidationError(
            f"Authorization phrase must be exactly: {AUTHORIZATION_PHRASE}"
        )
