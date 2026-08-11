"""Simple rate limiting to reduce load on the target host."""

from __future__ import annotations

import time
import threading


class RateLimiter:
    """
    Enforces a minimum interval between operations (e.g. HTTP requests).
    Thread-safe for sequential use from one scanner thread.
    """

    def __init__(self, min_interval_sec: float) -> None:
        if min_interval_sec < 0:
            raise ValueError("min_interval_sec must be non-negative")
        self._min_interval = float(min_interval_sec)
        self._last: float | None = None
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until the next slot is available."""
        with self._lock:
            now = time.monotonic()
            if self._last is None:
                self._last = now
                return
            elapsed = now - self._last
            wait = self._min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
