"""Simple sliding-window rate limiter."""

import time
import threading
import logging

logger = logging.getLogger("mcp-security.ratelimit")


class RateLimiter:
    def __init__(self, max_per_minute: int = 30):
        self.max_per_minute = max_per_minute
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def check(self, tool_name: str) -> None:
        """Raise if rate limit exceeded."""
        now = time.time()
        with self._lock:
            # Purge entries older than 60s
            self._timestamps = [t for t in self._timestamps if now - t < 60]
            if len(self._timestamps) >= self.max_per_minute:
                raise RuntimeError(
                    f"Rate limit exceeded ({self.max_per_minute}/min). "
                    f"Try again in a few seconds."
                )
            self._timestamps.append(now)
            logger.debug(
                f"Rate check OK for {tool_name}: "
                f"{len(self._timestamps)}/{self.max_per_minute}"
            )