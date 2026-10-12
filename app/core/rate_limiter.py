import time
from collections import defaultdict
from typing import Dict, List
from fastapi import HTTPException, Request, status
from app.core.config import get_settings


class SimpleRateLimiter:
    """Sliding window in-memory rate limiter for API protection."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(self, key: str, max_requests: int) -> int:
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old timestamps
        timestamps = [ts for ts in self._history[key] if ts > cutoff]
        self._history[key] = timestamps

        if len(timestamps) >= max_requests:
            retry_after = int(self.window_seconds - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please slow down.",
                headers={"Retry-After": str(max(1, retry_after))},
            )

        self._history[key].append(now)
        remaining = max_requests - len(self._history[key])
        return remaining


rate_limiter = SimpleRateLimiter()


async def check_api_rate_limit(request: Request) -> None:
    settings = get_settings()
    # Use client IP or auth header as unique caller identifier
    caller = (
        request.headers.get("x-goog-iap-jwt-assertion")
        or request.headers.get("x-mock-user-email")
        or (request.client.host if request.client else "unknown-client")
    )
    remaining = rate_limiter.check_rate_limit(
        key=caller,
        max_requests=settings.rate_limit_per_minute,
    )
    # Store remaining on request state for headers
    request.state.rate_limit_remaining = remaining
