import pytest
from fastapi import HTTPException
from app.core.rate_limiter import SimpleRateLimiter


def test_rate_limiter_allows_under_threshold():
    limiter = SimpleRateLimiter(window_seconds=10)
    for _ in range(5):
        remaining = limiter.check_rate_limit(key="user-1", max_requests=10)
        assert remaining >= 0


def test_rate_limiter_blocks_over_threshold():
    limiter = SimpleRateLimiter(window_seconds=10)
    for _ in range(3):
        limiter.check_rate_limit(key="user-2", max_requests=3)

    with pytest.raises(HTTPException) as exc:
        limiter.check_rate_limit(key="user-2", max_requests=3)
    assert exc.value.status_code == 429
    assert "Retry-After" in exc.value.headers
