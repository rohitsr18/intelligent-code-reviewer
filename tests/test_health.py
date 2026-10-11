import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_liveness_probe(async_client: AsyncClient):
    res = await async_client.get("/health/live")
    assert res.status_code == 200
    assert res.json() == {"status": "alive"}


@pytest.mark.asyncio
async def test_readiness_probe(async_client: AsyncClient):
    res = await async_client.get("/health/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["features"]["secret_scanning"] is True


@pytest.mark.asyncio
async def test_security_headers_present(async_client: AsyncClient):
    res = await async_client.get("/health/live")
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("x-xss-protection") == "1; mode=block"
    assert "max-age=" in res.headers.get("strict-transport-security", "")
    assert res.headers.get("referrer-policy") == "no-referrer"
