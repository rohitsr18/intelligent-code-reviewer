"""Tests for health check endpoints and security headers."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_liveness_probe(async_client: AsyncClient):
    """Verify /health/live returns 200 OK."""
    response = await async_client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


@pytest.mark.asyncio
async def test_readiness_probe(async_client: AsyncClient):
    """Verify /health/ready returns 200 OK and feature status."""
    response = await async_client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "features" in data
    assert data["features"]["secret_scanning"] is True


@pytest.mark.asyncio
async def test_security_headers_present(async_client: AsyncClient):
    """Verify defense-in-depth security headers are attached."""
    response = await async_client.get("/health/live")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("x-xss-protection") == "1; mode=block"
    assert "max-age=" in response.headers.get("strict-transport-security", "")
    assert response.headers.get("referrer-policy") == "no-referrer"
