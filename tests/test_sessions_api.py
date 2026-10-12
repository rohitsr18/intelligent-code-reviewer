import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_current_session_default(async_client: AsyncClient):
    res = await async_client.get("/api/v1/sessions/me")
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "developer@company.local"
    assert data["role"] == "engineer"
    assert data["is_admin"] is False


@pytest.mark.asyncio
async def test_get_current_session_admin(async_client: AsyncClient):
    headers = {"x-mock-user-email": "admin@company.com"}
    res = await async_client.get("/api/v1/sessions/me", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "admin@company.com"
    assert data["role"] == "admin"
    assert data["is_admin"] is True
