"""Shared pytest fixtures."""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.security.sanitizer import CodeSanitizer
from app.security.prompt_guard import PromptGuard


@pytest.fixture
def sanitizer() -> CodeSanitizer:
    """Fixture providing CodeSanitizer instance."""
    return CodeSanitizer()


@pytest.fixture
def prompt_guard() -> PromptGuard:
    """Fixture providing PromptGuard instance."""
    return PromptGuard()


@pytest.fixture
async def async_client():
    """Asynchronous HTTP test client for FastAPI."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
