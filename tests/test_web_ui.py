import os
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_endpoint_serves_html_ui(client: TestClient):
    """GET / should serve the interactive web UI dashboard."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Intelligent Code Reviewer" in response.text
    assert "Analyze & Review Code" in response.text
    assert "Pre-LLM Data Leak Prevention" in response.text


def test_ui_alias_endpoint_serves_html(client: TestClient):
    """GET /ui should serve the same interactive web UI."""
    response = client.get("/ui")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Intelligent Code Reviewer" in response.text


def test_security_headers_present_on_web_ui(client: TestClient):
    """Security headers must be present on HTML UI responses."""
    response = client.get("/")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "1; mode=block" in response.headers.get("x-xss-protection", "")
    assert "max-age=" in response.headers.get("strict-transport-security", "")


def test_static_asset_serving(client: TestClient):
    """Static assets under /static/ should be reachable."""
    response = client.get("/static/index.html")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_missing_ui_file_returns_404(client: TestClient):
    """When the static index.html is missing, the endpoint gracefully returns 404."""
    with patch("os.path.exists", return_value=False):
        response = client.get("/")
        assert response.status_code == 404
        assert response.json()["detail"] == "Web UI not found"

