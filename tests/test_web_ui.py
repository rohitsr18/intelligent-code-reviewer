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
    assert "Code Sarathi" in response.text
    assert "24/7 Intelligent Code Reviewer" in response.text
    assert "v1.0.0" in response.text
    assert "Run Intelligent Review" in response.text
    assert "Pre-LLM Data Leak Prevention" in response.text


def test_ui_alias_endpoint_serves_html(client: TestClient):
    """GET /ui should serve the same interactive web UI."""
    response = client.get("/ui")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Code Sarathi" in response.text


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


def test_local_file_upload_ui_elements(client: TestClient):
    """Verify local file upload and editor auto-fetch elements are present in the UI."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    # Filename input is readonly (upload-only) and triggers picker
    assert 'id="code-filename"' in html
    assert 'readonly' in html
    assert 'Upload only' in html
    # Filename local file picker input and button
    assert 'id="local-file-picker"' in html
    assert 'type="file"' in html
    assert 'triggerLocalFilePicker()' in html
    assert 'Upload File' in html
    # File reader and auto-fetch logic
    assert 'handleLocalFileSelected' in html
    assert 'loadCodeFromFile' in html
    assert 'FileReader' in html
    # Feedback status pill and drag zone
    assert 'id="file-loaded-pill"' in html
    assert 'id="code-editor-zone"' in html


def test_interactive_feedback_comment_ui_elements(client: TestClient):
    """Verify rating feedback comment container exists and obsolete text is removed."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    # Star rating and feedback comment elements
    assert 'id="star-rating"' in html
    assert 'id="feedback-comment-container"' in html
    assert 'id="feedback-comment"' in html
    assert 'id="send-feedback-btn"' in html
    assert 'id="rating-label"' in html
    # Obsolete BigQuery training sentence must be removed
    assert "Ratings train team-specific historical rules in BigQuery" not in html



