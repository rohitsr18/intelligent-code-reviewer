import pytest
import io
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_upload_rules_csv_as_reviewer(async_client: AsyncClient):
    csv_data = """rule_id,title,language,category,severity,pattern_or_anti_pattern,guidance,tags
SEC-ORG-01,No Hardcoded JWT,all,security,critical,Hardcoded JWT secret string,Use Secret Manager,security;jwt
PERF-ORG-01,Batch Database Calls,all,performance,medium,Calling query inside loop,Batch requests into single query,perf;n+1
"""
    files = {"file": ("team_rules.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")}
    headers = {"x-mock-user-role": "reviewer", "x-mock-user-email": "lead@company.com"}

    response = await async_client.post("/api/v1/rules/upload-csv", files=files, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["imported_count"] == 2
    assert data["total_rows"] == 2
    assert data["rejected_count"] == 0


@pytest.mark.asyncio
async def test_upload_rules_csv_forbidden_for_standard_engineer(async_client: AsyncClient):
    csv_data = "rule_id,title,language,category,severity,pattern_or_anti_pattern,guidance,tags\n"
    files = {"file": ("rules.csv", io.BytesIO(csv_data.encode("utf-8")), "text/csv")}
    headers = {"x-mock-user-role": "engineer", "x-mock-user-email": "dev@company.com"}

    response = await async_client.post("/api/v1/rules/upload-csv", files=files, headers=headers)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_upload_rules_rejects_non_csv_extension(async_client: AsyncClient):
    files = {"file": ("rules.txt", io.BytesIO(b"some,data"), "text/plain")}
    headers = {"x-mock-user-role": "admin"}

    response = await async_client.post("/api/v1/rules/upload-csv", files=files, headers=headers)
    assert response.status_code == 400
    assert "must be a valid .csv" in response.json()["detail"]


@pytest.mark.asyncio
async def test_list_rules_with_language_filter(async_client: AsyncClient):
    response = await async_client.get("/api/v1/rules?language=python")
    assert response.status_code == 200
    rules = response.json()
    assert isinstance(rules, list)
    assert len(rules) > 0
    # Every returned rule should either be 'python' or 'all'
    for r in rules:
        assert r["language"] in ("python", "all", "*")


@pytest.mark.asyncio
async def test_review_submission_enriched_with_historical_rules(async_client: AsyncClient):
    # Submit review for python code
    payload = {
        "code": "def calculate_total():\n    return sum([1, 2, 3])",
        "language": "python",
        "filename": "calc.py",
    }
    headers = {"x-mock-user-email": "dev@company.com", "x-mock-user-id": "user-dev-123"}
    response = await async_client.post("/api/v1/review/submit", json=payload, headers=headers)

    assert response.status_code == 201
    data = response.json()
    assert data["rules_applied_count"] > 0
    assert data["status"] == "accepted"

    # Now verify telemetry was recorded in BigQuery analytics endpoint
    analytics_res = await async_client.get(
        "/api/v1/rules/analytics",
        headers={"x-mock-user-email": "dev@company.com", "x-mock-user-id": "user-dev-123"},
    )
    assert analytics_res.status_code == 200
    events = analytics_res.json()
    assert len(events) > 0
    matching = [e for e in events if e["review_id"] == data["review_id"]]
    assert len(matching) == 1
    assert matching[0]["language"] == "python"
    assert matching[0]["rules_applied_count"] == data["rules_applied_count"]

