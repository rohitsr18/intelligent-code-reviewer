import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_paginated_reviews_api(async_client: AsyncClient):
    # Submit 2 reviews as Alice
    for i in range(2):
        await async_client.post(
            "/api/v1/review/submit",
            json={"code": f"def func_{i}(): pass", "language": "python", "filename": f"f_{i}.py"},
            headers={"x-mock-user-email": "alice@company.com", "x-mock-user-id": "dev-alice-01"},
        )

    # Alice fetches her reviews
    res = await async_client.get(
        "/api/v1/reviews?limit=10&offset=0",
        headers={"x-mock-user-email": "alice@company.com", "x-mock-user-id": "dev-alice-01"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 2
    assert len(data["items"]) >= 2
    assert data["items"][0]["submitted_by"] == "alice@company.com"


@pytest.mark.asyncio
async def test_submit_review_feedback_api(async_client: AsyncClient):
    # Alice submits code
    sub_res = await async_client.post(
        "/api/v1/review/submit",
        json={"code": "def calculate(): return 42", "language": "python"},
        headers={"x-mock-user-email": "alice@company.com", "x-mock-user-id": "dev-alice-01"},
    )
    assert sub_res.status_code == 201
    review_id = sub_res.json()["review_id"]

    # Alice submits feedback
    fb_res = await async_client.post(
        f"/api/v1/reviews/{review_id}/feedback",
        json={"rating": 5, "feedback": "Great suggestions on clean code!", "helpful": True},
        headers={"x-mock-user-email": "alice@company.com", "x-mock-user-id": "dev-alice-01"},
    )
    assert fb_res.status_code == 200
    assert fb_res.json()["rating"] == 5

    # Check detail includes feedback
    detail_res = await async_client.get(
        f"/api/v1/review/{review_id}",
        headers={"x-mock-user-email": "alice@company.com", "x-mock-user-id": "dev-alice-01"},
    )
    assert detail_res.status_code == 200
    assert detail_res.json()["feedback"] is not None
    assert detail_res.json()["feedback"]["rating"] == 5


@pytest.mark.asyncio
async def test_submit_feedback_forbidden_for_other_user(async_client: AsyncClient):
    # Alice submits code
    sub_res = await async_client.post(
        "/api/v1/review/submit",
        json={"code": "def task(): pass", "language": "python"},
        headers={"x-mock-user-email": "alice@company.com", "x-mock-user-id": "dev-alice-01"},
    )
    review_id = sub_res.json()["review_id"]

    # Bob attempts to submit feedback on Alice's review
    fb_res = await async_client.post(
        f"/api/v1/reviews/{review_id}/feedback",
        json={"rating": 1, "feedback": "not my review", "helpful": False},
        headers={"x-mock-user-email": "bob@company.com", "x-mock-user-id": "dev-bob-02"},
    )
    assert fb_res.status_code == 403


@pytest.mark.asyncio
async def test_developer_growth_profile_api(async_client: AsyncClient):
    # Submit code to establish profile
    await async_client.post(
        "/api/v1/review/submit",
        json={"code": "def process(): return True", "language": "python"},
        headers={"x-mock-user-email": "dave@company.com", "x-mock-user-id": "dev-dave-01"},
    )

    # Query /growth/me
    res = await async_client.get(
        "/api/v1/growth/me",
        headers={"x-mock-user-email": "dave@company.com", "x-mock-user-id": "dev-dave-01"},
    )
    assert res.status_code == 200
    profile = res.json()
    assert profile["user_id"] == "dev-dave-01"
    assert profile["total_reviews"] >= 1
    assert profile["average_score"] > 0
    assert "python" in profile["languages_used"]


@pytest.mark.asyncio
async def test_lead_inspect_growth_profile_rbac(async_client: AsyncClient):
    # Regular engineer tries to inspect another user's growth profile
    forbidden = await async_client.get(
        "/api/v1/growth/user/dev-dave-01",
        headers={"x-mock-user-role": "engineer", "x-mock-user-email": "other@company.com"},
    )
    assert forbidden.status_code == 403

    # Reviewer/Lead inspects profile
    allowed = await async_client.get(
        "/api/v1/growth/user/dev-dave-01",
        headers={"x-mock-user-role": "reviewer", "x-mock-user-email": "lead@company.com"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["user_id"] == "dev-dave-01"


@pytest.mark.asyncio
async def test_session_lifecycle_and_revision_api(async_client: AsyncClient):
    # 1. Create a review session
    create_res = await async_client.post(
        "/api/v1/sessions",
        json={"title": "Refactoring Payment Gateway", "language": "python"},
        headers={"x-mock-user-email": "emma@company.com", "x-mock-user-id": "dev-emma-01"},
    )
    assert create_res.status_code == 201
    session_data = create_res.json()
    session_id = session_data["session_id"]
    assert session_data["status"] == "active"
    assert len(session_data["revisions"]) == 0

    # 2. Submit initial revision
    rev1_res = await async_client.post(
        f"/api/v1/sessions/{session_id}/revise",
        json={
            "code": "def pay():\n    # Raw SQL without parameter\n    query = f'SELECT * FROM accounts WHERE id = {1}'\n    return query",
            "filename": "payment.py",
            "context": "Round 1 draft",
        },
        headers={"x-mock-user-email": "emma@company.com", "x-mock-user-id": "dev-emma-01"},
    )
    assert rev1_res.status_code == 200
    rev1_data = rev1_res.json()
    assert len(rev1_data["revisions"]) == 1
    assert rev1_data["revisions"][0]["revision_index"] == 1

    # 3. Submit fixed revision (Round 2)
    rev2_res = await async_client.post(
        f"/api/v1/sessions/{session_id}/revise",
        json={
            "code": "def pay(account_id: int):\n    # Parameterized query\n    query = 'SELECT * FROM accounts WHERE id = ?'\n    return db.execute(query, [account_id])",
            "filename": "payment.py",
            "context": "Round 2: fixed SQL injection",
        },
        headers={"x-mock-user-email": "emma@company.com", "x-mock-user-id": "dev-emma-01"},
    )
    assert rev2_res.status_code == 200
    rev2_data = rev2_res.json()
    assert len(rev2_data["revisions"]) == 2
    assert rev2_data["revisions"][1]["revision_index"] == 2
    assert rev2_data["revisions"][1]["overall_score"] >= rev1_data["revisions"][0]["overall_score"]

    # 4. Fetch session replay
    get_res = await async_client.get(
        f"/api/v1/sessions/{session_id}",
        headers={"x-mock-user-email": "emma@company.com", "x-mock-user-id": "dev-emma-01"},
    )
    assert get_res.status_code == 200
    replay = get_res.json()
    assert replay["session_id"] == session_id
    assert len(replay["revisions"]) == 2
