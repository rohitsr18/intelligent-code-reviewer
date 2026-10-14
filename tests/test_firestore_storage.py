import pytest
from datetime import datetime, timezone
from app.storage.models import (
    ReviewDocument,
    ReviewFeedback,
    DeveloperGrowthProfile,
    ReviewSessionDocument,
    SessionRevisionItem,
)
from app.storage.firestore import InMemoryFirestoreBackend, ProductionFirestoreBackend
from app.storage.service import StorageService


@pytest.mark.asyncio
async def test_firestore_save_and_get_review():
    backend = InMemoryFirestoreBackend()
    service = StorageService(backend=backend)

    review = ReviewDocument(
        review_id="rev-001",
        user_id="dev-1",
        submitted_by="dev1@company.com",
        status="accepted",
        filename="service.py",
        language="python",
        original_line_count=50,
        sanitized_code="def foo(): pass",
        secured_prompt="<untrusted_source_code>\ndef foo(): pass\n</untrusted_source_code>",
        analysis={"overall_score": 92, "findings": [], "growth_tips": [{"topic": "Typing"}]},
    )

    saved = await service.save_review(review)
    assert saved is True

    fetched = await service.get_review("rev-001")
    assert fetched is not None
    assert fetched.review_id == "rev-001"
    assert fetched.user_id == "dev-1"
    assert fetched.language == "python"


@pytest.mark.asyncio
async def test_firestore_pagination_and_filters():
    backend = InMemoryFirestoreBackend()
    service = StorageService(backend=backend)

    # Add 5 reviews for user 1 and 2 reviews for user 2
    for i in range(5):
        await service.save_review(
            ReviewDocument(
                review_id=f"rev-u1-{i}",
                user_id="user-1",
                submitted_by="u1@company.com",
                status="accepted" if i % 2 == 0 else "sanitized",
                language="python" if i < 3 else "typescript",
                sanitized_code="code",
                secured_prompt="prompt",
            )
        )

    for i in range(2):
        await service.save_review(
            ReviewDocument(
                review_id=f"rev-u2-{i}",
                user_id="user-2",
                submitted_by="u2@company.com",
                status="accepted",
                language="python",
                sanitized_code="code",
                secured_prompt="prompt",
            )
        )

    # Page 1 for user-1 with limit 3
    page1 = await service.list_reviews(user_id="user-1", limit=3, offset=0)
    assert page1.total == 5
    assert len(page1.items) == 3
    assert page1.has_next is True

    # Page 2 for user-1 with offset 3
    page2 = await service.list_reviews(user_id="user-1", limit=3, offset=3)
    assert len(page2.items) == 2
    assert page2.has_next is False

    # Filter by language
    py_reviews = await service.list_reviews(user_id="user-1", language="python")
    assert py_reviews.total == 3


@pytest.mark.asyncio
async def test_developer_growth_profile_calculation():
    backend = InMemoryFirestoreBackend()
    service = StorageService(backend=backend)

    # Review 1: score 80, security finding
    await service.save_review(
        ReviewDocument(
            review_id="rev-g1",
            user_id="dev-alice",
            submitted_by="alice@company.com",
            status="accepted",
            language="python",
            sanitized_code="code",
            secured_prompt="prompt",
            analysis={
                "overall_score": 80,
                "findings": [{"category": "security"}],
                "growth_tips": [{"topic": "SQL Sanitization"}],
            },
        )
    )

    # Review 2: score 90, performance finding
    await service.save_review(
        ReviewDocument(
            review_id="rev-g2",
            user_id="dev-alice",
            submitted_by="alice@company.com",
            status="accepted",
            language="python",
            sanitized_code="code",
            secured_prompt="prompt",
            analysis={
                "overall_score": 90,
                "findings": [{"category": "performance"}],
                "growth_tips": [{"topic": "Async I/O"}],
            },
        )
    )

    profile = await service.get_growth_profile("dev-alice")
    assert profile is not None
    assert profile.total_reviews == 2
    assert profile.average_score == 85.0
    assert profile.languages_used["python"] == 2
    assert profile.recurring_weaknesses["security"] == 1
    assert profile.recurring_weaknesses["performance"] == 1
    assert "SQL Sanitization" in profile.recommended_skills
    assert "Async I/O" in profile.recommended_skills
    assert len(profile.score_history) == 2


@pytest.mark.asyncio
async def test_review_feedback_and_rating():
    backend = InMemoryFirestoreBackend()
    service = StorageService(backend=backend)

    review = ReviewDocument(
        review_id="rev-fb",
        user_id="dev-bob",
        submitted_by="bob@company.com",
        status="accepted",
        language="python",
        sanitized_code="code",
        secured_prompt="prompt",
        analysis={"overall_score": 95},
    )
    await service.save_review(review)

    updated = await service.add_feedback(
        review_id="rev-fb",
        rating=5,
        feedback="Very helpful security finding!",
        helpful=True,
    )
    assert updated is not None
    assert updated.feedback is not None
    assert updated.feedback.rating == 5
    assert updated.feedback.feedback == "Very helpful security finding!"

    # Verify user profile feedback aggregation
    profile = await service.get_growth_profile("dev-bob")
    assert profile.total_feedback_given == 1
    assert profile.average_feedback_rating == 5.0


@pytest.mark.asyncio
async def test_review_session_lifecycle():
    backend = InMemoryFirestoreBackend()
    service = StorageService(backend=backend)

    session = await service.create_session(
        user_id="dev-carol",
        email="carol@company.com",
        title="Refactoring Auth Middleware",
        language="python",
    )
    assert session.session_id.startswith("sess-")
    assert session.status == "active"
    assert len(session.revisions) == 0

    # Add revision
    rev_doc = ReviewDocument(
        review_id="rev-c1",
        user_id="dev-carol",
        submitted_by="carol@company.com",
        status="accepted",
        filename="auth.py",
        language="python",
        sanitized_code="code",
        secured_prompt="prompt",
        analysis={"overall_score": 88, "findings": [{"title": "race condition"}]},
    )
    updated_session = await service.add_revision(
        session_id=session.session_id,
        review=rev_doc,
        summary="Initial revision with auth fixes",
    )
    assert len(updated_session.revisions) == 1
    assert updated_session.revisions[0].revision_index == 1
    assert updated_session.revisions[0].overall_score == 88


@pytest.mark.asyncio
async def test_production_firestore_fallback_when_unconfigured():
    backend = ProductionFirestoreBackend()
    review = ReviewDocument(
        review_id="rev-fb-prod",
        user_id="dev-test",
        submitted_by="test@company.com",
        status="accepted",
        language="python",
        sanitized_code="code",
        secured_prompt="prompt",
    )
    saved = await backend.save_review(review)
    assert saved is True
    fetched = await backend.get_review("rev-fb-prod")
    assert fetched is not None
    assert fetched.review_id == "rev-fb-prod"
