import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from app.storage.models import (
    ReviewDocument,
    DeveloperGrowthProfile,
    ReviewSessionDocument,
    SessionRevisionItem,
    PaginatedReviewsResponse,
)
from app.storage.firestore import BaseFirestoreBackend, get_firestore_backend

logger = logging.getLogger(__name__)


class StorageService:
    """Orchestrates persistent storage for reviews, sessions, feedback, and developer growth profiles."""

    def __init__(self, backend: Optional[BaseFirestoreBackend] = None) -> None:
        self.backend = backend or get_firestore_backend()

    async def save_review(self, review: ReviewDocument) -> bool:
        return await self.backend.save_review(review)

    async def get_review(self, review_id: str) -> Optional[ReviewDocument]:
        return await self.backend.get_review(review_id)

    async def list_reviews(
        self,
        user_id: Optional[str] = None,
        language: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> PaginatedReviewsResponse:
        items, total = await self.backend.list_reviews(
            user_id=user_id,
            language=language,
            status=status,
            limit=limit,
            offset=offset,
        )
        has_next = (offset + limit) < total
        return PaginatedReviewsResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_next=has_next,
        )

    async def add_feedback(
        self,
        review_id: str,
        rating: int,
        feedback: Optional[str] = None,
        helpful: bool = True,
    ) -> Optional[ReviewDocument]:
        return await self.backend.save_review_feedback(
            review_id=review_id,
            rating=rating,
            feedback=feedback,
            helpful=helpful,
        )

    async def get_growth_profile(self, user_id: str) -> Optional[DeveloperGrowthProfile]:
        return await self.backend.get_growth_profile(user_id)

    async def create_session(
        self, user_id: str, email: str, title: str, language: str
    ) -> ReviewSessionDocument:
        session_id = f"sess-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        session = ReviewSessionDocument(
            session_id=session_id,
            user_id=user_id,
            email=email,
            title=title,
            language=language.lower(),
            created_at=now,
            updated_at=now,
            status="active",
            revisions=[],
        )
        return await self.backend.create_session(session)

    async def get_session(self, session_id: str) -> Optional[ReviewSessionDocument]:
        return await self.backend.get_session(session_id)

    async def add_revision(
        self,
        session_id: str,
        review: ReviewDocument,
        summary: str,
    ) -> Optional[ReviewSessionDocument]:
        session = await self.backend.get_session(session_id)
        if not session:
            return None

        rev_index = len(session.revisions) + 1
        overall_score = 90
        findings_count = 0
        if review.analysis and isinstance(review.analysis, dict):
            overall_score = review.analysis.get("overall_score", 90)
            findings_count = len(review.analysis.get("findings", []))

        item = SessionRevisionItem(
            revision_index=rev_index,
            review_id=review.review_id,
            submitted_at=datetime.now(timezone.utc),
            filename=review.filename,
            overall_score=overall_score,
            findings_count=findings_count,
            summary=summary,
        )
        return await self.backend.add_session_revision(session_id, item)


_storage_service_instance: Optional[StorageService] = None


def get_storage_service() -> StorageService:
    global _storage_service_instance
    if _storage_service_instance is None:
        _storage_service_instance = StorageService()
    return _storage_service_instance
