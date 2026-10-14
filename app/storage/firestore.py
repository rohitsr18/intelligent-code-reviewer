import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from app.core.config import get_settings
from app.storage.models import (
    ReviewDocument,
    ReviewFeedback,
    DeveloperGrowthProfile,
    ReviewSessionDocument,
    SessionRevisionItem,
)

logger = logging.getLogger(__name__)


class BaseFirestoreBackend(ABC):
    @abstractmethod
    async def save_review(self, review: ReviewDocument) -> bool:
        pass

    @abstractmethod
    async def get_review(self, review_id: str) -> Optional[ReviewDocument]:
        pass

    @abstractmethod
    async def list_reviews(
        self,
        user_id: Optional[str] = None,
        language: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[ReviewDocument], int]:
        pass

    @abstractmethod
    async def save_review_feedback(
        self, review_id: str, rating: int, feedback: Optional[str], helpful: bool
    ) -> Optional[ReviewDocument]:
        pass

    @abstractmethod
    async def get_growth_profile(self, user_id: str) -> Optional[DeveloperGrowthProfile]:
        pass

    @abstractmethod
    async def update_growth_profile(
        self, user_id: str, email: str, review: ReviewDocument
    ) -> DeveloperGrowthProfile:
        pass

    @abstractmethod
    async def create_session(self, session: ReviewSessionDocument) -> ReviewSessionDocument:
        pass

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[ReviewSessionDocument]:
        pass

    @abstractmethod
    async def add_session_revision(
        self, session_id: str, revision: SessionRevisionItem
    ) -> Optional[ReviewSessionDocument]:
        pass


class InMemoryFirestoreBackend(BaseFirestoreBackend):
    """In-memory Firestore emulator for local development, CI tests, and offline runs."""

    def __init__(self) -> None:
        self._reviews: Dict[str, ReviewDocument] = {}
        self._profiles: Dict[str, DeveloperGrowthProfile] = {}
        self._sessions: Dict[str, ReviewSessionDocument] = {}

    async def save_review(self, review: ReviewDocument) -> bool:
        self._reviews[review.review_id] = review
        # Keep user growth profile updated automatically
        await self.update_growth_profile(
            user_id=review.user_id,
            email=review.submitted_by,
            review=review,
        )
        return True

    async def get_review(self, review_id: str) -> Optional[ReviewDocument]:
        return self._reviews.get(review_id)

    async def list_reviews(
        self,
        user_id: Optional[str] = None,
        language: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[ReviewDocument], int]:
        items = list(self._reviews.values())

        if user_id:
            items = [r for r in items if r.user_id == user_id]
        if language:
            items = [r for r in items if r.language.lower() == language.lower()]
        if status:
            items = [r for r in items if r.status.lower() == status.lower()]

        items.sort(key=lambda r: r.submitted_at, reverse=True)
        total = len(items)
        paginated = items[offset : offset + limit]
        return paginated, total

    async def save_review_feedback(
        self, review_id: str, rating: int, feedback: Optional[str], helpful: bool
    ) -> Optional[ReviewDocument]:
        review = self._reviews.get(review_id)
        if not review:
            return None

        review.feedback = ReviewFeedback(
            rating=rating,
            feedback=feedback,
            helpful=helpful,
            submitted_at=datetime.now(timezone.utc),
        )

        # Update growth profile rating metrics
        profile = self._profiles.get(review.user_id)
        if profile:
            profile.total_feedback_given += 1
            if profile.average_feedback_rating is None:
                profile.average_feedback_rating = float(rating)
            else:
                total = profile.total_feedback_given
                profile.average_feedback_rating = round(
                    ((profile.average_feedback_rating * (total - 1)) + rating) / total, 2
                )
            profile.updated_at = datetime.now(timezone.utc)

        return review

    async def get_growth_profile(self, user_id: str) -> Optional[DeveloperGrowthProfile]:
        return self._profiles.get(user_id)

    async def update_growth_profile(
        self, user_id: str, email: str, review: ReviewDocument
    ) -> DeveloperGrowthProfile:
        profile = self._profiles.get(user_id)
        if not profile:
            profile = DeveloperGrowthProfile(
                user_id=user_id,
                email=email,
            )
            self._profiles[user_id] = profile

        profile.total_reviews += 1
        lang = review.language.lower()
        profile.languages_used[lang] = profile.languages_used.get(lang, 0) + 1

        overall_score = 90
        if review.analysis and isinstance(review.analysis, dict):
            overall_score = review.analysis.get("overall_score", 90)

            # Extract recurring weaknesses from findings
            findings = review.analysis.get("findings", [])
            for f in findings:
                cat = f.get("category", "other")
                profile.recurring_weaknesses[cat] = profile.recurring_weaknesses.get(cat, 0) + 1

            # Extract recommended skills from growth tips
            tips = review.analysis.get("growth_tips", [])
            for tip in tips:
                topic = tip.get("topic")
                if topic and topic not in profile.recommended_skills:
                    profile.recommended_skills.append(topic)

        # Update moving average score
        total_revs = profile.total_reviews
        if total_revs == 1:
            profile.average_score = float(overall_score)
        else:
            profile.average_score = round(
                ((profile.average_score * (total_revs - 1)) + overall_score) / total_revs, 2
            )

        # Record in score trajectory (keep last 50)
        profile.score_history.append(
            {
                "review_id": review.review_id,
                "score": overall_score,
                "timestamp": review.submitted_at.isoformat(),
            }
        )
        if len(profile.score_history) > 50:
            profile.score_history = profile.score_history[-50:]

        profile.updated_at = datetime.now(timezone.utc)
        return profile

    async def create_session(self, session: ReviewSessionDocument) -> ReviewSessionDocument:
        self._sessions[session.session_id] = session
        return session

    async def get_session(self, session_id: str) -> Optional[ReviewSessionDocument]:
        return self._sessions.get(session_id)

    async def add_session_revision(
        self, session_id: str, revision: SessionRevisionItem
    ) -> Optional[ReviewSessionDocument]:
        session = self._sessions.get(session_id)
        if not session:
            return None
        session.revisions.append(revision)
        session.updated_at = datetime.now(timezone.utc)
        return session


class ProductionFirestoreBackend(BaseFirestoreBackend):
    """Production Firestore client backed by Google Cloud Firestore with local fallback."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._fallback = InMemoryFirestoreBackend()
        self._client = None
        self._initialized = False

    def _get_client(self):
        if self._client is None and not self._initialized:
            try:
                from google.cloud import firestore
                self._client = firestore.Client(
                    project=self.settings.gcp_project_id,
                )
            except Exception as e:
                logger.warning(
                    f"Firestore credentials not available or client init failed: {e}. "
                    f"Falling back seamlessly to in-memory store."
                )
                self._client = None
            self._initialized = True
        return self._client

    async def save_review(self, review: ReviewDocument) -> bool:
        client = self._get_client()
        if client is None:
            return await self._fallback.save_review(review)

        try:
            coll = client.collection(self.settings.firestore_collection_reviews)
            doc_ref = coll.document(review.review_id)
            doc_ref.set(review.model_dump(mode="json"))
            await self._fallback.save_review(review)
            return True
        except Exception as e:
            logger.warning(f"Firestore save_review error: {e}. Writing to fallback.")
            return await self._fallback.save_review(review)

    async def get_review(self, review_id: str) -> Optional[ReviewDocument]:
        client = self._get_client()
        if client is None:
            return await self._fallback.get_review(review_id)

        try:
            coll = client.collection(self.settings.firestore_collection_reviews)
            doc = coll.document(review_id).get()
            if doc.exists:
                return ReviewDocument.model_validate(doc.to_dict())
            return await self._fallback.get_review(review_id)
        except Exception as e:
            logger.warning(f"Firestore get_review error: {e}. Querying fallback.")
            return await self._fallback.get_review(review_id)

    async def list_reviews(
        self,
        user_id: Optional[str] = None,
        language: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Tuple[List[ReviewDocument], int]:
        client = self._get_client()
        if client is None:
            return await self._fallback.list_reviews(user_id, language, status, limit, offset)

        try:
            coll = client.collection(self.settings.firestore_collection_reviews)
            query = coll
            if user_id:
                query = query.where("user_id", "==", user_id)
            if language:
                query = query.where("language", "==", language.lower())
            if status:
                query = query.where("status", "==", status.lower())

            # Firestore snapshot count
            docs = list(query.order_by("submitted_at", direction="DESCENDING").offset(offset).limit(limit).stream())
            results = [ReviewDocument.model_validate(d.to_dict()) for d in docs]
            total = len(results)
            return results, total
        except Exception as e:
            logger.warning(f"Firestore list_reviews error: {e}. Delegating to fallback.")
            return await self._fallback.list_reviews(user_id, language, status, limit, offset)

    async def save_review_feedback(
        self, review_id: str, rating: int, feedback: Optional[str], helpful: bool
    ) -> Optional[ReviewDocument]:
        client = self._get_client()
        if client is None:
            return await self._fallback.save_review_feedback(review_id, rating, feedback, helpful)

        try:
            coll = client.collection(self.settings.firestore_collection_reviews)
            doc_ref = coll.document(review_id)
            fb_data = {
                "rating": rating,
                "feedback": feedback,
                "helpful": helpful,
                "submitted_at": datetime.now(timezone.utc).isoformat(),
            }
            doc_ref.update({"feedback": fb_data})
            return await self._fallback.save_review_feedback(review_id, rating, feedback, helpful)
        except Exception as e:
            logger.warning(f"Firestore feedback update error: {e}. Updating fallback.")
            return await self._fallback.save_review_feedback(review_id, rating, feedback, helpful)

    async def get_growth_profile(self, user_id: str) -> Optional[DeveloperGrowthProfile]:
        client = self._get_client()
        if client is None:
            return await self._fallback.get_growth_profile(user_id)

        try:
            coll = client.collection(self.settings.firestore_collection_users)
            doc = coll.document(user_id).get()
            if doc.exists:
                return DeveloperGrowthProfile.model_validate(doc.to_dict())
            return await self._fallback.get_growth_profile(user_id)
        except Exception as e:
            logger.warning(f"Firestore get_growth_profile error: {e}. Querying fallback.")
            return await self._fallback.get_growth_profile(user_id)

    async def update_growth_profile(
        self, user_id: str, email: str, review: ReviewDocument
    ) -> DeveloperGrowthProfile:
        client = self._get_client()
        profile = await self._fallback.update_growth_profile(user_id, email, review)
        if client is not None:
            try:
                coll = client.collection(self.settings.firestore_collection_users)
                coll.document(user_id).set(profile.model_dump(mode="json"))
            except Exception as e:
                logger.warning(f"Firestore profile write error: {e}.")
        return profile

    async def create_session(self, session: ReviewSessionDocument) -> ReviewSessionDocument:
        client = self._get_client()
        if client is not None:
            try:
                coll = client.collection(self.settings.firestore_collection_sessions)
                coll.document(session.session_id).set(session.model_dump(mode="json"))
            except Exception as e:
                logger.warning(f"Firestore session write error: {e}.")
        return await self._fallback.create_session(session)

    async def get_session(self, session_id: str) -> Optional[ReviewSessionDocument]:
        client = self._get_client()
        if client is None:
            return await self._fallback.get_session(session_id)

        try:
            coll = client.collection(self.settings.firestore_collection_sessions)
            doc = coll.document(session_id).get()
            if doc.exists:
                return ReviewSessionDocument.model_validate(doc.to_dict())
            return await self._fallback.get_session(session_id)
        except Exception as e:
            logger.warning(f"Firestore session read error: {e}. Checking fallback.")
            return await self._fallback.get_session(session_id)

    async def add_session_revision(
        self, session_id: str, revision: SessionRevisionItem
    ) -> Optional[ReviewSessionDocument]:
        client = self._get_client()
        updated = await self._fallback.add_session_revision(session_id, revision)
        if client is not None and updated:
            try:
                coll = client.collection(self.settings.firestore_collection_sessions)
                coll.document(session_id).set(updated.model_dump(mode="json"))
            except Exception as e:
                logger.warning(f"Firestore session revision update error: {e}.")
        return updated


_firestore_instance: Optional[BaseFirestoreBackend] = None


def get_firestore_backend() -> BaseFirestoreBackend:
    global _firestore_instance
    if _firestore_instance is None:
        settings = get_settings()
        if settings.environment in ("test", "testing"):
            _firestore_instance = InMemoryFirestoreBackend()
        else:
            _firestore_instance = ProductionFirestoreBackend()
    return _firestore_instance
