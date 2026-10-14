from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from app.auth.models import AuthenticatedUser
from app.auth.iap import get_current_user
from app.storage.models import (
    PaginatedReviewsResponse,
    ReviewFeedbackRequest,
)
from app.storage.service import StorageService, get_storage_service

router = APIRouter(prefix="/reviews", tags=["Reviews Query & Feedback"])


@router.get(
    "",
    response_model=PaginatedReviewsResponse,
    summary="List paginated review submissions with filters",
)
async def list_reviews(
    user_id: Optional[str] = Query(None, description="Filter by user ID (reviewer/admin only)"),
    language: Optional[str] = Query(None, description="Filter by language"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by review status"),
    limit: int = Query(20, ge=1, le=100, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    user: AuthenticatedUser = Depends(get_current_user),
    storage: StorageService = Depends(get_storage_service),
) -> PaginatedReviewsResponse:
    """Retrieves paginated review submissions.

    Engineers only have access to their own submissions.
    Reviewers and Admins can query all submissions or filter by user_id.
    """
    target_user_id = user.user_id
    if user.is_reviewer_or_above:
        target_user_id = user_id  # If None, queries across all users

    return await storage.list_reviews(
        user_id=target_user_id,
        language=language,
        status=status_filter,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/{review_id}/feedback",
    status_code=status.HTTP_200_OK,
    summary="Submit developer rating and feedback for a review",
)
async def submit_feedback(
    review_id: str,
    feedback_req: ReviewFeedbackRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    storage: StorageService = Depends(get_storage_service),
):
    """Allows developers to rate AI review findings (1-5 stars) and provide feedback.

    Ratings feed into developer growth analytics and model fine-tuning signals.
    """
    review = await storage.get_review(review_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review '{review_id}' not found",
        )

    # Only submission owner or reviewers/admins can leave feedback
    if not user.is_reviewer_or_above and user.user_id != review.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only provide feedback on your own review submissions",
        )

    updated = await storage.add_feedback(
        review_id=review_id,
        rating=feedback_req.rating,
        feedback=feedback_req.feedback,
        helpful=feedback_req.helpful,
    )

    return {
        "review_id": review_id,
        "rating": feedback_req.rating,
        "feedback": feedback_req.feedback,
        "helpful": feedback_req.helpful,
        "message": "Feedback recorded successfully",
    }
