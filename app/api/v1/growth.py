from fastapi import APIRouter, Depends, HTTPException, status
from app.auth.models import AuthenticatedUser, Role
from app.auth.iap import get_current_user
from app.auth.rbac import require_role
from app.storage.models import DeveloperGrowthProfile
from app.storage.service import StorageService, get_storage_service

router = APIRouter(prefix="/growth", tags=["Developer Growth & Insights"])


@router.get(
    "/me",
    response_model=DeveloperGrowthProfile,
    summary="Get authenticated developer's growth profile and skill trajectory",
)
async def get_my_growth_profile(
    user: AuthenticatedUser = Depends(get_current_user),
    storage: StorageService = Depends(get_storage_service),
) -> DeveloperGrowthProfile:
    """Retrieves long-term developer progress, moving average review score,

    recurring code weaknesses, and acquired growth recommendations.
    """
    profile = await storage.get_growth_profile(user.user_id)
    if not profile:
        # Return initial empty profile for new developer
        return DeveloperGrowthProfile(
            user_id=user.user_id,
            email=user.email,
        )
    return profile


@router.get(
    "/user/{user_id}",
    response_model=DeveloperGrowthProfile,
    summary="Get developer growth profile (Reviewer/Admin only)",
)
async def get_user_growth_profile(
    user_id: str,
    user: AuthenticatedUser = Depends(require_role(Role.REVIEWER)),
    storage: StorageService = Depends(get_storage_service),
) -> DeveloperGrowthProfile:
    """Allows engineering leads, reviewers, and admins to inspect a developer's growth trajectory."""
    profile = await storage.get_growth_profile(user_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Growth profile for user '{user_id}' not found",
        )
    return profile
