from fastapi import APIRouter, Depends
from app.api.v1.models import UserSessionResponse
from app.auth.models import AuthenticatedUser
from app.auth.iap import get_current_user

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.get("/me", response_model=UserSessionResponse)
async def get_current_session(
    user: AuthenticatedUser = Depends(get_current_user),
) -> UserSessionResponse:
    return UserSessionResponse(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        is_admin=user.is_admin,
        hosted_domain=user.hosted_domain,
    )
