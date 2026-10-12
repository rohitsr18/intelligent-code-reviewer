from typing import Callable
from fastapi import Depends, HTTPException, status
from app.auth.models import AuthenticatedUser, Role
from app.auth.iap import get_current_user

ROLE_HIERARCHY = {
    Role.ENGINEER: 1,
    Role.REVIEWER: 2,
    Role.ADMIN: 3,
}


def require_role(min_role: Role) -> Callable:
    async def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        required_level = ROLE_HIERARCHY.get(min_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires {min_role.value} privileges",
            )
        return user

    return role_checker


require_admin = require_role(Role.ADMIN)
require_reviewer = require_role(Role.REVIEWER)
