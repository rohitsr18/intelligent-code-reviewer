from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Role(str, Enum):
    ENGINEER = "engineer"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class AuthenticatedUser(BaseModel):
    user_id: str
    email: str
    role: Role = Role.ENGINEER
    hosted_domain: Optional[str] = None
    claims: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def is_reviewer_or_above(self) -> bool:
        return self.role in (Role.REVIEWER, Role.ADMIN)
