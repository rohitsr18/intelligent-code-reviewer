from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SecuritySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RedactedSecret(BaseModel):
    secret_type: str
    severity: SecuritySeverity
    redaction_token: str
    line_number: Optional[int] = None


class SanitizationResult(BaseModel):
    original_line_count: int
    sanitized_code: str
    redactions: List[RedactedSecret] = Field(default_factory=list)
    has_secrets: bool = False
    has_pii: bool = False

    @property
    def total_redactions(self) -> int:
        return len(self.redactions)


class PromptGuardResult(BaseModel):
    is_safe: bool = True
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    flags: List[str] = Field(default_factory=list)
    secured_prompt: str
