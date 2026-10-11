"""Data models for AI Security and Sanitization results."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class SecuritySeverity(str, Enum):
    """Severity ratings for detected security risks."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RedactedSecret(BaseModel):
    """Metadata describing a redacted secret or sensitive token."""
    secret_type: str = Field(..., description="Category of detected credential or PII")
    severity: SecuritySeverity = Field(..., description="Severity classification")
    redaction_token: str = Field(..., description="Placeholder token inserted into code")
    line_number: Optional[int] = Field(None, description="Source code line number")


class SanitizationResult(BaseModel):
    """Result of running code sanitization and data leak prevention."""
    original_line_count: int
    sanitized_code: str
    redactions: List[RedactedSecret] = Field(default_factory=list)
    has_secrets: bool = False
    has_pii: bool = False

    @property
    def total_redactions(self) -> int:
        return len(self.redactions)


class PromptGuardResult(BaseModel):
    """Result of prompt injection defense check."""
    is_safe: bool = True
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    flags: List[str] = Field(default_factory=list)
    secured_prompt: str = Field(..., description="Delimited, sandboxed prompt representation")
