from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
from app.auth.models import Role
from app.reviewer.models import ReviewAnalysisResult

SUPPORTED_LANGUAGES = {
    "python",
    "javascript",
    "typescript",
    "go",
    "java",
    "rust",
    "cpp",
    "c",
    "csharp",
    "ruby",
    "php",
    "sql",
    "html",
    "css",
    "yaml",
    "json",
    "dockerfile",
    "bash",
    "shell",
    "kotlin",
    "swift",
}


class ReviewSubmissionRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = Field(default="python")
    filename: Optional[str] = None
    repo_name: Optional[str] = None
    branch: Optional[str] = None
    context: Optional[str] = None

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        lang = v.strip().lower()
        if lang not in SUPPORTED_LANGUAGES:
            raise ValueError(
                f"Unsupported language: '{v}'. Supported: {', '.join(sorted(SUPPORTED_LANGUAGES))}"
            )
        return lang


class RedactionSummary(BaseModel):
    secret_type: str
    redaction_token: str
    line_number: Optional[int] = None


class ReviewSubmissionResponse(BaseModel):
    review_id: str
    status: str
    original_line_count: int
    redactions_count: int
    redactions: List[RedactionSummary] = Field(default_factory=list)
    risk_score: float
    is_safe_prompt: bool
    flags: List[str] = Field(default_factory=list)
    submitted_by: str
    submitted_at: datetime
    filename: Optional[str] = None
    language: str
    rules_applied_count: int = 0
    pruning_summary: Optional[Dict[str, Any]] = None
    analysis: Optional[ReviewAnalysisResult] = None


class ReviewDetailResponse(BaseModel):
    review_id: str
    status: str
    submitted_by: str
    submitted_at: datetime
    filename: Optional[str] = None
    language: str
    original_line_count: int
    redactions_count: int
    sanitized_code: str
    risk_score: float
    is_safe_prompt: bool
    flags: List[str] = Field(default_factory=list)
    rules_applied_count: int = 0
    feedback: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    pruning_summary: Optional[Dict[str, Any]] = None
    analysis: Optional[ReviewAnalysisResult] = None


class UserSessionResponse(BaseModel):
    user_id: str
    email: str
    role: Role
    is_admin: bool
    hosted_domain: Optional[str] = None
