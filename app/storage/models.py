from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class ReviewFeedbackRequest(BaseModel):
    rating: int = Field(..., ge=1, le=5, description="Star rating from 1 to 5")
    feedback: Optional[str] = Field(None, max_length=1000, description="Optional text feedback")
    helpful: bool = Field(True, description="Whether the review was helpful")


class ReviewFeedback(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    feedback: Optional[str] = None
    helpful: bool = True
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReviewDocument(BaseModel):
    review_id: str
    user_id: str
    submitted_by: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str
    filename: Optional[str] = None
    language: str
    original_line_count: int = 0
    sanitized_code: str
    secured_prompt: str
    redactions: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float = 0.0
    is_safe_prompt: bool = True
    flags: List[str] = Field(default_factory=list)
    rules_applied_count: int = 0
    pruning_summary: Optional[Dict[str, Any]] = None
    dependency_audit: Optional[Dict[str, Any]] = None
    sast_summary: Optional[Dict[str, Any]] = None
    test_audit_summary: Optional[Dict[str, Any]] = None
    intent_audit_summary: Optional[Dict[str, Any]] = None
    analysis: Optional[Dict[str, Any]] = None
    feedback: Optional[ReviewFeedback] = None
    session_id: Optional[str] = None


class DeveloperGrowthProfile(BaseModel):
    user_id: str
    email: str
    total_reviews: int = 0
    languages_used: Dict[str, int] = Field(default_factory=dict)
    average_score: float = 0.0
    score_history: List[Dict[str, Any]] = Field(default_factory=list)
    recurring_weaknesses: Dict[str, int] = Field(default_factory=dict)
    recommended_skills: List[str] = Field(default_factory=list)
    average_feedback_rating: Optional[float] = None
    total_feedback_given: int = 0
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SessionRevisionItem(BaseModel):
    revision_index: int
    review_id: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    filename: Optional[str] = None
    overall_score: int
    findings_count: int
    summary: str


class ReviewSessionDocument(BaseModel):
    session_id: str
    user_id: str
    email: str
    title: str
    language: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"
    revisions: List[SessionRevisionItem] = Field(default_factory=list)


class CreateSessionRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=120)
    language: str = Field(default="python")


class ReviseSessionRequest(BaseModel):
    code: str = Field(..., min_length=1)
    filename: Optional[str] = None
    context: Optional[str] = None


class PaginatedReviewsResponse(BaseModel):
    items: List[ReviewDocument]
    total: int
    limit: int
    offset: int
    has_next: bool
