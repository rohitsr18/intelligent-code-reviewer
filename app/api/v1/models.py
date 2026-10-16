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
    "auto",
}


class LanguageDetectRequest(BaseModel):
    code: str = Field(..., min_length=1)
    filename: Optional[str] = None


class LanguageDetectResponse(BaseModel):
    detected_language: str
    confidence: float
    detected_by: str
    is_ambiguous: bool
    candidate_scores: Dict[str, int] = Field(default_factory=dict)
    supported_languages: List[str] = Field(default_factory=list)


class DependencyAuditRequest(BaseModel):
    manifest_content: str = Field(..., min_length=1)
    filename: Optional[str] = None


class DependencyAuditResponse(BaseModel):
    manifest_type: Optional[str] = None
    is_manifest: bool
    total_dependencies_scanned: int
    vulnerable_packages_count: int
    license_violations_count: int
    dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class SASTScanRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = Field(default="auto")
    filename: Optional[str] = None


class SASTScanResponse(BaseModel):
    language: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class TestAuditRequest(BaseModel):
    code: str = Field(..., min_length=1)
    filename: Optional[str] = None
    language: str = Field(default="auto")


class TestAuditResponse(BaseModel):
    is_test_file: bool
    total_test_cases: int
    impacted_test_files: List[str] = Field(default_factory=list)
    has_missing_coverage: bool = False
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class IntentSweepRequest(BaseModel):
    code: str = Field(..., min_length=1)
    context: Optional[str] = None
    filename: Optional[str] = None
    language: str = Field(default="auto")


class IntentSweepResponse(BaseModel):
    intent_alignment_score: float
    is_aligned: bool
    scope_drift_detected: bool
    drift_reasons: List[str] = Field(default_factory=list)
    unintended_files: List[str] = Field(default_factory=list)
    missing_stated_items: List[str] = Field(default_factory=list)
    total_artifacts_count: int
    artifact_findings: List[Dict[str, Any]] = Field(default_factory=list)


class ReviewSubmissionRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = Field(default="auto")
    filename: Optional[str] = None
    repo_name: Optional[str] = None
    branch: Optional[str] = None
    context: Optional[str] = None
    min_severity: Optional[str] = "low"

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
    detected_language_confidence: Optional[float] = None
    detected_by: Optional[str] = None
    rules_applied_count: int = 0
    pruning_summary: Optional[Dict[str, Any]] = None
    dependency_audit: Optional[Dict[str, Any]] = None
    sast_summary: Optional[Dict[str, Any]] = None
    test_audit_summary: Optional[Dict[str, Any]] = None
    intent_audit_summary: Optional[Dict[str, Any]] = None
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
    dependency_audit: Optional[Dict[str, Any]] = None
    sast_summary: Optional[Dict[str, Any]] = None
    test_audit_summary: Optional[Dict[str, Any]] = None
    intent_audit_summary: Optional[Dict[str, Any]] = None
    analysis: Optional[ReviewAnalysisResult] = None


class UserSessionResponse(BaseModel):
    user_id: str
    email: str
    role: Role
    is_admin: bool
    hosted_domain: Optional[str] = None
