from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


class RuleCategory(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    ARCHITECTURE = "architecture"
    BUG = "bugs"
    STYLE = "style"


class RuleSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HistoricalRule(BaseModel):
    rule_id: str = Field(..., description="Unique rule code, e.g. SEC-001 or PERF-PY-01")
    title: str = Field(..., description="Short summary of the rule")
    language: str = Field(default="all", description="Target language: python, typescript, all, etc.")
    category: RuleCategory = Field(default=RuleCategory.ARCHITECTURE)
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM)
    pattern_or_anti_pattern: str = Field(..., description="Description of anti-pattern to avoid")
    guidance: str = Field(..., description="Clear remediation advice")
    tags: List[str] = Field(default_factory=list, description="Categorization tags")
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = Field(default="system")

    @field_validator("language")
    @classmethod
    def normalize_language(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("rule_id")
    @classmethod
    def normalize_rule_id(cls, v: str) -> str:
        return v.strip().upper()

    def to_prompt_instruction(self) -> str:
        return f"[{self.rule_id}] {self.title} ({self.severity.value.upper()}): {self.guidance}"


class RuleIngestResult(BaseModel):
    total_rows: int
    imported_count: int
    rejected_count: int
    errors: List[str] = Field(default_factory=list)
    imported_rules: List[HistoricalRule] = Field(default_factory=list)


class ReviewAnalyticsEvent(BaseModel):
    review_id: str
    user_id: str
    user_email: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    filename: Optional[str] = None
    language: str
    original_line_count: int = 0
    sanitized_secrets_count: int = 0
    prompt_risk_score: float = 0.0
    overall_score: int = 0
    total_findings: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0
    model_used: str = "mock-engine"
    evaluation_latency_ms: float = 0.0
    rules_applied_count: int = 0
    review_status: str = "accepted"

    def to_bigquery_row(self) -> Dict[str, Any]:
        return {
            "review_id": self.review_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "timestamp": self.timestamp.isoformat(),
            "filename": self.filename or "",
            "language": self.language.lower(),
            "original_line_count": self.original_line_count,
            "sanitized_secrets_count": self.sanitized_secrets_count,
            "prompt_risk_score": float(self.prompt_risk_score),
            "overall_score": self.overall_score,
            "total_findings": self.total_findings,
            "findings_critical": self.findings_critical,
            "findings_high": self.findings_high,
            "findings_medium": self.findings_medium,
            "findings_low": self.findings_low,
            "findings_info": self.findings_info,
            "model_used": self.model_used,
            "evaluation_latency_ms": float(self.evaluation_latency_ms),
            "rules_applied_count": self.rules_applied_count,
            "review_status": self.review_status,
        }

