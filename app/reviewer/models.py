from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class FindingCategory(str, Enum):
    BUG = "bug"
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    PERFORMANCE = "performance"
    GROWTH = "growth"
    STYLE = "style"
    MAINTAINABILITY = "maintainability"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReviewFinding(BaseModel):
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    suggested_fix: Optional[str] = None
    rule_id: Optional[str] = None
    is_fix_valid: bool = True
    fix_validation_note: Optional[str] = None


class GrowthTip(BaseModel):
    topic: str
    advice: str
    learning_resource: Optional[str] = None


class ReviewAnalysisResult(BaseModel):
    overall_score: int = Field(ge=0, le=100)
    summary: str
    category_scores: Dict[str, int] = Field(default_factory=dict)
    findings: List[ReviewFinding] = Field(default_factory=list)
    style_nits: List[ReviewFinding] = Field(default_factory=list)
    noise_reduction_applied: bool = False
    growth_tips: List[GrowthTip] = Field(default_factory=list)
    model_used: str = "gemini-1.5-pro"
    evaluation_latency_ms: float = 0.0
    total_files_reviewed: Optional[int] = 1
    fast_path_files_count: Optional[int] = 0
    parallel_speedup_factor: Optional[float] = 1.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
