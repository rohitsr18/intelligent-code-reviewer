"""Intelligent Review Noise Reducer & Anti-Nitpick Filter.

Eliminates AI reviewer chattiness, review fatigue, and cognitive overload.
Filters pedantic stylistic preferences and minor edge cases, grouping low-value
style comments into a consolidated, collapsible section so that critical bugs
and architectural flaws are never drowned out.
"""

from typing import List, Dict, Tuple, Optional
from app.reviewer.models import ReviewFinding, ReviewAnalysisResult, FindingSeverity, FindingCategory


class NoiseFilter:
    """Filters, deduplicates, and consolidates review findings to maximize Signal-to-Noise Ratio (SNR)."""

    SEVERITY_LEVELS: Dict[str, int] = {
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    STYLE_NIT_KEYWORDS = {
        "naming",
        "variable name",
        "casing",
        "formatting",
        "whitespace",
        "blank line",
        "docstring",
        "comment phrasing",
        "style convention",
        "redundant parenthesis",
        "cosmetic",
    }

    def __init__(self, default_min_severity: str = "low") -> None:
        self.default_min_severity = default_min_severity.lower()

    def is_style_nit(self, finding: ReviewFinding) -> bool:
        """Identifies if a finding is a minor stylistic nitpick rather than a substantive defect."""
        # Security and Bug issues are NEVER classified as nits
        if finding.category in (FindingCategory.SECURITY, FindingCategory.BUG):
            return False

        # Critical and High issues are NEVER nits
        if finding.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
            return False

        if finding.category == FindingCategory.STYLE:
            return True

        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()

        for kw in self.STYLE_NIT_KEYWORDS:
            if kw in title_lower or kw in desc_lower:
                return True

        return False

    def deduplicate_findings(self, findings: List[ReviewFinding]) -> List[ReviewFinding]:
        """Deduplicates redundant findings on the same line and category."""
        seen: Dict[Tuple[Optional[int], FindingCategory, str], ReviewFinding] = {}

        for f in findings:
            # Normalize title for fuzzy matching
            norm_title = "".join(ch for ch in f.title.lower() if ch.isalnum())[:30]
            key = (f.line_start, f.category, norm_title)

            if key not in seen:
                seen[key] = f
            else:
                # Keep finding with higher severity if duplicate exists
                existing = seen[key]
                if self.SEVERITY_LEVELS.get(f.severity.value, 0) > self.SEVERITY_LEVELS.get(existing.severity.value, 0):
                    seen[key] = f

        return list(seen.values())

    def filter_and_consolidate(
        self,
        analysis: ReviewAnalysisResult,
        min_severity: Optional[str] = None,
        consolidate_nits: bool = True,
    ) -> ReviewAnalysisResult:
        """Applies severity thresholds, deduplication, and nitpick consolidation to review results."""
        floor_name = (min_severity or self.default_min_severity).lower()
        floor_level = self.SEVERITY_LEVELS.get(floor_name, 1)

        raw_findings = self.deduplicate_findings(analysis.findings)
        primary_findings: List[ReviewFinding] = []
        style_nits: List[ReviewFinding] = []

        for f in raw_findings:
            f_level = self.SEVERITY_LEVELS.get(f.severity.value, 1)

            # Apply severity floor
            if f_level < floor_level:
                continue

            # Consolidate style nits into dedicated secondary list
            if consolidate_nits and self.is_style_nit(f):
                style_nits.append(f)
            else:
                primary_findings.append(f)

        # Sort primary findings by severity (CRITICAL first, then HIGH, MEDIUM, LOW)
        primary_findings.sort(
            key=lambda x: self.SEVERITY_LEVELS.get(x.severity.value, 0),
            reverse=True,
        )

        analysis.findings = primary_findings
        analysis.style_nits = style_nits
        analysis.noise_reduction_applied = (len(style_nits) > 0 or len(raw_findings) > len(primary_findings))

        return analysis
