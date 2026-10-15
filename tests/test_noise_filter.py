import pytest
from app.reviewer.models import (
    ReviewFinding,
    FindingCategory,
    FindingSeverity,
    ReviewAnalysisResult,
)
from app.reviewer.noise_filter import NoiseFilter
from app.reviewer.engine import MockReviewEngine
from scripts.pr_review_bot import format_markdown_pr_comment


def test_is_style_nit_detection():
    nf = NoiseFilter()

    # Style nit examples
    nit_finding = ReviewFinding(
        category=FindingCategory.STYLE,
        severity=FindingSeverity.LOW,
        title="Inconsistent variable naming convention",
        description="Consider using snake_case for python variables.",
        line_start=10,
    )
    assert nf.is_style_nit(nit_finding) is True

    docstring_nit = ReviewFinding(
        category=FindingCategory.MAINTAINABILITY,
        severity=FindingSeverity.INFO,
        title="Docstring formatting",
        description="Missing trailing blank line in docstring.",
        line_start=15,
    )
    assert nf.is_style_nit(docstring_nit) is True

    # Security is NEVER a nit, even if it mentions naming or cosmetic keywords
    sec_finding = ReviewFinding(
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.LOW,
        title="Insecure credential naming convention in config",
        description="Naming leaks internal secret variable names in cleartext.",
        line_start=5,
    )
    assert nf.is_style_nit(sec_finding) is False

    # Bug is NEVER a nit
    bug_finding = ReviewFinding(
        category=FindingCategory.BUG,
        severity=FindingSeverity.LOW,
        title="Variable name typo causes NameError",
        description="Typo in variable name at runtime.",
        line_start=20,
    )
    assert nf.is_style_nit(bug_finding) is False

    # Critical/High severity is NEVER a nit
    critical_finding = ReviewFinding(
        category=FindingCategory.STYLE,
        severity=FindingSeverity.HIGH,
        title="Critical naming collision in global namespace",
        description="Overrides built-in object causing systemic failure.",
        line_start=1,
    )
    assert nf.is_style_nit(critical_finding) is False


def test_deduplicate_findings():
    nf = NoiseFilter()
    findings = [
        ReviewFinding(
            category=FindingCategory.BUG,
            severity=FindingSeverity.LOW,
            title="Potential Index Error",
            description="May be out of range.",
            line_start=42,
        ),
        ReviewFinding(
            category=FindingCategory.BUG,
            severity=FindingSeverity.HIGH,
            title="Potential Index Error",
            description="Confirmed off-by-one index crash.",
            line_start=42,
        ),
        ReviewFinding(
            category=FindingCategory.SECURITY,
            severity=FindingSeverity.MEDIUM,
            title="Potential Index Error",
            description="Security risk.",
            line_start=42,
        ),
    ]

    deduped = nf.deduplicate_findings(findings)
    # The two BUG findings on line 42 should be deduplicated to 1 (keeping HIGH)
    assert len(deduped) == 2
    bug_finding = next(f for f in deduped if f.category == FindingCategory.BUG)
    assert bug_finding.severity == FindingSeverity.HIGH


def test_severity_floor_filtering():
    nf = NoiseFilter()
    analysis = ReviewAnalysisResult(
        overall_score=80,
        summary="Initial review",
        findings=[
            ReviewFinding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="SQL Injection",
                description="Raw query concatenation.",
                line_start=10,
            ),
            ReviewFinding(
                category=FindingCategory.BUG,
                severity=FindingSeverity.MEDIUM,
                title="Unhandled NoneType",
                description="Check for None before access.",
                line_start=15,
            ),
            ReviewFinding(
                category=FindingCategory.PERFORMANCE,
                severity=FindingSeverity.LOW,
                title="Unidiomatic Loop Indexing",
                description="Use enumerate instead of range(len()).",
                line_start=20,
            ),
            ReviewFinding(
                category=FindingCategory.STYLE,
                severity=FindingSeverity.INFO,
                title="Informational Note",
                description="General note.",
                line_start=25,
            ),
        ],
    )

    # Filter with min_severity="medium"
    filtered = nf.filter_and_consolidate(analysis, min_severity="medium")
    severities = [f.severity for f in filtered.findings]
    assert FindingSeverity.CRITICAL in severities
    assert FindingSeverity.MEDIUM in severities
    assert FindingSeverity.LOW not in severities
    assert FindingSeverity.INFO not in severities


def test_style_nit_consolidation():
    nf = NoiseFilter()
    analysis = ReviewAnalysisResult(
        overall_score=85,
        summary="Review with mixed findings",
        findings=[
            ReviewFinding(
                category=FindingCategory.BUG,
                severity=FindingSeverity.HIGH,
                title="Silent Exception Swallowing",
                description="Swallowing exceptions hides crashes.",
                line_start=12,
            ),
            ReviewFinding(
                category=FindingCategory.STYLE,
                severity=FindingSeverity.LOW,
                title="Variable naming convention",
                description="Consider snake_case variable names.",
                line_start=18,
            ),
        ],
    )

    res = nf.filter_and_consolidate(analysis, min_severity="low")
    assert len(res.findings) == 1
    assert res.findings[0].title == "Silent Exception Swallowing"
    assert len(res.style_nits) == 1
    assert res.style_nits[0].title == "Variable naming convention"
    assert res.noise_reduction_applied is True


@pytest.mark.asyncio
async def test_mock_engine_noise_filter_integration():
    engine = MockReviewEngine()
    # Code with exception swallowing (HIGH) and range(len()) (LOW)
    code = (
        "def process():\n"
        "    try:\n"
        "        for i in range(len(items)):\n"
        "            pass\n"
        "    except Exception:\n"
        "        pass\n"
    )

    # min_severity="high" should filter out the LOW performance finding
    res_high = await engine.analyze(code, language="python", min_severity="high")
    assert len(res_high.findings) == 1
    assert res_high.findings[0].severity == FindingSeverity.HIGH

    # min_severity="low" keeps both
    res_low = await engine.analyze(code, language="python", min_severity="low")
    assert len(res_low.findings) == 2


def test_pr_bot_renders_style_nits():
    review_data = {
        "analysis": {
            "overall_score": 88,
            "summary": "Clean PR with minor stylistic nits.",
            "findings": [
                {
                    "severity": "high",
                    "title": "Uncaught ValueError",
                    "description": "Validation error not handled.",
                    "line_start": 30,
                }
            ],
            "style_nits": [
                {
                    "severity": "low",
                    "title": "Trailing whitespace",
                    "description": "Remove unnecessary trailing spaces.",
                    "line_start": 44,
                    "suggested_fix": "clean_line()",
                }
            ],
            "growth_tips": [],
        }
    }

    markdown = format_markdown_pr_comment(review_data)
    assert "### 🔍 Detailed Findings (1)" in markdown
    assert "Uncaught ValueError" in markdown
    assert "<details>" in markdown
    assert "Style & Minor Suggestions (1)" in markdown
    assert "Trailing whitespace" in markdown

