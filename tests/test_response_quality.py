import pytest
from app.reviewer.models import (
    FindingCategory,
    FindingSeverity,
    ReviewFinding,
    ReviewVerdict,
    ReviewAnalysisResult,
    GrowthTip,
)
from app.reviewer.engine import MockReviewEngine, canonicalize_review_result
from app.reviewer.prompts import SYSTEM_INSTRUCTION
from app.reviewer.batch_engine import BatchReviewEngine, FileDiffUnit


def test_system_instruction_quality_guidelines():
    """Verify that SYSTEM_INSTRUCTION sets rigorous standards for impact, fixes, and score calibration."""
    assert "Principal Software Engineer" in SYSTEM_INSTRUCTION
    assert "HARD CAP" in SYSTEM_INSTRUCTION
    assert "REQUEST_CHANGES" in SYSTEM_INSTRUCTION
    assert "Why this matters in production" in SYSTEM_INSTRUCTION
    assert "effort_estimate" in SYSTEM_INSTRUCTION
    assert "quick_wins" in SYSTEM_INSTRUCTION
    assert "key_risks" in SYSTEM_INSTRUCTION


@pytest.mark.asyncio
async def test_mock_review_engine_response_depth():
    """Verify MockReviewEngine populates impact, fix_explanation, verdict, and effort estimate."""
    engine = MockReviewEngine()
    vulnerable_code = """
def run_command(cmd, user_id):
    query = "SELECT * FROM secrets WHERE id = " + str(user_id)
    eval(cmd)
"""
    result = await engine.analyze(code=vulnerable_code, language="python")

    # Score calibration cap for critical vulnerabilities
    assert result.overall_score <= 45
    assert result.verdict == "REQUEST_CHANGES"
    assert result.verdict_rationale is not None
    assert "must be resolved" in result.verdict_rationale
    assert result.effort_estimate in ("1 - 2 hours", "30 - 45 minutes")
    assert len(result.key_risks) >= 1
    assert any("Dynamic Code Execution" in r or "SQL Injection" in r for r in result.key_risks)

    # Findings depth
    for f in result.findings:
        assert f.impact is not None and len(f.impact) > 10
        assert f.fix_explanation is not None and len(f.fix_explanation) > 10
        assert f.suggested_fix is not None


@pytest.mark.asyncio
async def test_clean_code_verdict_and_metadata():
    """Verify clean code receives APPROVE verdict with 0 minutes effort."""
    engine = MockReviewEngine()
    clean_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    result = await engine.analyze(code=clean_code, language="python")

    assert result.overall_score >= 90
    assert result.verdict == "APPROVE"
    assert result.effort_estimate == "0 minutes"
    assert len(result.key_risks) == 0


def test_canonicalize_populates_missing_executive_fields():
    """Verify canonicalize_review_result gracefully computes missing verdict, rationale, and risks."""
    raw = ReviewAnalysisResult(
        overall_score=60,
        summary="Basic summary",
        findings=[
            ReviewFinding(
                category=FindingCategory.BUG,
                severity=FindingSeverity.HIGH,
                title="Race Condition in Cache Flush",
                description="State unlocked during flush",
                line_start=10,
            )
        ],
    )
    assert raw.verdict is None
    assert raw.effort_estimate is None

    canonical = canonicalize_review_result(raw)

    assert canonical.verdict == "REQUEST_CHANGES"
    assert "Race Condition in Cache Flush" in canonical.key_risks
    assert canonical.effort_estimate == "30 - 45 minutes"
    assert "Action required" in canonical.verdict_rationale


def test_batch_engine_composite_verdict_aggregation():
    """Verify BatchReviewEngine computes composite verdict and merges quick wins across files."""
    batch_engine = BatchReviewEngine()

    unit1 = FileDiffUnit(
        filename="service.py",
        diff_content="def bad(): eval('1')",
        language="python",
        line_count=1,
    )
    res1 = ReviewAnalysisResult(
        overall_score=40,
        summary="Critical flaw",
        verdict="REQUEST_CHANGES",
        key_risks=["Dynamic Code Execution"],
        quick_wins=["Use ast.literal_eval"],
        findings=[
            ReviewFinding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="Dynamic Code Execution",
                description="eval used",
            )
        ],
    )

    unit2 = FileDiffUnit(
        filename="util.py",
        diff_content="def good(): pass",
        language="python",
        line_count=1,
    )
    res2 = ReviewAnalysisResult(
        overall_score=95,
        summary="Clean file",
        verdict="APPROVE",
        quick_wins=["Add docstring"],
    )

    aggregated = batch_engine.aggregate_batch_results(
        results=[(unit1, res1), (unit2, res2)],
        total_wall_time_ms=150.0,
    )

    assert aggregated.verdict == "REQUEST_CHANGES"
    assert "Dynamic Code Execution" in aggregated.key_risks
    assert "Use ast.literal_eval" in aggregated.quick_wins
    assert "Add docstring" in aggregated.quick_wins
    assert aggregated.effort_estimate == "1 - 2 hours"
