import json
import pytest
from unittest.mock import MagicMock
from app.reviewer.models import (
    FindingCategory,
    FindingSeverity,
    ReviewFinding,
    GrowthTip,
    ReviewAnalysisResult,
)
from app.reviewer.prompts import build_review_prompt, SYSTEM_INSTRUCTION
from app.reviewer.engine import MockReviewEngine, GeminiReviewEngine


def test_build_review_prompt():
    prompt = build_review_prompt(
        code="def add(a, b): return a + b",
        language="python",
        filename="math_utils.py",
        context="Add basic math helpers",
        rules=["No global variables", "Use type hints"],
    )
    assert "Language: python" in prompt
    assert "Filename: math_utils.py" in prompt
    assert "PR/Task Context: Add basic math helpers" in prompt
    assert "- No global variables" in prompt
    assert "def add(a, b): return a + b" in prompt


def test_review_analysis_model_metrics():
    result = ReviewAnalysisResult(
        overall_score=85,
        summary="Good codebase with minor suggestions",
        category_scores={"bugs": 90, "security": 80},
        findings=[
            ReviewFinding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="SQL Injection",
                description="Raw string concatenation",
                line_start=12,
            ),
            ReviewFinding(
                category=FindingCategory.BUG,
                severity=FindingSeverity.HIGH,
                title="Null Dereference",
                description="Possible NoneType attribute access",
                line_start=24,
            ),
        ],
        growth_tips=[
            GrowthTip(
                topic="Testing",
                advice="Add unit tests using pytest fixtures",
            )
        ],
        model_used="gemini-1.5-pro",
    )
    assert result.total_findings == 2
    assert result.critical_count == 1
    assert result.high_count == 1


@pytest.mark.asyncio
async def test_mock_review_engine_clean_code():
    engine = MockReviewEngine()
    result = await engine.analyze(
        code="def square(x: int) -> int:\n    return x * x\n",
        language="python",
    )
    assert result.overall_score >= 90
    assert result.critical_count == 0
    assert len(result.findings) == 0
    assert len(result.growth_tips) >= 1
    assert result.growth_tips[0].topic == "Type Annotations"


@pytest.mark.asyncio
async def test_mock_review_engine_detects_security_and_bugs():
    engine = MockReviewEngine()
    vulnerable_code = """
def execute_query(user_id):
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    return eval(query)

def swallow():
    try:
        pass
    except Exception:
        pass
"""
    result = await engine.analyze(code=vulnerable_code, language="python")
    assert result.overall_score <= 75
    assert result.critical_count >= 1

    finding_titles = [f.title for f in result.findings]
    assert any("SQL Injection" in title for title in finding_titles)
    assert any("Dynamic Code Execution" in title for title in finding_titles)
    assert any("Silent Exception Swallowing" in title for title in finding_titles)


@pytest.mark.asyncio
async def test_gemini_review_engine_with_mocked_genai_client(monkeypatch):
    engine = GeminiReviewEngine()

    mock_client = MagicMock()
    mock_response = MagicMock()

    dummy_analysis = {
        "overall_score": 88,
        "summary": "Solid pull request with clean patterns",
        "category_scores": {"bugs": 95, "security": 90, "architecture": 85},
        "findings": [
            {
                "category": "performance",
                "severity": "low",
                "title": "Uncached lookup",
                "description": "Consider using @lru_cache on this function",
                "line_start": 5,
                "suggested_fix": "@lru_cache(maxsize=128)",
            }
        ],
        "growth_tips": [
            {
                "topic": "Caching",
                "advice": "Use functools.lru_cache for pure functions",
            }
        ],
        "model_used": "gemini-1.5-pro",
        "evaluation_latency_ms": 120.0,
    }

    mock_response.text = json.dumps(dummy_analysis)
    mock_client.models.generate_content.return_value = mock_response

    monkeypatch.setattr(engine, "_get_client", lambda: mock_client)

    result = await engine.analyze(
        code="def fetch_data(key): pass",
        language="python",
        filename="service.py",
    )

    assert result.overall_score == 88
    assert result.model_used == "gemini-1.5-pro"
    assert len(result.findings) == 1
    assert result.findings[0].category == FindingCategory.PERFORMANCE
    assert mock_client.models.generate_content.called


@pytest.mark.asyncio
async def test_gemini_review_engine_retries_and_fallback(monkeypatch):
    engine = GeminiReviewEngine()
    mock_client = MagicMock()

    # Simulate transient failures on all attempts
    mock_client.models.generate_content.side_effect = RuntimeError("ResourceExhausted quota error")
    monkeypatch.setattr(engine, "_get_client", lambda: mock_client)

    # Monkeypatch sleep to avoid slowing down tests
    import time
    monkeypatch.setattr(time, "sleep", lambda x: None)

    result = await engine.analyze(
        code="def test_fn(): eval('1+1')",
        language="python",
    )

    # Must fallback gracefully to mock heuristic engine
    assert "[Fallback Review]" in result.summary
    assert result.critical_count >= 1
