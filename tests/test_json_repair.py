import pytest
import json
from unittest.mock import MagicMock
from app.reviewer.engine import repair_truncated_json, GeminiReviewEngine
from app.reviewer.models import ReviewAnalysisResult, FindingSeverity, FindingCategory


def test_repair_already_valid_json():
    valid = '{"overall_score": 90, "summary": "Clean code", "findings": []}'
    repaired = repair_truncated_json(valid)
    assert repaired == valid
    parsed = json.loads(repaired)
    assert parsed["overall_score"] == 90


def test_repair_markdown_fenced_json():
    fenced = '```json\n{"overall_score": 85, "summary": "Solid"}\n```'
    repaired = repair_truncated_json(fenced)
    parsed = json.loads(repaired)
    assert parsed["overall_score"] == 85


def test_repair_user_exact_truncated_json():
    """Reproduces and verifies fix for the user's reported EOF while parsing a string error."""
    truncated = (
        '{\n'
        '  "overall_score": 70,\n'
        '  "summary": "Identified potential security risks",\n'
        '  "findings": [\n'
        '    {\n'
        '      "category": "security",\n'
        '      "severity": "critical",\n'
        '      "title": "Directory Traversal",\n'
        '      "description": "User supplied path joined unsafely",\n'
        '      "fix_explanation": "Moving'
    )
    repaired = repair_truncated_json(truncated)
    parsed = json.loads(repaired)
    assert parsed["overall_score"] == 70
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["fix_explanation"] == "Moving"
    # Verify Pydantic ReviewAnalysisResult deserialization succeeds
    res = ReviewAnalysisResult.model_validate_json(repaired)
    assert res.overall_score == 70
    assert len(res.findings) == 1
    assert res.findings[0].severity == FindingSeverity.CRITICAL


def test_repair_truncated_after_trailing_comma_or_key():
    truncated = (
        '{"overall_score": 80, "summary": "Good", "findings": ['
        '{"category": "bug", "severity": "high", "title": "Off by one", "description": "Index out of range"},'
    )
    repaired = repair_truncated_json(truncated)
    parsed = json.loads(repaired)
    assert parsed["overall_score"] == 80
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["title"] == "Off by one"


def test_repair_truncated_mid_unclosed_key():
    truncated = (
        '{"overall_score": 88, "summary": "Fast", "findings": ['
        '{"category": "performance", "severity": "medium", "title": "Cache", "description": "Slow query", '
        '"suggested_fix":'
    )
    repaired = repair_truncated_json(truncated)
    parsed = json.loads(repaired)
    assert parsed["overall_score"] == 88
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["title"] == "Cache"


@pytest.mark.asyncio
async def test_gemini_review_engine_survives_truncated_json(monkeypatch):
    """Verify GeminiReviewEngine repairs truncated JSON from upstream model without falling back to mock."""
    engine = GeminiReviewEngine()
    mock_client = MagicMock()
    mock_resp = MagicMock()

    # Truncated response directly from upstream model
    mock_resp.text = (
        '{\n'
        '  "overall_score": 75,\n'
        '  "summary": "Upstream model truncated output",\n'
        '  "findings": [\n'
        '    {\n'
        '      "category": "security",\n'
        '      "severity": "high",\n'
        '      "title": "Insecure Secret",\n'
        '      "description": "Hardcoded secret in source",\n'
        '      "fix_explanation": "Moving to environment'
    )
    mock_client.models.generate_content.return_value = mock_resp
    monkeypatch.setattr(engine, "_get_client", lambda: mock_client)

    result = await engine.analyze(
        code="token = 'xyz123'",
        language="python",
        filename="auth.py",
    )

    # Must NOT fail into [Fallback Review]
    assert "[Fallback Review]" not in result.summary
    assert result.overall_score == 75
    assert len(result.findings) == 1
    assert result.findings[0].title == "Insecure Secret"
    assert result.findings[0].fix_explanation == "Moving to environment"

