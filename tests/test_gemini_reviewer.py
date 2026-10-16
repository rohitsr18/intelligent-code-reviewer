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
from app.reviewer.engine import (
    MockReviewEngine,
    GeminiReviewEngine,
    is_valid_gemini_model,
    VALID_STABLE_GEMINI_MODELS,
    is_gemini_35_plus,
    SUPPORTED_GEMINI_35_PLUS_MODELS,
)


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
        model_used="gemini-3.8-flash",
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
        "model_used": "gemini-3.8-flash",
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
    assert result.model_used == "gemini-3.8-flash"
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


def test_gemini_review_engine_client_init_with_api_key(monkeypatch):
    """Verify that GEMINI_API_KEY initializes direct Google AI Studio client."""
    from unittest.mock import patch

    with patch("google.genai.Client") as mock_genai_client:
        monkeypatch.setenv("GEMINI_API_KEY", "test-api-key-12345")
        engine = GeminiReviewEngine()
        engine.settings.gemini_api_key = "test-api-key-12345"
        client = engine._get_client()

        assert client is not None
        mock_genai_client.assert_called_once_with(api_key="test-api-key-12345")


@pytest.mark.asyncio
async def test_gemini_review_engine_model_fallback_on_404(monkeypatch):
    """Verify that 404 on primary model triggers fallback to next candidate model."""
    engine = GeminiReviewEngine()
    engine.settings.gemini_model = "gemini-3.8-flash"
    mock_client = MagicMock()

    calls = []

    def mock_generate_content(model, contents, config):
        calls.append(model)
        if model == "gemini-3.8-flash":
            raise RuntimeError("404 NOT_FOUND. Publisher model gemini-3.8-flash was not found")
        # Fallback model succeeds
        mock_resp = MagicMock()
        mock_resp.text = json.dumps({
            "overall_score": 92,
            "summary": f"Reviewed using {model}",
            "category_scores": {"bugs": 95, "security": 90},
            "findings": [],
            "growth_tips": [],
            "model_used": model,
        })
        return mock_resp

    mock_client.models.generate_content.side_effect = mock_generate_content
    monkeypatch.setattr(engine, "_get_client", lambda: mock_client)

    result = await engine.analyze(
        code="def hello(): return 'world'",
        language="python",
    )

    assert "gemini-3.8-flash" in calls
    assert len(calls) >= 2  # Tried primary, then tried fallback model
    assert calls[0] == "gemini-3.8-flash"
    assert calls[1] == "gemini-3.6-flash"
    for m in calls:
        assert is_valid_gemini_model(m) is True
    # Ensure non-existent model gemini-3.5-pro is NEVER queried
    assert "gemini-3.5-pro" not in calls
    assert result.overall_score == 92
    assert "[Fallback Review]" not in result.summary


@pytest.mark.asyncio
async def test_deterministic_review_cache_returns_identical_result(monkeypatch):
    """Verify that identical code inputs return 100% identical findings and scores via cache."""
    from app.reviewer.engine import ReviewDeterministicCache, GeminiReviewEngine

    cache = ReviewDeterministicCache(capacity=10)
    engine = GeminiReviewEngine()
    engine.cache = cache

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = json.dumps({
        "overall_score": 87,
        "summary": "Deterministic code review analysis",
        "category_scores": {"bugs": 90, "security": 85},
        "findings": [
            {
                "category": "security",
                "severity": "high",
                "title": "Insecure Randomness",
                "description": "Use secrets instead of random",
                "line_start": 3,
                "suggested_fix": "import secrets",
            }
        ],
        "growth_tips": [],
        "model_used": "gemini-3.8-flash",
    })
    mock_client.models.generate_content.return_value = mock_resp
    monkeypatch.setattr(engine, "_get_client", lambda: mock_client)

    sample_code = "import random\ndef token(): return random.randint(1, 100)"

    # First analysis (cache miss)
    result1 = await engine.analyze(code=sample_code, language="python", filename="auth.py")
    assert mock_client.models.generate_content.call_count == 1

    # Second analysis (cache hit)
    result2 = await engine.analyze(code=sample_code, language="python", filename="auth.py")
    # Underlying LLM generate_content must NOT be called again
    assert mock_client.models.generate_content.call_count == 1

    # Both findings and scores must be 100% identical
    assert result1.overall_score == result2.overall_score == 87
    assert len(result1.findings) == len(result2.findings) == 1
    assert result1.findings[0].title == result2.findings[0].title
    assert result1.category_scores == result2.category_scores


def test_canonicalize_review_result_dedup_and_sorting():
    """Verify that findings are deduplicated and canonically sorted by severity and line."""
    from app.reviewer.engine import canonicalize_review_result

    raw = ReviewAnalysisResult(
        overall_score=75,
        summary="Test findings",
        findings=[
            ReviewFinding(
                category=FindingCategory.STYLE,
                severity=FindingSeverity.LOW,
                title="Naming convention",
                description="Use snake_case",
                line_start=15,
            ),
            ReviewFinding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="SQL Injection",
                description="Unsanitized input in SQL",
                line_start=20,
            ),
            # Duplicate of the SQL Injection
            ReviewFinding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="SQL Injection",
                description="Unsanitized input in SQL",
                line_start=20,
            ),
            ReviewFinding(
                category=FindingCategory.BUG,
                severity=FindingSeverity.HIGH,
                title="Null Dereference",
                description="Object may be null",
                line_start=5,
            ),
        ],
        style_nits=[],
    )

    canonical = canonicalize_review_result(raw)

    # 1. Duplicates stripped: 4 findings -> 3 findings
    assert len(canonical.findings) == 3

    # 2. Sorted by Severity: CRITICAL first, then HIGH, then LOW
    assert canonical.findings[0].severity == FindingSeverity.CRITICAL
    assert canonical.findings[0].title == "SQL Injection"
    assert canonical.findings[1].severity == FindingSeverity.HIGH
    assert canonical.findings[1].title == "Null Dereference"
    assert canonical.findings[2].severity == FindingSeverity.LOW
    assert canonical.findings[2].title == "Naming convention"


def test_valid_stable_gemini_model_filter():
    """Verify is_valid_gemini_model identifies only valid, officially released models."""
    from app.reviewer.engine import is_valid_gemini_model

    # Valid and officially released stable models from https://ai.google.dev/gemini-api/docs/models
    assert is_valid_gemini_model("gemini-3.8-flash") is True
    assert is_valid_gemini_model("gemini-3.6-flash") is True
    assert is_valid_gemini_model("gemini-3.5-flash-lite") is True
    assert is_valid_gemini_model("gemini-2.5-flash") is True
    assert is_valid_gemini_model("gemini-2.5-pro") is True
    assert is_valid_gemini_model("publishers/google/models/gemini-3.8-flash") is True

    # Hallucinated or unreleased models must be rejected
    assert is_valid_gemini_model("gemini-3.5-pro") is False
    assert is_valid_gemini_model("gemini-3.5-flash") is False
    assert is_valid_gemini_model(None) is False
    assert is_valid_gemini_model("") is False
    assert is_valid_gemini_model("claude-3-opus") is False


def test_gemini_config_handles_unreleased_models():
    """Verify Settings defaults invalid/unreleased models safely to gemini-3.8-flash."""
    from app.core.config import Settings

    # Valid models preserved
    s1 = Settings(gemini_model="gemini-3.8-flash")
    assert s1.gemini_model == "gemini-3.8-flash"
    s2 = Settings(gemini_model="gemini-3.6-flash")
    assert s2.gemini_model == "gemini-3.6-flash"
    s3 = Settings(gemini_model="gemini-2.5-flash")
    assert s3.gemini_model == "gemini-2.5-flash"

    # Fictitious or unreleased models (e.g. 3.5-pro) automatically fall back to gemini-3.8-flash
    s_fictitious1 = Settings(gemini_model="gemini-3.5-pro")
    assert s_fictitious1.gemini_model == "gemini-3.8-flash"

    s_fictitious2 = Settings(gemini_model="gemini-3.5-flash")
    assert s_fictitious2.gemini_model == "gemini-3.8-flash"


@pytest.mark.asyncio
async def test_gemini_engine_sanitizes_unreleased_models(monkeypatch):
    """Verify GeminiReviewEngine ignores any forced unreleased model and defaults to gemini-3.8-flash."""
    from app.reviewer.engine import GeminiReviewEngine

    engine = GeminiReviewEngine()
    engine.settings.gemini_api_key = "dummy-key"
    object.__setattr__(engine.settings, "gemini_model", "gemini-3.5-pro")

    mock_client = MagicMock()
    called_models = []

    def mock_generate_content(model, contents, config):
        called_models.append(model)
        mock_resp = MagicMock()
        mock_resp.text = json.dumps({
            "overall_score": 90,
            "summary": "OK",
            "category_scores": {"bugs": 90},
            "findings": [],
            "growth_tips": [],
            "model_used": model,
        })
        return mock_resp

    mock_client.models.generate_content.side_effect = mock_generate_content
    monkeypatch.setattr(engine, "_get_client", lambda: mock_client)

    result = await engine.analyze(code="print('test')", language="python")

    assert "gemini-3.5-pro" not in called_models
    assert called_models[0] == "gemini-3.8-flash"
    assert result.model_used == "gemini-3.8-flash"



