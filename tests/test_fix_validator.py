import pytest
from app.reviewer.fix_validator import FixValidator, FixValidationResult
from app.reviewer.models import ReviewFinding, FindingCategory, FindingSeverity
from app.reviewer.engine import MockReviewEngine


@pytest.fixture
def validator():
    return FixValidator()


def test_valid_python_fix_passes(validator: FixValidator):
    valid_snippet = """
def add(a: int, b: int) -> int:
    return a + b
"""
    res = validator.validate_fix(valid_snippet, language="python")
    assert res.is_valid is True
    assert res.syntax_confidence >= 0.95
    assert res.error_message is None


def test_invalid_python_syntax_fails(validator: FixValidator):
    broken_snippet = "def broken(a, b\n    return a + b"
    res = validator.validate_fix(broken_snippet, language="python")
    assert res.is_valid is False
    assert "Syntax" in res.error_message
    assert res.syntax_confidence <= 0.2


def test_unbalanced_delimiters_fails(validator: FixValidator):
    unbalanced = "const calculate = (x, y => { return x + y;"  # missing closing ) and }
    res = validator.validate_fix(unbalanced, language="javascript")
    assert res.is_valid is False
    assert "Unbalanced delimiters" in res.error_message


def test_indented_python_snippet_repaired(validator: FixValidator):
    # LLMs frequently output code intended to replace an indented body
    indented_snippet = "    for i, item in enumerate(items):\n        process(item)"
    res = validator.validate_fix(indented_snippet, language="python")
    assert res.is_valid is True
    assert res.cleaned_fix.startswith("for i, item")


def test_valid_and_invalid_json_syntax(validator: FixValidator):
    valid_json = '{"name": "code-reviewer", "status": "active"}'
    assert validator.validate_fix(valid_json, language="json").is_valid is True

    invalid_json = '{"name": "code-reviewer", status: active}'  # missing quotes
    assert validator.validate_fix(invalid_json, language="json").is_valid is False


def test_markdown_fence_stripping(validator: FixValidator):
    fenced = "```python\nx = 1\ny = 2\n```"
    res = validator.validate_fix(fenced, language="python")
    assert res.is_valid is True
    assert "```" not in res.cleaned_fix


def test_validate_and_sanitize_findings(validator: FixValidator):
    findings = [
        ReviewFinding(
            category=FindingCategory.PERFORMANCE,
            severity=FindingSeverity.LOW,
            title="Unidiomatic Loop",
            description="Use enumerate()",
            suggested_fix="for i, item in enumerate(items): pass",
        ),
        ReviewFinding(
            category=FindingCategory.SECURITY,
            severity=FindingSeverity.CRITICAL,
            title="Broken Logic",
            description="Syntax error in suggestion",
            suggested_fix="def wrong(:\n    pass",
        ),
    ]

    sanitized = validator.validate_and_sanitize_findings(findings, language="python")
    assert sanitized[0].is_fix_valid is True
    assert "enumerate" in sanitized[0].suggested_fix

    assert sanitized[1].is_fix_valid is False
    assert "Dry-Run Warning" in sanitized[1].suggested_fix
    assert sanitized[1].fix_validation_note is not None


@pytest.mark.asyncio
async def test_mock_engine_validates_fixes_end_to_end():
    engine = MockReviewEngine()
    code = "for i in range(len(collection)): print(i)"
    result = await engine.analyze(code=code, language="python")

    assert len(result.findings) >= 1
    perf_finding = next(f for f in result.findings if f.category == FindingCategory.PERFORMANCE)
    assert perf_finding.is_fix_valid is True
    assert "enumerate" in perf_finding.suggested_fix
