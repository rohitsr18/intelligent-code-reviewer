import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.reviewer.models import FindingCategory, FindingSeverity
from app.reviewer.batch_engine import BatchReviewEngine, FileDiffUnit
from app.reviewer.engine import MockReviewEngine
from scripts.pr_review_bot import format_markdown_pr_comment


def test_language_detection():
    engine = BatchReviewEngine()
    assert engine.detect_language("main.py") == "python"
    assert engine.detect_language("service.ts") == "typescript"
    assert engine.detect_language("app.jsx") == "javascript"
    assert engine.detect_language("handler.go") == "go"
    assert engine.detect_language("README.md") == "python" or engine.detect_language("README.md") in ("python", "markdown")


def test_classify_file_unit_fast_path():
    engine = BatchReviewEngine()

    # Documentation is fast-pathed
    is_fast, reason = engine.classify_file_unit("docs/guide.md", "+# New Documentation\n+Some details.")
    assert is_fast is True
    assert "Documentation" in reason

    # Lightweight config changes are fast-pathed
    is_fast_cfg, reason_cfg = engine.classify_file_unit("config.yaml", "+timeout: 30\n+retries: 3\n")
    assert is_fast_cfg is True
    assert "configuration" in reason_cfg.lower()

    # Micro patch (< 4 added lines without risk keywords) is fast-pathed
    is_fast_micro, reason_micro = engine.classify_file_unit("utils.py", "+# Add comment\n+x = 1\n")
    assert is_fast_micro is True
    assert "Micro patch" in reason_micro

    # Logic change with functions or security risk is NOT fast-pathed
    complex_code = (
        "+def authenticate_user(user, password):\n"
        "+    return verify(password)\n"
    )
    is_fast_logic, _ = engine.classify_file_unit("auth.py", complex_code)
    assert is_fast_logic is False


def test_split_diff_into_units_and_pruning():
    raw_diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,3 +1,4 @@\n"
        "+# Updated Documentation\n"
        "diff --git a/package-lock.json b/package-lock.json\n"
        "--- a/package-lock.json\n"
        "+++ b/package-lock.json\n"
        "@@ -1,5 +1,10 @@\n"
        "+  \"version\": \"1.0.0\"\n"
        "diff --git a/app/worker.py b/app/worker.py\n"
        "--- a/app/worker.py\n"
        "+++ b/app/worker.py\n"
        "@@ -10,3 +10,6 @@\n"
        "+def run_task():\n"
        "+    pass\n"
    )

    engine = BatchReviewEngine()
    units = engine.split_diff_into_units(raw_diff)

    filenames = [u.filename for u in units]
    # package-lock.json should be pruned automatically!
    assert "docs/README.md" in filenames
    assert "app/worker.py" in filenames
    assert "package-lock.json" not in filenames
    assert len(units) == 2


@pytest.mark.asyncio
async def test_fast_path_evaluation():
    engine = BatchReviewEngine()
    unit = FileDiffUnit(
        filename="docs/index.md",
        diff_content="+[Click here]() to learn more.\n",
        language="markdown",
        line_count=1,
        is_fast_path=True,
        fast_path_reason="Documentation file",
    )
    res = await engine._evaluate_fast_path(unit)
    assert res.overall_score < 95
    assert len(res.findings) == 1
    assert res.findings[0].title == "Empty Markdown Link Target"
    assert res.fast_path_files_count == 1


@pytest.mark.asyncio
async def test_analyze_diff_parallel_mock():
    mock_engine = MockReviewEngine()
    batch_engine = BatchReviewEngine(engine=mock_engine, max_concurrency=4)

    multi_diff = (
        "diff --git a/docs/CHANGELOG.md b/docs/CHANGELOG.md\n"
        "--- a/docs/CHANGELOG.md\n"
        "+++ b/docs/CHANGELOG.md\n"
        "@@ -1,2 +1,3 @@\n"
        "+- Added new security features\n"
        "diff --git a/src/service.py b/src/service.py\n"
        "--- a/src/service.py\n"
        "+++ b/src/service.py\n"
        "@@ -5,3 +5,6 @@\n"
        "+try:\n"
        "+    do_work()\n"
        "+except Exception:\n"
        "+    pass\n"
    )

    result = await batch_engine.analyze_diff_parallel(multi_diff)
    assert result.total_files_reviewed == 2
    assert result.fast_path_files_count >= 1
    assert result.parallel_speedup_factor is not None
    assert len(result.findings) >= 1
    # Check filename prefixing on finding titles
    assert any("[src/service.py]" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_api_review_endpoint_integrates_batch_parallel():
    multi_diff = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,2 +1,3 @@\n"
        "+# Intelligent Code Reviewer\n"
        "diff --git a/app/core.py b/app/core.py\n"
        "--- a/app/core.py\n"
        "+++ b/app/core.py\n"
        "@@ -1,2 +1,5 @@\n"
        "+for i in range(len(items)):\n"
        "+    pass\n"
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/review/submit",
            json={
                "code": multi_diff,
                "language": "python",
                "filename": "pull_request.diff",
                "repo_name": "enterprise-repo",
            },
            headers={"X-Goog-Authenticated-User-Email": "dev@corp.internal"},
        )
        assert resp.status_code == 201
        data = resp.json()
        analysis = data["analysis"]
        assert analysis["total_files_reviewed"] == 2
        assert analysis["fast_path_files_count"] >= 1


def test_pr_bot_renders_parallel_speedup_tip():
    review_data = {
        "analysis": {
            "overall_score": 92,
            "summary": "Multi-file review completed.",
            "findings": [],
            "total_files_reviewed": 5,
            "fast_path_files_count": 2,
            "parallel_speedup_factor": 3.4,
        }
    }

    markdown = format_markdown_pr_comment(review_data)
    assert "Parallel Review & Fast-Path Triage" in markdown
    assert "5 files concurrently" in markdown
    assert "~3.4x throughput speedup" in markdown
