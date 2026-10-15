import json
import os
from unittest.mock import patch, MagicMock
import pytest
from scripts.pr_review_bot import (
    detect_language_from_diff,
    format_markdown_pr_comment,
    analyze_diff_locally,
    analyze_diff_remotely,
    post_github_pr_comment,
    get_git_diff,
    main,
)


def test_detect_language_from_diff():
    py_diff = "+++ b/src/core/auth.py\n+def login(): pass"
    assert detect_language_from_diff(py_diff) == "python"

    ts_diff = "+++ b/web/src/App.tsx\n+const a = 1;"
    assert detect_language_from_diff(ts_diff) == "typescript"
    
    go_diff = "+++ b/pkg/server/main.go\n+package main"
    assert detect_language_from_diff(go_diff) == "go"

    sql_diff = "+++ b/migrations/001_init.sql\n+CREATE TABLE users;"
    assert detect_language_from_diff(sql_diff) == "sql"


def test_format_markdown_pr_comment_clean():
    clean_data = {
        "review_id": "test-123",
        "redactions_count": 0,
        "analysis": {
            "overall_score": 95,
            "summary": "Code looks clean and conforms to style.",
            "findings": [],
            "growth_tips": [
                {"topic": "Type Safety", "advice": "Use explicit return types.", "learning_resource": "https://example.com"}
            ],
            "model_used": "gemini-1.5-flash",
        },
    }
    comment = format_markdown_pr_comment(clean_data)
    assert "## 🤖 24/7 Intelligent Code Reviewer Report" in comment
    assert "**Quality Score:** 🟢 **`95/100`**" in comment
    assert "✅ No Critical Defects Found" in comment
    assert "Type Safety" in comment


def test_format_markdown_pr_comment_with_critical_issues():
    critical_data = {
        "review_id": "test-456",
        "redactions_count": 2,
        "analysis": {
            "overall_score": 40,
            "summary": "Critical vulnerabilities detected.",
            "findings": [
                {
                    "severity": "critical",
                    "title": "Hardcoded GitHub Token",
                    "description": "Exposed token in plaintext.",
                    "suggested_fix": "os.environ['GITHUB_TOKEN']",
                    "line_start": 12,
                }
            ],
            "growth_tips": [],
            "model_used": "gemini-1.5-flash",
        },
    }
    comment = format_markdown_pr_comment(critical_data)
    assert "**Quality Score:** 🔴 **`40/100`**" in comment
    assert "Pre-LLM Data Leak Prevention Alert" in comment
    assert "2 sensitive credentials" in comment
    assert "🚨 [CRITICAL] Hardcoded GitHub Token `Line 12`" in comment
    assert "os.environ['GITHUB_TOKEN']" in comment


def test_analyze_diff_locally_detects_credentials_and_eval():
    diff_with_flaws = """
--- a/app.py
+++ b/app.py
@@ -1,3 +1,6 @@
+def execute(query):
+    api_key = "ghp_1234567890abcdef1234567890abcdef1234"
+    return eval(query)
"""
    result = analyze_diff_locally(diff_with_flaws, "python")
    assert result["redactions_count"] >= 1
    analysis = result["analysis"]
    assert analysis["overall_score"] < 70
    titles = [f["title"] for f in analysis["findings"]]
    assert any("Sensitive GITHUB_TOKEN Detected" in t for t in titles)
    assert any("Arbitrary Code Execution Risk" in t for t in titles)


def test_analyze_diff_remotely_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"review_id": "remote-123", "analysis": {"overall_score": 90}}

    with patch("httpx.Client.post", return_value=mock_resp):
        res = analyze_diff_remotely("https://example.com", "code", "python", "repo")
        assert res is not None
        assert res["review_id"] == "remote-123"


def test_analyze_diff_remotely_failure_fallback():
    with patch("httpx.Client.post", side_effect=Exception("Connection refused")):
        res = analyze_diff_remotely("https://example.com", "code", "python", "repo")
        assert res is None


def test_post_github_pr_comment_success(tmp_path):
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({
        "pull_request": {
            "comments_url": "https://api.github.com/repos/owner/repo/issues/1/comments"
        }
    }))

    mock_resp = MagicMock()
    mock_resp.status_code = 201

    with patch.dict(os.environ, {
        "GITHUB_TOKEN": "mock-token",
        "GITHUB_EVENT_PATH": str(event_file),
    }):
        with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
            assert post_github_pr_comment("LGTM") is True
            mock_post.assert_called_once()


def test_post_github_pr_comment_missing_env():
    with patch.dict(os.environ, {}, clear=True):
        assert post_github_pr_comment("LGTM") is False


def test_main_cli_execution_clean_diff():
    clean_diff = "+++ b/main.py\n+def add(a, b): return a + b"
    with patch("scripts.pr_review_bot.get_git_diff", return_value=clean_diff):
        with patch("sys.argv", ["pr_review_bot.py", "--mode=local"]):
            code = main()
            assert code == 0


def test_main_cli_execution_fails_on_critical_diff():
    bad_diff = "+++ b/main.py\n+api_key = \"ghp_1234567890abcdef1234567890abcdef1234\""
    with patch("scripts.pr_review_bot.get_git_diff", return_value=bad_diff):
        with patch("sys.argv", ["pr_review_bot.py", "--mode=local", "--service-url="]):
            code = main()
            assert code == 1

