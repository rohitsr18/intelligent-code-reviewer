#!/usr/bin/env python3
"""Automated Pull Request and Pre-Push Code Review Bot.

Analyzes Git diffs using the Intelligent Code Reviewer engine or live Cloud Run API,
enforces security guardrails (blocking on critical credentials/vulnerabilities),
and formats structured Markdown review comments for GitHub Pull Requests.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple, Any

import httpx
from app.security.sanitizer import CodeSanitizer
from app.reviewer.models import FindingSeverity


def get_git_diff(base_ref: Optional[str] = None, staged_only: bool = False) -> str:
    """Retrieves Git diff for analysis.
    
    In PR mode: compares against base_ref (e.g. origin/main).
    In pre-push mode: inspects outgoing unpushed commits or staged files.
    """
    cmd = ["git", "diff"]
    if staged_only:
        cmd.append("--cached")
    elif base_ref:
        cmd.extend([f"{base_ref}...HEAD"])
    else:
        # Default: compare against tracking remote or HEAD~1
        try:
            upstream = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            cmd.extend([f"{upstream}..HEAD"])
        except Exception:
            cmd.extend(["HEAD~1..HEAD"])

    try:
        diff_output = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
        return diff_output.strip()
    except subprocess.CalledProcessError as e:
        sys.stderr.write(f"Warning: Failed to execute git diff: {e.stderr}\n")
        return ""


def detect_language_from_diff(diff_text: str) -> str:
    """Infers primary language from file paths in the git diff."""
    extension_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".java": "java",
        ".rs": "rust",
        ".cpp": "cpp",
        ".c": "c",
        ".sql": "sql",
        "dockerfile": "dockerfile",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".sh": "shell",
    }
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            filename = line[6:].strip().lower()
            for ext, lang in extension_map.items():
                if filename.endswith(ext):
                    return lang
    return "python"


def analyze_diff_remotely(
    service_url: str,
    diff_text: str,
    language: str,
    repo_name: str,
    auth_email: str = "accounts.google.com:ci-bot@company.com",
    timeout: float = 30.0,
) -> Optional[Dict[str, Any]]:
    """Calls the deployed Cloud Run Intelligent Code Reviewer service."""
    endpoint = f"{service_url.rstrip('/')}/api/v1/review/submit"
    payload = {
        "code": diff_text,
        "language": language,
        "filename": "pull_request.diff",
        "repo_name": repo_name,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Goog-Authenticated-User-Email": auth_email,
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(endpoint, json=payload, headers=headers)
            if resp.status_code == 201:
                return resp.json()
            sys.stderr.write(f"Remote review returned HTTP {resp.status_code}: {resp.text}\n")
            return None
    except Exception as e:
        sys.stderr.write(f"Could not reach remote review service: {e}\n")
        return None


def analyze_diff_locally(diff_text: str, language: str) -> Dict[str, Any]:
    """Fallback offline analyzer when Cloud Run service is unreachable."""
    sanitizer = CodeSanitizer()
    sanitized_res = sanitizer.sanitize(diff_text)
    redactions = sanitized_res.redactions
    
    findings = []
    # Identify obvious critical leaks
    for r in redactions:
        findings.append({
            "category": "security",
            "severity": "critical",
            "title": f"Sensitive {r.secret_type} Detected",
            "description": f"Diff contains sensitive {r.secret_type} at line {r.line_number}. Secret was masked to prevent leakage.",
            "suggested_fix": "# Store credentials in Secret Manager, never in source code.",
            "line_start": r.line_number,
        })

    # Basic heuristic check for eval/exec in added lines
    for idx, line in enumerate(diff_text.splitlines(), start=1):
        if line.startswith("+") and not line.startswith("+++"):
            code_line = line[1:].strip()
            if "eval(" in code_line or "exec(" in code_line:
                findings.append({
                    "category": "security",
                    "severity": "high",
                    "title": "Arbitrary Code Execution Risk",
                    "description": "Dynamic execution via eval() or exec() detected in added lines.",
                    "suggested_fix": "Use safe parsing (e.g. ast.literal_eval or json.loads).",
                    "line_start": idx,
                })

    has_critical = any(f["severity"] == "critical" for f in findings)
    overall_score = 45 if has_critical else 90 if not findings else 75

    return {
        "review_id": "local-ci-eval",
        "redactions_count": len(redactions),
        "redactions": [{"secret_type": r.secret_type, "line_number": r.line_number} for r in redactions],
        "analysis": {
            "overall_score": overall_score,
            "summary": "Automated code review completed.",
            "findings": findings,
            "growth_tips": [
                {
                    "topic": "Zero Secret Commits",
                    "advice": "Use pre-commit hooks or Secret Manager to keep credentials out of version control.",
                    "learning_resource": "https://cloud.google.com/secret-manager/docs",
                }
            ],
            "model_used": "local-security-analyzer",
        },
    }


def format_markdown_pr_comment(review_data: Dict[str, Any]) -> str:
    """Formats review findings as a clean GitHub PR markdown comment."""
    analysis = review_data.get("analysis", {})
    score = analysis.get("overall_score", 0)
    findings = analysis.get("findings", [])
    redactions_count = review_data.get("redactions_count", 0)
    model_used = analysis.get("model_used", "intelligent-code-reviewer")

    status_icon = "🟢" if score >= 85 else "🟡" if score >= 70 else "🔴"
    status_label = "Approved / High Quality" if score >= 85 else "Needs Improvements" if score >= 70 else "Blocked (Critical Issues)"

    md = [
        "## 🤖 24/7 Intelligent Code Reviewer Report",
        "",
        f"**Quality Score:** {status_icon} **`{score}/100`** ({status_label})  ",
        f"**Engine:** `{model_used}`",
        "",
    ]

    # Pre-LLM DLP alert
    if redactions_count > 0:
        md.extend([
            "> [!CAUTION]",
            f"> **Pre-LLM Data Leak Prevention Alert:** Detected and masked **{redactions_count} sensitive credentials** in this diff before external evaluation.",
            "",
        ])

    # Executive Summary
    summary = analysis.get("summary", "Analysis completed.")
    md.extend([
        "### 📋 Summary",
        summary,
        "",
    ])

    # Findings
    if findings:
        md.extend([
            f"### 🔍 Detailed Findings ({len(findings)})",
            "",
        ])
        for f in findings:
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Notice")
            desc = f.get("description", "")
            fix = f.get("suggested_fix")
            line = f.get("line_start")
            loc_str = f" `Line {line}`" if line else ""

            badge = "🚨" if sev == "CRITICAL" else "⚠️" if sev in ("HIGH", "MEDIUM") else "ℹ️"
            md.append(f"#### {badge} [{sev}] {title}{loc_str}")
            md.append(desc)
            if fix:
                md.append("")
                md.append("```suggestion")
                md.append(fix)
                md.append("```")
            md.append("")
    else:
        md.extend([
            "### ✅ No Critical Defects Found",
            "This change adheres to code quality and security standards.",
            "",
        ])

    # Growth Tips
    growth_tips = analysis.get("growth_tips", [])
    if growth_tips:
        md.append("### 💡 Developer Growth & Best Practices")
        for tip in growth_tips:
            topic = tip.get("topic", "Best Practice")
            advice = tip.get("advice", "")
            link = tip.get("learning_resource")
            link_md = f" ([Reference Guide]({link}))" if link else ""
            md.append(f"- **{topic}**: {advice}{link_md}")
        md.append("")

    md.append("---")
    md.append("*Powered by Google Cloud Run & Vertex AI Intelligent Code Reviewer*")
    return "\n".join(md)


def post_github_pr_comment(comment_body: str) -> bool:
    """Posts or updates comment on current Pull Request via GitHub Actions REST API."""
    github_token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if not github_token or not event_path or not os.path.exists(event_path):
        return False

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)

        comments_url = event_data.get("pull_request", {}).get("comments_url")
        if not comments_url:
            return False

        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(comments_url, json={"body": comment_body}, headers=headers)
            return resp.status_code == 201
    except Exception as e:
        sys.stderr.write(f"Warning: Failed to post GitHub PR comment: {e}\n")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated Intelligent Code Reviewer Bot")
    parser.add_argument("--mode", choices=["pr", "pre-push", "local"], default="local", help="Review trigger mode")
    parser.add_argument("--base-ref", default="origin/main", help="Base git reference to diff against in PR mode")
    parser.add_argument("--service-url", default=os.environ.get("REVIEWER_SERVICE_URL", "https://code-reviewer-633952982144.us-central1.run.app"), help="Cloud Run Reviewer URL")
    parser.add_argument("--fail-on-critical", action="store_true", default=True, help="Exit with non-zero code if critical findings are found")
    args = parser.parse_args()

    # 1. Grab Git Diff
    staged = (args.mode == "pre-push")
    diff_text = get_git_diff(base_ref=args.base_ref if args.mode == "pr" else None, staged_only=staged)
    if not diff_text:
        print("ℹ️ No code changes detected in diff. Skipping review.")
        return 0

    language = detect_language_from_diff(diff_text)
    repo_name = os.environ.get("GITHUB_REPOSITORY", "intelligent-code-reviewer")

    print(f"🔍 Analyzing diff ({len(diff_text.splitlines())} lines, detected {language})...")

    # 2. Run Review (Remote service first, local fallback if unreachable)
    review_data = None
    if args.service_url:
        review_data = analyze_diff_remotely(args.service_url, diff_text, language, repo_name)
    if not review_data:
        review_data = analyze_diff_locally(diff_text, language)

    # 3. Format Comment
    markdown_comment = format_markdown_pr_comment(review_data)
    print("\n" + markdown_comment + "\n")

    # 4. If in GitHub Actions PR mode, post comment to PR
    if args.mode == "pr":
        posted = post_github_pr_comment(markdown_comment)
        if posted:
            print("✅ Successfully posted review comment to Pull Request.")

    # 5. Enforce Quality Gate
    analysis = review_data.get("analysis", {})
    findings = analysis.get("findings", [])
    has_critical = any(f.get("severity") in ("critical", "CRITICAL") for f in findings)

    if has_critical and args.fail_on_critical:
        sys.stderr.write("❌ Review Quality Gate Failed: Critical security or defect issues detected.\n")
        return 1

    print("✅ Quality Gate Passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
