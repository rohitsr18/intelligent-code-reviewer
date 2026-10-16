"""Unit and integration tests for PR Intent Verification & Artifact Sweeper."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reviewer.intent_sweeper import IntentArtifactSweeper
from app.reviewer.models import FindingSeverity


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sweeper():
    return IntentArtifactSweeper()


def test_detects_python_breakpoint_and_pdb(sweeper):
    code = """
def process_data(records):
    for r in records:
        if not r.valid:
            breakpoint()
            import pdb; pdb.set_trace()
    return records
"""
    res = sweeper.sweep_artifacts(code, language="python", filename="processor.py")
    rule_ids = [f.rule_id for f in res]
    assert "ART-PY-BREAKPOINT-001" in rule_ids
    assert "ART-PY-PDB-001" in rule_ids
    bp = next(f for f in res if f.rule_id == "ART-PY-BREAKPOINT-001")
    assert bp.severity == FindingSeverity.CRITICAL
    assert bp.line_number == 5


def test_detects_production_print_and_exempts_tests_and_cli(sweeper):
    code = """
def compute_metrics(val):
    print("Debug metric:", val)
    return val * 2
"""
    # In production service file, print should be flagged
    res_prod = sweeper.sweep_artifacts(code, language="python", filename="app/services/metrics.py")
    assert any(f.rule_id == "ART-DEBUG-PRINT-001" for f in res_prod)

    # In test or CLI scripts, print is acceptable
    res_test = sweeper.sweep_artifacts(code, language="python", filename="tests/test_metrics.py")
    assert not any(f.rule_id == "ART-DEBUG-PRINT-001" for f in res_test)

    res_cli = sweeper.sweep_artifacts(code, language="python", filename="cli/run.py")
    assert not any(f.rule_id == "ART-DEBUG-PRINT-001" for f in res_cli)


def test_detects_javascript_console_and_debugger(sweeper):
    js_code = """
function handleClick(event) {
    console.log("clicked", event);
    console.debug("event details", event.detail);
    debugger;
}
"""
    res = sweeper.sweep_artifacts(js_code, language="javascript", filename="Button.tsx")
    rule_ids = [f.rule_id for f in res]
    assert "ART-JS-CONSOLE-001" in rule_ids
    assert "ART-JS-DEBUGGER-001" in rule_ids


def test_detects_go_and_java_stray_prints(sweeper):
    go_code = """
package handler

import "fmt"

func Handle() {
    fmt.Println("debug handler")
}
"""
    res_go = sweeper.sweep_artifacts(go_code, language="go", filename="handler.go")
    assert any(f.rule_id == "ART-GO-PRINT-001" for f in res_go)

    java_code = """
public class Service {
    public void execute() {
        try {
            work();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("failed");
        }
    }
}
"""
    res_java = sweeper.sweep_artifacts(java_code, language="java", filename="Service.java")
    rule_ids = [f.rule_id for f in res_java]
    assert "ART-JAVA-PRINT-001" in rule_ids
    assert "ART-JAVA-STACKTRACE-001" in rule_ids


def test_detects_merge_conflict_markers(sweeper):
    code = """
def merge_logic():
<<<<<<< HEAD
    return 1
=======
    return 2
>>>>>>> branch-b
"""
    res = sweeper.sweep_artifacts(code, language="python", filename="merge.py")
    assert any(f.rule_id == "ART-GIT-CONFLICT-001" for f in res)


def test_detects_dev_scratch_tags(sweeper):
    code = """
# TODO: remove before production release
# TEMP: debug quick fix
# HACK: delete before merge
def temp_fix():
    pass
"""
    res = sweeper.sweep_artifacts(code, language="python", filename="fix.py")
    assert any(f.rule_id == "ART-DEV-TEMP-TAG-001" for f in res)


def test_intent_verification_detects_scope_drift(sweeper):
    diff = """diff --git a/app/auth/jwt_tokens.py b/app/auth/jwt_tokens.py
index 1234..5678 100644
--- a/app/auth/jwt_tokens.py
+++ b/app/auth/jwt_tokens.py
@@ -10,2 +10,3 @@
+def bypass_token_check(): pass
"""
    # Stated context is completely unrelated: UI styling
    context = "Update marketing banner button colors and css padding"
    report = sweeper.verify_intent(diff, context=context)

    assert report.scope_drift_detected is True
    assert report.is_aligned is False
    assert report.intent_alignment_score < 75.0
    assert any("jwt_tokens.py" in f for f in report.unintended_files)
    assert any("touches 'auth' domain" in r for r in report.drift_reasons)


def test_intent_verification_aligned(sweeper):
    diff = """diff --git a/app/auth/jwt_tokens.py b/app/auth/jwt_tokens.py
index 1234..5678 100644
--- a/app/auth/jwt_tokens.py
+++ b/app/auth/jwt_tokens.py
@@ -10,2 +10,3 @@
+def refresh_jwt_token(): pass
"""
    context = "Refresh expired authentication jwt tokens in auth service"
    report = sweeper.verify_intent(diff, context=context)

    assert report.scope_drift_detected is False
    assert report.is_aligned is True
    assert report.intent_alignment_score >= 80.0
    assert len(report.unintended_files) == 0


def test_intent_sweep_endpoint(client):
    payload = {
        "code": "def run():\n    breakpoint()\n    # TEMP: debug\n    return 42\n",
        "context": "Refactor runner execution logic",
        "language": "python",
        "filename": "runner.py",
    }
    resp = client.post("/api/v1/review/sweep-artifacts", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_artifacts_count"] >= 2
    rule_ids = [f["rule_id"] for f in data["artifact_findings"]]
    assert "ART-PY-BREAKPOINT-001" in rule_ids
    assert "ART-DEV-TEMP-TAG-001" in rule_ids


def test_submit_code_integrates_intent_and_artifacts(client):
    code_with_artifacts = """
def transfer_funds(account_from, account_to, amount):
    print("Transferring:", amount)
    breakpoint()
    return True
"""
    resp = client.post(
        "/api/v1/review/submit",
        json={
            "code": code_with_artifacts,
            "language": "python",
            "filename": "transfer.py",
            "context": "Implement transfer funds functionality",
        },
    )
    assert resp.status_code == 201
    data = resp.json()

    assert data["intent_audit_summary"] is not None
    assert data["intent_audit_summary"]["total_artifacts_count"] >= 2

    findings = data["analysis"]["findings"]
    assert any("ART-PY-BREAKPOINT-001" in f["title"] for f in findings)
    assert any("ART-DEBUG-PRINT-001" in f["title"] for f in findings)

    # Verify retrieval
    review_id = data["review_id"]
    get_resp = client.get(f"/api/v1/review/{review_id}")
    assert get_resp.status_code == 200
    detail = get_resp.json()
    assert detail["intent_audit_summary"] is not None
    assert detail["intent_audit_summary"]["total_artifacts_count"] >= 2
