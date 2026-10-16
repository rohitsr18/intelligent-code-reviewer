"""Unit and integration tests for Test Health & Coverage Auditor."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reviewer.models import FindingSeverity
from app.reviewer.test_auditor import TestHealthAuditor


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auditor():
    return TestHealthAuditor()


def test_is_test_file_detection(auditor):
    assert auditor.is_test_file("tests/test_auth.py", "def test_login(): pass") is True
    assert auditor.is_test_file("src/utils_test.go", "func TestUtils(t *testing.T) {}") is True
    assert auditor.is_test_file("components/Button.spec.tsx", "it('renders', () => {})") is True
    assert auditor.is_test_file("app/main.py", "def start_server(): pass") is False


def test_predict_impacted_tests(auditor):
    py_tests = auditor.predict_impacted_tests("app/services/payment.py")
    assert "tests/test_payment.py" in py_tests

    ts_tests = auditor.predict_impacted_tests("src/utils/calculator.ts")
    assert any("calculator.test.ts" in t or "calculator.spec.ts" in t for t in ts_tests)

    go_tests = auditor.predict_impacted_tests("pkg/auth/token.go")
    assert "pkg/auth/token_test.go" in go_tests


def test_detects_tautology_assert_true(auditor):
    code = """
def test_something():
    x = 10
    assert True
"""
    res = auditor.audit_code(code, filename="test_something.py")
    assert res.total_test_cases == 1
    tautology = next(f for f in res.findings if f.rule_id == "TEST-TAUTOLOGY-001")
    assert tautology.severity == FindingSeverity.HIGH
    assert tautology.line_number == 4


def test_detects_self_comparing_tautology(auditor):
    code = """
def test_variable_comparison():
    value = compute()
    assert value == value
"""
    res = auditor.audit_code(code, filename="test_compare.py")
    assert any(f.rule_id == "TEST-TAUTOLOGY-002" for f in res.findings)


def test_detects_void_test_without_assertions(auditor):
    code = """
def test_unasserted_workflow():
    payload = {"data": 123}
    process_payload(payload)
    print("Done")
"""
    res = auditor.audit_code(code, filename="test_workflow.py")
    dead_test = next(f for f in res.findings if f.rule_id == "TEST-DEAD-001")
    assert dead_test.severity == FindingSeverity.HIGH
    assert dead_test.test_function == "test_unasserted_workflow"


def test_detects_flaky_hardcoded_sleep(auditor):
    code = """
import time

def test_async_job():
    trigger_job()
    time.sleep(5)
    assert check_job() is True
"""
    res = auditor.audit_code(code, filename="test_job.py")
    sleep_finding = next(f for f in res.findings if f.rule_id == "TEST-FLAKY-SLEEP-001")
    assert sleep_finding.severity == FindingSeverity.MEDIUM
    assert sleep_finding.line_number == 6


def test_detects_silent_exception_suppression(auditor):
    code = """
def test_database_operation():
    try:
        db.query("SELECT 1")
    except Exception:
        pass
    assert True
"""
    res = auditor.audit_code(code, filename="test_db.py")
    assert any(f.rule_id == "TEST-SILENT-EXCEPT-001" for f in res.findings)


def test_detects_missing_coverage_on_new_business_logic(auditor):
    code = """
class BillingService:
    def __init__(self, gateway):
        self.gateway = gateway

    def charge(self, user_id, amount):
        if amount <= 0:
            raise ValueError("Invalid amount")
        if not self.gateway.is_available():
            raise ConnectionError("Gateway unavailable")
        return self.gateway.process_payment(user_id, amount)
"""
    res = auditor.audit_code(code, filename="app/services/billing.py")
    assert res.is_test_file is False
    assert res.has_missing_coverage is True
    assert any(f.rule_id == "TEST-COV-001" for f in res.findings)


def test_multi_file_diff_missing_tests(auditor):
    diff = """diff --git a/app/api/checkout.py b/app/api/checkout.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/app/api/checkout.py
@@ -0,0 +1,15 @@
+def checkout_cart(cart):
+    return sum(cart.items)
"""
    res = auditor.audit_diff(diff)
    assert res.has_missing_coverage is True
    assert any(f.rule_id == "TEST-COV-002" for f in res.findings)


def test_multi_lang_javascript_flaky_patterns(auditor):
    js_test = """
describe('auth flow', () => {
    it('always passes', () => {
        expect(true).toBe(true);
        setTimeout(1000);
    });
});
"""
    res = auditor.audit_code(js_test, filename="auth.test.js")
    assert any(f.rule_id == "TEST-JS-TAUTOLOGY-001" for f in res.findings)
    assert any(f.rule_id == "TEST-JS-SLEEP-001" for f in res.findings)


def test_audit_tests_endpoint(client):
    payload = {
        "code": "def test_fake(): assert True",
        "filename": "test_fake.py",
        "language": "python",
    }
    resp = client.post("/api/v1/review/audit-tests", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_test_file"] is True
    assert data["total_test_cases"] == 1
    assert any(f["rule_id"] == "TEST-TAUTOLOGY-001" for f in data["findings"])


def test_submit_code_for_review_integrates_test_audit(client):
    code = """
def test_calc():
    assert True
"""
    resp = client.post(
        "/api/v1/review/submit",
        json={"code": code, "language": "python", "filename": "test_calc.py"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["test_audit_summary"] is not None
    assert data["test_audit_summary"]["is_test_file"] is True
    assert any("TEST-TAUTOLOGY-001" in f["title"] for f in data["analysis"]["findings"])
