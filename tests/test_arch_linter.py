"""Unit and integration tests for Repo Architectural Context & Clean Architecture Linter."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reviewer.arch_linter import RepoArchitecturalLinter
from app.reviewer.models import FindingSeverity


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def linter():
    return RepoArchitecturalLinter()


def test_detects_core_domain_import_violation(linter):
    core_code = """
import fastapi
from app.api.v1 import users

class UserDomainEntity:
    pass
"""
    report = linter.lint(core_code, filename="app/core/user_entity.py")
    assert report.is_compliant is False
    assert report.layer_violations_count >= 1
    assert any(f.rule_id == "ARCH-LAYER-CORE-IMPORT-001" for f in report.findings)


def test_detects_service_layer_web_import_violation(linter):
    service_code = """
from app.api.routers import billing_router

class BillingService:
    def process(self):
        pass
"""
    report = linter.lint(service_code, filename="app/services/billing.py")
    assert report.is_compliant is False
    assert any(f.rule_id == "ARCH-LAYER-SERVICE-WEB-IMPORT-001" for f in report.findings)


def test_clean_architecture_is_compliant(linter):
    clean_domain_code = """
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class Account:
    id: str
    balance: float
"""
    report = linter.lint(clean_domain_code, filename="app/domain/account.py")
    assert report.is_compliant is True
    assert report.overall_arch_score == 100.0
    assert len(report.findings) == 0


def test_detects_leaky_db_execution_in_controller(linter):
    controller_code = """
@router.get("/users")
async def get_users():
    cursor.execute("SELECT * FROM users WHERE active = 1")
    return cursor.fetchall()
"""
    report = linter.lint(controller_code, filename="app/api/v1/users.py")
    assert any(f.rule_id == "ARCH-LEAKY-DB-CONTROLLER-001" for f in report.findings)


def test_detects_circular_dependencies_in_diff(linter):
    diff = """diff --git a/app/services/order.py b/app/services/order.py
--- a/app/services/order.py
+++ b/app/services/order.py
@@ -1,2 +1,3 @@
+from app.services.inventory import check_stock
 def create_order(): pass

diff --git a/app/services/inventory.py b/app/services/inventory.py
--- a/app/services/inventory.py
+++ b/app/services/inventory.py
@@ -1,2 +1,3 @@
+from app.services.order import cancel_order
 def check_stock(): pass
"""
    report = linter.lint(diff)
    assert report.is_compliant is False
    assert report.circular_deps_count >= 1
    assert any(f.rule_id == "ARCH-CIRCULAR-IMPORT-001" for f in report.findings)


def test_detects_unsynchronized_shared_mutable_state(linter):
    code = """
session_cache = {}

def add_session(session_id, data):
    session_cache.update({session_id: data})
"""
    report = linter.lint(code, filename="app/services/auth_cache.py")
    assert any(f.rule_id == "ARCH-SHARED-MUTABLE-STATE-001" for f in report.findings)


def test_detects_god_object_anti_pattern(linter):
    methods = "\n".join(f"    def action_{i}(self): pass" for i in range(25))
    code = f"""
class EnterpriseManager:
{methods}
"""
    report = linter.lint(code, filename="app/services/manager.py")
    assert any(f.rule_id == "ARCH-ANTI-GOD-OBJECT-001" for f in report.findings)


def test_lint_architecture_api_endpoint(client):
    payload = {
        "code": "from fastapi import Request\n\nclass CoreEntity:\n    pass\n",
        "filename": "app/core/entity.py",
        "language": "python",
    }
    resp = client.post("/api/v1/review/lint-architecture", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_compliant"] is False
    assert data["layer_violations_count"] >= 1
    assert any(f["rule_id"] == "ARCH-LAYER-CORE-IMPORT-001" for f in data["findings"])


def test_submit_code_integrates_architecture_lint(client):
    violating_diff = """diff --git a/app/domain/user.py b/app/domain/user.py
--- a/app/domain/user.py
+++ b/app/domain/user.py
@@ -1,2 +1,3 @@
+from app.api.v1 import users_router
 class UserEntity: pass
"""
    resp = client.post(
        "/api/v1/review/submit",
        json={
            "code": violating_diff,
            "language": "python",
            "filename": "app/domain/user.py",
        },
    )
    assert resp.status_code == 201
    data = resp.json()

    assert data["architecture_lint_summary"] is not None
    assert data["architecture_lint_summary"]["is_compliant"] is False

    findings = data["analysis"]["findings"]
    assert any("ARCH-LAYER-CORE-IMPORT-001" in f["title"] for f in findings)
    # Architecture score calibrated down
    assert data["analysis"]["category_scores"]["architecture"] <= 75

    # Verify retrieval
    review_id = data["review_id"]
    get_resp = client.get(f"/api/v1/review/{review_id}")
    assert get_resp.status_code == 200
    detail = get_resp.json()
    assert detail["architecture_lint_summary"] is not None
    assert detail["architecture_lint_summary"]["is_compliant"] is False

