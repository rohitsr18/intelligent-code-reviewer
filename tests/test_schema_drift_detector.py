"""Unit and integration tests for Schema & API Contract Drift Detector."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.reviewer.models import FindingSeverity
from app.reviewer.schema_drift_detector import SchemaContractDriftDetector


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def detector():
    return SchemaContractDriftDetector()


def test_detects_alembic_drop_column(detector):
    migration_code = """
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.drop_column('users', 'legacy_token')
"""
    report = detector.detect_drift(migration_code, filename="alembic/versions/001_drop.py")
    assert report.has_breaking_changes is True
    assert report.breaking_changes_count >= 1
    assert any(f.rule_id == "DRIFT-DB-DROP-COLUMN-001" for f in report.findings)
    assert report.drift_score < 70.0


def test_detects_alembic_drop_table(detector):
    migration_code = """
def upgrade():
    op.drop_table('legacy_sessions')
"""
    report = detector.detect_drift(migration_code, filename="migrations/drop_table.py")
    assert report.has_breaking_changes is True
    assert any(f.rule_id == "DRIFT-DB-DROP-TABLE-001" for f in report.findings)


def test_detects_not_null_without_server_default(detector):
    migration_code = """
def upgrade():
    op.add_column('orders', sa.Column('status_code', sa.String(20), nullable=False))
"""
    report = detector.detect_drift(migration_code, filename="migrations/002_add_status.py")
    assert report.has_breaking_changes is True
    assert any(f.rule_id == "DRIFT-DB-NOT-NULL-NO-DEFAULT-001" for f in report.findings)


def test_detects_column_rename_in_place(detector):
    migration_code = """
def upgrade():
    op.alter_column('accounts', 'user_email', new_column_name='email')
"""
    report = detector.detect_drift(migration_code, filename="alembic/versions/rename.py")
    assert report.has_breaking_changes is True
    assert any(f.rule_id == "DRIFT-DB-RENAME-COLUMN-001" for f in report.findings)


def test_detects_raw_sql_drop_statements(detector):
    sql_code = """
ALTER TABLE customers DROP COLUMN fax_number;
DROP TABLE deprecated_logs;
"""
    report = detector.detect_drift(sql_code, filename="schema.sql")
    assert report.has_breaking_changes is True
    rule_ids = [f.rule_id for f in report.findings]
    assert "DRIFT-DB-SQL-DROP-COLUMN-001" in rule_ids
    assert "DRIFT-DB-SQL-DROP-TABLE-001" in rule_ids


def test_detects_empty_migration_downgrade(detector):
    migration_code = """
def upgrade():
    op.create_table('audit_logs')

def downgrade():
    pass
"""
    report = detector.detect_drift(migration_code, filename="alembic/versions/004_logs.py")
    assert any(f.rule_id == "DRIFT-DB-EMPTY-DOWNGRADE-001" for f in report.findings)


def test_detects_removed_api_endpoint(detector):
    diff = """diff --git a/app/api/v1/users.py b/app/api/v1/users.py
--- a/app/api/v1/users.py
+++ b/app/api/v1/users.py
@@ -20,4 +20,1 @@
-@router.get("/v1/users/{user_id}")
-def get_user(user_id: str):
-    return {"id": user_id}
+def internal_helper(): pass
"""
    report = detector.detect_drift(diff, filename="app/api/v1/users.py")
    assert report.has_breaking_changes is True
    assert any(f.rule_id == "DRIFT-API-ROUTE-REMOVED-001" for f in report.findings)


def test_detects_api_schema_breaking_changes(detector):
    diff = """diff --git a/app/api/models.py b/app/api/models.py
--- a/app/api/models.py
+++ b/app/api/models.py
@@ -10,3 +10,4 @@
 class UserProfile(BaseModel):
-    phone_number: str
-    age: int
+    age: str
+    organization_id: str
+    nickname: Optional[str] = None
"""
    report = detector.detect_drift(diff, filename="app/api/models.py")
    assert report.has_breaking_changes is True
    rule_ids = [f.rule_id for f in report.findings]

    # Removed field: phone_number
    assert "DRIFT-API-REMOVED-FIELD-001" in rule_ids
    # Type mutation: age int -> str
    assert "DRIFT-API-TYPE-MUTATION-001" in rule_ids
    # Newly added required field without default: organization_id
    assert "DRIFT-API-REQUIRED-FIELD-NO-DEFAULT-001" in rule_ids
    # Optional field nickname should NOT be flagged as breaking
    assert not any(f.title.endswith("'nickname'") for f in report.findings)


def test_clean_schema_has_high_score(detector):
    diff = """diff --git a/app/schemas.py b/app/schemas.py
--- a/app/schemas.py
+++ b/app/schemas.py
@@ -10,2 +10,3 @@
 class Settings(BaseModel):
     theme: str = "light"
+    auto_save: Optional[bool] = True
"""
    report = detector.detect_drift(diff, filename="app/schemas.py")
    assert report.has_breaking_changes is False
    assert report.drift_score == 100.0


def test_detect_contract_drift_api_endpoint(client):
    payload = {
        "code": "op.drop_column('invoices', 'amount_cents')",
        "filename": "alembic/versions/drop.py",
        "language": "python",
    }
    resp = client.post("/api/v1/review/detect-contract-drift", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["has_breaking_changes"] is True
    assert data["breaking_changes_count"] >= 1
    assert any(f["rule_id"] == "DRIFT-DB-DROP-COLUMN-001" for f in data["findings"])


def test_submit_code_integrates_contract_drift(client):
    breaking_diff = """diff --git a/app/api/v1/orders.py b/app/api/v1/orders.py
--- a/app/api/v1/orders.py
+++ b/app/api/v1/orders.py
@@ -10,2 +10,1 @@
-@router.delete("/orders/{order_id}")
+def internal_cancel(): pass
"""
    resp = client.post(
        "/api/v1/review/submit",
        json={
            "code": breaking_diff,
            "language": "python",
            "filename": "app/api/v1/orders.py",
        },
    )
    assert resp.status_code == 201
    data = resp.json()

    assert data["contract_drift_summary"] is not None
    assert data["contract_drift_summary"]["has_breaking_changes"] is True

    findings = data["analysis"]["findings"]
    assert any("DRIFT-API-ROUTE-REMOVED-001" in f["title"] for f in findings)
    # Architecture score calibrated down
    assert data["analysis"]["category_scores"]["architecture"] <= 75

    # Verify retrieval
    review_id = data["review_id"]
    get_resp = client.get(f"/api/v1/review/{review_id}")
    assert get_resp.status_code == 200
    detail = get_resp.json()
    assert detail["contract_drift_summary"] is not None
    assert detail["contract_drift_summary"]["has_breaking_changes"] is True

