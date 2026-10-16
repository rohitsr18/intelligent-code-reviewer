import pytest
from datetime import datetime, timezone
from app.analytics.models import (
    HistoricalRule,
    ReviewAnalyticsEvent,
    RuleCategory,
    RuleSeverity,
)
from app.analytics.client import InMemoryBigQueryBackend, ProductionBigQueryBackend
from app.analytics.schemas import (
    HISTORICAL_RULES_SCHEMA,
    REVIEW_EVENTS_SCHEMA,
    REVIEW_EVENTS_PARTITION_FIELD,
    REVIEW_EVENTS_CLUSTERING_FIELDS,
)
from app.reviewer.models import (
    ReviewAnalysisResult,
    ReviewFinding,
    FindingCategory,
    FindingSeverity,
)
from app.analytics.service import HistoricalLearningService


@pytest.mark.asyncio
async def test_in_memory_backend_rules_crud():
    backend = InMemoryBigQueryBackend(seed=False)

    rules = [
        HistoricalRule(
            rule_id="RULE-PY-01",
            title="Python Specific Rule",
            language="python",
            category=RuleCategory.BUG,
            severity=RuleSeverity.HIGH,
            pattern_or_anti_pattern="pattern",
            guidance="guidance",
        ),
        HistoricalRule(
            rule_id="RULE-GEN-01",
            title="General Rule",
            language="all",
            category=RuleCategory.SECURITY,
            severity=RuleSeverity.CRITICAL,
            pattern_or_anti_pattern="pattern",
            guidance="guidance",
        ),
    ]

    saved = await backend.insert_rules(rules)
    assert saved == 2

    # Query for Python -> should match both Python and All
    py_rules = await backend.get_active_rules(language="python")
    rule_ids = {r.rule_id for r in py_rules}
    assert "RULE-PY-01" in rule_ids
    assert "RULE-GEN-01" in rule_ids

    # Query for TypeScript -> should only match All
    ts_rules = await backend.get_active_rules(language="typescript")
    assert len(ts_rules) == 1
    assert ts_rules[0].rule_id == "RULE-GEN-01"


@pytest.mark.asyncio
async def test_analytics_event_recording():
    backend = InMemoryBigQueryBackend(seed=False)
    service = HistoricalLearningService(backend=backend)

    analysis = ReviewAnalysisResult(
        overall_score=85,
        summary="Good structure with one security finding.",
        category_scores={"security": 70, "bugs": 95},
        findings=[
            ReviewFinding(
                category=FindingCategory.SECURITY,
                severity=FindingSeverity.CRITICAL,
                title="SQL Injection",
                description="Raw string concat",
                rule_id="SEC-002",
            )
        ],
        model_used="gemini-3.8-flash",
        evaluation_latency_ms=350.5,
    )

    event = await service.record_review_event(
        review_id="rev-1234",
        user_id="user-999",
        user_email="engineer@company.com",
        language="python",
        filename="auth_service.py",
        original_line_count=120,
        sanitized_secrets_count=1,
        prompt_risk_score=0.1,
        review_status="accepted",
        analysis=analysis,
        rules_applied_count=4,
    )

    assert event.review_id == "rev-1234"
    assert event.findings_critical == 1
    assert event.total_findings == 1
    assert event.rules_applied_count == 4

    # Verify BigQuery row conversion
    bq_row = event.to_bigquery_row()
    assert bq_row["review_id"] == "rev-1234"
    assert bq_row["user_id"] == "user-999"
    assert bq_row["language"] == "python"
    assert bq_row["findings_critical"] == 1

    # Verify retrieval
    stored = await service.get_user_events(user_id="user-999")
    assert len(stored) == 1
    assert stored[0]["review_id"] == "rev-1234"


def test_schema_partitioning_and_clustering_definitions():
    assert REVIEW_EVENTS_PARTITION_FIELD == "timestamp"
    assert REVIEW_EVENTS_CLUSTERING_FIELDS == ["user_id", "language"]
    assert len(HISTORICAL_RULES_SCHEMA) > 0
    assert len(REVIEW_EVENTS_SCHEMA) > 0

    field_names = [f.name for f in REVIEW_EVENTS_SCHEMA]
    assert "review_id" in field_names
    assert "user_id" in field_names
    assert "timestamp" in field_names
    assert "language" in field_names
    assert "findings_critical" in field_names


@pytest.mark.asyncio
async def test_production_backend_fallback_without_credentials():
    backend = ProductionBigQueryBackend()
    # When credentials are dummy/unavailable, calls seamlessly route to fallback
    active_rules = await backend.get_active_rules(language="python")
    assert len(active_rules) > 0  # Default seed rules

