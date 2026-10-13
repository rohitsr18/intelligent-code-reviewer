import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from app.core.config import get_settings
from app.analytics.models import HistoricalRule, ReviewAnalyticsEvent, RuleCategory, RuleSeverity

logger = logging.getLogger(__name__)


# Built-in seed rules for instant out-of-the-box rule enforcement
DEFAULT_SEED_RULES = [
    HistoricalRule(
        rule_id="SEC-001",
        title="Disallow Dynamic Code Execution",
        language="all",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        pattern_or_anti_pattern="Direct use of eval(), exec(), or Function() constructor with untrusted input.",
        guidance="Use deterministic parsing, AST node validation, or structured lookups instead of dynamic evaluation.",
        tags=["security", "cwe-95", "injection"],
        is_active=True,
    ),
    HistoricalRule(
        rule_id="SEC-002",
        title="Enforce Parameterized SQL Queries",
        language="all",
        category=RuleCategory.SECURITY,
        severity=RuleSeverity.CRITICAL,
        pattern_or_anti_pattern="String interpolation, f-strings, or raw concatenation inside database queries.",
        guidance="Always use parameterized query bindings or ORM query builders to prevent SQL injection vulnerabilities.",
        tags=["security", "owasp-a03", "sql-injection"],
        is_active=True,
    ),
    HistoricalRule(
        rule_id="PERF-PY-001",
        title="Avoid Index-Based Iteration in Python",
        language="python",
        category=RuleCategory.PERFORMANCE,
        severity=RuleSeverity.LOW,
        pattern_or_anti_pattern="Iterating using range(len(collection)) instead of enumerate() or direct iteration.",
        guidance="Use `for idx, item in enumerate(collection):` for clean, idiomatic, and faster iteration.",
        tags=["performance", "idiomatic-python", "clean-code"],
        is_active=True,
    ),
    HistoricalRule(
        rule_id="ARCH-GEN-001",
        title="Avoid Silent Exception Swallowing",
        language="all",
        category=RuleCategory.BUG,
        severity=RuleSeverity.HIGH,
        pattern_or_anti_pattern="Bare `except:` or catching generic `Exception` with a pass statement.",
        guidance="Catch specific exception types, log context, and either handle gracefully or re-raise.",
        tags=["reliability", "error-handling"],
        is_active=True,
    ),
]


class BaseBigQueryBackend(ABC):
    @abstractmethod
    async def insert_rules(self, rules: List[HistoricalRule]) -> int:
        pass

    @abstractmethod
    async def get_active_rules(self, language: Optional[str] = None) -> List[HistoricalRule]:
        pass

    @abstractmethod
    async def insert_analytics_event(self, event: ReviewAnalyticsEvent) -> bool:
        pass

    @abstractmethod
    async def get_analytics_events(
        self, user_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        pass


class InMemoryBigQueryBackend(BaseBigQueryBackend):
    """In-memory fallback backend for local development, CI tests, and offline runs."""

    def __init__(self, seed: bool = True) -> None:
        self._rules: Dict[str, HistoricalRule] = {}
        self._events: List[Dict[str, Any]] = []

        if seed:
            for rule in DEFAULT_SEED_RULES:
                self._rules[rule.rule_id] = rule

    async def insert_rules(self, rules: List[HistoricalRule]) -> int:
        count = 0
        for rule in rules:
            self._rules[rule.rule_id] = rule
            count += 1
        return count

    async def get_active_rules(self, language: Optional[str] = None) -> List[HistoricalRule]:
        active = [r for r in self._rules.values() if r.is_active]
        if not language:
            return active

        lang_clean = language.strip().lower()
        return [
            r for r in active
            if r.language in (lang_clean, "all", "*")
        ]

    async def insert_analytics_event(self, event: ReviewAnalyticsEvent) -> bool:
        row = event.to_bigquery_row()
        self._events.append(row)
        return True

    async def get_analytics_events(
        self, user_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        filtered = self._events
        if user_id:
            filtered = [e for e in filtered if e.get("user_id") == user_id]
        # Return sorted by timestamp descending
        filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return filtered[:limit]


class ProductionBigQueryBackend(BaseBigQueryBackend):
    """Production BigQuery client supporting partitioned and clustered tables."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._fallback = InMemoryBigQueryBackend(seed=True)
        self._client = None
        self._initialized = False

    def _get_client(self):
        if self._client is None and not self._initialized:
            try:
                from google.cloud import bigquery
                self._client = bigquery.Client(
                    project=self.settings.gcp_project_id,
                    location=self.settings.gcp_location,
                )
                self._ensure_dataset_and_tables()
            except Exception as e:
                logger.warning(
                    f"BigQuery credentials not available or client init failed: {e}. "
                    f"Falling back seamlessly to in-memory store."
                )
                self._client = None
            self._initialized = True
        return self._client

    def _ensure_dataset_and_tables(self) -> None:
        if self._client is None:
            return
        from google.cloud import bigquery
        from app.analytics.schemas import (
            HISTORICAL_RULES_SCHEMA,
            REVIEW_EVENTS_SCHEMA,
            REVIEW_EVENTS_PARTITION_FIELD,
            REVIEW_EVENTS_CLUSTERING_FIELDS,
        )

        dataset_ref = bigquery.DatasetReference(
            self.settings.gcp_project_id, self.settings.bq_dataset_id
        )
        try:
            self._client.get_dataset(dataset_ref)
        except Exception:
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = self.settings.gcp_location
            try:
                self._client.create_dataset(dataset, exists_ok=True)
            except Exception as e:
                logger.error(f"Failed to create BigQuery dataset {self.settings.bq_dataset_id}: {e}")

        # Ensure Rules table
        rules_table_id = f"{self.settings.gcp_project_id}.{self.settings.bq_dataset_id}.{self.settings.bq_rules_table}"
        try:
            self._client.get_table(rules_table_id)
        except Exception:
            rules_table = bigquery.Table(rules_table_id, schema=HISTORICAL_RULES_SCHEMA)
            try:
                self._client.create_table(rules_table, exists_ok=True)
            except Exception as e:
                logger.error(f"Failed to create BigQuery rules table: {e}")

        # Ensure Review Events table with Partitioning and Clustering
        events_table_id = f"{self.settings.gcp_project_id}.{self.settings.bq_dataset_id}.{self.settings.bq_reviews_table}"
        try:
            self._client.get_table(events_table_id)
        except Exception:
            events_table = bigquery.Table(events_table_id, schema=REVIEW_EVENTS_SCHEMA)
            events_table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field=REVIEW_EVENTS_PARTITION_FIELD,
            )
            events_table.clustering_fields = REVIEW_EVENTS_CLUSTERING_FIELDS
            try:
                self._client.create_table(events_table, exists_ok=True)
            except Exception as e:
                logger.error(f"Failed to create partitioned/clustered events table: {e}")

    async def insert_rules(self, rules: List[HistoricalRule]) -> int:
        client = self._get_client()
        if client is None:
            return await self._fallback.insert_rules(rules)

        table_id = f"{self.settings.gcp_project_id}.{self.settings.bq_dataset_id}.{self.settings.bq_rules_table}"
        rows = [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "language": r.language,
                "category": r.category.value,
                "severity": r.severity.value,
                "pattern_or_anti_pattern": r.pattern_or_anti_pattern,
                "guidance": r.guidance,
                "tags": r.tags,
                "is_active": r.is_active,
                "created_at": r.created_at.isoformat(),
                "created_by": r.created_by,
            }
            for r in rules
        ]

        try:
            errors = client.insert_rows_json(table_id, rows)
            if errors:
                logger.error(f"BigQuery rules streaming insert errors: {errors}")
                return await self._fallback.insert_rules(rules)
            # Also keep local fallback in sync for fast read-through
            await self._fallback.insert_rules(rules)
            return len(rules)
        except Exception as e:
            logger.warning(f"BigQuery rule insert encountered error: {e}. Writing to fallback.")
            return await self._fallback.insert_rules(rules)

    async def get_active_rules(self, language: Optional[str] = None) -> List[HistoricalRule]:
        client = self._get_client()
        if client is None:
            return await self._fallback.get_active_rules(language)

        from google.cloud import bigquery
        table_id = f"`{self.settings.gcp_project_id}.{self.settings.bq_dataset_id}.{self.settings.bq_rules_table}`"

        query = f"""
            SELECT rule_id, title, language, category, severity,
                   pattern_or_anti_pattern, guidance, tags, is_active,
                   created_at, created_by
            FROM {table_id}
            WHERE is_active = TRUE
        """
        job_config = bigquery.QueryJobConfig()
        if language:
            query += " AND (LOWER(language) = @lang OR LOWER(language) IN ('all', '*'))"
            job_config.query_parameters = [
                bigquery.ScalarQueryParameter("lang", "STRING", language.strip().lower())
            ]

        try:
            query_job = client.query(query, job_config=job_config)
            results = query_job.result()
            rules = []
            for row in results:
                rules.append(
                    HistoricalRule(
                        rule_id=row.rule_id,
                        title=row.title,
                        language=row.language,
                        category=RuleCategory(row.category) if row.category in RuleCategory._value2member_map_ else RuleCategory.ARCHITECTURE,
                        severity=RuleSeverity(row.severity) if row.severity in RuleSeverity._value2member_map_ else RuleSeverity.MEDIUM,
                        pattern_or_anti_pattern=row.pattern_or_anti_pattern,
                        guidance=row.guidance,
                        tags=list(row.tags or []),
                        is_active=bool(row.is_active),
                        created_at=row.created_at if isinstance(row.created_at, datetime) else datetime.now(timezone.utc),
                        created_by=row.created_by or "system",
                    )
                )
            return rules
        except Exception as e:
            logger.warning(f"BigQuery rule query error: {e}. Reading from local fallback.")
            return await self._fallback.get_active_rules(language)

    async def insert_analytics_event(self, event: ReviewAnalyticsEvent) -> bool:
        client = self._get_client()
        if client is None:
            return await self._fallback.insert_analytics_event(event)

        table_id = f"{self.settings.gcp_project_id}.{self.settings.bq_dataset_id}.{self.settings.bq_reviews_table}"
        row = event.to_bigquery_row()

        try:
            errors = client.insert_rows_json(table_id, [row])
            if errors:
                logger.error(f"BigQuery event insert error: {errors}")
                return await self._fallback.insert_analytics_event(event)
            await self._fallback.insert_analytics_event(event)
            return True
        except Exception as e:
            logger.warning(f"BigQuery streaming error: {e}. Writing to fallback.")
            return await self._fallback.insert_analytics_event(event)

    async def get_analytics_events(
        self, user_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        client = self._get_client()
        if client is None:
            return await self._fallback.get_analytics_events(user_id=user_id, limit=limit)

        from google.cloud import bigquery
        table_id = f"`{self.settings.gcp_project_id}.{self.settings.bq_dataset_id}.{self.settings.bq_reviews_table}`"
        query = f"SELECT * FROM {table_id}"
        job_config = bigquery.QueryJobConfig()

        if user_id:
            query += " WHERE user_id = @user_id"
            job_config.query_parameters = [
                bigquery.ScalarQueryParameter("user_id", "STRING", user_id)
            ]
        query += f" ORDER BY timestamp DESC LIMIT {limit}"

        try:
            job = client.query(query, job_config=job_config)
            return [dict(row.items()) for row in job.result()]
        except Exception as e:
            logger.warning(f"BigQuery query error: {e}. Returning fallback events.")
            return await self._fallback.get_analytics_events(user_id=user_id, limit=limit)


_backend_instance: Optional[BaseBigQueryBackend] = None


def get_bigquery_backend() -> BaseBigQueryBackend:
    global _backend_instance
    if _backend_instance is None:
        settings = get_settings()
        if settings.environment in ("test", "testing"):
            _backend_instance = InMemoryBigQueryBackend(seed=True)
        else:
            _backend_instance = ProductionBigQueryBackend()
    return _backend_instance

