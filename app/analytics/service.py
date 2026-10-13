import logging
from typing import List, Optional, Dict, Any
from app.analytics.models import (
    HistoricalRule,
    ReviewAnalyticsEvent,
    RuleIngestResult,
)
from app.analytics.csv_parser import parse_rules_csv
from app.analytics.client import BaseBigQueryBackend, get_bigquery_backend
from app.reviewer.models import ReviewAnalysisResult, FindingSeverity

logger = logging.getLogger(__name__)


class HistoricalLearningService:
    """Service orchestrating CSV rule ingestion, prompt enrichment, and review telemetry."""

    def __init__(self, backend: Optional[BaseBigQueryBackend] = None) -> None:
        self.backend = backend or get_bigquery_backend()

    async def ingest_csv(
        self,
        csv_content: str,
        created_by: str = "system",
    ) -> RuleIngestResult:
        result = parse_rules_csv(csv_content=csv_content, created_by=created_by)
        if result.imported_rules:
            saved_count = await self.backend.insert_rules(result.imported_rules)
            logger.info(f"Ingested {saved_count} historical rules successfully.")
        return result

    async def get_enrichment_rules(self, language: str) -> List[HistoricalRule]:
        return await self.backend.get_active_rules(language=language)

    def format_rules_for_prompt(self, rules: List[HistoricalRule]) -> List[str]:
        return [rule.to_prompt_instruction() for rule in rules]

    async def record_review_event(
        self,
        review_id: str,
        user_id: str,
        user_email: str,
        language: str,
        filename: Optional[str],
        original_line_count: int,
        sanitized_secrets_count: int,
        prompt_risk_score: float,
        review_status: str,
        analysis: ReviewAnalysisResult,
        rules_applied_count: int = 0,
    ) -> ReviewAnalyticsEvent:
        # Tally findings by severity
        crit_count = sum(1 for f in analysis.findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in analysis.findings if f.severity == FindingSeverity.HIGH)
        med_count = sum(1 for f in analysis.findings if f.severity == FindingSeverity.MEDIUM)
        low_count = sum(1 for f in analysis.findings if f.severity == FindingSeverity.LOW)
        info_count = sum(1 for f in analysis.findings if f.severity == FindingSeverity.INFO)

        event = ReviewAnalyticsEvent(
            review_id=review_id,
            user_id=user_id,
            user_email=user_email,
            filename=filename,
            language=language,
            original_line_count=original_line_count,
            sanitized_secrets_count=sanitized_secrets_count,
            prompt_risk_score=prompt_risk_score,
            overall_score=analysis.overall_score,
            total_findings=len(analysis.findings),
            findings_critical=crit_count,
            findings_high=high_count,
            findings_medium=med_count,
            findings_low=low_count,
            findings_info=info_count,
            model_used=analysis.model_used,
            evaluation_latency_ms=analysis.evaluation_latency_ms,
            rules_applied_count=rules_applied_count,
            review_status=review_status,
        )

        try:
            await self.backend.insert_analytics_event(event)
        except Exception as e:
            logger.error(f"Failed to record analytics event for review {review_id}: {e}")

        return event

    async def get_user_events(
        self, user_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        return await self.backend.get_analytics_events(user_id=user_id, limit=limit)


_service_instance: Optional[HistoricalLearningService] = None


def get_historical_learning_service() -> HistoricalLearningService:
    global _service_instance
    if _service_instance is None:
        _service_instance = HistoricalLearningService()
    return _service_instance

