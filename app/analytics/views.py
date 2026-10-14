import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

VIEW_DEFINITIONS = {
    "vw_developer_scorecard": """
        SELECT
            user_id,
            user_email,
            language,
            COUNT(DISTINCT review_id) AS total_reviews,
            ROUND(AVG(overall_score), 1) AS avg_code_score,
            ROUND(AVG(original_line_count), 0) AS avg_lines_reviewed,
            SUM(original_line_count) AS total_lines_reviewed,
            SUM(sanitized_secrets_count) AS total_secrets_prevented,
            SUM(findings_critical) AS total_critical_findings,
            SUM(findings_high) AS total_high_findings,
            SUM(findings_medium) AS total_medium_findings,
            SUM(findings_low) AS total_low_findings,
            ROUND(
                SAFE_DIVIDE(SUM(findings_critical + findings_high) * 1000, NULLIF(SUM(original_line_count), 0)),
                2
            ) AS high_severity_defect_density_per_kloc,
            ROUND(AVG(evaluation_latency_ms), 1) AS avg_review_latency_ms,
            MAX(timestamp) AS last_review_at
        FROM
            `{project_id}.{dataset_id}.review_events`
        GROUP BY
            user_id,
            user_email,
            language
    """,
    "vw_code_quality_trends": """
        SELECT
            DATE(timestamp) AS review_date,
            language,
            COUNT(DISTINCT review_id) AS reviews_submitted,
            COUNT(DISTINCT user_id) AS active_engineers,
            ROUND(AVG(overall_score), 1) AS daily_avg_score,
            ROUND(AVG(prompt_risk_score), 3) AS avg_prompt_risk,
            SUM(sanitized_secrets_count) AS daily_secrets_scrubbed,
            SUM(findings_critical) AS daily_critical_count,
            SUM(findings_high) AS daily_high_count,
            SUM(findings_medium) AS daily_medium_count,
            SUM(rules_applied_count) AS total_historical_rules_enforced,
            ROUND(AVG(evaluation_latency_ms), 1) AS avg_evaluation_latency_ms
        FROM
            `{project_id}.{dataset_id}.review_events`
        GROUP BY
            review_date,
            language
        ORDER BY
            review_date DESC,
            reviews_submitted DESC
    """,
    "vw_recurring_anti_patterns": """
        SELECT
            hr.rule_id,
            hr.title,
            hr.language,
            hr.category,
            hr.severity,
            hr.guidance,
            COUNT(re.review_id) AS total_enforcements,
            COUNT(DISTINCT re.user_id) AS engineers_affected,
            MAX(re.timestamp) AS last_detected_at
        FROM
            `{project_id}.{dataset_id}.historical_rules` hr
        LEFT JOIN
            `{project_id}.{dataset_id}.review_events` re
            ON (hr.language = re.language OR hr.language IN ('all', '*'))
            AND re.rules_applied_count > 0
        WHERE
            hr.is_active = TRUE
        GROUP BY
            hr.rule_id,
            hr.title,
            hr.language,
            hr.category,
            hr.severity,
            hr.guidance
        ORDER BY
            total_enforcements DESC
    """,
}


def get_rendered_view_sql(view_name: str, project_id: str, dataset_id: str) -> str:
    raw_sql = VIEW_DEFINITIONS.get(view_name)
    if not raw_sql:
        raise ValueError(f"View '{view_name}' is not defined. Available: {list(VIEW_DEFINITIONS.keys())}")
    return raw_sql.format(project_id=project_id, dataset_id=dataset_id).strip()


def provision_looker_views(client: Any, project_id: str, dataset_id: str) -> Dict[str, bool]:
    """Provisions or updates BigQuery views for Looker Studio dashboards."""
    from google.cloud import bigquery

    results: Dict[str, bool] = {}
    for view_name, raw_sql in VIEW_DEFINITIONS.items():
        view_id = f"{project_id}.{dataset_id}.{view_name}"
        rendered_sql = raw_sql.format(project_id=project_id, dataset_id=dataset_id).strip()

        view_table = bigquery.Table(view_id)
        view_table.view_query = rendered_sql

        try:
            client.create_table(view_table, exists_ok=True)
            results[view_name] = True
            logger.info(f"Successfully provisioned BigQuery view {view_name}")
        except Exception as e:
            logger.warning(f"Could not provision view {view_name}: {e}")
            results[view_name] = False

    return results
