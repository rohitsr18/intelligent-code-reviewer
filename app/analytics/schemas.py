from typing import List, Dict, Any

try:
    from google.cloud import bigquery

    HISTORICAL_RULES_SCHEMA = [
        bigquery.SchemaField("rule_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("title", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("language", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("category", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("pattern_or_anti_pattern", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("guidance", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("tags", "STRING", mode="REPEATED"),
        bigquery.SchemaField("is_active", "BOOLEAN", mode="REQUIRED"),
        bigquery.SchemaField("created_at", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("created_by", "STRING", mode="NULLABLE"),
    ]

    REVIEW_EVENTS_SCHEMA = [
        bigquery.SchemaField("review_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("user_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("user_email", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("filename", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("language", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("original_line_count", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("sanitized_secrets_count", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("prompt_risk_score", "FLOAT", mode="NULLABLE"),
        bigquery.SchemaField("overall_score", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("total_findings", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("findings_critical", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("findings_high", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("findings_medium", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("findings_low", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("findings_info", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("model_used", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("evaluation_latency_ms", "FLOAT", mode="NULLABLE"),
        bigquery.SchemaField("rules_applied_count", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("review_status", "STRING", mode="NULLABLE"),
    ]

except ImportError:
    HISTORICAL_RULES_SCHEMA = []
    REVIEW_EVENTS_SCHEMA = []

REVIEW_EVENTS_PARTITION_FIELD = "timestamp"
REVIEW_EVENTS_CLUSTERING_FIELDS = ["user_id", "language"]

