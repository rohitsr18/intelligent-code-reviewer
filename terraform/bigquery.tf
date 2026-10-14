resource "google_bigquery_dataset" "analytics" {
  dataset_id                  = var.bq_dataset_id
  friendly_name               = "Code Reviewer Analytics"
  description                 = "Contains historical rules, partitioned review events, and Looker Studio views"
  location                    = var.region
  default_table_expiration_ms = null

  depends_on = [google_project_service.enabled_apis]
}

# Historical Rules Table
resource "google_bigquery_table" "historical_rules" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "historical_rules"
  deletion_protection = false

  schema = jsonencode([
    { name = "rule_id", type = "STRING", mode = "REQUIRED" },
    { name = "title", type = "STRING", mode = "REQUIRED" },
    { name = "language", type = "STRING", mode = "REQUIRED" },
    { name = "category", type = "STRING", mode = "REQUIRED" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "pattern_or_anti_pattern", type = "STRING", mode = "REQUIRED" },
    { name = "guidance", type = "STRING", mode = "REQUIRED" },
    { name = "tags", type = "STRING", mode = "REPEATED" },
    { name = "is_active", type = "BOOLEAN", mode = "REQUIRED" },
    { name = "created_at", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "created_by", type = "STRING", mode = "NULLABLE" }
  ])
}

# Partitioned and Clustered Review Events Table
resource "google_bigquery_table" "review_events" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "review_events"
  deletion_protection = false

  time_partitioning {
    type  = "DAY"
    field = "timestamp"
  }

  clustering = ["user_id", "language"]

  schema = jsonencode([
    { name = "review_id", type = "STRING", mode = "REQUIRED" },
    { name = "user_id", type = "STRING", mode = "REQUIRED" },
    { name = "user_email", type = "STRING", mode = "NULLABLE" },
    { name = "timestamp", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "filename", type = "STRING", mode = "NULLABLE" },
    { name = "language", type = "STRING", mode = "REQUIRED" },
    { name = "original_line_count", type = "INTEGER", mode = "NULLABLE" },
    { name = "sanitized_secrets_count", type = "INTEGER", mode = "NULLABLE" },
    { name = "prompt_risk_score", type = "FLOAT", mode = "NULLABLE" },
    { name = "overall_score", type = "INTEGER", mode = "NULLABLE" },
    { name = "total_findings", type = "INTEGER", mode = "NULLABLE" },
    { name = "findings_critical", type = "INTEGER", mode = "NULLABLE" },
    { name = "findings_high", type = "INTEGER", mode = "NULLABLE" },
    { name = "findings_medium", type = "INTEGER", mode = "NULLABLE" },
    { name = "findings_low", type = "INTEGER", mode = "NULLABLE" },
    { name = "findings_info", type = "INTEGER", mode = "NULLABLE" },
    { name = "model_used", type = "STRING", mode = "NULLABLE" },
    { name = "evaluation_latency_ms", type = "FLOAT", mode = "NULLABLE" },
    { name = "rules_applied_count", type = "INTEGER", mode = "NULLABLE" },
    { name = "review_status", type = "STRING", mode = "NULLABLE" }
  ])
}

# Looker Studio View: Developer Quality Scorecard
resource "google_bigquery_table" "vw_developer_scorecard" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "vw_developer_scorecard"
  deletion_protection = false

  view {
    query          = replace(replace(file("${path.module}/../sql/views/vw_developer_scorecard.sql"), "{{project_id}}", var.project_id), "{{dataset_id}}", var.bq_dataset_id)
    use_legacy_sql = false
  }

  depends_on = [google_bigquery_table.review_events]
}

# Looker Studio View: Daily Code Quality Trends
resource "google_bigquery_table" "vw_code_quality_trends" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "vw_code_quality_trends"
  deletion_protection = false

  view {
    query          = replace(replace(file("${path.module}/../sql/views/vw_code_quality_trends.sql"), "{{project_id}}", var.project_id), "{{dataset_id}}", var.bq_dataset_id)
    use_legacy_sql = false
  }

  depends_on = [google_bigquery_table.review_events]
}

# Looker Studio View: Recurring Anti-Patterns
resource "google_bigquery_table" "vw_recurring_anti_patterns" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "vw_recurring_anti_patterns"
  deletion_protection = false

  view {
    query          = replace(replace(file("${path.module}/../sql/views/vw_recurring_anti_patterns.sql"), "{{project_id}}", var.project_id), "{{dataset_id}}", var.bq_dataset_id)
    use_legacy_sql = false
  }

  depends_on = [google_bigquery_table.review_events, google_bigquery_table.historical_rules]
}

