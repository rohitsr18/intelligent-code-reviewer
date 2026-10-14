output "cloud_run_service_url" {
  description = "The publicly accessible URL of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.code_reviewer_api.uri
}

output "bigquery_dataset_id" {
  description = "The BigQuery dataset ID hosting analytical review events and views"
  value       = google_bigquery_dataset.analytics.dataset_id
}

output "looker_view_scorecard" {
  description = "BigQuery View ID for Looker Studio Developer Scorecard"
  value       = "${var.project_id}.${var.bq_dataset_id}.vw_developer_scorecard"
}

output "looker_view_trends" {
  description = "BigQuery View ID for Looker Studio Quality Trends"
  value       = "${var.project_id}.${var.bq_dataset_id}.vw_code_quality_trends"
}

output "looker_view_anti_patterns" {
  description = "BigQuery View ID for Looker Studio Recurring Anti-Patterns"
  value       = "${var.project_id}.${var.bq_dataset_id}.vw_recurring_anti_patterns"
}

output "service_account_email" {
  description = "Service account email assigned to Cloud Run"
  value       = google_service_account.reviewer_sa.email
}
