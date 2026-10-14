# Service Account for Cloud Run Intelligent Code Reviewer
resource "google_service_account" "reviewer_sa" {
  account_id   = "sa-code-reviewer"
  display_name = "Intelligent Code Reviewer Microservice Service Account"
}

# IAM Role: BigQuery Data Editor (streaming inserts and querying rules/events)
resource "google_project_iam_member" "bq_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.reviewer_sa.email}"
}

# IAM Role: BigQuery User (running query jobs)
resource "google_project_iam_member" "bq_user" {
  project = var.project_id
  role    = "roles/bigquery.user"
  member  = "serviceAccount:${google_service_account.reviewer_sa.email}"
}

# IAM Role: Vertex AI User (calling Gemini LLM models)
resource "google_project_iam_member" "vertex_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.reviewer_sa.email}"
}

# IAM Role: Cloud Datastore User (Firestore reads and writes)
resource "google_project_iam_member" "firestore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.reviewer_sa.email}"
}

# IAM Role: Cloud Run Invoker (for authorized users / IAP proxy)
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.code_reviewer_api.name
  role     = "roles/run.invoker"
  member   = "allUsers" # Protected cryptographically at application layer by IAP middleware
}

