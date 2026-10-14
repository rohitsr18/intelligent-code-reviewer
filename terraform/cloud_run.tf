resource "google_cloud_run_v2_service" "code_reviewer_api" {
  name     = "intelligent-code-reviewer"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.reviewer_sa.email

    scaling {
      min_instance_count = 1
      max_instance_count = 10
    }

    containers {
      image = var.container_image

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
        cpu_idle = false
      }

      ports {
        container_port = 8080
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GCP_LOCATION"
        value = var.region
      }
      env {
        name  = "GEMINI_MODEL"
        value = "gemini-1.5-pro"
      }
      env {
        name  = "BQ_DATASET_ID"
        value = var.bq_dataset_id
      }
      env {
        name  = "IAP_ENABLED"
        value = tostring(var.iap_enabled)
      }
      env {
        name  = "IAP_AUDIENCE"
        value = var.iap_audience
      }

      startup_probe {
        initial_delay_seconds = 5
        timeout_seconds       = 3
        period_seconds        = 10
        failure_threshold     = 3
        http_get {
          path = "/health/ready"
          port = 8080
        }
      }

      liveness_probe {
        initial_delay_seconds = 10
        timeout_seconds       = 3
        period_seconds        = 15
        failure_threshold     = 3
        http_get {
          path = "/health/live"
          port = 8080
        }
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_bigquery_dataset.analytics,
  ]
}
