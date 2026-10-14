variable "project_id" {
  description = "Google Cloud Platform Project ID"
  type        = string
  default     = "intelligent-code-reviewer-prod"
}

variable "region" {
  description = "GCP deployment region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment name (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "container_image" {
  description = "Container image URL in Artifact Registry"
  type        = string
  default     = "us-central1-docker.pkg.dev/intelligent-code-reviewer-prod/reviewer-repo/intelligent-code-reviewer:latest"
}

variable "bq_dataset_id" {
  description = "BigQuery dataset ID for analytics and historical rules"
  type        = string
  default     = "code_reviewer_analytics"
}

variable "iap_enabled" {
  description = "Whether to enforce Google Cloud Identity-Aware Proxy JWT validation"
  type        = bool
  default     = true
}

variable "iap_audience" {
  description = "Signed IAP JWT audience string (/projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID)"
  type        = string
  default     = ""
}

variable "admin_emails" {
  description = "List of administrator emails granted system privileges"
  type        = list(string)
  default     = ["admin@company.com"]
}

