# Production Deployment Runbook

This runbook outlines the zero-downtime deployment process, infrastructure provisioning, and disaster recovery procedures for the 24/7 Intelligent Code Reviewer on Google Cloud Platform.

---

## 1. Prerequisites

Ensure you have the following CLI utilities installed and authenticated:
- `gcloud` CLI ($\ge 460.0.0$)
- `terraform` ($\ge 1.5.0$)
- Docker ($\ge 24.0.0$)

Authenticate against GCP:
```bash
gcloud auth login
gcloud auth application-default login
gcloud config set project <YOUR_GCP_PROJECT_ID>
```

---

## 2. Infrastructure as Code (Terraform)

Navigate to the `terraform/` directory:

```bash
cd terraform

# 1. Initialize Terraform state & providers
terraform init

# 2. Review the execution plan
terraform plan \
  -var="project_id=<YOUR_GCP_PROJECT_ID>" \
  -var="region=us-central1" \
  -var="environment=production"

# 3. Apply infrastructure
terraform apply \
  -var="project_id=<YOUR_GCP_PROJECT_ID>" \
  -var="region=us-central1" \
  -var="environment=production" \
  -auto-approve
```

Resources created:
- Cloud Run v2 service with health probes and autoscaling (1 to 10 instances).
- BigQuery dataset `code_reviewer_analytics`, tables `historical_rules` & `review_events`, and 3 Looker Studio analytical views.
- Firestore in Native mode (`FIRESTORE_NATIVE`).
- IAM Service Account (`sa-code-reviewer`) with least-privilege roles.

---

## 3. GitHub Actions CI/CD Secrets Setup

In your GitHub repository, navigate to **Settings** > **Secrets and variables** > **Actions** and add the following repository secrets:

| Secret Name | Value | Description |
|---|---|---|
| `GCP_PROJECT_ID` | `<YOUR_PROJECT_ID>` | Target Google Cloud project |
| `GCP_WIF_PROVIDER` | `projects/123/locations/global/workloadIdentityPools/github-pool/providers/github-provider` | Workload Identity Federation provider |
| `GCP_WIF_SA_EMAIL` | `sa-github-deployer@<PROJECT_ID>.iam.gserviceaccount.com` | Deployment service account |

---

## 4. Manual / Local Container Verification

Before pushing to production, verify the multi-stage distroless container locally:

```bash
# Build production image
docker build -t intelligent-code-reviewer:local .

# Verify container runs as non-root user (UID 10001)
docker run --rm intelligent-code-reviewer:local id -u
# Output must be: 10001

# Test container health endpoints
docker run -d -p 8080:8080 -e ENVIRONMENT=development --name reviewer-test intelligent-code-reviewer:local
curl -f http://localhost:8080/health/live
curl -f http://localhost:8080/health/ready
docker rm -f reviewer-test
```

---

## 5. Rollback & Disaster Recovery SOP

### Instant Cloud Run Traffic Rollback
If a regression or critical bug is detected in production:

1. List available Cloud Run revisions:
   ```bash
   gcloud run revisions list --service intelligent-code-reviewer --region us-central1
   ```
2. Roll back 100% of traffic to the previous healthy revision:
   ```bash
   gcloud run services update-traffic intelligent-code-reviewer \
     --region us-central1 \
     --to-revisions <PREVIOUS_HEALTHY_REVISION_NAME>=100
   ```
3. Verification:
   ```bash
   curl -I https://<SERVICE_URL>/health/live
   ```

---

## 6. Monitoring & Alerting

- **Cloud Logging:** Filter by `resource.type="cloud_run_revision" AND severity>=ERROR`.
- **Cloud Monitoring Dashboard:** Review container CPU utilization, memory consumption, and request latency (p95 / p99).

