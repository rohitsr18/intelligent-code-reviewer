# 24/7 Intelligent Code Reviewer

An enterprise-grade, multi-language automated code review and developer growth platform powered by Google Cloud Platform (Gemini, BigQuery, Firestore, Cloud Run, Looker Studio).

---

## 👥 Users & Problem Statement
- **Audience:** Software engineering teams across varied languages and frameworks.
- **Pain Point:** Manual peer code reviews are slow, inconsistent, create delivery bottlenecks, and lack long-term developer growth tracking.
- **Solution:** 24/7 real-time, multi-language intelligent feedback enriched with historical company review rules, secure persistence, and growth analytics.

---

## 🏗️ Architecture & GCP Stack

```
[ Developer / CI/CD ]
         │ (Code Submission)
         ▼
[ Google Cloud Identity-Aware Proxy (IAP) ]
         │ (Cryptographic JWT Assertion)
         ▼
[ Cloud Run (FastAPI Microservice) ]
   ├── [ AI Security & Data Leak Prevention Layer ] (Secret Scrubbing & Prompt Injection Defense)
   ├── [ Gemini 1.5 Review Engine (Vertex AI) ]     (Bugs, Architecture, Security, Optimizations)
   ├── [ BigQuery Historical Enrichment Engine ]   (CSV Rule Ingestion & Metric Partitioning)
   └── [ Firestore Persistent Store ]               (User Sessions, Growth Profiles, Ratings)
         │
         ▼
[ Looker Studio ] (Developer Progress & Code Quality Dashboards)
```

---

## 🗺️ Feature Branch Roadmap

In accordance with strict SDLC standards, each feature is developed, tested, and reviewed on dedicated branches before merging:

1. **`feature/01-foundation-and-security`** (Active)
   - Enterprise project scaffolding, configuration management, Dockerfile for Cloud Run.
   - Pre-LLM Data Leak Prevention Layer (high-entropy secrets, cloud keys, PII redaction).
   - Prompt Injection & boundary defense mechanisms.
2. **`feature/02-auth-iap-and-api-gateway`**
   - Cryptographic Identity-Aware Proxy (IAP) JWT verification middleware.
   - Core API endpoints (`/health`, `/api/v1/review`, `/api/v1/sessions`).
   - Rate limiting, RBAC, and payload validation.
3. **`feature/03-gemini-ai-review-engine`**
   - Gemini Vertex AI engine with structured schema output.
   - Multi-language AST/code analysis (Bugs, Architecture, Performance, Security, Growth).
   - System prompts, exponential backoff, and zero-data-retention compliance.
4. **`feature/04-bigquery-historical-learning`**
   - CSV rule ingestion pipeline (custom team rules and anti-patterns).
   - Historical rule enrichment engine.
   - Partitioned and clustered analytical event ingestion.
5. **`feature/05-firestore-persistence-and-growth`**
   - Firestore schema and repositories for reviews, sessions, user skill tracking, and feedback.
   - Pagination, search, and session replay endpoints.
6. **`feature/06-looker-insights-and-ci-cd`**
   - BigQuery analytical views and Looker Studio dashboard configurations.
   - GitHub Actions CI/CD workflows, Terraform IaC, and production deployment runbook.
