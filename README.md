# Code Sarathi — Intelligent Code Review Platform

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Google Cloud](https://img.shields.io/badge/GCP-Cloud%20Run%20%7C%20Vertex%20AI%20%7C%20BigQuery-4285F4.svg)](https://cloud.google.com)
[![Tests Passing](https://img.shields.io/badge/tests-228%20passed%20%7C%20100%25-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-ready automated code review platform built on **Google Cloud Platform**. Code Sarathi analyzes pull requests and code changes using static security guardrails, Google Gemini models on Vertex AI, organizational coding standards stored in BigQuery, and AST fix validation.

---

## Overview

Peer code reviews are essential for maintaining software quality and security, but manual reviews are often constrained by time, inconsistent across teams, and vulnerable to review fatigue. 

**Code Sarathi** augments development teams with automated, multi-language code reviews:
- **Pre-LLM Security:** Redacts credentials and detects injection patterns before external model calls.
- **Context-Aware Analysis:** Combines static analysis with Gemini 3.8 Flash to evaluate logic, security, architecture, and maintainability.
- **Institutional Standards:** Incorporates team-specific anti-patterns and rules stored in BigQuery.
- **Verifiable Recommendations:** Validates proposed code fixes using language parsers (AST) to prevent syntax errors.
- **Developer Growth:** Surfaces actionable runtime impact statements, remediation steps, and references to official documentation.

---

## Architecture & Google Cloud Platform Stack

```
[ Developer / CI/CD ]
         │ (Code Submission / Git Diff Webhook)
         ▼
[ Google Cloud Identity-Aware Proxy (IAP) ]
         │ (JWT Assertion & Access Verification)
         ▼
[ Cloud Run (FastAPI Microservice) ]
   ├── Pre-LLM Guardrails        (Secret Redaction, Prompt Defense, SAST Scanner)
   ├── Concurrency & Caching     (Multi-File Diff Batching, Token Pruner, LRU Cache)
   ├── Review Engine             (Gemini on Vertex AI with Structured Outputs)
   ├── Verification Layer        (AST Syntax Validation, Architecture Linter)
   ├── BigQuery Integration      (Historical Team Standards & Analytics Ingestion)
   └── Firestore Storage         (Review History, User Profiles, Feedback)
         │
         ▼
[ Looker Studio ] (Quality Trends, Defect Density & Review Metrics)
```

### System Diagrams

- **Cloud Architecture Diagram:** [docs/architecture/architecture_diagram.jpg](docs/architecture/architecture_diagram.jpg) (vector: [docs/architecture/architecture_diagram.svg](docs/architecture/architecture_diagram.svg))
- **End-to-End Review Pipeline:** [docs/architecture/process_flow_diagram.jpg](docs/architecture/process_flow_diagram.jpg) (vector: [docs/architecture/process_flow_diagram.svg](docs/architecture/process_flow_diagram.svg))

### Core Google Cloud Technologies

| GCP Service | Role in Architecture |
| :--- | :--- |
| **Google Cloud Run** | Hosts the containerized, asynchronous FastAPI service with automatic scaling. |
| **Google Vertex AI** | Powers code reasoning via Gemini 3.8 Flash with structured JSON outputs. |
| **Google Cloud IAP** | Secures endpoints using cryptographic JWT assertions and role-based access. |
| **Google Cloud BigQuery** | Stores historical team coding standards and logs partitioned review telemetry. |
| **Google Cloud Firestore** | Manages document persistence for reviews, developer profiles, and ratings. |
| **Looker Studio** | Provides dashboards for defect distribution, review cycle times, and quality metrics. |

---

## Core Capabilities

### 1. Security & Pre-LLM Guardrails
- **Data Leak Prevention (DLP):** High-entropy regex scanners identify and redact over 15 credential types (cloud keys, tokens, connection strings) before code is sent to external APIs.
- **Prompt Boundary Defense:** Sanitizes code comments and PR metadata to prevent delimiter manipulation or prompt override attempts.
- **Static SAST Checks:** Scans for high-risk functions such as unvalidated command execution (`os.system`, `subprocess`), insecure deserialization (`pickle.loads`), and outdated cryptography.
- **Dependency & License Audit:** Parses package manifests (`requirements.txt`, `package.json`, `go.mod`, `pom.xml`, `Cargo.toml`) to identify vulnerable packages and copyleft licenses.

### 2. Review Engine & Calibrated Scoring
- **Multi-Pillar Review:** Identifies functional bugs, security vulnerabilities, performance regressions, architecture concerns, and code maintainability issues.
- **Calibrated Scoring:** Applies deterministic score ceilings (e.g., critical security issues cap score at $\le 45$, high-severity defects at $\le 70$) to prevent inflated ratings.
- **Runtime Impact Analysis:** Explains concrete consequences for each finding (e.g., connection leaks under concurrency, memory bloat, unhandled exceptions).
- **Executive Triage:** Provides a quick-triage summary including a review verdict (`Approved`, `Changes Requested`, `Comment`), primary risks, and quick wins (< 5 mins).
- **JSON Stream Resilience:** Includes automated repair for truncated outputs and handles up to 16,384 tokens for large diff reviews.

### 3. AST-Based Fix Verification
- **Syntax Validation:** Tests generated Python fix snippets against native `ast.parse` before displaying them, ensuring recommendations are syntactically sound.
- **Actionable Fix Snippets:** Presents changes in standardized replacement snippets and unified diff formats.

### 4. Performance & Token Optimization
- **Multi-File Concurrency:** Reviews multi-file pull requests concurrently using asynchronous task queues.
- **Diff Token Pruning:** Automatically strips generated lockfiles (`package-lock.json`, `yarn.lock`, `poetry.lock`) and minified assets, reducing payload size and token usage.
- **Deterministic Caching:** SHA-256 content hashing returns instant cached results for unchanged submissions.

### 5. Architectural & Schema Integrity
- **Architecture & Layering Linter:** Checks modular boundaries, flags clean architecture violations (e.g., domain logic directly importing presentation or infrastructure layers), and detects circular imports.
- **Schema Drift Detection:** Identifies breaking API changes in OpenAPI definitions and ORM database models.
- **PR Scope & Intent Verification:** Evaluates pull request changes against the provided title/description to flag unexpected modifications.
- **Test Coverage Audit:** Verifies whether modified functions include corresponding unit tests and checks assertion density.

### 6. Team Standards & Developer Growth
- **BigQuery Team Standards:** Matches code changes against institutional rules and recurring anti-patterns defined by the organization.
- **Anti-Nitpick Grouping:** Groups minor stylistic suggestions into a secondary section so critical defects remain prominent.
- **Curated Documentation:** Pairs recommendations with references to official documentation (PEPs, MDN, Go documentation).
- **Feedback Collection:** Records developer feedback to evaluate and improve review quality over time.

### 7. Developer Workbench UI
- Responsive web interface built with Tailwind CSS.
- Interactive radial quality score dial with severity-coded status indicators.
- Side-by-side findings review with one-click fix copying.
- Multi-file uploader with drag-and-drop support.
- Automated programming language detection across 20+ languages.

---

## Supported Programming Languages

Code Sarathi supports code analysis and automatic language detection across major languages and file types:

| Category | Supported Languages |
| :--- | :--- |
| **Backend & Systems** | Python, Go, Rust, Java, C++, C, C#, Kotlin, Swift |
| **Web & Scripting** | JavaScript, TypeScript, PHP, Ruby, Bash / Shell |
| **Data & Queries** | SQL |
| **Configuration & Infra** | Dockerfile, YAML, JSON, HTML, CSS |

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/review/submit` | Primary review submission endpoint (runs DLP, SAST, intent, architecture, and LLM review). |
| `GET` | `/api/v1/review/{review_id}` | Retrieves completed review details and triage findings. |
| `POST` | `/api/v1/review/{review_id}/feedback` | Submits developer rating and feedback for a review. |
| `POST` | `/api/v1/review/detect-language` | Detects programming language with confidence score. |
| `POST` | `/api/v1/review/audit-dependencies` | Audits package manifests for known vulnerabilities and copyleft licenses. |
| `POST` | `/api/v1/review/scan-sast` | Performs static rule-based security scans for unsafe APIs and command injection. |
| `POST` | `/api/v1/review/audit-tests` | Evaluates unit test coverage and assertion density for modified code. |
| `POST` | `/api/v1/review/sweep-intent` | Checks alignment between code changes and the stated PR description. |
| `POST` | `/api/v1/review/detect-drift` | Detects breaking changes and schema drift in API contracts and data models. |
| `POST` | `/api/v1/review/lint-architecture` | Analyzes code layering, dependency direction, and circular imports. |
| `GET` | `/api/v1/sessions` | Lists paginated historical user review sessions. |
| `GET` | `/health` | Service health check returning uptime and version. |

---

## Getting Started

### Prerequisites
- Python 3.9+ (Python 3.11 recommended)
- Google Cloud CLI (`gcloud`) with Application Default Credentials (ADC), or a `GEMINI_API_KEY` from Google AI Studio.

### Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rohitsr18/intelligent-code-reviewer.git
   cd intelligent-code-reviewer
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables:**
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   export GCP_PROJECT_ID="your-gcp-project"
   export GCP_LOCATION="us-central1"
   export ENVIRONMENT="development"
   ```

5. **Run tests:**
   ```bash
   pytest -v
   ```

6. **Start development server:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
   ```
   Access the web workbench at [http://localhost:8080](http://localhost:8080).

---

## Deployment

The service is packaged as a Docker container optimized for Google Cloud Run:

```bash
# Build container image
docker build -t gcr.io/${GCP_PROJECT_ID}/code-sarathi:latest .

# Deploy to Google Cloud Run
gcloud run deploy code-sarathi \
  --image gcr.io/${GCP_PROJECT_ID}/code-sarathi:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

Continuous integration and automated testing run on every pull request via GitHub Actions.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

