# Looker Studio Analytics & Dashboard Setup Guide

This guide details how to connect **Google Looker Studio** to the BigQuery analytical views provisioned for the 24/7 Intelligent Code Reviewer platform.

---

## 1. Architecture Overview

Looker Studio connects directly to BigQuery analytical views hosted in the dataset `code_reviewer_analytics`:

```
[ Code Review Submissions ] 
             │
             ▼ (Partitioned by Day & Clustered by user_id, language)
    [ BigQuery Table: review_events ]
             │
   ┌─────────┴───────────────────────┬──────────────────────────────┐
   ▼                                 ▼                              ▼
[ View: vw_developer_scorecard ]   [ View: vw_code_quality_trends ]  [ View: vw_recurring_anti_patterns ]
   │                                 │                              │
   └─────────────────────────────────┼──────────────────────────────┘
                                     ▼
                     [ Looker Studio Executive & Team Dashboards ]
```

---

## 2. Connecting Looker Studio to BigQuery Views

### Step 1: Create Data Sources
1. Open [Google Looker Studio](https://lookerstudio.google.com/).
2. Click **Create** > **Data Source**.
3. Select the **BigQuery** connector.
4. Authorize access to your GCP project.
5. In the dataset browser:
   - **Project:** `<YOUR_GCP_PROJECT_ID>`
   - **Dataset:** `code_reviewer_analytics`
   - **Table/View:** Select `vw_developer_scorecard`
6. Click **Connect** in the top right.
7. Repeat the steps to add `vw_code_quality_trends` and `vw_recurring_anti_patterns` as supplementary data sources.

---

## 3. Recommended Dashboard Layouts

### Dashboard 1: Executive Engineering Overview
- **Scorecards (Top KPI Banner):**
  - **Total Reviews Completed:** `COUNT(review_id)`
  - **Average Code Quality Score:** `AVG(avg_code_score)` (Format: Number, Target: $\ge 85$)
  - **Secrets Leaked / Prevented:** `SUM(total_secrets_prevented)` (Target: $0$ unredacted)
  - **Critical Defect Density:** `AVG(high_severity_defect_density_per_kloc)`
- **Time-Series Area Chart:**
  - **Data Source:** `vw_code_quality_trends`
  - **Dimension:** `review_date`
  - **Breakdown:** `language`
  - **Metric:** `daily_avg_score`
- **Bar Chart:**
  - **Dimension:** `language`
  - **Metric:** `reviews_submitted`

### Dashboard 2: Developer Growth & Mentorship Tracker
- **Data Source:** `vw_developer_scorecard`
- **Table with Heatmap:**
  - **Dimensions:** `user_email`, `language`
  - **Metrics:** `total_reviews`, `avg_code_score`, `total_critical_findings`, `high_severity_defect_density_per_kloc`, `last_review_at`
- **Scatter Plot (Velocity vs Quality):**
  - **X-Axis:** `total_lines_reviewed`
  - **Y-Axis:** `avg_code_score`
  - **Bubble Size:** `total_reviews`

### Dashboard 3: Anti-Pattern & Compliance Radar
- **Data Source:** `vw_recurring_anti_patterns`
- **Table / Leaderboard:**
  - **Dimensions:** `rule_id`, `title`, `category`, `severity`
  - **Metrics:** `total_enforcements`, `engineers_affected`, `last_detected_at`
- **Donut Chart:**
  - **Dimension:** `category` (e.g. `security`, `bugs`, `performance`, `architecture`)
  - **Metric:** `total_enforcements`

---

## 4. Calculated Fields Reference

For advanced metrics, create calculated fields in Looker Studio:

| Field Name | Formula | Purpose |
|---|---|---|
| **Quality Health Status** | `CASE WHEN avg_code_score >= 85 THEN 'Exemplary' WHEN avg_code_score >= 70 THEN 'Adequate' ELSE 'Needs Mentorship' END` | Categorizes engineer health band |
| **Clean Submission Ratio** | `SUM(CASE WHEN total_critical_findings = 0 THEN 1 ELSE 0 END) / COUNT(total_reviews)` | Percentage of zero-critical PRs |

---

## 5. Scheduled Delivery & Access Control
- Set dashboard access to your Google Workspace organization domain.
- Schedule weekly summary PDFs to engineering managers via **Share** > **Schedule Delivery**.

