-- View: vw_developer_scorecard
-- Aggregates rolling developer quality metrics, scores, and defect density for Looker Studio

SELECT
    user_id,
    user_email,
    language,
    COUNT(DISTINCT review_id) AS total_reviews,
    ROUND(AVG(overall_score), 1) AS avg_code_score,
    ROUND(AVG(original_line_count), 0) AS avg_lines_reviewed,
    SUM(original_line_count) AS total_lines_reviewed,
    SUM(sanitized_secrets_count) AS total_secrets_prevented,
    SUM(findings_critical) AS total_critical_findings,
    SUM(findings_high) AS total_high_findings,
    SUM(findings_medium) AS total_medium_findings,
    SUM(findings_low) AS total_low_findings,
    -- Defect density: critical & high issues per 1,000 lines of code
    ROUND(
        SAFE_DIVIDE(SUM(findings_critical + findings_high) * 1000, NULLIF(SUM(original_line_count), 0)),
        2
    ) AS high_severity_defect_density_per_kloc,
    ROUND(AVG(evaluation_latency_ms), 1) AS avg_review_latency_ms,
    MAX(timestamp) AS last_review_at
FROM
    `{{project_id}}.{{dataset_id}}.review_events`
GROUP BY
    user_id,
    user_email,
    language;

