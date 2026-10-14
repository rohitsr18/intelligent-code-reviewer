-- View: vw_code_quality_trends
-- Time-series daily quality trajectories partitioned by date for Looker Studio charts

SELECT
    DATE(timestamp) AS review_date,
    language,
    COUNT(DISTINCT review_id) AS reviews_submitted,
    COUNT(DISTINCT user_id) AS active_engineers,
    ROUND(AVG(overall_score), 1) AS daily_avg_score,
    ROUND(AVG(prompt_risk_score), 3) AS avg_prompt_risk,
    SUM(sanitized_secrets_count) AS daily_secrets_scrubbed,
    SUM(findings_critical) AS daily_critical_count,
    SUM(findings_high) AS daily_high_count,
    SUM(findings_medium) AS daily_medium_count,
    SUM(rules_applied_count) AS total_historical_rules_enforced,
    ROUND(AVG(evaluation_latency_ms), 1) AS avg_evaluation_latency_ms
FROM
    `{{project_id}}.{{dataset_id}}.review_events`
GROUP BY
    review_date,
    language
ORDER BY
    review_date DESC,
    reviews_submitted DESC;

