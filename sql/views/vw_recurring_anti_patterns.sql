-- View: vw_recurring_anti_patterns
-- Identifies most frequently triggered historical rules and company anti-patterns

SELECT
    hr.rule_id,
    hr.title,
    hr.language,
    hr.category,
    hr.severity,
    hr.guidance,
    COUNT(re.review_id) AS total_enforcements,
    COUNT(DISTINCT re.user_id) AS engineers_affected,
    MAX(re.timestamp) AS last_detected_at
FROM
    `{{project_id}}.{{dataset_id}}.historical_rules` hr
LEFT JOIN
    `{{project_id}}.{{dataset_id}}.review_events` re
    ON (hr.language = re.language OR hr.language IN ('all', '*'))
    AND re.rules_applied_count > 0
WHERE
    hr.is_active = TRUE
GROUP BY
    hr.rule_id,
    hr.title,
    hr.language,
    hr.category,
    hr.severity,
    hr.guidance
ORDER BY
    total_enforcements DESC;
