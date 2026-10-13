import csv
import io
from typing import List, Tuple
from app.analytics.models import (
    HistoricalRule,
    RuleCategory,
    RuleSeverity,
    RuleIngestResult,
)


REQUIRED_HEADERS = {
    "rule_id",
    "title",
    "pattern_or_anti_pattern",
    "guidance",
}


def _parse_tags(raw_tags: str) -> List[str]:
    if not raw_tags:
        return []
    # Support pipe, semicolon, or comma delimiters
    delimiter = "|" if "|" in raw_tags else (";" if ";" in raw_tags else ",")
    tags = [t.strip().lower() for t in raw_tags.split(delimiter) if t.strip()]
    return tags


def parse_rules_csv(
    csv_content: str,
    created_by: str = "system",
) -> RuleIngestResult:
    """Parses and validates CSV content containing team historical rules.

    Expected columns:
    rule_id, title, language, category, severity, pattern_or_anti_pattern, guidance, tags
    """
    if not csv_content or not csv_content.strip():
        return RuleIngestResult(
            total_rows=0,
            imported_count=0,
            rejected_count=0,
            errors=["CSV payload is empty"],
            imported_rules=[],
        )

    stream = io.StringIO(csv_content.strip())
    reader = csv.DictReader(stream)

    if not reader.fieldnames:
        return RuleIngestResult(
            total_rows=0,
            imported_count=0,
            rejected_count=0,
            errors=["Missing header row in CSV"],
            imported_rules=[],
        )

    # Normalize header names (lowercase, stripped)
    normalized_fieldnames = {f.strip().lower(): f for f in reader.fieldnames if f}
    missing = REQUIRED_HEADERS - set(normalized_fieldnames.keys())
    if missing:
        return RuleIngestResult(
            total_rows=0,
            imported_count=0,
            rejected_count=0,
            errors=[f"Missing required columns in CSV header: {', '.join(sorted(missing))}"],
            imported_rules=[],
        )

    imported_rules: List[HistoricalRule] = []
    errors: List[str] = []
    total_rows = 0

    for line_num, row in enumerate(reader, start=2):
        total_rows += 1
        clean_row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k}

        rule_id = clean_row.get("rule_id", "")
        title = clean_row.get("title", "")
        pattern = clean_row.get("pattern_or_anti_pattern", "")
        guidance = clean_row.get("guidance", "")

        if not rule_id or not title or not pattern or not guidance:
            errors.append(f"Row {line_num}: rule_id, title, pattern_or_anti_pattern, and guidance cannot be empty")
            continue

        language = clean_row.get("language", "all") or "all"
        raw_cat = clean_row.get("category", "architecture").lower()
        raw_sev = clean_row.get("severity", "medium").lower()

        # Parse Category
        try:
            category = RuleCategory(raw_cat)
        except ValueError:
            category = RuleCategory.ARCHITECTURE

        # Parse Severity
        try:
            severity = RuleSeverity(raw_sev)
        except ValueError:
            severity = RuleSeverity.MEDIUM

        tags = _parse_tags(clean_row.get("tags", ""))

        try:
            rule = HistoricalRule(
                rule_id=rule_id,
                title=title,
                language=language,
                category=category,
                severity=severity,
                pattern_or_anti_pattern=pattern,
                guidance=guidance,
                tags=tags,
                is_active=True,
                created_by=created_by,
            )
            imported_rules.append(rule)
        except Exception as e:
            errors.append(f"Row {line_num} validation failed: {str(e)}")

    return RuleIngestResult(
        total_rows=total_rows,
        imported_count=len(imported_rules),
        rejected_count=len(errors),
        errors=errors,
        imported_rules=imported_rules,
    )

