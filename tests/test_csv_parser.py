import pytest
from app.analytics.csv_parser import parse_rules_csv
from app.analytics.models import RuleCategory, RuleSeverity


def test_parse_valid_rules_csv():
    csv_text = """rule_id,title,language,category,severity,pattern_or_anti_pattern,guidance,tags
SEC-001,No Eval,all,security,critical,Using eval is unsafe,Use ast.literal_eval,cwe-95;injection
PERF-01,Enumerate Loops,python,performance,low,range(len()) loop,Use enumerate,loops|speed
ARCH-01,Decouple Layers,typescript,architecture,medium,Direct DB calls in UI,Use repository pattern,clean-arch
"""
    result = parse_rules_csv(csv_text, created_by="lead@company.com")
    assert result.total_rows == 3
    assert result.imported_count == 3
    assert result.rejected_count == 0
    assert len(result.errors) == 0

    rule1 = result.imported_rules[0]
    assert rule1.rule_id == "SEC-001"
    assert rule1.title == "No Eval"
    assert rule1.language == "all"
    assert rule1.category == RuleCategory.SECURITY
    assert rule1.severity == RuleSeverity.CRITICAL
    assert rule1.tags == ["cwe-95", "injection"]
    assert rule1.created_by == "lead@company.com"

    rule2 = result.imported_rules[1]
    assert rule2.rule_id == "PERF-01"
    assert rule2.language == "python"
    assert rule2.tags == ["loops", "speed"]


def test_parse_empty_csv():
    result = parse_rules_csv("", created_by="tester")
    assert result.total_rows == 0
    assert result.imported_count == 0
    assert "empty" in result.errors[0].lower()


def test_parse_missing_required_headers():
    csv_text = """title,language,category
No Rule ID,python,security
"""
    result = parse_rules_csv(csv_text)
    assert result.imported_count == 0
    assert "missing required columns" in result.errors[0].lower()


def test_parse_csv_with_malformed_and_valid_rows():
    csv_text = """rule_id,title,language,category,severity,pattern_or_anti_pattern,guidance,tags
SEC-001,No Eval,python,security,critical,eval() call,ast.literal_eval,security
,,,invalid,,missing fields,,
SEC-002,No Shell Exec,python,security,high,shell=True in subprocess,Set shell=False,security
"""
    result = parse_rules_csv(csv_text)
    assert result.total_rows == 3
    assert result.imported_count == 2
    assert result.rejected_count == 1
    assert "Row 3" in result.errors[0]

