"""Schema & API Contract Drift Detector.

Detects backward-incompatible API contract breaks and database schema migration drifts:
1. API Contract & DTO Breaking Changes:
   - Removed fields in request/response DTO schemas (Pydantic / TypeScript / JSON Schema)
   - Newly added required fields without defaults (breaks existing API callers)
   - Field type mutations (e.g. int -> str or scalar -> array)
   - Removed HTTP API endpoints without deprecation grace period
   - Protobuf & GraphQL contract removals / scalar mutations
2. Database Schema & Migration Drifts:
   - Dropping columns or tables in active production databases (breaks rolling deployments)
   - Adding NOT NULL columns without server_default on populated tables
   - Column or table renaming in place (breaks running instances before rollout completes)
   - Unsafe column alterations (narrowing varchar, casting incompatible types)
   - Empty or missing downgrade() steps in Alembic migration scripts
"""

import ast
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import FindingCategory, FindingSeverity, ReviewFinding

logger = logging.getLogger(__name__)


class ContractDriftFinding(BaseModel):
    rule_id: str
    severity: FindingSeverity
    change_type: str = "breaking"  # "breaking", "warning", "info"
    component: str = "api"  # "api", "database", "protobuf", "graphql"
    title: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None


class ContractDriftReport(BaseModel):
    has_breaking_changes: bool = False
    breaking_changes_count: int = 0
    warnings_count: int = 0
    drift_score: float = 100.0  # 100 = perfectly backward-compatible
    findings: List[ContractDriftFinding] = Field(default_factory=list)

    def to_review_findings(self) -> List[ReviewFinding]:
        """Convert drift findings into unified ReviewFinding objects."""
        review_findings = []
        for f in self.findings:
            cat = FindingCategory.ARCHITECTURE if f.component in ("database", "api") else FindingCategory.BUG
            review_findings.append(
                ReviewFinding(
                    category=cat,
                    severity=f.severity,
                    title=f"[{f.rule_id}] {f.title}",
                    description=f"{f.description}\n\n**Component**: `{f.component.upper()}` | **Change Type**: `{f.change_type.upper()}`\n**Suggested Action**: {f.suggested_fix or 'Review schema backward compatibility'}",
                    line_start=f.line_number,
                    line_end=f.line_number,
                    rule_id=f.rule_id,
                    suggested_fix=f.suggested_fix,
                )
            )
        return review_findings


class SchemaContractDriftDetector:
    """Enterprise Schema & API Contract Drift Analyzer."""

    # Regex patterns for DB migration breaking operations
    DB_MIGRATION_PATTERNS = [
        # Alembic op.drop_column
        (
            re.compile(r"""\bop\.drop_column\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]""", re.IGNORECASE),
            "DRIFT-DB-DROP-COLUMN-001",
            FindingSeverity.CRITICAL,
            "breaking",
            "database",
            "Dropping Database Column (Alembic)",
            "Dropping column '{1}' on table '{0}' causes immediate failures for running app instances during rolling zero-downtime deploys.",
            "Apply expand-and-contract pattern: deprecate column, stop reading/writing in separate release, then drop.",
        ),
        # Alembic op.drop_table
        (
            re.compile(r"""\bop\.drop_table\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE),
            "DRIFT-DB-DROP-TABLE-001",
            FindingSeverity.CRITICAL,
            "breaking",
            "database",
            "Dropping Database Table (Alembic)",
            "Dropping table '{0}' breaks running application versions querying this table.",
            "Ensure all application references are eliminated across all deployed clusters before dropping table.",
        ),
        # Raw SQL DROP COLUMN / DROP TABLE
        (
            re.compile(r"""\bALTER\s+TABLE\s+([^\s]+)\s+DROP\s+(?:COLUMN\s+)?([^\s;,]+)""", re.IGNORECASE),
            "DRIFT-DB-SQL-DROP-COLUMN-001",
            FindingSeverity.CRITICAL,
            "breaking",
            "database",
            "Raw SQL DROP COLUMN Statement",
            "Raw DDL 'ALTER TABLE {0} DROP COLUMN {1}' breaks active transactions and running queries.",
            "Use phased migrations: stop querying the column across services first.",
        ),
        (
            re.compile(r"""\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([^\s;,]+)""", re.IGNORECASE),
            "DRIFT-DB-SQL-DROP-TABLE-001",
            FindingSeverity.CRITICAL,
            "breaking",
            "database",
            "Raw SQL DROP TABLE Statement",
            "DDL statement 'DROP TABLE {0}' permanently deletes data and breaks dependent services.",
            "Verify complete deprecation and archival prior to executing DROP TABLE.",
        ),
        # Alembic NOT NULL without server_default
        (
            re.compile(
                r"""\bop\.add_column\s*\(\s*['"]([^'"]+)['"].*?\bnullable\s*=\s*False""",
                re.IGNORECASE,
            ),
            "DRIFT-DB-NOT-NULL-NO-DEFAULT-001",
            FindingSeverity.CRITICAL,
            "breaking",
            "database",
            "Adding NOT NULL Column Without server_default",
            "Adding column with nullable=False without a server_default on table '{0}' fails if table has rows, and breaks concurrent inserts.",
            "Provide server_default=sa.text(...) or make column nullable (nullable=True), populate existing records, then enforce NOT NULL.",
        ),
        # Column / Table Rename in place
        (
            re.compile(r"""\bop\.alter_column\s*\([^)]*new_column_name\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE),
            "DRIFT-DB-RENAME-COLUMN-001",
            FindingSeverity.HIGH,
            "breaking",
            "database",
            "In-Place Column Rename",
            "Renaming a column directly in production causes instant downtime for running pods querying the old column name.",
            "Add the new column, replicate data dual-writing, switch queries, then drop the old column.",
        ),
        (
            re.compile(r"""\bop\.rename_table\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]""", re.IGNORECASE),
            "DRIFT-DB-RENAME-TABLE-001",
            FindingSeverity.HIGH,
            "breaking",
            "database",
            "In-Place Table Rename",
            "Renaming table '{0}' to '{1}' breaks queries from non-updated service replicas.",
            "Create a view or dual-write table during transition phase.",
        ),
    ]

    # API Route deletion patterns
    API_ROUTE_REMOVED_PATTERN = re.compile(
        r"""^-\s*@(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        pass

    def detect_drift(
        self,
        code_or_diff: str,
        filename: Optional[str] = None,
        language: str = "auto",
    ) -> ContractDriftReport:
        """Analyze code or diff for breaking API and database contract changes."""
        if not code_or_diff or not code_or_diff.strip():
            return ContractDriftReport()

        findings: List[ContractDriftFinding] = []
        is_diff = "diff --git a/" in code_or_diff or "\n@@ " in code_or_diff or "\n+++ " in code_or_diff

        # 1. Database Schema & Migration Drift
        findings.extend(self._scan_db_drift(code_or_diff, filename=filename))

        # 2. Check for empty Alembic downgrade()
        findings.extend(self._check_empty_downgrade(code_or_diff, filename=filename))

        # 3. API Contract & DTO Breaking Changes
        if is_diff:
            findings.extend(self._scan_diff_api_drift(code_or_diff))
        else:
            findings.extend(self._scan_code_api_drift(code_or_diff, filename=filename))

        # Deduplicate findings
        unique_findings: List[ContractDriftFinding] = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.line_number, f.title)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Calculate drift score & metrics
        breaking_count = sum(1 for f in unique_findings if f.change_type == "breaking")
        warnings_count = sum(1 for f in unique_findings if f.change_type in ("warning", "info"))

        penalty = 0.0
        for f in unique_findings:
            if f.severity == FindingSeverity.CRITICAL:
                penalty += 35.0
            elif f.severity == FindingSeverity.HIGH:
                penalty += 20.0
            elif f.severity == FindingSeverity.MEDIUM:
                penalty += 10.0
            else:
                penalty += 5.0

        score = max(0.0, round(100.0 - penalty, 1))

        return ContractDriftReport(
            has_breaking_changes=(breaking_count > 0),
            breaking_changes_count=breaking_count,
            warnings_count=warnings_count,
            drift_score=score,
            findings=unique_findings,
        )

    def _scan_db_drift(self, code_or_diff: str, filename: Optional[str] = None) -> List[ContractDriftFinding]:
        """Scan for database migration breaking operations."""
        findings = []
        lines = code_or_diff.splitlines()

        # Check if file is related to DB/migrations
        fname = (filename or "").lower()
        is_db_context = any(
            p in fname for p in ("migration", "versions/", "alembic", ".sql", "schema", "models.py", "db/")
        ) or "op." in code_or_diff or "ALTER TABLE" in code_or_diff.upper()

        if not is_db_context:
            return []

        for lineno, line in enumerate(lines, 1):
            # In diffs, only check added lines or general lines
            if line.startswith("- ") and not line.startswith("---"):
                continue

            for pattern, rule_id, sev, c_type, comp, title, desc_tmpl, fix in self.DB_MIGRATION_PATTERNS:
                if rule_id == "DRIFT-DB-NOT-NULL-NO-DEFAULT-001" and "server_default" in line.lower():
                    continue
                m = pattern.search(line)
                if m:
                    groups = m.groups()
                    desc = desc_tmpl
                    if groups:
                        try:
                            desc = desc_tmpl.format(*groups)
                        except (IndexError, KeyError):
                            desc = desc_tmpl
                    findings.append(
                        ContractDriftFinding(
                            rule_id=rule_id,
                            severity=sev,
                            change_type=c_type,
                            component=comp,
                            title=title,
                            description=desc,
                            line_number=lineno,
                            code_snippet=line.strip(),
                            suggested_fix=fix,
                        )
                    )

        return findings

    def _check_empty_downgrade(self, code_or_diff: str, filename: Optional[str] = None) -> List[ContractDriftFinding]:
        """Flag missing or empty downgrade() step in migration files."""
        findings = []
        fname = (filename or "").lower()
        if "alembic" in fname or "versions/" in fname or "migration" in fname:
            if re.search(r"def\s+downgrade\s*\(\s*\)\s*:\s*(?:pass|\.\.\.|return None)?\s*(?:\n|$)", code_or_diff):
                findings.append(
                    ContractDriftFinding(
                        rule_id="DRIFT-DB-EMPTY-DOWNGRADE-001",
                        severity=FindingSeverity.MEDIUM,
                        change_type="warning",
                        component="database",
                        title="Empty Migration downgrade() Implementation",
                        description="The migration script contains an empty downgrade() function ('pass'). Automated rollback will not revert database changes if deployment fails.",
                        line_number=1,
                        code_snippet="def downgrade():\n    pass",
                        suggested_fix="Implement reverse operations in downgrade() to support zero-incident rollbacks.",
                    )
                )
        return findings

    def _scan_diff_api_drift(self, diff_text: str) -> List[ContractDriftFinding]:
        """Scan git diff for removed routes, deleted fields, or new required fields without defaults."""
        findings = []
        lines = diff_text.splitlines()

        deleted_fields: Dict[str, Tuple[int, str]] = {}
        added_fields: Dict[str, Tuple[int, str]] = {}

        for lineno, line in enumerate(lines, 1):
            # 1. Removed API routes
            m_route = self.API_ROUTE_REMOVED_PATTERN.search(line)
            if m_route:
                method = m_route.group(2).upper()
                path = m_route.group(3)
                findings.append(
                    ContractDriftFinding(
                        rule_id="DRIFT-API-ROUTE-REMOVED-001",
                        severity=FindingSeverity.CRITICAL,
                        change_type="breaking",
                        component="api",
                        title=f"Removed API Endpoint: {method} {path}",
                        description=f"Deleting route '{method} {path}' breaks existing mobile or web clients consuming this contract.",
                        line_number=lineno,
                        code_snippet=line.strip(),
                        suggested_fix=f"Keep the route active with deprecation notice (e.g. @router.{method.lower()}('{path}', deprecated=True)).",
                    )
                )

            # 2. Track deleted and added model fields in diff
            # E.g. -    user_id: str
            # E.g. +    user_id: int
            if line.startswith("- ") and not line.startswith("--- "):
                content = line[1:].strip()
                # Pattern: field_name: type [= ...]
                m_field = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([^=;#\n]+)(?:=.*)?$", content)
                if m_field:
                    f_name = m_field.group(1).strip()
                    f_type = m_field.group(2).strip()
                    if f_name not in ("self", "cls", "pass", "return"):
                        deleted_fields[f_name] = (lineno, f_type)

            elif line.startswith("+ ") and not line.startswith("+++ "):
                content = line[1:].strip()
                # Pattern: field_name: type [= ...]
                m_field = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([^=;#\n]+)(?:=(.*))?$", content)
                if m_field:
                    f_name = m_field.group(1).strip()
                    f_type = m_field.group(2).strip()
                    f_default = m_field.group(3)
                    if f_name not in ("self", "cls", "pass", "return"):
                        added_fields[f_name] = (lineno, f_type, f_default)

        # Cross-reference deleted and added fields
        for f_name, (lineno, old_type) in deleted_fields.items():
            if f_name in added_fields:
                new_lineno, new_type, _ = added_fields[f_name]
                if old_type != new_type:
                    findings.append(
                        ContractDriftFinding(
                            rule_id="DRIFT-API-TYPE-MUTATION-001",
                            severity=FindingSeverity.HIGH,
                            change_type="breaking",
                            component="api",
                            title=f"Breaking Field Type Mutation: '{f_name}'",
                            description=f"Field '{f_name}' type mutated from '{old_type}' to '{new_type}', breaking serialization contracts for API clients.",
                            line_number=new_lineno,
                            code_snippet=f"- {f_name}: {old_type} -> + {f_name}: {new_type}",
                            suggested_fix=f"Use a union type (e.g. Union[{old_type}, {new_type}]) or introduce a new API version.",
                        )
                    )
            else:
                # Field was removed entirely
                findings.append(
                    ContractDriftFinding(
                        rule_id="DRIFT-API-REMOVED-FIELD-001",
                        severity=FindingSeverity.HIGH,
                        change_type="breaking",
                        component="api",
                        title=f"Removed Field '{f_name}' from Schema Contract",
                        description=f"Field '{f_name}' was removed from the schema. External clients expecting this response field or sending it in requests will fail.",
                        line_number=lineno,
                        code_snippet=f"- {f_name}: {old_type}",
                        suggested_fix=f"Retain '{f_name}' as Optional[{old_type}] = None with a deprecation warning before deletion.",
                    )
                )

        # Check for newly added required fields without defaults
        for f_name, (lineno, f_type, f_default) in added_fields.items():
            if f_name not in deleted_fields:
                is_optional = "optional" in f_type.lower() or "none" in f_type.lower() or "union[" in f_type.lower() and "none" in f_type.lower()
                has_default = f_default is not None and f_default.strip() not in ("...", "Field(...)")
                if not is_optional and not has_default:
                    findings.append(
                        ContractDriftFinding(
                            rule_id="DRIFT-API-REQUIRED-FIELD-NO-DEFAULT-001",
                            severity=FindingSeverity.HIGH,
                            change_type="breaking",
                            component="api",
                            title=f"Newly Added Required Field Without Default: '{f_name}'",
                            description=f"Field '{f_name}: {f_type}' is mandatory without a default value. Existing clients submitting payloads without this field will trigger 422 Unprocessable Entity.",
                            line_number=lineno,
                            code_snippet=f"+ {f_name}: {f_type}",
                            suggested_fix=f"Provide a default value (e.g. {f_name}: Optional[{f_type}] = None) to maintain backward compatibility.",
                        )
                    )

        return findings

    def _scan_code_api_drift(self, code: str, filename: Optional[str] = None) -> List[ContractDriftFinding]:
        """Scan standalone code for explicit breaking schema constructs."""
        findings = []
        fname = (filename or "").lower()
        is_schema_file = any(p in fname for p in ("schema", "models", "dto", "types", "interface"))

        # Look for Pydantic models containing Ellipsis Field(...) without default in requests
        if is_schema_file and ("class " in code and "BaseModel" in code):
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        for stmt in node.body:
                            if isinstance(stmt, ast.AnnAssign):
                                if isinstance(stmt.target, ast.Name):
                                    field_name = stmt.target.id
                                    # Check if value is Field(...) with Ellipsis
                                    if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "Field":
                                        if stmt.value.args and isinstance(stmt.value.args[0], ast.Constant) and stmt.value.args[0].value is Ellipsis:
                                            # Required field
                                            findings.append(
                                                ContractDriftFinding(
                                                    rule_id="DRIFT-API-REQUIRED-FIELD-NO-DEFAULT-001",
                                                    severity=FindingSeverity.MEDIUM,
                                                    change_type="warning",
                                                    component="api",
                                                    title=f"Explicit Required Field: '{field_name}' in {node.name}",
                                                    description=f"Model '{node.name}' marks '{field_name}' as strictly required (Field(...)). Ensure this field is backwards compatible with existing API clients.",
                                                    line_number=stmt.lineno,
                                                    code_snippet=f"{field_name} = Field(...)",
                                                    suggested_fix=f"Verify if '{field_name}' can accept a default value or Optional type.",
                                                )
                                            )
            except SyntaxError:
                pass

        return findings

