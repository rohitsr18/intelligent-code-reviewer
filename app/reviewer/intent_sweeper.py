"""PR Intent Verification & Leftover Artifact Sweeper.

Ensures pull requests and code modifications remain true to their stated intent
while aggressively sweeping for leftover development and debugging artifacts:
1. Scope Drift & Intent Verification:
   - Validates that code diffs match stated PR description / commit task context.
   - Flags unintended modifications to sensitive or unrelated modules (scope creep).
   - Identifies stated promises missing from the code diff.
2. Leftover Debugging & Development Artifact Sweep:
   - Python: breakpoint(), pdb.set_trace(), unescaped debug print() calls in production.
   - JS / TS: console.log, console.debug, debugger statements.
   - Go / Java: fmt.Println in packages, System.out.println, e.printStackTrace().
   - Universal: Stray merge conflict markers (<<<<<<<, =======, >>>>>>>).
   - Temporary dev tags: 'TODO: remove', 'FIXME: temporary', 'HACK: delete before merge', 'TEMP: debug'.
"""

import ast
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import FindingCategory, FindingSeverity, ReviewFinding

logger = logging.getLogger(__name__)


class ArtifactFinding(BaseModel):
    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None


class IntentAuditReport(BaseModel):
    intent_alignment_score: float = 100.0
    is_aligned: bool = True
    scope_drift_detected: bool = False
    drift_reasons: List[str] = Field(default_factory=list)
    unintended_files: List[str] = Field(default_factory=list)
    missing_stated_items: List[str] = Field(default_factory=list)
    artifact_findings: List[ArtifactFinding] = Field(default_factory=list)
    total_artifacts_count: int = 0

    def to_review_findings(self) -> List[ReviewFinding]:
        """Convert intent and artifact findings into unified ReviewFinding objects."""
        review_findings = []

        # Scope drift findings
        if self.scope_drift_detected:
            reasons_str = "\n".join(f"- {r}" for r in self.drift_reasons)
            review_findings.append(
                ReviewFinding(
                    category=FindingCategory.ARCHITECTURE,
                    severity=FindingSeverity.HIGH,
                    title="[INTENT-DRIFT-001] Code Changes Diverge from Stated PR Intent",
                    description=f"PR modifications appear to exceed or diverge from the stated task context.\n\n**Detected Scope Drift**:\n{reasons_str}",
                    line_start=1,
                    line_end=1,
                    rule_id="INTENT-DRIFT-001",
                    suggested_fix="Split unrelated modifications into a separate PR or update the PR context description.",
                )
            )

        # Artifact sweep findings
        for a in self.artifact_findings:
            review_findings.append(
                ReviewFinding(
                    category=FindingCategory.MAINTAINABILITY,
                    severity=a.severity,
                    title=f"[{a.rule_id}] {a.title}",
                    description=f"{a.description}\n\n**Suggested Action**: {a.suggested_fix or 'Remove debug artifact'}",
                    line_start=a.line_number,
                    line_end=a.line_number,
                    rule_id=a.rule_id,
                    suggested_fix=a.suggested_fix,
                )
            )

        return review_findings


class _PythonASTArtifactVisitor(ast.NodeVisitor):
    """AST visitor for identifying Python debugger traps and stray print statements."""

    def __init__(self, source_lines: List[str], filename: Optional[str] = None) -> None:
        self.source_lines = source_lines
        self.filename = (filename or "").lower()
        self.findings: List[ArtifactFinding] = []

    def _get_snippet(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node.func)
        snippet = self._get_snippet(node)
        lineno = getattr(node, "lineno", None)

        # 1. breakpoint() or pdb.set_trace()
        if func_name in ("breakpoint", "builtins.breakpoint"):
            self.findings.append(
                ArtifactFinding(
                    rule_id="ART-PY-BREAKPOINT-001",
                    severity=FindingSeverity.CRITICAL,
                    title="Active Debugger Breakpoint in Production Code",
                    description=f"Invocation of {func_name}() will halt execution in production environments.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix=f"Remove '{snippet}' before merging to production.",
                )
            )
        elif func_name in ("pdb.set_trace", "ipdb.set_trace"):
            self.findings.append(
                ArtifactFinding(
                    rule_id="ART-PY-PDB-001",
                    severity=FindingSeverity.CRITICAL,
                    title="Active pdb Debugger Trap in Python Code",
                    description=f"Invocation of {func_name}() will halt execution in production environments.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix=f"Remove '{snippet}' before merging to production.",
                )
            )

        # 2. print(...) in non-script / non-test application code
        elif func_name == "print":
            is_script_or_test = any(
                p in self.filename
                for p in ("test_", "_test.", "cli.py", "cli/", "/cli", "scripts/", "manage.py", "setup.py", "test/")
            )
            if not is_script_or_test:
                self.findings.append(
                    ArtifactFinding(
                        rule_id="ART-DEBUG-PRINT-001",
                        severity=FindingSeverity.LOW,
                        title="Leftover print() Statement in Production Module",
                        description="Direct print() statements pollute stdout and bypass structured logging pipelines.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Replace with structured logger (e.g. logger.info or logger.debug).",
                    )
                )

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            prefix = self._get_call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""


class IntentArtifactSweeper:
    """Enterprise PR Intent Verifier & Leftover Artifact Sweeper."""

    # Universal Artifact Regexes
    ARTIFACT_PATTERNS = [
        # Git merge conflict markers
        (
            re.compile(r"^\s*(?:<<<<<<<|=======|>>>>>>>)(?:\s.*)?$"),
            "ART-GIT-CONFLICT-001",
            FindingSeverity.CRITICAL,
            "Unresolved Git Merge Conflict Marker",
            "Unresolved conflict delimiter detected; file contains unmerged code.",
            "Resolve the git merge conflict and remove conflict markers.",
        ),
        # Temporary development tags
        (
            re.compile(
                r"""(?:#|//|/\*)\s*(?:TODO|FIXME|HACK|TEMP|XXX)\s*:\s*(?:remove|delete|temporary|temp|debug|debugging|test only|cleanup before merge)\b""",
                re.IGNORECASE,
            ),
            "ART-DEV-TEMP-TAG-001",
            FindingSeverity.MEDIUM,
            "Unresolved Temporary Dev Tag ('TODO: remove' / 'TEMP: debug')",
            "Developer tag indicates code was intended as a temporary scratch fix.",
            "Remove the temporary code or finalize implementation before merging.",
        ),
        # JavaScript/TypeScript console.log / console.debug / debugger
        (
            re.compile(r"""\bconsole\.(?:log|debug|dir|table)\s*\("""),
            "ART-JS-CONSOLE-001",
            FindingSeverity.LOW,
            "Leftover console.log Statement in Production Code",
            "console.log calls clutter browser/server logs and may inadvertently leak internal state.",
            "Remove console.log or use a structured logging utility.",
        ),
        (
            re.compile(r"""^\s*debugger\s*;?"""),
            "ART-JS-DEBUGGER-001",
            FindingSeverity.CRITICAL,
            "Active debugger; Statement in JavaScript Code",
            "debugger statement suspends JavaScript execution if developer tools are open.",
            "Remove 'debugger;' statement.",
        ),
        # Java System.out.println / printStackTrace
        (
            re.compile(r"""\bSystem\.out\.print(?:ln)?\s*\("""),
            "ART-JAVA-PRINT-001",
            FindingSeverity.LOW,
            "System.out.println in Java Production Code",
            "System.out.println bypasses enterprise logging frameworks (SLF4J/Logback).",
            "Replace with logger.debug(...) or logger.info(...).",
        ),
        (
            re.compile(r"""\b\.printStackTrace\s*\(\s*\)"""),
            "ART-JAVA-STACKTRACE-001",
            FindingSeverity.MEDIUM,
            "Raw e.printStackTrace() Call in Java Code",
            "printStackTrace prints directly to stderr, masking exceptions from logging aggregators.",
            "Use logger.error('Context error message', e) to log exceptions safely.",
        ),
        # Go fmt.Println in non-main packages
        (
            re.compile(r"""\bfmt\.Print(?:ln|f)?\s*\("""),
            "ART-GO-PRINT-001",
            FindingSeverity.LOW,
            "fmt.Println in Go Package Code",
            "Direct fmt.Println calls in libraries and services bypass structured loggers (zap/zerolog).",
            "Use a configured structured logger instead of fmt.Println.",
        ),
    ]

    # Sensitive modules that should not drift unexpectedly
    SENSITIVE_DOMAINS = {
        "auth": ["auth", "login", "jwt", "token", "session", "permission", "iap"],
        "billing": ["billing", "payment", "stripe", "charge", "subscription", "pricing"],
        "database": ["migration", "schema", "database", "models.py", "db/"],
        "security": ["sanitizer", "guard", "crypto", "firewall", "secret"],
        "infrastructure": ["dockerfile", "cd.yml", "ci.yml", "deploy", "terraform", "k8s"],
    }

    def __init__(self) -> None:
        pass

    def sweep_artifacts(
        self,
        code: str,
        language: str = "auto",
        filename: Optional[str] = None,
    ) -> List[ArtifactFinding]:
        """Scan code for leftover debugging and development artifacts."""
        if not code or not code.strip():
            return []

        source_lines = code.splitlines()
        findings: List[ArtifactFinding] = []

        # 1. Python AST Deep Scan
        lang = language.lower()
        if lang in ("python", "py", "auto"):
            try:
                tree = ast.parse(code)
                visitor = _PythonASTArtifactVisitor(source_lines, filename=filename)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # 2. Universal & Multi-language Regex Sweeper
        for lineno, line in enumerate(source_lines, 1):
            for pattern, rule_id, sev, title, desc, fix in self.ARTIFACT_PATTERNS:
                if pattern.search(line):
                    # Avoid duplicate if AST already flagged print in python
                    if rule_id == "ART-DEBUG-PRINT-001" and any(
                        f.rule_id == rule_id and f.line_number == lineno for f in findings
                    ):
                        continue
                    findings.append(
                        ArtifactFinding(
                            rule_id=rule_id,
                            severity=sev,
                            title=title,
                            description=desc,
                            line_number=lineno,
                            code_snippet=line.strip(),
                            suggested_fix=fix,
                        )
                    )

        # Deduplicate
        unique = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def verify_intent(
        self,
        code_or_diff: str,
        context: Optional[str] = None,
        filename: Optional[str] = None,
        language: str = "auto",
    ) -> IntentAuditReport:
        """Verify code alignment against declared context and sweep for artifacts."""
        artifacts = self.sweep_artifacts(code=code_or_diff, language=language, filename=filename)

        if not context or not context.strip():
            # No context declared: cannot determine drift, only artifacts
            return IntentAuditReport(
                intent_alignment_score=100.0,
                is_aligned=True,
                scope_drift_detected=False,
                artifact_findings=artifacts,
                total_artifacts_count=len(artifacts),
            )

        context_lower = context.lower()
        drift_reasons: List[str] = []
        unintended_files: List[str] = []
        missing_items: List[str] = []

        # Determine target domains from context
        context_domains = set()
        for domain, keywords in self.SENSITIVE_DOMAINS.items():
            if any(kw in context_lower for kw in keywords):
                context_domains.add(domain)

        # Detect files from diff or filename
        modified_files = []
        if "diff --git a/" in code_or_diff:
            for chunk in code_or_diff.split("diff --git a/")[1:]:
                header = chunk.splitlines()[0]
                path = header.split(" ")[0].strip()
                modified_files.append(path)
        elif filename:
            modified_files.append(filename)

        # Check for scope creep in sensitive domains
        for f_path in modified_files:
            f_lower = f_path.lower()
            for domain, keywords in self.SENSITIVE_DOMAINS.items():
                if any(kw in f_lower for kw in keywords):
                    if domain not in context_domains:
                        unintended_files.append(f_path)
                        drift_reasons.append(
                            f"File '{f_path}' touches '{domain}' domain, which was not mentioned in context '{context}'."
                        )

        # Check if prominent context terms are completely missing from the changes
        significant_terms = [
            w for w in re.findall(r"\b[a-zA-Z]{4,}\b", context_lower)
            if w not in ("with", "from", "that", "this", "have", "make", "need", "into", "some", "only")
        ]
        code_lower = code_or_diff.lower()
        for term in significant_terms[:4]:
            if term not in code_lower:
                missing_items.append(term)

        # Calculate alignment score
        score = 100.0
        if unintended_files:
            score -= min(50.0, len(unintended_files) * 30.0)
        if len(missing_items) >= 3:
            score -= 25.0
            drift_reasons.append(
                f"Key keywords from PR context ({', '.join(missing_items[:3])}) were not found in the code changes."
            )

        has_drift = len(drift_reasons) > 0 or score < 75.0

        return IntentAuditReport(
            intent_alignment_score=max(0.0, round(score, 1)),
            is_aligned=not has_drift,
            scope_drift_detected=has_drift,
            drift_reasons=drift_reasons,
            unintended_files=list(dict.fromkeys(unintended_files)),
            missing_stated_items=missing_items,
            artifact_findings=artifacts,
            total_artifacts_count=len(artifacts),
        )
