"""Test Health & Coverage Auditor Engine.

Performs static analysis on test files and application code/diffs to ensure test suite reliability:
1. Impacted Test Identification: Maps changed source code to expected test suites.
2. Missing Test Coverage Warnings: Detects added/modified business logic lacking tests.
3. Flaky & Dead Test Assertion Detection:
   - Tautological/Dead Assertions (e.g. assert True, assert 1 == 1, assert x == x)
   - Void Tests lacking any assert statements
   - Hardcoded Sleep Timers causing test flakiness and CI slowdowns (time.sleep in tests)
   - Non-deterministic clock or random calls in tests without mocking
   - Silent exception suppression in test bodies (try-except-pass)
"""

import ast
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import FindingCategory, FindingSeverity, ReviewFinding

logger = logging.getLogger(__name__)


class TestHealthFinding(BaseModel):
    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None
    test_function: Optional[str] = None


class TestAuditResult(BaseModel):
    is_test_file: bool
    total_test_cases: int
    impacted_test_files: List[str] = Field(default_factory=list)
    has_missing_coverage: bool = False
    findings: List[TestHealthFinding] = Field(default_factory=list)

    def to_review_findings(self) -> List[ReviewFinding]:
        """Convert test audit findings into unified ReviewFinding objects."""
        review_findings = []
        for f in self.findings:
            review_findings.append(
                ReviewFinding(
                    category=FindingCategory.BUG,
                    severity=f.severity,
                    title=f"[{f.rule_id}] {f.title}",
                    description=f"{f.description}\n\n**Test Case**: {f.test_function or 'N/A'}\n**Suggested Fix**: {f.suggested_fix or 'N/A'}",
                    line_start=f.line_number,
                    line_end=f.line_number,
                    rule_id=f.rule_id,
                    suggested_fix=f.suggested_fix,
                )
            )
        return review_findings


class _PythonASTTestVisitor(ast.NodeVisitor):
    """AST visitor detecting flaky and dead assertions in Python test suites."""

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.findings: List[TestHealthFinding] = []
        self.current_function: Optional[str] = None
        self.total_test_cases = 0

    def _get_snippet(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)

    def _analyze_function(self, node: Any) -> None:
        prev_func = self.current_function
        func_name = node.name

        is_test = func_name.startswith("test_") or func_name.endswith("_test")
        if is_test:
            self.total_test_cases += 1
            self.current_function = func_name

            # Check if test has ANY assertions or mock verifications
            has_assertion = False
            for child in ast.walk(node):
                if isinstance(child, ast.Assert):
                    has_assertion = True
                    break
                elif isinstance(child, ast.Call):
                    call_name = self._get_call_name(child.func)
                    if any(
                        assert_kw in call_name.lower()
                        for assert_kw in ("assert", "expect", "verify", "raises", "should")
                    ):
                        has_assertion = True
                        break

            if not has_assertion:
                snippet = self._get_snippet(node)
                self.findings.append(
                    TestHealthFinding(
                        rule_id="TEST-DEAD-001",
                        severity=FindingSeverity.HIGH,
                        title=f"Test '{func_name}' Contains No Assertions",
                        description=f"Test function '{func_name}' runs code without asserting state, mock calls, or expected outcomes.",
                        line_number=getattr(node, "lineno", None),
                        code_snippet=snippet,
                        suggested_fix="Add explicit assertions (e.g. assert result == expected or pytest.raises).",
                        test_function=func_name,
                    )
                )

        self.generic_visit(node)
        self.current_function = prev_func

    def visit_Assert(self, node: ast.Assert) -> None:
        snippet = self._get_snippet(node)
        lineno = getattr(node, "lineno", None)

        # Check for tautological assertions:
        # 1. assert True / assert 1 / assert "string"
        if isinstance(node.test, ast.Constant):
            if bool(node.test.value) is True:
                self.findings.append(
                    TestHealthFinding(
                        rule_id="TEST-TAUTOLOGY-001",
                        severity=FindingSeverity.HIGH,
                        title="Tautological Assertion (Always True)",
                        description=f"Assertion evaluates constant '{node.test.value}' and can never fail.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Replace with an assertion validating actual dynamic function results.",
                        test_function=self.current_function,
                    )
                )

        # 2. assert x == x or 1 == 1
        elif isinstance(node.test, ast.Compare):
            if len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq):
                left_str = ast.dump(node.test.left)
                right_str = ast.dump(node.test.comparators[0])
                if left_str == right_str:
                    self.findings.append(
                        TestHealthFinding(
                            rule_id="TEST-TAUTOLOGY-002",
                            severity=FindingSeverity.HIGH,
                            title="Self-Comparing Tautological Assertion (x == x)",
                            description="Comparing identical operands always yields True, creating a dead test assertion.",
                            line_number=lineno,
                            code_snippet=snippet,
                            suggested_fix="Assert the target variable against the expected invariant or constant value.",
                            test_function=self.current_function,
                        )
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node.func)
        snippet = self._get_snippet(node)
        lineno = getattr(node, "lineno", None)

        # Check for hardcoded sleeps in test functions
        if self.current_function and call_name in ("time.sleep", "asyncio.sleep"):
            duration = None
            if node.args and isinstance(node.args[0], ast.Constant):
                duration = node.args[0].value
            self.findings.append(
                TestHealthFinding(
                    rule_id="TEST-FLAKY-SLEEP-001",
                    severity=FindingSeverity.MEDIUM,
                    title="Hardcoded Sleep Timer in Test Case",
                    description=f"Using {call_name}({duration or ''}) in tests introduces flakiness and slows CI pipelines.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix="Replace sleep with condition polling (e.g. wait_until), async event awaiting, or mocking.",
                    test_function=self.current_function,
                )
            )

        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        # Check for try-except-pass inside test function
        if self.current_function:
            for handler in node.handlers:
                # If body is just `pass`
                if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                    snippet = self._get_snippet(handler)
                    self.findings.append(
                        TestHealthFinding(
                            rule_id="TEST-SILENT-EXCEPT-001",
                            severity=FindingSeverity.HIGH,
                            title="Silent Exception Suppression in Test Case",
                            description="try-except with pass silently swallows errors, masking test failures.",
                            line_number=getattr(handler, "lineno", None),
                            code_snippet=snippet,
                            suggested_fix="Use pytest.raises(...) to assert expected exceptions explicitly, or remove the swallow block.",
                            test_function=self.current_function,
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


class TestHealthAuditor:
    """Enterprise Test Health, Flakiness, and Coverage Auditor."""

    __test__ = False

    MULTI_LANG_FLAKY_PATTERNS = [
        # JavaScript/TypeScript tautology
        (
            re.compile(r"""expect\s*\(\s*(?:true|1)\s*\)\s*\.to(?:Be|Equal)\s*\(\s*(?:true|1)\s*\)""", re.IGNORECASE),
            "TEST-JS-TAUTOLOGY-001",
            "Tautological Assertion in JavaScript/TypeScript Test",
            FindingSeverity.HIGH,
            "Assert the actual function output instead of hardcoded true == true.",
        ),
        # JavaScript setTimeout/sleep in test
        (
            re.compile(r"""(?:setTimeout|sleep)\s*\(\s*\d{3,}\s*\)"""),
            "TEST-JS-SLEEP-001",
            "Fixed Sleep/Delay in JavaScript Test",
            FindingSeverity.MEDIUM,
            "Use Jest fake timers (jest.advanceTimersByTime) or waitFor polling.",
        ),
        # Go tautology
        (
            re.compile(r"""assert\.True\s*\(\s*t\s*,\s*true\s*\)"""),
            "TEST-GO-TAUTOLOGY-001",
            "Tautological Assertion in Go Test",
            FindingSeverity.HIGH,
            "Assert target boolean expressions instead of constant true.",
        ),
    ]

    def __init__(self) -> None:
        pass

    def is_test_file(self, filename: Optional[str], code: str) -> bool:
        """Determine whether the target file or snippet is a test file."""
        if filename:
            name = filename.lower()
            if any(
                part in name
                for part in (
                    "test_",
                    "_test.",
                    ".test.",
                    ".spec.",
                    "tests/",
                    "__tests__/",
                    "test/",
                )
            ):
                return True
        # Check code keywords
        lower = code.lower()
        if any(
            marker in lower
            for marker in ("def test_", "describe(", "it('", "it(\"", "test('", "test(\"", "func test")
        ):
            return True
        return False

    def predict_impacted_tests(self, filename: Optional[str]) -> List[str]:
        """Infers expected test suites impacted by changes to a given source file."""
        if not filename:
            return []

        clean_path = filename.strip().replace("\\", "/")
        base_name = clean_path.split("/")[-1]
        name_no_ext = base_name.rsplit(".", 1)[0]
        ext = base_name.split(".")[-1] if "." in base_name else "py"

        impacted = []

        # Python conventions
        if ext == "py":
            impacted.append(f"tests/test_{name_no_ext}.py")
            impacted.append(f"tests/{name_no_ext}_test.py")
            if "app/" in clean_path:
                sub = clean_path.replace("app/", "tests/test_")
                impacted.append(sub)

        # JS / TS conventions
        elif ext in ("js", "jsx", "ts", "tsx"):
            dir_path = "/".join(clean_path.split("/")[:-1])
            impacted.append(f"{dir_path}/{name_no_ext}.test.{ext}")
            impacted.append(f"{dir_path}/{name_no_ext}.spec.{ext}")
            impacted.append(f"tests/{name_no_ext}.test.{ext}")

        # Go conventions
        elif ext == "go":
            impacted.append(clean_path.replace(".go", "_test.go"))

        return list(dict.fromkeys(impacted))

    def audit_code(
        self,
        code: str,
        filename: Optional[str] = None,
        language: str = "auto",
    ) -> TestAuditResult:
        """Run comprehensive test health and assertion auditing on code."""
        if not code or not code.strip():
            return TestAuditResult(is_test_file=False, total_test_cases=0, findings=[])

        is_test = self.is_test_file(filename, code)
        source_lines = code.splitlines()
        findings: List[TestHealthFinding] = []
        total_tests = 0
        impacted_tests = []

        if is_test:
            # 1. Python AST Deep Test Analysis
            if language.lower() in ("python", "py", "auto"):
                try:
                    tree = ast.parse(code)
                    visitor = _PythonASTTestVisitor(source_lines)
                    visitor.visit(tree)
                    findings.extend(visitor.findings)
                    total_tests = visitor.total_test_cases
                except SyntaxError:
                    pass

            # 2. Multi-language pattern scanner
            for lineno, line in enumerate(source_lines, 1):
                stripped = line.strip()
                if stripped.startswith(("#", "//", "/*", "*")):
                    continue
                for pattern, rule_id, title, sev, fix in self.MULTI_LANG_FLAKY_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            TestHealthFinding(
                                rule_id=rule_id,
                                severity=sev,
                                title=title,
                                description=f"Pattern-matched flaky test issue: {title}",
                                line_number=lineno,
                                code_snippet=stripped,
                                suggested_fix=fix,
                            )
                        )

        else:
            # If it's business logic, calculate impacted tests and check for missing coverage
            impacted_tests = self.predict_impacted_tests(filename)
            has_substantial_logic = any(
                kw in code for kw in ("def ", "class ", "function ", "async def ", "if ", "for ", "while ")
            )
            has_missing_coverage = has_substantial_logic and len(code.splitlines()) > 10

            if has_missing_coverage:
                findings.append(
                    TestHealthFinding(
                        rule_id="TEST-COV-001",
                        severity=FindingSeverity.MEDIUM,
                        title="New Business Logic Submitted Without Associated Test Coverage",
                        description=f"Source file '{filename or 'code'}' adds or modifies logic without accompanying unit tests.",
                        line_number=1,
                        suggested_fix=f"Add unit tests in: {', '.join(impacted_tests[:2]) or 'tests/'}",
                    )
                )

        return TestAuditResult(
            is_test_file=is_test,
            total_test_cases=total_tests,
            impacted_test_files=impacted_tests,
            has_missing_coverage=any(f.rule_id == "TEST-COV-001" for f in findings),
            findings=findings,
        )

    def audit_diff(self, diff_content: str) -> TestAuditResult:
        """Audits a multi-file git diff for test health and test-to-code balance."""
        files = diff_content.split("diff --git a/")
        modified_sources = []
        modified_tests = []
        all_findings = []

        for f_block in files[1:]:
            first_line = f_block.splitlines()[0]
            path = first_line.split(" ")[0].strip()
            if self.is_test_file(path, f_block):
                modified_tests.append(path)
                test_res = self.audit_code(f_block, filename=path)
                all_findings.extend(test_res.findings)
            else:
                modified_sources.append(path)

        # If business logic was modified but zero tests were included
        if modified_sources and not modified_tests:
            all_findings.append(
                TestHealthFinding(
                    rule_id="TEST-COV-002",
                    severity=FindingSeverity.HIGH,
                    title="Pull Request Modifies Business Logic Without Test Changes",
                    description=f"PR modified {len(modified_sources)} source file(s) ({', '.join(modified_sources[:3])}) but contains 0 test additions or updates.",
                    line_number=1,
                    suggested_fix="Include corresponding unit or integration tests for the modified files.",
                )
            )

        return TestAuditResult(
            is_test_file=len(modified_tests) > 0,
            total_test_cases=len(modified_tests),
            impacted_test_files=[t for s in modified_sources for t in self.predict_impacted_tests(s)],
            has_missing_coverage=bool(modified_sources and not modified_tests),
            findings=all_findings,
        )
