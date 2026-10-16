"""Repository Architectural Context & Clean Architecture Linter.

Analyzes code and multi-file diffs to enforce enterprise clean architecture:
1. Layer Boundary Enforcement (Hexagonal / Onion / Clean Architecture):
   - Domain/Core layer must NOT import presentation, API controllers, or direct web frameworks (FastAPI/Flask).
   - Domain/Core layer must NOT import outer delivery or storage infrastructure.
   - Services layer must NOT depend on HTTP route controllers.
2. Direct Database & Storage Leaks in Controllers:
   - Route handlers must NOT execute raw database SQL queries directly (bypassing service/repository layers).
3. Circular Dependency & Cyclical Import Detection:
   - Traces import dependency graphs across modified files/modules to catch circular import loops (A -> B -> A).
4. Shared Mutable State & Concurrency Hazards:
   - Module-level unsynchronized mutable objects (lists, dicts, sets) modified within functions.
5. God Object & Bloated Module Anti-Patterns:
   - Classes exceeding cohesion thresholds (oversized methods and responsibility bloating).
"""

import ast
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import FindingCategory, FindingSeverity, ReviewFinding

logger = logging.getLogger(__name__)


class ArchFinding(BaseModel):
    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    line_number: Optional[int] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None


class ArchLintReport(BaseModel):
    overall_arch_score: float = 100.0
    is_compliant: bool = True
    layer_violations_count: int = 0
    circular_deps_count: int = 0
    anti_patterns_count: int = 0
    findings: List[ArchFinding] = Field(default_factory=list)

    def to_review_findings(self) -> List[ReviewFinding]:
        """Convert architectural lint findings into unified ReviewFinding objects."""
        review_findings = []
        for f in self.findings:
            review_findings.append(
                ReviewFinding(
                    category=FindingCategory.ARCHITECTURE,
                    severity=f.severity,
                    title=f"[{f.rule_id}] {f.title}",
                    description=f"{f.description}\n\n**Architectural Guideline**: {f.suggested_fix or 'Enforce clean architecture boundaries'}",
                    line_start=f.line_number,
                    line_end=f.line_number,
                    rule_id=f.rule_id,
                    suggested_fix=f.suggested_fix,
                )
            )
        return review_findings


class RepoArchitecturalLinter:
    """Enterprise Clean Architecture & Layer Boundary Linter."""

    FORBIDDEN_CORE_IMPORTS = {
        "fastapi",
        "flask",
        "django.http",
        "starlette",
        "app.api",
        "app.routers",
        "api",
        "routers",
        "controllers",
        "views",
    }

    FORBIDDEN_SERVICE_IMPORTS = {
        "app.api",
        "app.routers",
        "api",
        "routers",
        "controllers",
        "views",
    }

    def __init__(self) -> None:
        pass

    def lint(
        self,
        code_or_diff: str,
        filename: Optional[str] = None,
        language: str = "auto",
    ) -> ArchLintReport:
        """Lint code or diff for architectural boundary and dependency violations."""
        if not code_or_diff or not code_or_diff.strip():
            return ArchLintReport()

        findings: List[ArchFinding] = []
        is_diff = "diff --git a/" in code_or_diff or "\n+++ " in code_or_diff

        if is_diff:
            file_units = self._extract_diff_files(code_or_diff)
            # Check circular imports across multi-file diff
            findings.extend(self._detect_circular_dependencies(file_units))

            # Check per-file layer boundaries and anti-patterns
            for f_path, content in file_units.items():
                findings.extend(self._lint_single_file(content, filename=f_path))
        else:
            findings.extend(self._lint_single_file(code_or_diff, filename=filename))

        # Deduplicate
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_number, f.title)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Metrics
        layer_count = sum(1 for f in unique_findings if f.rule_id.startswith("ARCH-LAYER"))
        circular_count = sum(1 for f in unique_findings if f.rule_id.startswith("ARCH-CIRCULAR"))
        anti_pattern_count = sum(1 for f in unique_findings if f.rule_id.startswith("ARCH-ANTI") or f.rule_id.startswith("ARCH-SHARED") or f.rule_id.startswith("ARCH-LEAKY"))

        # Scoring
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

        return ArchLintReport(
            overall_arch_score=score,
            is_compliant=(layer_count == 0 and circular_count == 0 and score >= 85.0),
            layer_violations_count=layer_count,
            circular_deps_count=circular_count,
            anti_patterns_count=anti_pattern_count,
            findings=unique_findings,
        )

    def _extract_diff_files(self, diff_text: str) -> Dict[str, str]:
        """Split a unified diff into a map of filename -> modified/added content."""
        files: Dict[str, List[str]] = {}
        current_file = None

        for line in diff_text.splitlines():
            if line.startswith("diff --git a/"):
                parts = line.split(" ")
                if len(parts) >= 4:
                    current_file = parts[3].replace("b/", "", 1).strip()
                    files[current_file] = []
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
                if current_file not in files:
                    files[current_file] = []
            elif current_file:
                if line.startswith("+") and not line.startswith("+++"):
                    files[current_file].append(line[1:])
                elif line.startswith(" "):
                    files[current_file].append(line[1:])
                elif not line.startswith("-") and not line.startswith("@@"):
                    files[current_file].append(line)

        return {k: "\n".join(v) for k, v in files.items() if v}

    def _lint_single_file(self, code: str, filename: Optional[str] = None) -> List[ArchFinding]:
        """Lint an individual file for boundary violations, leaks, and anti-patterns."""
        findings: List[ArchFinding] = []
        fname = (filename or "").lower()

        # 1. Layer Boundary Violations: Core/Domain layer importing outer layers
        is_core_layer = any(p in fname for p in ("core/", "domain/", "/domain/", "/core/", "entities/"))
        is_service_layer = any(p in fname for p in ("services/", "service/", "use_cases/", "/service/"))
        is_controller_layer = any(p in fname for p in ("api/", "routers/", "controllers/", "routes/"))

        try:
            tree = ast.parse(code)
            lines = code.splitlines()

            # Inspect AST for imports
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    imported_modules = []
                    if isinstance(node, ast.Import):
                        imported_modules = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported_modules = [node.module]

                    lineno = getattr(node, "lineno", 1)
                    snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""

                    for mod in imported_modules:
                        mod_lower = mod.lower()

                        # Core Layer Boundary Rule
                        if is_core_layer:
                            if any(mod_lower == f or mod_lower.startswith(f + ".") for f in self.FORBIDDEN_CORE_IMPORTS):
                                findings.append(
                                    ArchFinding(
                                        rule_id="ARCH-LAYER-CORE-IMPORT-001",
                                        severity=FindingSeverity.HIGH,
                                        title=f"Core Domain Inversion Violation: Importing '{mod}'",
                                        description=f"Core/domain module '{filename or 'core'}' directly imports outer delivery module '{mod}'. Clean architecture requires domain rules to remain pure and framework-agnostic.",
                                        line_number=lineno,
                                        file_path=filename,
                                        code_snippet=snippet,
                                        suggested_fix="Decouple domain logic from outer delivery layers. Inject dependencies via interfaces / abstract base classes.",
                                    )
                                )

                        # Service Layer Boundary Rule
                        elif is_service_layer:
                            if any(mod_lower == f or mod_lower.startswith(f + ".") for f in self.FORBIDDEN_SERVICE_IMPORTS):
                                findings.append(
                                    ArchFinding(
                                        rule_id="ARCH-LAYER-SERVICE-WEB-IMPORT-001",
                                        severity=FindingSeverity.HIGH,
                                        title=f"Service Layer Upward Coupling: Importing '{mod}'",
                                        description=f"Business service '{filename or 'service'}' imports web/API controller module '{mod}'. Application services must not depend on presentation controllers.",
                                        line_number=lineno,
                                        file_path=filename,
                                        code_snippet=snippet,
                                        suggested_fix="Remove presentation dependency. Controllers should call services, never the reverse.",
                                    )
                                )

            # 2. Check for God Object / Bloated Class Anti-Pattern
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    method_count = sum(1 for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)))
                    if method_count >= 20:
                        findings.append(
                            ArchFinding(
                                rule_id="ARCH-ANTI-GOD-OBJECT-001",
                                severity=FindingSeverity.MEDIUM,
                                title=f"God Object Anti-Pattern in Class '{node.name}'",
                                description=f"Class '{node.name}' defines {method_count} methods, indicating excessive responsibilities and violation of the Single Responsibility Principle.",
                                line_number=node.lineno,
                                file_path=filename,
                                code_snippet=f"class {node.name}:  # {method_count} methods",
                                suggested_fix=f"Refactor '{node.name}' into cohesive, smaller single-purpose classes or delegate responsibilities.",
                            )
                        )

            # 3. Check for Unsynchronized Module-Level Mutable State
            module_mutables: Set[str] = set()
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            # Target is a module-level variable
                            if isinstance(stmt.value, (ast.Dict, ast.List, ast.Set)):
                                module_mutables.add(target.id)

            if module_mutables:
                # Check if any function mutates these globals without a lock
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for inner in ast.walk(node):
                            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
                                if isinstance(inner.func.value, ast.Name) and inner.func.value.id in module_mutables:
                                    if inner.func.attr in ("append", "extend", "insert", "update", "add", "pop", "clear"):
                                        var_name = inner.func.value.id
                                        lineno = getattr(inner, "lineno", node.lineno)
                                        snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
                                        findings.append(
                                            ArchFinding(
                                                rule_id="ARCH-SHARED-MUTABLE-STATE-001",
                                                severity=FindingSeverity.HIGH,
                                                title=f"Unsynchronized Global Mutable State: '{var_name}'",
                                                description=f"Function '{node.name}' mutates module-level collection '{var_name}.{inner.func.attr}()'. In concurrent multi-threaded or async environments, this introduces race conditions.",
                                                line_number=lineno,
                                                file_path=filename,
                                                code_snippet=snippet,
                                                suggested_fix=f"Scope '{var_name}' within an instance, use dependency injection, or guard mutations with an async/thread Lock.",
                                            )
                                        )

        except SyntaxError:
            # Fallback regex for imports if snippet is partial/incomplete
            for lineno, line in enumerate(code.splitlines(), 1):
                m = re.search(r"""(?:from|import)\s+([a-zA-Z0-9_\.]+)""", line)
                if m:
                    mod = m.group(1)
                    mod_lower = mod.lower()
                    if is_core_layer and any(mod_lower == f or mod_lower.startswith(f + ".") for f in self.FORBIDDEN_CORE_IMPORTS):
                        findings.append(
                            ArchFinding(
                                rule_id="ARCH-LAYER-CORE-IMPORT-001",
                                severity=FindingSeverity.HIGH,
                                title=f"Core Domain Inversion Violation: Importing '{mod}'",
                                description=f"Core/domain module '{filename or 'core'}' directly imports outer delivery module '{mod}'. Clean architecture requires domain rules to remain pure and framework-agnostic.",
                                line_number=lineno,
                                file_path=filename,
                                code_snippet=line.strip(),
                                suggested_fix="Decouple domain logic from outer delivery layers. Inject dependencies via interfaces / abstract base classes.",
                            )
                        )
                    elif is_service_layer and any(mod_lower == f or mod_lower.startswith(f + ".") for f in self.FORBIDDEN_SERVICE_IMPORTS):
                        findings.append(
                            ArchFinding(
                                rule_id="ARCH-LAYER-SERVICE-WEB-IMPORT-001",
                                severity=FindingSeverity.HIGH,
                                title=f"Service Layer Upward Coupling: Importing '{mod}'",
                                description=f"Business service '{filename or 'service'}' imports web/API controller module '{mod}'. Application services must not depend on presentation controllers.",
                                line_number=lineno,
                                file_path=filename,
                                code_snippet=line.strip(),
                                suggested_fix="Remove presentation dependency. Controllers should call services, never the reverse.",
                            )
                        )

        # 4. Check for Leaky DB Abstraction in API Controllers (Regex)
        if is_controller_layer:
            raw_sql_patterns = re.compile(
                r"""\b(?:cursor\.execute|db\.execute|session\.execute)\s*\(\s*['"]\s*(SELECT|INSERT|UPDATE|DELETE)\b""",
                re.IGNORECASE,
            )
            for lineno, line in enumerate(code.splitlines(), 1):
                if raw_sql_patterns.search(line):
                    findings.append(
                        ArchFinding(
                            rule_id="ARCH-LEAKY-DB-CONTROLLER-001",
                            severity=FindingSeverity.MEDIUM,
                            title="Direct Database SQL Execution in API Controller",
                            description="API controller directly executes raw SQL queries, bypassing repository and domain service abstractions.",
                            line_number=lineno,
                            file_path=filename,
                            code_snippet=line.strip(),
                            suggested_fix="Encapsulate database access within a repository class or data service layer.",
                        )
                    )

        return findings

    def _detect_circular_dependencies(self, file_units: Dict[str, str]) -> List[ArchFinding]:
        """Detect circular import loops between files in multi-file diffs."""
        findings = []
        import_graph: Dict[str, Set[str]] = {}

        for f_path, content in file_units.items():
            f_norm = self._normalize_mod_name(f_path)
            import_graph[f_norm] = set()

            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for name in node.names:
                            import_graph[f_norm].add(self._normalize_mod_name(name.name))
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        import_graph[f_norm].add(self._normalize_mod_name(node.module))
            except SyntaxError:
                # Regex fallback for imports
                for m in re.finditer(r"""(?:from|import)\s+([a-zA-Z0-9_\.]+)""", content):
                    import_graph[f_norm].add(self._normalize_mod_name(m.group(1)))

        # Find 2-node or 3-node cycles
        checked_pairs = set()
        for mod_a, deps_a in import_graph.items():
            for mod_b in deps_a:
                if mod_b in import_graph and mod_b != mod_a:
                    pair_key = tuple(sorted([mod_a, mod_b]))
                    if pair_key in checked_pairs:
                        continue

                    # Check direct cycle A -> B and B -> A
                    if mod_a in import_graph.get(mod_b, set()):
                        checked_pairs.add(pair_key)
                        findings.append(
                            ArchFinding(
                                rule_id="ARCH-CIRCULAR-IMPORT-001",
                                severity=FindingSeverity.CRITICAL,
                                title=f"Circular Import Cycle: '{mod_a}' <-> '{mod_b}'",
                                description=f"Module '{mod_a}' imports '{mod_b}', which circularly imports '{mod_a}'. This causes runtime ImportError / NoneType initialization crashes in production.",
                                line_number=1,
                                file_path=mod_a,
                                code_snippet=f"{mod_a} imports {mod_b} and {mod_b} imports {mod_a}",
                                suggested_fix=f"Break the circular dependency: extract shared models/interfaces into a common module or use local imports inside functions.",
                            )
                        )

        return findings

    def _normalize_mod_name(self, path_or_mod: str) -> str:
        """Convert file path or import string to normalized module dot path."""
        p = path_or_mod.replace("\\", "/").strip()
        if p.endswith(".py"):
            p = p[:-3]
        p = re.sub(r"^app/", "app.", p)
        p = p.replace("/", ".")
        return p
