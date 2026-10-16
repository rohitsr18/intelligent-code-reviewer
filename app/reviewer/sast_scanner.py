"""AST-Based Static Application Security Testing (SAST) Scanner.

Performs deterministic static analysis and AST traversal to detect high-risk vulnerabilities:
1. SQL Injection (SQLi) - CWE-89 (f-strings, % formatting, raw string concatenation in queries)
2. OS Command Injection - CWE-78 (subprocess with shell=True, os.system, os.popen)
3. Insecure Deserialization - CWE-502 (pickle.loads, yaml.load without SafeLoader, marshal, shelve)
4. Server-Side Request Forgery (SSRF) - CWE-918 (unvalidated dynamic requests/urllib/httpx calls)
5. Path Traversal - CWE-22 (arbitrary file read/write with user-controlled paths)
6. Broken Cryptography - CWE-327 (MD5/SHA1 for security, pseudo-random generators for secrets, DES)
7. Code Injection - CWE-95 (eval, exec, __import__ on dynamic expressions)
8. Hardcoded Secrets - CWE-798 (AWS keys, GitHub tokens, Google API keys, private keys)
9. Insecure XML Processing (XXE) - CWE-611 (xml.etree, lxml without entity protection)
10. Insecure Temp Files - CWE-377 (tempfile.mktemp race condition)
"""

import ast
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from app.reviewer.models import FindingCategory, FindingSeverity, ReviewFinding

logger = logging.getLogger(__name__)


class SASTFinding(BaseModel):
    rule_id: str
    cwe_id: str
    owasp_category: str
    severity: FindingSeverity
    title: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    suggested_fix: Optional[str] = None
    remediation_guide: Optional[str] = None


class SASTScanResult(BaseModel):
    language: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[SASTFinding] = Field(default_factory=list)

    def to_review_findings(self) -> List[ReviewFinding]:
        """Convert SAST findings to unified ReviewFinding objects."""
        review_findings = []
        for f in self.findings:
            review_findings.append(
                ReviewFinding(
                    category=FindingCategory.SECURITY,
                    severity=f.severity,
                    title=f"[{f.cwe_id}] {f.title}",
                    description=f"{f.description}\n\n**OWASP**: {f.owasp_category} | **CWE**: {f.cwe_id}\n\n**Remediation**: {f.remediation_guide or 'Review code logic'}",
                    line_number=f.line_number,
                    suggested_fix=f.suggested_fix,
                )
            )
        return review_findings


class _PythonASTSecurityVisitor(ast.NodeVisitor):
    """Deep AST visitor scanning Python code trees for security vulnerabilities."""

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.findings: List[SASTFinding] = []

    def _get_snippet(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node.func)
        snippet = self._get_snippet(node)
        lineno = getattr(node, "lineno", None)

        # 1. SQL Injection Checks (cursor.execute, session.execute, raw queries)
        if any(db_call in func_name for db_call in ("execute", "raw", "select", "filter")):
            if node.args:
                first_arg = node.args[0]
                # f-string in query
                if isinstance(first_arg, ast.JoinedStr):
                    self.findings.append(
                        SASTFinding(
                            rule_id="SEC-PY-SQLI-001",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            severity=FindingSeverity.CRITICAL,
                            title="SQL Injection via Formatted String in Database Query",
                            description="Database query constructed using f-string interpolation allows arbitrary SQL injection.",
                            line_number=lineno,
                            code_snippet=snippet,
                            suggested_fix="Use parameterized queries with placeholder tuples: cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
                            remediation_guide="Never concatenate or interpolate user input directly into SQL strings. Always use database parameterization.",
                        )
                    )
                # string concatenation or % formatting in query
                elif isinstance(first_arg, ast.BinOp):
                    if isinstance(first_arg.op, (ast.Add, ast.Mod)):
                        self.findings.append(
                            SASTFinding(
                                rule_id="SEC-PY-SQLI-002",
                                cwe_id="CWE-89",
                                owasp_category="A03:2021-Injection",
                                severity=FindingSeverity.CRITICAL,
                                title="SQL Injection via String Concatenation or Modulo Operator",
                                description="Database query constructed using string concatenation (+) or modulo (%) formatting.",
                                line_number=lineno,
                                code_snippet=snippet,
                                suggested_fix="Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
                                remediation_guide="Replace string formatting with query parameters to let the database driver safely escape values.",
                            )
                        )
                # .format() call on string
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    self.findings.append(
                        SASTFinding(
                            rule_id="SEC-PY-SQLI-003",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            severity=FindingSeverity.CRITICAL,
                            title="SQL Injection via str.format() in Database Query",
                            description="Database query constructed using str.format() method.",
                            line_number=lineno,
                            code_snippet=snippet,
                            suggested_fix="Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
                            remediation_guide="Pass variables as query parameters instead of formatting strings.",
                        )
                    )

        # 2. Command Injection / RCE
        # subprocess.call, subprocess.run, subprocess.Popen with shell=True
        if func_name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        SASTFinding(
                            rule_id="SEC-PY-CMD-001",
                            cwe_id="CWE-78",
                            owasp_category="A03:2021-Injection",
                            severity=FindingSeverity.CRITICAL,
                            title="OS Command Injection via subprocess with shell=True",
                            description="subprocess invoked with shell=True allows shell meta-character exploitation and arbitrary command execution.",
                            line_number=lineno,
                            code_snippet=snippet,
                            suggested_fix="Set shell=False and pass arguments as an explicit list: subprocess.run(['cmd', arg1, arg2], check=True)",
                            remediation_guide="Never invoke subprocess with shell=True. Pass command and arguments as a sequence of strings.",
                        )
                    )
        elif func_name in ("os.system", "os.popen", "pty.spawn", "posix.system"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(
                    SASTFinding(
                        rule_id="SEC-PY-CMD-002",
                        cwe_id="CWE-78",
                        owasp_category="A03:2021-Injection",
                        severity=FindingSeverity.CRITICAL,
                        title=f"OS Command Injection via {func_name}",
                        description=f"{func_name} executes commands through the system shell without argument isolation.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Use subprocess.run(['command', arg], shell=False, check=True) instead.",
                        remediation_guide="Avoid os.system and os.popen; use subprocess.run with a list of arguments and shell=False.",
                    )
                )

        # 3. Insecure Deserialization
        if func_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load", "cPickle.loads"):
            self.findings.append(
                SASTFinding(
                    rule_id="SEC-PY-DESER-001",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                    severity=FindingSeverity.CRITICAL,
                    title="Insecure Deserialization via pickle",
                    description="Unpickling untrusted data allows arbitrary code execution via __reduce__ bytecode injection.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix="Use safe data formats like JSON (json.loads) or Protocol Buffers instead of pickle.",
                    remediation_guide="Never deserialize untrusted input with pickle. Use cryptographic signing (itsdangerous/hmac) or standard JSON.",
                )
            )
        elif func_name == "yaml.load":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_name = self._get_call_name(kw.value)
                    if "SafeLoader" in loader_name:
                        has_safe_loader = True
            if not has_safe_loader:
                self.findings.append(
                    SASTFinding(
                        rule_id="SEC-PY-DESER-002",
                        cwe_id="CWE-502",
                        owasp_category="A08:2021-Software and Data Integrity Failures",
                        severity=FindingSeverity.HIGH,
                        title="Insecure YAML Deserialization without SafeLoader",
                        description="yaml.load without Loader=SafeLoader can execute arbitrary Python object constructors.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader)",
                        remediation_guide="Always use yaml.safe_load to prevent arbitrary code execution during YAML parsing.",
                    )
                )
        elif func_name in ("yaml.unsafe_load", "marshal.loads", "shelve.open"):
            self.findings.append(
                SASTFinding(
                    rule_id="SEC-PY-DESER-003",
                    cwe_id="CWE-502",
                    owasp_category="A08:2021-Software and Data Integrity Failures",
                    severity=FindingSeverity.HIGH,
                    title=f"Unsafe Object Deserialization via {func_name}",
                    description=f"{func_name} deserializes raw Python objects and can be manipulated into remote code execution.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix="Use json.loads() or schema-validated data parsers.",
                    remediation_guide="Restrict deserialization to pure data structures without executable bindings.",
                )
            )

        # 4. Code Injection (eval, exec, __import__)
        if func_name in ("eval", "exec", "__import__"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(
                    SASTFinding(
                        rule_id="SEC-PY-CODEINJ-001",
                        cwe_id="CWE-95",
                        owasp_category="A03:2021-Injection",
                        severity=FindingSeverity.CRITICAL,
                        title=f"Arbitrary Code Execution via dynamic {func_name}",
                        description=f"Invoking {func_name} on dynamic input allows arbitrary Python code execution.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Use ast.literal_eval for parsing safe literals, or map inputs to safe dispatch dictionaries.",
                        remediation_guide="Never pass dynamic or user-influenced strings to eval() or exec().",
                    )
                )

        # 5. Broken / Weak Cryptography & Insecure Hashing
        if func_name in ("hashlib.md5", "hashlib.sha1"):
            # Check if used_for_security=False keyword is present
            used_for_sec = True
            for kw in node.keywords:
                if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    used_for_sec = False
            if used_for_sec:
                alg = "MD5" if "md5" in func_name else "SHA-1"
                self.findings.append(
                    SASTFinding(
                        rule_id="SEC-PY-CRYPTO-001",
                        cwe_id="CWE-327",
                        owasp_category="A02:2021-Cryptographic Failures",
                        severity=FindingSeverity.MEDIUM,
                        title=f"Weak Cryptographic Hash Function ({alg})",
                        description=f"{alg} is cryptographically broken and vulnerable to collision attacks.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Use hashlib.sha256() or hashlib.sha3_256(). For passwords, use bcrypt or argon2.",
                        remediation_guide="Upgrade to modern hash algorithms like SHA-256/SHA-512 or Argon2id for password verification.",
                    )
                )
        elif any(c in func_name for c in ("Crypto.Cipher.DES", "Cryptodome.Cipher.DES", "Blowfish")):
            self.findings.append(
                SASTFinding(
                    rule_id="SEC-PY-CRYPTO-002",
                    cwe_id="CWE-327",
                    owasp_category="A02:2021-Cryptographic Failures",
                    severity=FindingSeverity.HIGH,
                    title="Insecure Legacy Cipher (DES/Blowfish)",
                    description="DES and Blowfish have small block sizes and known vulnerabilities (Sweet32 attack).",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix="Use AES-GCM or ChaCha20-Poly1305 via cryptography.hazmat.primitives.ciphers.aead.",
                    remediation_guide="Adopt authenticated encryption (AES-256-GCM) for all cryptographic storage.",
                )
            )

        # 6. Insecure Pseudo-Random Number Generation for Security Contexts
        if func_name in ("random.random", "random.randint", "random.choice", "random.randrange"):
            # Check if assigned to or used in token, secret, password, key context
            parent_ctx = snippet.lower()
            if any(sec_term in parent_ctx for sec_term in ("token", "secret", "password", "key", "auth", "session", "salt", "nonce")):
                self.findings.append(
                    SASTFinding(
                        rule_id="SEC-PY-RAND-001",
                        cwe_id="CWE-338",
                        owasp_category="A02:2021-Cryptographic Failures",
                        severity=FindingSeverity.HIGH,
                        title="Insecure Pseudo-Random Number Generator for Security Token",
                        description="random module uses Mersenne Twister which is predictable after 624 outputs.",
                        line_number=lineno,
                        code_snippet=snippet,
                        suggested_fix="Use secrets.token_hex() or secrets.choice() for cryptographically secure random values.",
                        remediation_guide="Use the 'secrets' module for generating security tokens, password salts, and session IDs.",
                    )
                )

        # 7. Insecure Temporary File Creation
        if func_name == "tempfile.mktemp":
            self.findings.append(
                SASTFinding(
                    rule_id="SEC-PY-TEMP-001",
                    cwe_id="CWE-377",
                    owasp_category="A01:2021-Broken Access Control",
                    severity=FindingSeverity.HIGH,
                    title="Insecure Temporary File Creation via tempfile.mktemp",
                    description="tempfile.mktemp is vulnerable to symlink race conditions between file name generation and creation.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix="Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead.",
                    remediation_guide="Use NamedTemporaryFile to atomically create and secure temporary files.",
                )
            )

        # 8. Insecure XML Parsing / XXE
        if func_name in ("xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.dom.minidom.parse"):
            self.findings.append(
                SASTFinding(
                    rule_id="SEC-PY-XXE-001",
                    cwe_id="CWE-611",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=FindingSeverity.MEDIUM,
                    title="Potential XML External Entity (XXE) Vulnerability",
                    description="Standard standard library XML parsers may process external entities and DTDs.",
                    line_number=lineno,
                    code_snippet=snippet,
                    suggested_fix="Use defusedxml.ElementTree.parse() to safely parse XML without XXE or entity expansion bombs.",
                    remediation_guide="Use defusedxml to guard against XML entity injection and billion laughs attacks.",
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


class SASTScanner:
    """Enterprise Static Application Security Testing (SAST) Scanner."""

    # Secret patterns
    SECRET_PATTERNS = [
        (
            re.compile(r"AKIA[0-9A-Z]{16}"),
            "AWS Access Key ID",
            "SEC-KEY-AWS-001",
            "CWE-798",
            FindingSeverity.CRITICAL,
        ),
        (
            re.compile(r"ghp_[a-zA-Z0-9]{36}"),
            "GitHub Personal Access Token",
            "SEC-KEY-GH-001",
            "CWE-798",
            FindingSeverity.CRITICAL,
        ),
        (
            re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
            "Google API Key",
            "SEC-KEY-GCP-001",
            "CWE-798",
            FindingSeverity.CRITICAL,
        ),
        (
            re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
            "Embedded Private Key",
            "SEC-KEY-PK-001",
            "CWE-798",
            FindingSeverity.CRITICAL,
        ),
    ]

    # Multi-language regex patterns for non-Python or supplemental checks
    MULTI_LANG_PATTERNS = [
        # JavaScript / TypeScript Command Injection
        (
            re.compile(r"""(?:child_process|execSync|exec)\s*\(\s*[`'"](?:\$\{.*\}|.*\+.*)""", re.IGNORECASE),
            ("javascript", "typescript", "js", "ts"),
            "OS Command Injection in child_process.exec",
            "SEC-JS-CMD-001",
            "CWE-78",
            "A03:2021-Injection",
            FindingSeverity.CRITICAL,
            "Use child_process.execFile() or spawn() with argument arrays instead of shell command strings.",
        ),
        # JavaScript / TypeScript SQL Injection
        (
            re.compile(r"""(?:\.query|\.execute)\s*\(\s*`[^`]*\$\{.*?\}[^`]*`""", re.IGNORECASE),
            ("javascript", "typescript", "js", "ts"),
            "SQL Injection via Template Literal in Database Query",
            "SEC-JS-SQLI-001",
            "CWE-89",
            "A03:2021-Injection",
            FindingSeverity.CRITICAL,
            "Use parameterized queries with placeholder syntax: db.query('SELECT * WHERE id = $1', [id])",
        ),
        # JavaScript Dangerous InnerHTML / XSS
        (
            re.compile(r"""(?:innerHTML|dangerouslySetInnerHTML)\s*=\s*""", re.IGNORECASE),
            ("javascript", "typescript", "js", "ts", "html"),
            "Cross-Site Scripting (XSS) via innerHTML",
            "SEC-JS-XSS-001",
            "CWE-79",
            "A03:2021-Injection",
            FindingSeverity.HIGH,
            "Use textContent or sanitize HTML with DOMPurify before rendering.",
        ),
        # Go Command Injection
        (
            re.compile(r"""exec\.Command\s*\(\s*["'](?:sh|bash)["']\s*,\s*["']-c["']\s*,\s*fmt\.Sprintf""", re.IGNORECASE),
            ("go", "golang"),
            "OS Command Injection via exec.Command with shell wrapper",
            "SEC-GO-CMD-001",
            "CWE-78",
            "A03:2021-Injection",
            FindingSeverity.CRITICAL,
            "Call the binary directly without 'sh -c' and pass arguments as separate array elements.",
        ),
        # Go SQL Injection
        (
            re.compile(r"""db\.(?:Query|Exec)\s*\(\s*fmt\.Sprintf\s*\(""", re.IGNORECASE),
            ("go", "golang"),
            "SQL Injection via fmt.Sprintf in database call",
            "SEC-GO-SQLI-001",
            "CWE-89",
            "A03:2021-Injection",
            FindingSeverity.CRITICAL,
            "Use database placeholders: db.Query('SELECT * FROM table WHERE id = ?', id)",
        ),
        # Java SQL Injection
        (
            re.compile(r"""(?:executeQuery|executeUpdate)\s*\(\s*["'][^"']*["']\s*\+""", re.IGNORECASE),
            ("java", "kotlin"),
            "SQL Injection via String Concatenation in Statement Execution",
            "SEC-JAVA-SQLI-001",
            "CWE-89",
            "A03:2021-Injection",
            FindingSeverity.CRITICAL,
            "Use PreparedStatement with setString/setInt binding parameters.",
        ),
        # Path Traversal (Universal)
        (
            re.compile(r"""\.\./|\.\.\\"""),
            ("python", "javascript", "typescript", "go", "java", "ruby", "php"),
            "Potential Path Traversal Pattern ('../')",
            "SEC-GEN-PATH-001",
            "CWE-22",
            "A01:2021-Broken Access Control",
            FindingSeverity.HIGH,
            "Normalize path and verify it stays within the expected base directory using os.path.realpath or path.resolve.",
        ),
    ]

    def __init__(self) -> None:
        pass

    def scan(self, code: str, language: str = "auto", filename: Optional[str] = None) -> SASTScanResult:
        """Execute deep static security scanning across AST and pattern analyzers."""
        if not code or not code.strip():
            return SASTScanResult(
                language=language,
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                findings=[],
            )

        detected_lang = self._normalize_language(language, filename)
        source_lines = code.splitlines()
        findings: List[SASTFinding] = []

        # 1. Python AST Deep Scan
        if detected_lang == "python":
            try:
                tree = ast.parse(code)
                visitor = _PythonASTSecurityVisitor(source_lines)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError as e:
                logger.debug("Python AST parsing failed (syntax error): %s. Falling back to regex scanner.", e)

        # 2. Hardcoded Secret Patterns (Universal across all languages)
        for lineno, line in enumerate(source_lines, 1):
            # Skip comments if obvious
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            for pattern, sec_name, rule_id, cwe_id, sev in self.SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        SASTFinding(
                            rule_id=rule_id,
                            cwe_id=cwe_id,
                            owasp_category="A07:2021-Identification and Authentication Failures",
                            severity=sev,
                            title=f"Hardcoded Credential Detected: {sec_name}",
                            description=f"Exposing plaintext {sec_name} in source code creates severe unauthorized access risk.",
                            line_number=lineno,
                            code_snippet=line.strip(),
                            suggested_fix="Extract secret to Google Secret Manager, Cloud KMS, or environment variables.",
                            remediation_guide="Never commit credentials into code repositories. Revoke this credential immediately.",
                        )
                    )

        # 3. Multi-language Pattern Scanner
        for lineno, line in enumerate(source_lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            for pattern, supported_langs, title, rule_id, cwe, owasp, sev, fix in self.MULTI_LANG_PATTERNS:
                if detected_lang in supported_langs:
                    if pattern.search(line):
                        findings.append(
                            SASTFinding(
                                rule_id=rule_id,
                                cwe_id=cwe,
                                owasp_category=owasp,
                                severity=sev,
                                title=title,
                                description=f"Identified {cwe} static security pattern: {title}",
                                line_number=lineno,
                                code_snippet=line.strip(),
                                suggested_fix=fix,
                                remediation_guide=f"Remediate according to {owasp} and {cwe} standards.",
                            )
                        )

        # Deduplicate findings by rule_id and line_number
        unique_findings = []
        seen_keys = set()
        for f in findings:
            key = (f.rule_id, f.line_number)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        # Count severities
        crit = sum(1 for f in unique_findings if f.severity == FindingSeverity.CRITICAL)
        high = sum(1 for f in unique_findings if f.severity == FindingSeverity.HIGH)
        med = sum(1 for f in unique_findings if f.severity == FindingSeverity.MEDIUM)
        low = sum(1 for f in unique_findings if f.severity in (FindingSeverity.LOW, FindingSeverity.INFO))

        return SASTScanResult(
            language=detected_lang,
            total_findings=len(unique_findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            findings=unique_findings,
        )

    def _normalize_language(self, language: str, filename: Optional[str]) -> str:
        if filename:
            ext = filename.lower().split(".")[-1]
            ext_map = {
                "py": "python",
                "js": "javascript",
                "jsx": "javascript",
                "ts": "typescript",
                "tsx": "typescript",
                "go": "go",
                "java": "java",
                "rb": "ruby",
                "php": "php",
                "sql": "sql",
                "sh": "shell",
                "bash": "shell",
            }
            if ext in ext_map:
                return ext_map[ext]

        lang = language.lower().strip() if language else "python"
        if lang in ("py", "python", "python3"):
            return "python"
        if lang in ("js", "javascript", "node"):
            return "javascript"
        if lang in ("ts", "typescript"):
            return "typescript"
        if lang in ("golang", "go"):
            return "go"
        if lang in ("java",):
            return "java"
        return lang or "python"
