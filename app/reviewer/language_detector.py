"""Automatic Programming Language Detector.

Detects code languages automatically using file extensions, shebang lines,
and AST/syntax keyword heuristics. If detection confidence is low or ambiguous,
prompts the caller or defaults gracefully to standard review engines.
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class LanguageDetectionResult(BaseModel):
    detected_language: str
    confidence: float = Field(ge=0.0, le=1.0)
    detected_by: str  # "extension", "shebang", "syntax_heuristic", "diff_header", "fallback"
    is_ambiguous: bool = False
    candidate_scores: Dict[str, int] = Field(default_factory=dict)


class LanguageDetector:
    """Robust multi-signal programming language classifier."""

    EXTENSION_MAP = {
        ".py": "python",
        ".pyi": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".cts": "typescript",
        ".go": "go",
        ".java": "java",
        ".rs": "rust",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".h": "cpp",
        ".c": "c",
        ".cs": "csharp",
        ".rb": "ruby",
        ".php": "php",
        ".sql": "sql",
        ".html": "html",
        ".htm": "html",
        ".css": "css",
        ".scss": "css",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".sh": "bash",
        ".bash": "bash",
        ".zsh": "bash",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".swift": "swift",
        "dockerfile": "dockerfile",
    }

    PATTERNS: Dict[str, List[Tuple[str, int]]] = {
        "python": [
            (r"\bdef\s+[a-zA-Z_]\w*\s*\(.*?\)\s*:", 4),
            (r"\bimport\s+[a-zA-Z_]|\bfrom\s+[a-zA-Z_]\w*\s+import\b", 3),
            (r"\bclass\s+[a-zA-Z_]\w*(\(.*?\))?\s*:", 3),
            (r"\belif\b", 3),
            (r"__name__\s*==\s*['\"]__main__['\"]", 4),
            (r"\bprint\s*\(", 1),
            (r"\bNone\b|\bTrue\b|\bFalse\b", 2),
        ],
        "typescript": [
            (r":\s*(string|number|boolean|any|void|unknown|never)\b", 4),
            (r"\binterface\s+[A-Z]\w*\s*\{", 4),
            (r"\btype\s+[A-Z]\w*\s*=", 4),
            (r"\bas\s+[A-Z]\w*\b", 2),
            (r"\bconst\b|\blet\b", 1),
            (r"\bexport\s+(interface|type|class|const)\b", 3),
        ],
        "javascript": [
            (r"\bconsole\.(log|error|warn|debug)\s*\(", 4),
            (r"\bconst\b|\blet\b|\bvar\b", 2),
            (r"\bfunction\s+[a-zA-Z_]\w*\s*\(.*?\)\s*\{", 3),
            (r"=>\s*\{", 2),
            (r"\bimport\s+.*?from\s+['\"].*?['\"]", 3),
            (r"\brequire\s*\(['\"].*?['\"]\)", 3),
            (r"\bdocument\.(getElementById|querySelector)\b", 4),
        ],
        "go": [
            (r"\bpackage\s+[a-zA-Z_]\w*", 5),
            (r"\bfunc\s+(\([a-zA-Z_*\s]+\)\s+)?[a-zA-Z_]\w*\s*\(.*?\)", 4),
            (r"\bfmt\.(Println|Printf|Sprintf)\b", 4),
            (r":=\s*", 3),
            (r"\bgo\s+[a-zA-Z_]\w*\(", 3),
            (r"\bimport\s*\(\s*\"[a-zA-Z0-9_./]+\"", 4),
        ],
        "java": [
            (r"\bpublic\s+class\s+[a-zA-Z_]\w*", 5),
            (r"\bSystem\.out\.(println|print)\s*\(", 5),
            (r"\bpublic\s+static\s+void\s+main\s*\(", 5),
            (r"\bpackage\s+[a-zA-Z_][\w.]*;", 3),
            (r"\b@Override\b", 3),
        ],
        "rust": [
            (r"\bfn\s+[a-zA-Z_]\w*\s*\(.*?\)\s*(->\s*.*?)?\s*\{", 5),
            (r"\blet\s+mut\b", 4),
            (r"\bprintln!\s*\(", 4),
            (r"\bimpl(\s+<.*?>)?\s+[A-Z]", 4),
            (r"\bpub(\(crate\))?\s+(fn|struct|enum)\b", 4),
        ],
        "cpp": [
            (r"#include\s*<[a-zA-Z0-9_./]+>", 4),
            (r"\bstd::(cout|cin|string|vector|map|unique_ptr)\b", 5),
            (r"\bcout\s*<<", 4),
            (r"\bcin\s*>>", 4),
            (r"\bnamespace\s+[a-zA-Z_]\w*\s*\{", 3),
        ],
        "c": [
            (r"#include\s*<stdio\.h>|#include\s*<stdlib\.h>", 5),
            (r"\bprintf\s*\(|\bscanf\s*\(", 4),
            (r"\bint\s+main\s*\(\s*(void|int\s+argc)?", 3),
        ],
        "csharp": [
            (r"\busing\s+System(\.[a-zA-Z0-9_]+)*;", 5),
            (r"\bConsole\.WriteLine\s*\(", 5),
            (r"\bpublic\s+class\s+[a-zA-Z_]\w*\s*:\s*[A-Z]", 3),
            (r"\bnamespace\s+[a-zA-Z0-9_.]+\b", 3),
        ],
        "ruby": [
            (r"\bdef\s+[a-zA-Z_]\w*.*?\n.*?\bend\b", 4),
            (r"\battr_accessor\b|\battr_reader\b", 4),
            (r"\bputs\s+['\"].*?['\"]", 3),
            (r"\brequire_relative\b", 3),
        ],
        "php": [
            (r"<\?php", 6),
            (r"\$[a-zA-Z_]\w*", 3),
            (r"\becho\s+['\"].*?['\"]", 3),
            (r"->\w+\(", 2),
        ],
        "sql": [
            (r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b", 5),
            (r"\bFROM\b.*?\bWHERE\b", 4),
            (r"\bGROUP\s+BY\b|\bORDER\s+BY\b", 3),
            (r"\bJOIN\b.*?\bON\b", 3),
        ],
        "html": [
            (r"<!DOCTYPE\s+html>", 6),
            (r"<\s*(html|head|body|div|span|script|p|table)\b.*?>", 4),
            (r"<\/\s*(html|body|div|p)\s*>", 4),
        ],
        "dockerfile": [
            (r"^(FROM|RUN|COPY|ADD|ENTRYPOINT|CMD|ENV|EXPOSE)\s+", 5),
        ],
        "bash": [
            (r"^#!\s*\/bin\/(bash|sh|zsh)", 6),
            (r"\bif\s+\[\[?.*?\]\]?;\s*then\b", 4),
            (r"\becho\s+['\"].*?['\"]", 2),
            (r"\$\(.*?\)|\`.*?\`", 2),
        ],
        "kotlin": [
            (r"\bfun\s+[a-zA-Z_]\w*\s*\(.*?\)", 5),
            (r"\bval\s+[a-zA-Z_]\w*|\bvar\s+[a-zA-Z_]\w*", 3),
            (r"\bprintln\s*\(", 3),
        ],
        "swift": [
            (r"\bimport\s+Foundation\b|\bimport\s+UIKit\b|\bimport\s+SwiftUI\b", 5),
            (r"\bfunc\s+[a-zA-Z_]\w*\s*\(.*?\)\s*(->\s*.*?)?\s*\{", 4),
            (r"\blet\s+[a-zA-Z_]\w*:\s*[A-Z]", 3),
        ],
    }

    def detect_from_filename(self, filename: str) -> Optional[str]:
        """Extracts language from filename or file path extension."""
        clean = filename.strip().lower()
        base = os.path.basename(clean)

        if base in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[base]

        _, ext = os.path.splitext(base)
        if ext in self.EXTENSION_MAP:
            return self.EXTENSION_MAP[ext]

        return None

    def detect_from_diff_header(self, code: str) -> Optional[str]:
        """Scans git diff headers (e.g. diff --git a/... b/...) for file extensions."""
        m = re.search(r"^\+\+\+\s+b/(.*)$", code, re.MULTILINE)
        if m:
            return self.detect_from_filename(m.group(1))

        m2 = re.search(r"^diff\s+--git\s+a/.*?\s+b/(.*?)$", code, re.MULTILINE)
        if m2:
            return self.detect_from_filename(m2.group(1))

        return None

    def detect_from_shebang(self, code: str) -> Optional[str]:
        """Extracts language from script shebang line."""
        first_line = code.strip().splitlines()[0] if code.strip() else ""
        if first_line.startswith("#!"):
            line_lower = first_line.lower()
            if "python" in line_lower:
                return "python"
            if "node" in line_lower:
                return "javascript"
            if "bash" in line_lower or "sh" in line_lower or "zsh" in line_lower:
                return "bash"
            if "ruby" in line_lower:
                return "ruby"
            if "php" in line_lower:
                return "php"
        return None

    def detect(self, code: str, filename: Optional[str] = None) -> LanguageDetectionResult:
        """Determines programming language using multi-layer signal analysis."""
        if not code or not code.strip():
            return LanguageDetectionResult(
                detected_language="python",
                confidence=0.5,
                detected_by="fallback",
                is_ambiguous=True,
            )

        # 1. Primary Signal: Explicit filename extension
        if filename:
            ext_lang = self.detect_from_filename(filename)
            if ext_lang:
                return LanguageDetectionResult(
                    detected_language=ext_lang,
                    confidence=0.99,
                    detected_by="extension",
                    is_ambiguous=False,
                )

        # 2. Secondary Signal: Diff header filename
        diff_lang = self.detect_from_diff_header(code)
        if diff_lang:
            return LanguageDetectionResult(
                detected_language=diff_lang,
                confidence=0.98,
                detected_by="diff_header",
                is_ambiguous=False,
            )

        # 3. Tertiary Signal: Script Shebang line
        shebang_lang = self.detect_from_shebang(code)
        if shebang_lang:
            return LanguageDetectionResult(
                detected_language=shebang_lang,
                confidence=0.95,
                detected_by="shebang",
                is_ambiguous=False,
            )

        # 4. JSON Direct Verification
        stripped = code.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                json.loads(stripped)
                return LanguageDetectionResult(
                    detected_language="json",
                    confidence=0.95,
                    detected_by="syntax_heuristic",
                    is_ambiguous=False,
                )
            except Exception:
                pass

        # 5. Syntax Heuristic Pattern Scoring
        scores: Dict[str, int] = {}
        for lang, patterns in self.PATTERNS.items():
            score = 0
            for regex, weight in patterns:
                matches = len(re.findall(regex, code, re.MULTILINE))
                if matches > 0:
                    score += weight * min(matches, 3)
            if score > 0:
                scores[lang] = score

        if not scores:
            return LanguageDetectionResult(
                detected_language="python",
                confidence=0.3,
                detected_by="fallback",
                is_ambiguous=True,
            )

        # Sort candidates by score descending
        sorted_candidates = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_lang, top_score = sorted_candidates[0]

        # Calculate confidence based on lead over runner-up
        runner_up_score = sorted_candidates[1][1] if len(sorted_candidates) > 1 else 0
        score_diff = top_score - runner_up_score

        if top_score >= 6 and score_diff >= 3:
            confidence = 0.90
            is_ambiguous = False
        elif top_score >= 4:
            confidence = 0.75
            is_ambiguous = (score_diff <= 1 and runner_up_score > 0)
        else:
            confidence = 0.50
            is_ambiguous = True

        return LanguageDetectionResult(
            detected_language=top_lang,
            confidence=round(confidence, 2),
            detected_by="syntax_heuristic",
            is_ambiguous=is_ambiguous,
            candidate_scores=scores,
        )

