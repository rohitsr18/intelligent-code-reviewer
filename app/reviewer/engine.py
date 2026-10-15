import json
import logging
import time
from abc import ABC, abstractmethod
from typing import List, Optional
from app.core.config import get_settings
from app.reviewer.models import (
    ReviewAnalysisResult,
    ReviewFinding,
    FindingCategory,
    FindingSeverity,
    GrowthTip,
)
from app.reviewer.prompts import SYSTEM_INSTRUCTION, build_review_prompt
from app.reviewer.fix_validator import FixValidator

logger = logging.getLogger(__name__)


class BaseReviewEngine(ABC):
    @abstractmethod
    async def analyze(
        self,
        code: str,
        language: str,
        filename: Optional[str] = None,
        context: Optional[str] = None,
        rules: Optional[List[str]] = None,
    ) -> ReviewAnalysisResult:
        pass


class MockReviewEngine(BaseReviewEngine):
    """Deterministic reviewer for local development, CI tests, and offline runs."""

    async def analyze(
        self,
        code: str,
        language: str,
        filename: Optional[str] = None,
        context: Optional[str] = None,
        rules: Optional[List[str]] = None,
    ) -> ReviewAnalysisResult:
        start_time = time.time()
        findings: List[ReviewFinding] = []
        growth_tips: List[GrowthTip] = []
        scores = {
            "bugs": 95,
            "architecture": 90,
            "security": 95,
            "performance": 90,
            "maintainability": 90,
        }

        lines = code.splitlines()

        # Heuristic checks for test verification & offline review
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Security: eval or exec
            if "eval(" in stripped or "exec(" in stripped:
                findings.append(
                    ReviewFinding(
                        category=FindingCategory.SECURITY,
                        severity=FindingSeverity.CRITICAL,
                        title="Dynamic Code Execution Detected",
                        description="Direct use of eval() or exec() can allow arbitrary code injection.",
                        line_start=idx,
                        line_end=idx,
                        suggested_fix="# Replace eval with a safe parser or lookup mapping",
                        rule_id="SEC-001",
                    )
                )
                scores["security"] = max(20, scores["security"] - 40)

            # Security: raw SQL concatenation
            if any(sql in stripped.upper() for sql in ["SELECT ", "INSERT INTO ", "DELETE FROM "]) and (
                " % " in stripped or " + " in stripped or f'f"' in stripped or f"f'" in stripped
            ):
                findings.append(
                    ReviewFinding(
                        category=FindingCategory.SECURITY,
                        severity=FindingSeverity.CRITICAL,
                        title="Potential SQL Injection",
                        description="String formatting or concatenation used in SQL statement.",
                        line_start=idx,
                        line_end=idx,
                        suggested_fix="# Use parameterized queries with query placeholders (?)",
                        rule_id="SEC-002",
                    )
                )
                scores["security"] = max(30, scores["security"] - 35)

            # Bugs: except Exception: pass
            if "except Exception:" in stripped or "except:" in stripped:
                findings.append(
                    ReviewFinding(
                        category=FindingCategory.BUG,
                        severity=FindingSeverity.HIGH,
                        title="Silent Exception Swallowing",
                        description="Catching generic Exception without logging or re-raising hides critical errors.",
                        line_start=idx,
                        line_end=idx,
                        suggested_fix="except SpecificError as e:\n    logger.error('Operation failed', exc_info=e)",
                        rule_id="BUG-001",
                    )
                )
                scores["bugs"] = max(40, scores["bugs"] - 25)

            # Performance: range(len())
            if "for i in range(len(" in stripped:
                findings.append(
                    ReviewFinding(
                        category=FindingCategory.PERFORMANCE,
                        severity=FindingSeverity.LOW,
                        title="Unidiomatic Loop Indexing",
                        description="Iterating over range(len(collection)) is slower and less readable than enumerate().",
                        line_start=idx,
                        line_end=idx,
                        suggested_fix="for i, item in enumerate(collection):",
                        rule_id="PERF-001",
                    )
                )
                scores["performance"] = max(50, scores["performance"] - 10)

        # Standard growth tips based on language
        if language.lower() in ("python", "py"):
            growth_tips.append(
                GrowthTip(
                    topic="Type Annotations",
                    advice="Add comprehensive type hints and run mypy to catch boundary bugs at build time.",
                    learning_resource="https://docs.python.org/3/library/typing.html",
                )
            )
        elif language.lower() in ("javascript", "typescript", "js", "ts"):
            growth_tips.append(
                GrowthTip(
                    topic="Strict Null Checks",
                    advice="Enable strictNullChecks in tsconfig.json to prevent undefined runtime crashes.",
                    learning_resource="https://www.typescriptlang.org/tsconfig#strictNullChecks",
                )
            )

        if not findings:
            summary = "Code looks clean, well-structured, and meets engineering standards."
            overall_score = 95
        else:
            worst_score = min(scores.values())
            overall_score = max(30, int(sum(scores.values()) / len(scores)))
            summary = f"Identified {len(findings)} potential areas for improvement, including security or correctness concerns."

        # Validate syntax of all suggested fixes to eliminate hallucinated/broken code
        validator = FixValidator()
        findings = validator.validate_and_sanitize_findings(findings, language)

        latency_ms = (time.time() - start_time) * 1000

        return ReviewAnalysisResult(
            overall_score=overall_score,
            summary=summary,
            category_scores=scores,
            findings=findings,
            growth_tips=growth_tips,
            model_used="mock-engine",
            evaluation_latency_ms=round(latency_ms, 2),
        )


class GeminiReviewEngine(BaseReviewEngine):
    """Production Vertex AI / Gemini review engine."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(
                    vertexai=True,
                    project=self.settings.gcp_project_id,
                    location=self.settings.gcp_location,
                )
            except Exception as e:
                logger.warning(f"Could not initialize Google GenAI Client: {e}. Falling back to mock engine.")
                self._client = None
        return self._client

    async def analyze(
        self,
        code: str,
        language: str,
        filename: Optional[str] = None,
        context: Optional[str] = None,
        rules: Optional[List[str]] = None,
    ) -> ReviewAnalysisResult:
        client = self._get_client()
        if client is None:
            # Fall back to mock analyzer when credentials are unavailable
            fallback = MockReviewEngine()
            return await fallback.analyze(code, language, filename, context, rules)

        prompt = build_review_prompt(code, language, filename, context, rules)
        start_time = time.time()

        from google.genai import types

        # Retry loop for transient rate limits or network issues
        max_retries = 3
        last_exception = None

        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=self.settings.gemini_model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        response_mime_type="application/json",
                        response_schema=ReviewAnalysisResult,
                        temperature=self.settings.gemini_temperature,
                        max_output_tokens=self.settings.gemini_max_output_tokens,
                    ),
                )
                latency_ms = (time.time() - start_time) * 1000
                result = ReviewAnalysisResult.model_validate_json(response.text)
                result.evaluation_latency_ms = round(latency_ms, 2)
                result.model_used = self.settings.gemini_model

                # Validate syntax of all suggested fixes to eliminate hallucinated/broken code
                validator = FixValidator()
                result.findings = validator.validate_and_sanitize_findings(result.findings, language)

                return result

            except Exception as e:
                last_exception = e
                err_msg = str(e).lower()
                if "credentials were not found" in err_msg or "default credentials" in err_msg:
                    logger.info("ADC credentials not configured; falling back immediately to local review engine.")
                    break

                logger.warning(f"Gemini API attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)

        logger.error(f"Gemini analysis failed after {max_retries} retries: {last_exception}")
        # Graceful fallback so API caller still gets structured feedback
        fallback = MockReviewEngine()
        res = await fallback.analyze(code, language, filename, context, rules)
        res.summary = f"[Fallback Review] Upstream model error: {str(last_exception)}. Heuristic review generated."
        return res


_engine_instance: Optional[BaseReviewEngine] = None


def get_review_engine() -> BaseReviewEngine:
    global _engine_instance
    if _engine_instance is None:
        settings = get_settings()
        if settings.environment in ("test", "testing"):
            _engine_instance = MockReviewEngine()
        else:
            _engine_instance = GeminiReviewEngine()
    return _engine_instance
