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
from app.reviewer.noise_filter import NoiseFilter

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
        min_severity: Optional[str] = "low",
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
        min_severity: Optional[str] = "low",
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

        result = ReviewAnalysisResult(
            overall_score=overall_score,
            summary=summary,
            category_scores=scores,
            findings=findings,
            growth_tips=growth_tips,
            model_used="mock-engine",
            evaluation_latency_ms=round(latency_ms, 2),
        )

        # Apply intelligent noise reduction and nitpick consolidation
        noise_filter = NoiseFilter()
        return noise_filter.filter_and_consolidate(result, min_severity=min_severity)


class GeminiReviewEngine(BaseReviewEngine):
    """Production Vertex AI / Gemini review engine."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import os
                from google import genai

                api_key = self.settings.gemini_api_key or os.environ.get("GEMINI_API_KEY")
                if api_key:
                    logger.info("Initializing Google GenAI Client with direct GEMINI_API_KEY")
                    self._client = genai.Client(api_key=api_key)
                else:
                    logger.info("Initializing Google GenAI Client with Vertex AI backend")
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
        min_severity: Optional[str] = "low",
    ) -> ReviewAnalysisResult:
        client = self._get_client()
        if client is None:
            # Fall back to mock analyzer when credentials are unavailable
            fallback = MockReviewEngine()
            return await fallback.analyze(code, language, filename, context, rules, min_severity=min_severity)

        prompt = build_review_prompt(code, language, filename, context, rules)
        start_time = time.time()

        from google.genai import types

        # Build prioritized list of models to try
        primary_model = self.settings.gemini_model or "gemini-3.8-flash"
        candidate_models = [primary_model]
        for fallback_model in ["gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]:
            if fallback_model not in candidate_models:
                candidate_models.append(fallback_model)

        last_exception = None

        for model_to_try in candidate_models:
            max_retries = 2
            model_not_found = False

            for attempt in range(max_retries):
                try:
                    response = client.models.generate_content(
                        model=model_to_try,
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
                    result.model_used = model_to_try

                    # Validate syntax of all suggested fixes to eliminate hallucinated/broken code
                    validator = FixValidator()
                    result.findings = validator.validate_and_sanitize_findings(result.findings, language)

                    # Apply intelligent noise reduction and nitpick consolidation
                    noise_filter = NoiseFilter()
                    return noise_filter.filter_and_consolidate(result, min_severity=min_severity)

                except Exception as e:
                    last_exception = e
                    err_msg = str(e).lower()
                    if "404" in err_msg and ("not_found" in err_msg or "was not found" in err_msg or "not found" in err_msg):
                        logger.warning(f"Model {model_to_try} returned 404 Not Found. Attempting fallback model...")
                        model_not_found = True
                        break

                    if "credentials were not found" in err_msg or "default credentials" in err_msg:
                        logger.info("ADC credentials not configured; falling back immediately to local review engine.")
                        fallback = MockReviewEngine()
                        return await fallback.analyze(code, language, filename, context, rules, min_severity=min_severity)

                    logger.warning(f"Gemini API attempt {attempt + 1} with {model_to_try} failed: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(1)

            if not model_not_found and last_exception:
                # If the error was not a 404 (e.g. rate limit or bad request), don't cycle through other models
                break

        logger.error(f"Gemini analysis failed: {last_exception}")
        # Graceful fallback so API caller still gets structured feedback
        fallback = MockReviewEngine()
        res = await fallback.analyze(code, language, filename, context, rules, min_severity=min_severity)
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
