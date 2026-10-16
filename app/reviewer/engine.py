import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
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

SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}

SUPPORTED_GEMINI_35_PLUS_MODELS = [
    "gemini-3.8-flash",
    "gemini-3.5-flash",
    "gemini-3.8-pro",
    "gemini-3.5-pro",
]


def is_gemini_35_plus(model_name: Optional[str]) -> bool:
    """Check if model is Gemini 3.5 Flash or higher."""
    if not model_name:
        return False
    name = model_name.split("/")[-1].lower().strip()
    if name in SUPPORTED_GEMINI_35_PLUS_MODELS:
        return True
    import re
    match = re.search(r"gemini-(\d+(?:\.\d+)?)", name)
    if not match:
        return False
    try:
        version = float(match.group(1))
        return version >= 3.5
    except ValueError:
        return False


def canonicalize_review_result(result: ReviewAnalysisResult) -> ReviewAnalysisResult:
    """Sorts, deduplicates, and deterministically normalizes findings and style nits."""
    # Deduplicate findings by title, line range, category, and severity
    seen_findings = set()
    deduped_findings = []
    for f in result.findings:
        sig = (f.title.strip().lower(), f.line_start or 0, f.line_end or 0, str(f.category), str(f.severity))
        if sig not in seen_findings:
            seen_findings.add(sig)
            deduped_findings.append(f)

    # Sort deterministically: severity first (CRITICAL -> INFO), then line_start, then title
    deduped_findings.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x.severity, 5),
            x.line_start or 0,
            x.line_end or 0,
            x.title.strip().lower(),
        )
    )
    result.findings = deduped_findings

    # Deduplicate and sort style nits
    seen_nits = set()
    deduped_nits = []
    for n in result.style_nits:
        sig = (n.title.strip().lower(), n.line_start or 0, n.line_end or 0)
        if sig not in seen_nits:
            seen_nits.add(sig)
            deduped_nits.append(n)
    deduped_nits.sort(key=lambda x: (x.line_start or 0, x.title.strip().lower()))
    result.style_nits = deduped_nits

    return result


class ReviewDeterministicCache:
    """Thread-safe in-memory content-addressable cache ensuring deterministic review output."""

    def __init__(self, capacity: int = 512):
        self.capacity = capacity
        self._cache: OrderedDict[str, ReviewAnalysisResult] = OrderedDict()

    @staticmethod
    def compute_key(
        code: str,
        language: str,
        filename: Optional[str] = None,
        context: Optional[str] = None,
        rules: Optional[List[str]] = None,
        min_severity: Optional[str] = "low",
        model: Optional[str] = None,
    ) -> str:
        rules_repr = ",".join(sorted(rules or []))
        canonical = f"{language}|{filename or ''}|{context or ''}|{rules_repr}|{min_severity or 'low'}|{model or ''}\n{code.strip()}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[ReviewAnalysisResult]:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key].model_copy(deep=True)
        return None

    def put(self, key: str, value: ReviewAnalysisResult) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value.model_copy(deep=True)
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


_global_review_cache = ReviewDeterministicCache()


def get_review_cache() -> ReviewDeterministicCache:
    return _global_review_cache


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
        result = noise_filter.filter_and_consolidate(result, min_severity=min_severity)
        return canonicalize_review_result(result)


class GeminiReviewEngine(BaseReviewEngine):
    """Production Vertex AI / Gemini review engine with deterministic caching and output canonicalization."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = None
        self.cache = _global_review_cache

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
        # Deterministic cache check: guarantees identical code gets identical findings & scores
        cache_key = None
        if self.settings.review_cache_enabled:
            cache_key = self.cache.compute_key(
                code=code,
                language=language,
                filename=filename,
                context=context,
                rules=rules,
                min_severity=min_severity,
                model=self.settings.gemini_model,
            )
            cached_res = self.cache.get(cache_key)
            if cached_res is not None:
                logger.info(f"Serving deterministic cached review for key {cache_key[:12]}")
                return cached_res

        client = self._get_client()
        if client is None:
            # Fall back to mock analyzer when credentials are unavailable
            fallback = MockReviewEngine()
            fallback_res = await fallback.analyze(code, language, filename, context, rules, min_severity=min_severity)
            if self.settings.review_cache_enabled and cache_key:
                self.cache.put(cache_key, fallback_res)
            return fallback_res

        prompt = build_review_prompt(code, language, filename, context, rules)
        start_time = time.time()

        from google.genai import types

        # Build prioritized list of models to try - strictly Gemini 3.5 Flash and above
        primary_model = self.settings.gemini_model or "gemini-3.8-flash"
        if not is_gemini_35_plus(primary_model):
            logger.warning(
                "Configured model '%s' is below Gemini 3.5. Defaulting to gemini-3.8-flash.",
                primary_model,
            )
            primary_model = "gemini-3.8-flash"

        candidate_models = [primary_model]
        for fallback_model in SUPPORTED_GEMINI_35_PLUS_MODELS:
            if fallback_model not in candidate_models and is_gemini_35_plus(fallback_model):
                candidate_models.append(fallback_model)

        last_exception = None

        for model_to_try in candidate_models:
            max_retries = 2
            model_not_found = False

            for attempt in range(max_retries):
                try:
                    config_kwargs = {
                        "system_instruction": SYSTEM_INSTRUCTION,
                        "response_mime_type": "application/json",
                        "response_schema": ReviewAnalysisResult,
                        "temperature": self.settings.gemini_temperature,
                        "max_output_tokens": self.settings.gemini_max_output_tokens,
                    }
                    if self.settings.gemini_seed is not None:
                        config_kwargs["seed"] = self.settings.gemini_seed

                    response = client.models.generate_content(
                        model=model_to_try,
                        contents=prompt,
                        config=types.GenerateContentConfig(**config_kwargs),
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
                    result = noise_filter.filter_and_consolidate(result, min_severity=min_severity)

                    # Canonicalize finding order and remove any duplicate reports
                    result = canonicalize_review_result(result)

                    # Cache deterministic output for future identical requests
                    if self.settings.review_cache_enabled and cache_key:
                        self.cache.put(cache_key, result)

                    return result

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
                        fallback_res = await fallback.analyze(code, language, filename, context, rules, min_severity=min_severity)
                        if self.settings.review_cache_enabled and cache_key:
                            self.cache.put(cache_key, fallback_res)
                        return fallback_res

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
        res = canonicalize_review_result(res)
        if self.settings.review_cache_enabled and cache_key:
            self.cache.put(cache_key, res)
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
