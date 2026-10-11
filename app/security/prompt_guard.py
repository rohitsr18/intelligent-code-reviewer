import re
from typing import List, Tuple
from app.security.models import PromptGuardResult


class PromptGuard:
    """Guards against prompt injection and delimiters escape in uploaded code."""

    INJECTION_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        (
            "OVERRIDE_INSTRUCTIONS",
            re.compile(
                r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules|directives)\b"
            ),
            0.9,
        ),
        (
            "ROLEPLAY_JAILBREAK",
            re.compile(
                r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:dan|developer\s+mode|unrestricted|an\s+unfiltered)\b"
            ),
            0.85,
        ),
        (
            "OUTPUT_MANIPULATION",
            re.compile(
                r"(?i)\b(?:always\s+respond\s+with|output\s+only|approve\s+this\s+pr|just\s+say\s+['\"]?lgtm['\"]?)\b"
            ),
            0.75,
        ),
        (
            "PROMPT_LEAK_REQUEST",
            re.compile(
                r"(?i)\b(?:print|reveal|repeat|output|show)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|secret\s+instructions)\b"
            ),
            0.8,
        ),
    ]

    BOUNDARY_TAG_OPEN = "<untrusted_source_code"
    BOUNDARY_TAG_CLOSE = "</untrusted_source_code>"

    def __init__(self, risk_threshold: float = 0.7) -> None:
        self.risk_threshold = risk_threshold

    def inspect_and_wrap(
        self,
        code: str,
        language: str = "text",
        context: str = "",
    ) -> PromptGuardResult:
        if not code:
            return PromptGuardResult(
                is_safe=True,
                risk_score=0.0,
                flags=[],
                secured_prompt="",
            )

        flags: List[str] = []
        max_risk: float = 0.0

        for flag_name, pattern, weight in self.INJECTION_PATTERNS:
            if pattern.search(code) or (context and pattern.search(context)):
                flags.append(flag_name)
                max_risk = max(max_risk, weight)

        # Defuse closing tags in user code to prevent premature boundary closing
        escaped_code = code.replace(
            self.BOUNDARY_TAG_CLOSE,
            "&lt;/untrusted_source_code&gt;",
        )

        # Wrap in unambiguous tags so the model treats content strictly as data
        secured_prompt = (
            f'{self.BOUNDARY_TAG_OPEN} language="{language}">\n'
            f"{escaped_code}\n"
            f"{self.BOUNDARY_TAG_CLOSE}"
        )

        return PromptGuardResult(
            is_safe=(max_risk < self.risk_threshold),
            risk_score=round(max_risk, 2),
            flags=flags,
            secured_prompt=secured_prompt,
        )
