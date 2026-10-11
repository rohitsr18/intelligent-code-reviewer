"""Production-grade Code Sanitizer and Secret / PII Scrubber.

Prevents sensitive data leaks (API keys, credentials, private keys, PII)
from ever reaching LLMs (Gemini) or third-party APIs.
"""

import math
import re
from typing import List, Tuple, Dict, Any
from app.security.models import (
    RedactedSecret,
    SanitizationResult,
    SecuritySeverity,
)


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    frequencies: Dict[str, int] = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


class CodeSanitizer:
    """Detects and redacts credentials, secrets, and PII in source code."""

    def __init__(
        self,
        entropy_threshold: float = 4.3,
        scan_secrets: bool = True,
        scan_pii: bool = True,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.scan_secrets = scan_secrets
        self.scan_pii = scan_pii

        # Precompiled regex patterns for known credentials
        self._secret_patterns: List[Tuple[str, re.Pattern, SecuritySeverity]] = [
            (
                "PRIVATE_KEY",
                re.compile(
                    r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----[\s\S]+?-----END (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----",
                    re.MULTILINE,
                ),
                SecuritySeverity.CRITICAL,
            ),
            (
                "AWS_ACCESS_KEY",
                re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                SecuritySeverity.CRITICAL,
            ),
            (
                "GCP_API_KEY",
                re.compile(r"\b(AIza[0-9A-Za-z\-_]{32,40})\b"),
                SecuritySeverity.CRITICAL,
            ),
            (
                "GITHUB_TOKEN",
                re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
                SecuritySeverity.CRITICAL,
            ),
            (
                "SLACK_TOKEN",
                re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
                SecuritySeverity.HIGH,
            ),
            (
                "JWT_TOKEN",
                re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
                SecuritySeverity.HIGH,
            ),
        ]

        # Password / secret assignment pattern
        self._assignment_pattern = re.compile(
            r"""(?i)(["']?(?:[a-zA-Z0-9_]*(?:password|passwd|pass|pwd|secret|api_key|apikey|token|credential)[a-zA-Z0-9_]*)["']?\s*[:=]\s*["'])([^"'\n\r]{6,})(["'])""",
            re.MULTILINE,
        )

        # Database connection URI credentials pattern
        self._db_uri_pattern = re.compile(
            r"""((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[a-zA-Z0-9_\-\.%]+:)([^@/\s]+)(@[a-zA-Z0-9_\-\.]+)""",
            re.IGNORECASE,
        )

        # PII patterns
        self._email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        )
        self._ipv4_pattern = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )

    def sanitize(self, code: str) -> SanitizationResult:
        """Sanitize code by scrubbing all detected secrets and PII."""
        if not code:
            return SanitizationResult(
                original_line_count=0,
                sanitized_code="",
                redactions=[],
                has_secrets=False,
                has_pii=False,
            )

        sanitized = code
        redactions: List[RedactedSecret] = []
        has_secrets = False
        has_pii = False
        redaction_counter = 0

        # 1. Private Keys & Multi-line credentials
        if self.scan_secrets:
            for secret_type, pattern, severity in self._secret_patterns:
                def replace_secret(match: re.Match) -> str:
                    nonlocal redaction_counter, has_secrets
                    redaction_counter += 1
                    has_secrets = True
                    token = f"<REDACTED_SECRET:{secret_type}:{redaction_counter}>"
                    
                    # Compute line number
                    start_pos = match.start()
                    line_no = code[:start_pos].count("\n") + 1
                    
                    redactions.append(
                        RedactedSecret(
                            secret_type=secret_type,
                            severity=severity,
                            redaction_token=token,
                            line_number=line_no,
                        )
                    )
                    return token

                sanitized = pattern.sub(replace_secret, sanitized)

            # 2. Database URI passwords
            def replace_db_pwd(match: re.Match) -> str:
                nonlocal redaction_counter, has_secrets
                redaction_counter += 1
                has_secrets = True
                token = f"<REDACTED_DB_PWD:{redaction_counter}>"
                line_no = sanitized[:match.start()].count("\n") + 1
                redactions.append(
                    RedactedSecret(
                        secret_type="DATABASE_URI_PASSWORD",
                        severity=SecuritySeverity.CRITICAL,
                        redaction_token=token,
                        line_number=line_no,
                    )
                )
                return f"{match.group(1)}{token}{match.group(3)}"

            sanitized = self._db_uri_pattern.sub(replace_db_pwd, sanitized)

            # 3. Key-Value Secret & Password assignments
            def replace_assignment(match: re.Match) -> str:
                nonlocal redaction_counter, has_secrets
                prefix = match.group(1)
                val = match.group(2)
                suffix = match.group(3)
                
                # If already redacted, keep it
                if "<REDACTED" in val:
                    return match.group(0)

                redaction_counter += 1
                has_secrets = True
                token = f"<REDACTED_CREDENTIAL:{redaction_counter}>"
                line_no = sanitized[:match.start()].count("\n") + 1
                redactions.append(
                    RedactedSecret(
                        secret_type="ASSIGNED_CREDENTIAL",
                        severity=SecuritySeverity.HIGH,
                        redaction_token=token,
                        line_number=line_no,
                    )
                )
                return f"{prefix}{token}{suffix}"

            sanitized = self._assignment_pattern.sub(replace_assignment, sanitized)

            # 4. High-Entropy String Scanner (captures non-standard API keys)
            sanitized = self._scrub_high_entropy_strings(sanitized, redactions)
            if any(r.secret_type == "HIGH_ENTROPY_TOKEN" for r in redactions):
                has_secrets = True

        # 5. PII Scrubbing
        if self.scan_pii:
            # Email addresses
            def replace_email(match: re.Match) -> str:
                nonlocal redaction_counter, has_pii
                email = match.group(0)
                # Ignore common code comment placeholders like example@example.com
                if "example.com" in email.lower() or "test.com" in email.lower():
                    return email
                redaction_counter += 1
                has_pii = True
                token = f"<REDACTED_PII:EMAIL:{redaction_counter}>"
                line_no = sanitized[:match.start()].count("\n") + 1
                redactions.append(
                    RedactedSecret(
                        secret_type="PII_EMAIL",
                        severity=SecuritySeverity.MEDIUM,
                        redaction_token=token,
                        line_number=line_no,
                    )
                )
                return token

            sanitized = self._email_pattern.sub(replace_email, sanitized)

            # External IP Addresses (ignore loopback / broadcast)
            def replace_ip(match: re.Match) -> str:
                nonlocal redaction_counter, has_pii
                ip = match.group(0)
                if ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255", "1.1.1.1", "8.8.8.8"):
                    return ip
                redaction_counter += 1
                has_pii = True
                token = f"<REDACTED_PII:IP:{redaction_counter}>"
                line_no = sanitized[:match.start()].count("\n") + 1
                redactions.append(
                    RedactedSecret(
                        secret_type="PII_IP_ADDRESS",
                        severity=SecuritySeverity.LOW,
                        redaction_token=token,
                        line_number=line_no,
                    )
                )
                return token

            sanitized = self._ipv4_pattern.sub(replace_ip, sanitized)

        return SanitizationResult(
            original_line_count=len(code.splitlines()),
            sanitized_code=sanitized,
            redactions=redactions,
            has_secrets=has_secrets,
            has_pii=has_pii,
        )

    def _scrub_high_entropy_strings(
        self, code: str, redactions: List[RedactedSecret]
    ) -> str:
        """Scan string literals for suspiciously high Shannon entropy."""
        str_literal_pattern = re.compile(r"""(["'])([^"'\r\n]{16,})\1""")
        entropy_counter = len(redactions)

        def check_entropy(match: re.Match) -> str:
            nonlocal entropy_counter
            quote = match.group(1)
            candidate = match.group(2)

            # Ignore already redacted tokens
            if "<REDACTED" in candidate:
                return match.group(0)

            entropy = calculate_shannon_entropy(candidate)
            if entropy >= self.entropy_threshold:
                entropy_counter += 1
                token = f"<REDACTED_SECRET:HIGH_ENTROPY_TOKEN:{entropy_counter}>"
                line_no = code[:match.start()].count("\n") + 1
                redactions.append(
                    RedactedSecret(
                        secret_type="HIGH_ENTROPY_TOKEN",
                        severity=SecuritySeverity.HIGH,
                        redaction_token=token,
                        line_number=line_no,
                    )
                )
                return f"{quote}{token}{quote}"

            return match.group(0)

        return str_literal_pattern.sub(check_entropy, code)
