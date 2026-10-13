import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1.models import (
    ReviewSubmissionRequest,
    ReviewSubmissionResponse,
    ReviewDetailResponse,
    RedactionSummary,
)
from app.auth.models import AuthenticatedUser
from app.auth.iap import get_current_user
from app.core.config import get_settings
from app.core.rate_limiter import check_api_rate_limit
from app.security.sanitizer import CodeSanitizer
from app.security.prompt_guard import PromptGuard
from app.reviewer.engine import BaseReviewEngine, get_review_engine
from app.analytics.service import HistoricalLearningService, get_historical_learning_service

router = APIRouter(prefix="/review", tags=["Review"])

# In-memory submission store for gateway stage (persisted in Firestore in Feature 5)
_review_store: Dict[str, Dict[str, Any]] = {}


def get_sanitizer() -> CodeSanitizer:
    settings = get_settings()
    return CodeSanitizer(
        entropy_threshold=settings.entropy_threshold,
        scan_secrets=settings.secret_scanning_enabled,
        scan_pii=settings.pii_redaction_enabled,
    )


def get_prompt_guard() -> PromptGuard:
    return PromptGuard()


@router.post(
    "/submit",
    response_model=ReviewSubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_api_rate_limit)],
)
async def submit_code_for_review(
    submission: ReviewSubmissionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    sanitizer: CodeSanitizer = Depends(get_sanitizer),
    guard: PromptGuard = Depends(get_prompt_guard),
    engine: BaseReviewEngine = Depends(get_review_engine),
    learning_service: HistoricalLearningService = Depends(get_historical_learning_service),
) -> ReviewSubmissionResponse:
    settings = get_settings()

    # Payload size and line limit checks
    code_bytes = len(submission.code.encode("utf-8"))
    if code_bytes > settings.max_code_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Code payload ({code_bytes} bytes) exceeds limit of {settings.max_code_size_bytes} bytes",
        )

    code_lines = len(submission.code.splitlines())
    if code_lines > settings.max_code_lines:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Code length ({code_lines} lines) exceeds limit of {settings.max_code_lines} lines",
        )

    # 1. Scrub credentials and PII
    sanitization_result = sanitizer.sanitize(submission.code)

    # 2. Guard against prompt injection and isolate boundaries
    guard_result = guard.inspect_and_wrap(
        code=sanitization_result.sanitized_code,
        language=submission.language,
        context=submission.context or "",
    )

    review_id = str(uuid.uuid4())
    submitted_at = datetime.now(timezone.utc)

    # Determine status flag
    if not guard_result.is_safe:
        review_status = "flagged_risk"
    elif sanitization_result.has_secrets or sanitization_result.has_pii:
        review_status = "sanitized"
    else:
        review_status = "accepted"

    redaction_summaries = [
        RedactionSummary(
            secret_type=r.secret_type,
            redaction_token=r.redaction_token,
            line_number=r.line_number,
        )
        for r in sanitization_result.redactions
    ]

    # 3. Retrieve matching team rules from BigQuery historical engine
    active_rules = await learning_service.get_enrichment_rules(language=submission.language)
    prompt_rules = learning_service.format_rules_for_prompt(active_rules)

    # 4. Analyze code with AI review engine enriched with team rules
    analysis = await engine.analyze(
        code=guard_result.secured_prompt,
        language=submission.language,
        filename=submission.filename,
        context=submission.context,
        rules=prompt_rules,
    )

    # 5. Record analytical telemetry in BigQuery
    await learning_service.record_review_event(
        review_id=review_id,
        user_id=user.user_id,
        user_email=user.email,
        language=submission.language,
        filename=submission.filename,
        original_line_count=sanitization_result.original_line_count,
        sanitized_secrets_count=sanitization_result.total_redactions,
        prompt_risk_score=guard_result.risk_score,
        review_status=review_status,
        analysis=analysis,
        rules_applied_count=len(prompt_rules),
    )

    record = {
        "review_id": review_id,
        "status": review_status,
        "user_id": user.user_id,
        "submitted_by": user.email,
        "submitted_at": submitted_at,
        "filename": submission.filename,
        "language": submission.language,
        "original_line_count": sanitization_result.original_line_count,
        "sanitized_code": sanitization_result.sanitized_code,
        "secured_prompt": guard_result.secured_prompt,
        "redactions": redaction_summaries,
        "risk_score": guard_result.risk_score,
        "is_safe_prompt": guard_result.is_safe,
        "flags": guard_result.flags,
        "rules_applied_count": len(prompt_rules),
        "analysis": analysis,
    }

    _review_store[review_id] = record

    return ReviewSubmissionResponse(
        review_id=review_id,
        status=review_status,
        original_line_count=sanitization_result.original_line_count,
        redactions_count=sanitization_result.total_redactions,
        redactions=redaction_summaries,
        risk_score=guard_result.risk_score,
        is_safe_prompt=guard_result.is_safe,
        flags=guard_result.flags,
        submitted_by=user.email,
        submitted_at=submitted_at,
        filename=submission.filename,
        language=submission.language,
        rules_applied_count=len(prompt_rules),
        analysis=analysis,
    )


@router.get(
    "/{review_id}",
    response_model=ReviewDetailResponse,
)
async def get_review_submission(
    review_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> ReviewDetailResponse:
    record = _review_store.get(review_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review submission '{review_id}' not found",
        )

    # Developers can view their own reviews; reviewers/admins can view all
    if not user.is_reviewer_or_above and user.user_id != record["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you can only view your own review submissions",
        )

    return ReviewDetailResponse(
        review_id=record["review_id"],
        status=record["status"],
        submitted_by=record["submitted_by"],
        submitted_at=record["submitted_at"],
        filename=record.get("filename"),
        language=record["language"],
        original_line_count=record["original_line_count"],
        redactions_count=len(record.get("redactions", [])),
        sanitized_code=record["sanitized_code"],
        risk_score=record["risk_score"],
        is_safe_prompt=record["is_safe_prompt"],
        flags=record.get("flags", []),
        rules_applied_count=record.get("rules_applied_count", 0),
        analysis=record.get("analysis"),
    )
