import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1.models import UserSessionResponse, RedactionSummary
from app.auth.models import AuthenticatedUser
from app.auth.iap import get_current_user
from app.core.config import get_settings
from app.security.sanitizer import CodeSanitizer
from app.security.prompt_guard import PromptGuard
from app.reviewer.engine import BaseReviewEngine, get_review_engine
from app.analytics.service import HistoricalLearningService, get_historical_learning_service
from app.storage.models import (
    CreateSessionRequest,
    ReviseSessionRequest,
    ReviewSessionDocument,
    ReviewDocument,
)
from app.storage.service import StorageService, get_storage_service

router = APIRouter(prefix="/sessions", tags=["Sessions"])


def get_sanitizer() -> CodeSanitizer:
    settings = get_settings()
    return CodeSanitizer(
        entropy_threshold=settings.entropy_threshold,
        scan_secrets=settings.secret_scanning_enabled,
        scan_pii=settings.pii_redaction_enabled,
    )


def get_prompt_guard() -> PromptGuard:
    return PromptGuard()


@router.get("/me", response_model=UserSessionResponse, summary="Get current user IAP session info")
async def get_current_session(
    user: AuthenticatedUser = Depends(get_current_user),
) -> UserSessionResponse:
    return UserSessionResponse(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        is_admin=user.is_admin,
        hosted_domain=user.hosted_domain,
    )


@router.post(
    "",
    response_model=ReviewSessionDocument,
    status_code=status.HTTP_201_CREATED,
    summary="Create an interactive multi-round code review session",
)
async def create_review_session(
    req: CreateSessionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    storage: StorageService = Depends(get_storage_service),
) -> ReviewSessionDocument:
    return await storage.create_session(
        user_id=user.user_id,
        email=user.email,
        title=req.title,
        language=req.language,
    )


@router.get(
    "/{session_id}",
    response_model=ReviewSessionDocument,
    summary="Get review session details and revision history replay",
)
async def get_review_session(
    session_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
    storage: StorageService = Depends(get_storage_service),
) -> ReviewSessionDocument:
    session = await storage.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review session '{session_id}' not found",
        )

    # Developers can view their own sessions; reviewers/admins can view all
    if not user.is_reviewer_or_above and user.user_id != session.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you can only view your own review sessions",
        )

    return session


@router.post(
    "/{session_id}/revise",
    response_model=ReviewSessionDocument,
    status_code=status.HTTP_200_OK,
    summary="Submit a code revision in an ongoing review session",
)
async def submit_session_revision(
    session_id: str,
    req: ReviseSessionRequest,
    user: AuthenticatedUser = Depends(get_current_user),
    sanitizer: CodeSanitizer = Depends(get_sanitizer),
    guard: PromptGuard = Depends(get_prompt_guard),
    engine: BaseReviewEngine = Depends(get_review_engine),
    learning_service: HistoricalLearningService = Depends(get_historical_learning_service),
    storage: StorageService = Depends(get_storage_service),
) -> ReviewSessionDocument:
    session = await storage.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review session '{session_id}' not found",
        )

    if not user.is_reviewer_or_above and user.user_id != session.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you can only revise your own review sessions",
        )

    # 1. Sanitize & guard code
    sanitization_result = sanitizer.sanitize(req.code)
    guard_result = guard.inspect_and_wrap(
        code=sanitization_result.sanitized_code,
        language=session.language,
        context=req.context or f"Session {session_id} revision",
    )

    review_id = str(uuid.uuid4())
    submitted_at = datetime.now(timezone.utc)
    review_status = "accepted"
    if not guard_result.is_safe:
        review_status = "flagged_risk"
    elif sanitization_result.has_secrets or sanitization_result.has_pii:
        review_status = "sanitized"

    # 2. Enrich with historical rules
    active_rules = await learning_service.get_enrichment_rules(language=session.language)
    prompt_rules = learning_service.format_rules_for_prompt(active_rules)

    # 3. Analyze revision
    analysis = await engine.analyze(
        code=guard_result.secured_prompt,
        language=session.language,
        filename=req.filename,
        context=req.context,
        rules=prompt_rules,
    )

    # 4. Stream BigQuery telemetry
    await learning_service.record_review_event(
        review_id=review_id,
        user_id=user.user_id,
        user_email=user.email,
        language=session.language,
        filename=req.filename,
        original_line_count=sanitization_result.original_line_count,
        sanitized_secrets_count=sanitization_result.total_redactions,
        prompt_risk_score=guard_result.risk_score,
        review_status=review_status,
        analysis=analysis,
        rules_applied_count=len(prompt_rules),
    )

    # 5. Persist review document
    review_doc = ReviewDocument(
        review_id=review_id,
        user_id=user.user_id,
        submitted_by=user.email,
        submitted_at=submitted_at,
        status=review_status,
        filename=req.filename,
        language=session.language,
        original_line_count=sanitization_result.original_line_count,
        sanitized_code=sanitization_result.sanitized_code,
        secured_prompt=guard_result.secured_prompt,
        redactions=[
            RedactionSummary(
                secret_type=r.secret_type,
                redaction_token=r.redaction_token,
                line_number=r.line_number,
            ).model_dump()
            for r in sanitization_result.redactions
        ],
        risk_score=guard_result.risk_score,
        is_safe_prompt=guard_result.is_safe,
        flags=guard_result.flags,
        rules_applied_count=len(prompt_rules),
        analysis=analysis.model_dump() if analysis else None,
        session_id=session_id,
    )
    await storage.save_review(review_doc)

    # 6. Add revision item to session
    summary = analysis.summary if analysis else "Code revised"
    updated_session = await storage.add_revision(
        session_id=session_id,
        review=review_doc,
        summary=summary,
    )
    return updated_session or session
