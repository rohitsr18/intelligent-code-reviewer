from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, Query
from app.auth.models import AuthenticatedUser, Role
from app.auth.iap import get_current_user
from app.auth.rbac import require_role
from app.analytics.models import HistoricalRule, RuleIngestResult
from app.analytics.service import HistoricalLearningService, get_historical_learning_service

router = APIRouter(prefix="/rules", tags=["Historical Rules & Learning"])


@router.post(
    "/upload-csv",
    response_model=RuleIngestResult,
    status_code=status.HTTP_201_CREATED,
    summary="Upload CSV of team historical coding rules",
)
async def upload_rules_csv(
    file: UploadFile = File(..., description="CSV file with columns: rule_id,title,language,category,severity,pattern_or_anti_pattern,guidance,tags"),
    user: AuthenticatedUser = Depends(require_role(Role.REVIEWER)),
    service: HistoricalLearningService = Depends(get_historical_learning_service),
) -> RuleIngestResult:
    """Ingests custom team rules and historical anti-patterns from a CSV file into BigQuery.

    Requires REVIEWER or ADMIN privileges.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a valid .csv file",
        )

    content_bytes = await file.read()
    try:
        csv_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file must be UTF-8 encoded",
        )

    result = await service.ingest_csv(
        csv_content=csv_text,
        created_by=user.email,
    )

    if result.imported_count == 0 and result.errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Failed to import rules from CSV", "errors": result.errors},
        )

    return result


@router.get(
    "",
    response_model=List[HistoricalRule],
    summary="List active historical rules",
)
async def list_rules(
    language: Optional[str] = Query(None, description="Filter rules by programming language (e.g. python, typescript)"),
    user: AuthenticatedUser = Depends(get_current_user),
    service: HistoricalLearningService = Depends(get_historical_learning_service),
) -> List[HistoricalRule]:
    """Retrieves active coding standards and anti-pattern rules.

    Accessible to all authenticated engineers.
    """
    return await service.get_enrichment_rules(language=language or "")


@router.get(
    "/analytics",
    response_model=List[Dict[str, Any]],
    summary="Retrieve review analytical events",
)
async def get_review_analytics(
    user_id: Optional[str] = Query(None, description="Filter by user ID (reviewer/admin only)"),
    limit: int = Query(50, ge=1, le=100),
    user: AuthenticatedUser = Depends(get_current_user),
    service: HistoricalLearningService = Depends(get_historical_learning_service),
) -> List[Dict[str, Any]]:
    """Retrieves review event metrics for Looker Studio telemetry inspection."""
    target_user_id = user.user_id
    if user.is_reviewer_or_above and user_id:
        target_user_id = user_id

    return await service.get_user_events(user_id=target_user_id, limit=limit)
