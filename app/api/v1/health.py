"""Health check endpoints for Cloud Run container lifecycle."""

from typing import Dict, Any
from fastapi import APIRouter, status
from app.core.config import get_settings

router = APIRouter(tags=["Health"])


@router.get(
    "/health/live",
    status_code=status.HTTP_200_OK,
    summary="Liveness Probe",
    description="Returns 200 if the container process is responsive.",
)
async def liveness() -> Dict[str, str]:
    return {"status": "alive"}


@router.get(
    "/health/ready",
    status_code=status.HTTP_200_OK,
    summary="Readiness Probe",
    description="Returns 200 when all core configurations are valid.",
)
async def readiness() -> Dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ready",
        "app_name": settings.app_name,
        "environment": settings.environment,
        "features": {
            "secret_scanning": settings.secret_scanning_enabled,
            "pii_redaction": settings.pii_redaction_enabled,
            "prompt_injection_defense": settings.prompt_injection_defense_enabled,
            "iap_enabled": settings.iap_enabled,
        },
    }
