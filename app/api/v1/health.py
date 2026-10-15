from typing import Dict, Any
from fastapi import APIRouter
from app.core.config import get_settings

router = APIRouter(tags=["Health"])


@router.get("/health/live")
async def liveness() -> Dict[str, str]:
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness() -> Dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ready",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "features": {
            "secret_scanning": settings.secret_scanning_enabled,
            "pii_redaction": settings.pii_redaction_enabled,
            "prompt_injection_defense": settings.prompt_injection_defense_enabled,
            "iap_enabled": settings.iap_enabled,
        },
    }
