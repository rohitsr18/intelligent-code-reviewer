import time
from typing import Any, Dict, Optional
import httpx
from fastapi import Header, HTTPException, Request, status
from jose import jwt, JWTError
from app.auth.models import AuthenticatedUser, Role
from app.core.config import get_settings

IAP_ISSUER = "https://cloud.google.com/iap"
IAP_JWK_URL = "https://www.gstatic.com/iap/verify/public_key-jwk"

# In-memory cache for Google IAP public signing keys
_cached_jwk_keys: Optional[Dict[str, Any]] = None
_jwk_cached_at: float = 0
JWK_CACHE_TTL = 3600  # 1 hour


async def get_iap_public_keys(client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    global _cached_jwk_keys, _jwk_cached_at
    now = time.time()
    if _cached_jwk_keys and (now - _jwk_cached_at < JWK_CACHE_TTL):
        return _cached_jwk_keys

    try:
        if client:
            res = await client.get(IAP_JWK_URL, timeout=5.0)
        else:
            async with httpx.AsyncClient() as c:
                res = await c.get(IAP_JWK_URL, timeout=5.0)
        res.raise_for_status()
        _cached_jwk_keys = res.json()
        _jwk_cached_at = now
        return _cached_jwk_keys
    except Exception as e:
        if _cached_jwk_keys:
            return _cached_jwk_keys
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to fetch IAP verification keys",
        ) from e


def resolve_role(email: str, claims: Dict[str, Any]) -> Role:
    settings = get_settings()
    if email.lower() in [admin.lower() for admin in settings.admin_emails]:
        return Role.ADMIN
    if claims.get("role") == "admin":
        return Role.ADMIN
    if claims.get("role") == "reviewer":
        return Role.REVIEWER
    return Role.ENGINEER


async def verify_iap_token(
    token: str,
    expected_audience: Optional[str] = None,
    public_keys: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not public_keys:
        public_keys = await get_iap_public_keys()

    try:
        # Decode without verification first to extract header 'kid'
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed IAP token header",
        ) from e

    kid = unverified_header.get("kid")
    key = None
    if isinstance(public_keys, dict) and "keys" in public_keys:
        for k in public_keys["keys"]:
            if k.get("kid") == kid:
                key = k
                break
    elif isinstance(public_keys, dict) and kid in public_keys:
        key = public_keys[kid]

    if not key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown or expired IAP key ID",
        )

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["ES256", "RS256"],
            audience=expected_audience,
            issuer=IAP_ISSUER,
        )
        return claims
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid IAP token assertion: {str(e)}",
        ) from e


async def get_current_user(
    request: Request,
    x_goog_iap_jwt_assertion: Optional[str] = Header(None, alias="x-goog-iap-jwt-assertion"),
    x_mock_user_email: Optional[str] = Header(None, alias="x-mock-user-email"),
    x_mock_user_role: Optional[str] = Header(None, alias="x-mock-user-role"),
) -> AuthenticatedUser:
    settings = get_settings()

    # Normalize if invoked directly without FastAPI DI
    headers = getattr(request, "headers", {})
    if not isinstance(x_goog_iap_jwt_assertion, str):
        val = headers.get("x-goog-iap-jwt-assertion") if hasattr(headers, "get") else None
        x_goog_iap_jwt_assertion = val if isinstance(val, str) else None

    if not isinstance(x_mock_user_email, str):
        val = headers.get("x-mock-user-email") if hasattr(headers, "get") else None
        x_mock_user_email = val if isinstance(val, str) else None

    if not isinstance(x_mock_user_role, str):
        val = headers.get("x-mock-user-role") if hasattr(headers, "get") else None
        x_mock_user_role = val if isinstance(val, str) else None

    # Local development or testing mode
    if not settings.iap_enabled:
        if x_goog_iap_jwt_assertion:
            # If an assertion token was explicitly passed, verify it if audience is configured
            try:
                claims = await verify_iap_token(
                    x_goog_iap_jwt_assertion,
                    expected_audience=settings.iap_audience,
                )
                email = claims.get("email", "unknown@company.local")
                sub = claims.get("sub", email)
                role = resolve_role(email, claims)
                return AuthenticatedUser(
                    user_id=sub,
                    email=email,
                    role=role,
                    hosted_domain=claims.get("hd"),
                    claims=claims,
                )
            except HTTPException:
                if not x_mock_user_email:
                    raise

        # Fallback to mock header or default dev user
        email = x_mock_user_email or "developer@company.local"
        claims = {"dev_mode": True}
        if x_mock_user_role:
            claims["role"] = x_mock_user_role.lower()
        role = resolve_role(email, claims)
        return AuthenticatedUser(
            user_id=f"dev-user-{email.split('@')[0]}",
            email=email,
            role=role,
            hosted_domain="company.local",
            claims=claims,
        )

    # Production IAP enforcement
    if not x_goog_iap_jwt_assertion:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required x-goog-iap-jwt-assertion header",
        )

    claims = await verify_iap_token(
        x_goog_iap_jwt_assertion,
        expected_audience=settings.iap_audience,
    )

    email = claims.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="IAP token missing email claim",
        )

    sub = claims.get("sub", email)
    role = resolve_role(email, claims)

    return AuthenticatedUser(
        user_id=sub,
        email=email,
        role=role,
        hosted_domain=claims.get("hd"),
        claims=claims,
    )
