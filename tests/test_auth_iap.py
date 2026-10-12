import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from jose import jwt
from fastapi import HTTPException
from app.auth.models import Role, AuthenticatedUser
from app.auth.iap import verify_iap_token, resolve_role, get_current_user, IAP_ISSUER
from app.auth.rbac import require_role
from app.core.config import Settings


@pytest.fixture
def test_ec_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {
        "kid": "test-key-id-1",
        "private_pem": pem_private,
        "public_pem": pem_public,
    }


def make_token(
    key_info: dict,
    email: str = "alice@company.com",
    sub: str = "accounts.google.com:12345",
    aud: str = "/projects/123/global/backendServices/456",
    exp_offset: int = 3600,
    issuer: str = IAP_ISSUER,
) -> str:
    payload = {
        "iss": issuer,
        "aud": aud,
        "sub": sub,
        "email": email,
        "hd": "company.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
    }
    headers = {"kid": key_info["kid"], "alg": "ES256"}
    return jwt.encode(payload, key_info["private_pem"], algorithm="ES256", headers=headers)


@pytest.mark.asyncio
async def test_valid_iap_token_verification(test_ec_key):
    aud = "/projects/123/global/backendServices/456"
    token = make_token(test_ec_key, aud=aud)
    public_keys = {test_ec_key["kid"]: test_ec_key["public_pem"]}

    claims = await verify_iap_token(token, expected_audience=aud, public_keys=public_keys)
    assert claims["email"] == "alice@company.com"
    assert claims["sub"] == "accounts.google.com:12345"


@pytest.mark.asyncio
async def test_expired_iap_token_rejected(test_ec_key):
    aud = "/projects/123/global/backendServices/456"
    token = make_token(test_ec_key, aud=aud, exp_offset=-60)
    public_keys = {test_ec_key["kid"]: test_ec_key["public_pem"]}

    with pytest.raises(HTTPException) as exc_info:
        await verify_iap_token(token, expected_audience=aud, public_keys=public_keys)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_wrong_audience_rejected(test_ec_key):
    token = make_token(test_ec_key, aud="/projects/999/global/backendServices/999")
    public_keys = {test_ec_key["kid"]: test_ec_key["public_pem"]}

    with pytest.raises(HTTPException) as exc_info:
        await verify_iap_token(
            token,
            expected_audience="/projects/123/global/backendServices/456",
            public_keys=public_keys,
        )
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_unknown_key_id_rejected(test_ec_key):
    token = make_token(test_ec_key)
    public_keys = {"other-key": test_ec_key["public_pem"]}

    with pytest.raises(HTTPException) as exc_info:
        await verify_iap_token(token, public_keys=public_keys)
    assert exc_info.value.status_code == 401
    assert "Unknown or expired IAP key ID" in exc_info.value.detail


def test_resolve_role():
    assert resolve_role("admin@company.com", {}) == Role.ADMIN
    assert resolve_role("user@company.com", {"role": "reviewer"}) == Role.REVIEWER
    assert resolve_role("user@company.com", {}) == Role.ENGINEER


@pytest.mark.asyncio
async def test_rbac_require_role():
    admin_user = AuthenticatedUser(user_id="1", email="a@c.com", role=Role.ADMIN)
    reviewer_user = AuthenticatedUser(user_id="2", email="b@c.com", role=Role.REVIEWER)
    engineer_user = AuthenticatedUser(user_id="3", email="c@c.com", role=Role.ENGINEER)

    check_admin = require_role(Role.ADMIN)
    assert await check_admin(admin_user) == admin_user

    with pytest.raises(HTTPException) as exc:
        await check_admin(engineer_user)
    assert exc.value.status_code == 403

    check_reviewer = require_role(Role.REVIEWER)
    assert await check_reviewer(reviewer_user) == reviewer_user
    assert await check_reviewer(admin_user) == admin_user

    with pytest.raises(HTTPException) as exc:
        await check_reviewer(engineer_user)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_get_current_user_dev_mode(monkeypatch):
    from unittest.mock import MagicMock
    request = MagicMock()
    request.headers = {}

    user = await get_current_user(request)
    assert user.email == "developer@company.local"
    assert user.role == Role.ENGINEER

    user_custom = await get_current_user(request, x_mock_user_email="admin@company.com")
    assert user_custom.email == "admin@company.com"
    assert user_custom.role == Role.ADMIN


@pytest.mark.asyncio
async def test_get_current_user_prod_mode_missing_header(monkeypatch):
    from unittest.mock import MagicMock
    from app.core import config

    monkeypatch.setattr(config.get_settings(), "iap_enabled", True)
    request = MagicMock()
    request.headers = {}

    with pytest.raises(HTTPException) as exc:
        await get_current_user(request, x_goog_iap_jwt_assertion=None)
    assert exc.value.status_code == 401
    assert "Missing required x-goog-iap-jwt-assertion" in exc.value.detail


@pytest.mark.asyncio
async def test_get_current_user_prod_mode_valid(monkeypatch, test_ec_key):
    from unittest.mock import MagicMock
    from app.core import config
    from app.auth import iap

    monkeypatch.setattr(config.get_settings(), "iap_enabled", True)
    monkeypatch.setattr(config.get_settings(), "iap_audience", "test-aud")

    # Mock public keys fetch
    async def mock_keys():
        return {test_ec_key["kid"]: test_ec_key["public_pem"]}

    monkeypatch.setattr(iap, "get_iap_public_keys", mock_keys)

    token = make_token(test_ec_key, aud="test-aud", email="staff.eng@company.com")
    request = MagicMock()
    request.headers = {}

    user = await get_current_user(request, x_goog_iap_jwt_assertion=token)
    assert user.email == "staff.eng@company.com"
    assert user.role == Role.ENGINEER
    assert user.hosted_domain == "company.com"


@pytest.mark.asyncio
async def test_get_iap_public_keys_mocked():
    import httpx
    from app.auth.iap import get_iap_public_keys

    async def mock_handler(request: httpx.Request):
        return httpx.Response(200, json={"keys": [{"kid": "k1", "alg": "ES256"}]})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        keys = await get_iap_public_keys(client=client)
        assert "keys" in keys
        assert keys["keys"][0]["kid"] == "k1"


