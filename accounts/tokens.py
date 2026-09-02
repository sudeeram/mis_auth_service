import base64
import hashlib
import secrets
from datetime import timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.utils import timezone

from .models import RefreshSession


def effective_access(user):
    roles = list(user.role_assignments.values_list("role__key", flat=True).order_by("role__key"))
    permissions = list(
        user.role_assignments.values_list("role__permissions__key", flat=True).distinct().order_by("role__permissions__key")
    )
    services = sorted({permission.split(":", 1)[0] for permission in permissions})
    return roles, permissions, services


def _read_key(path):
    return Path(path).read_text()


def create_access_token(user):
    now = timezone.now()
    roles, permissions, services = effective_access(user)
    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": str(user.id),
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=settings.ACCESS_TOKEN_TTL_SECONDS),
        "jti": secrets.token_hex(16),
        "account_type": user.account_type,
        "roles": roles,
        "permissions": permissions,
        "services": services,
    }
    return jwt.encode(payload, _read_key(settings.JWT_PRIVATE_KEY_FILE), algorithm="RS256", headers={"kid": settings.JWT_KEY_ID})


def create_refresh_session(user, authentication_method):
    secret = secrets.token_urlsafe(48)
    session = RefreshSession.objects.create(
        user=user,
        token_hash=hashlib.sha256(secret.encode()).hexdigest(),
        authentication_method=authentication_method,
        expires_at=timezone.now() + timedelta(seconds=settings.REFRESH_TOKEN_TTL_SECONDS),
    )
    return session, f"{session.id}.{secret}"


def parse_refresh_token(raw_token):
    try:
        session_id, secret = raw_token.split(".", 1)
        session = RefreshSession.objects.select_related("user").get(id=session_id)
    except (ValueError, RefreshSession.DoesNotExist):
        return None
    if session.revoked_at or session.expires_at <= timezone.now():
        return None
    candidate = hashlib.sha256(secret.encode()).hexdigest()
    return session if secrets.compare_digest(candidate, session.token_hash) else None


def jwks_document():
    public_key = serialization.load_pem_public_key(Path(settings.JWT_PUBLIC_KEY_FILE).read_bytes())
    numbers = public_key.public_numbers()

    def encode_int(value):
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": settings.JWT_KEY_ID,
        "n": encode_int(numbers.n), "e": encode_int(numbers.e),
    }]}


def set_auth_cookies(response, access_token, refresh_token=None):
    common = {"secure": settings.AUTH_COOKIE_SECURE, "httponly": True, "samesite": "Lax"}
    response.set_cookie(settings.ACCESS_COOKIE_NAME, access_token, max_age=settings.ACCESS_TOKEN_TTL_SECONDS, path="/api/", **common)
    if refresh_token:
        response.set_cookie(settings.REFRESH_COOKIE_NAME, refresh_token, max_age=settings.REFRESH_TOKEN_TTL_SECONDS, path="/api/auth/", **common)

