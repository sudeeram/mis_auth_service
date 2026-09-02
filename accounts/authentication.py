import jwt
from django.conf import settings
from rest_framework.authentication import BaseAuthentication, CSRFCheck
from rest_framework.exceptions import AuthenticationFailed

from .models import AccountStatus, User


class PlatformJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get(settings.ACCESS_COOKIE_NAME)
        authorization = request.headers.get("Authorization", "")
        if not token and authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
        if not token:
            return None
        try:
            payload = jwt.decode(
                token,
                open(settings.JWT_PUBLIC_KEY_FILE).read(),
                algorithms=["RS256"],
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
            )
            user = User.objects.get(id=payload["sub"], status=AccountStatus.ACTIVE)
        except (OSError, KeyError, jwt.PyJWTError, User.DoesNotExist) as exc:
            raise AuthenticationFailed("Invalid or expired access token") from exc
        request.platform_claims = payload
        return user, payload


class EnforceCsrfAuthentication(BaseAuthentication):
    """Require Django CSRF validation even on DRF's otherwise exempt API views."""

    def authenticate(self, request):
        check = CSRFCheck(lambda inner_request: None)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise AuthenticationFailed(f"CSRF validation failed: {reason}")
        return None
