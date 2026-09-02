from .models import AccountType
from .tokens import create_access_token, create_refresh_session, set_auth_cookies


class SamlSessionBridgeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        user = getattr(request, "user", None)
        if (
            user and user.is_authenticated and user.account_type == AccountType.ENTRA
            and "platform_refresh" not in request.COOKIES
        ):
            _, raw_refresh = create_refresh_session(user, "saml")
            set_auth_cookies(response, create_access_token(user), raw_refresh)
        return response

