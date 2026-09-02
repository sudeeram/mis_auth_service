from django.conf import settings
from django.contrib.auth import authenticate
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import EnforceCsrfAuthentication
from .models import AccountStatus, RefreshSession, Role, SecurityAuditEvent, User, UserRole
from .serializers import CreateLocalUserSerializer, LoginSerializer, MeSerializer, RoleSerializer, UserSerializer
from .tokens import create_access_token, create_refresh_session, jwks_document, parse_refresh_token, set_auth_cookies


def audit(request, event_type, outcome, user=None):
    SecurityAuditEvent.objects.create(
        user=user, event_type=event_type, outcome=outcome,
        ip_address=request.META.get("REMOTE_ADDR"),
    )


class CsrfView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({"csrfToken": get_token(request)})


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = [EnforceCsrfAuthentication]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(request, email=serializer.validated_data["email"], password=serializer.validated_data["password"])
        if not user:
            audit(request, "local_login", "failure")
            return Response({"error": {"code": "invalid_credentials", "message": "Invalid credentials."}}, status=401)
        session, raw_refresh = create_refresh_session(user, "local")
        audit(request, "local_login", "success", user)
        response = Response(MeSerializer(user).data)
        set_auth_cookies(response, create_access_token(user), raw_refresh)
        return response


class RefreshView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = [EnforceCsrfAuthentication]

    def post(self, request):
        old = parse_refresh_token(request.COOKIES.get(settings.REFRESH_COOKIE_NAME, ""))
        if not old or not old.user.is_active:
            return Response({"error": {"code": "invalid_session", "message": "Session is invalid or expired."}}, status=401)
        old.revoked_at = timezone.now()
        old.last_used_at = timezone.now()
        old.save(update_fields=("revoked_at", "last_used_at"))
        _, raw_refresh = create_refresh_session(old.user, old.authentication_method)
        response = Response(MeSerializer(old.user).data)
        set_auth_cookies(response, create_access_token(old.user), raw_refresh)
        return response


class LogoutView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = [EnforceCsrfAuthentication]

    def post(self, request):
        session = parse_refresh_token(request.COOKIES.get(settings.REFRESH_COOKIE_NAME, ""))
        if session:
            session.revoked_at = timezone.now()
            session.save(update_fields=("revoked_at",))
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie(settings.ACCESS_COOKIE_NAME, path="/api/")
        response.delete_cookie(settings.REFRESH_COOKIE_NAME, path="/api/auth/")
        return response


class MeView(APIView):
    def get(self, request):
        return Response(MeSerializer(request.user).data)


class JwksView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response(jwks_document())


class HealthLiveView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request): return Response({"status": "ok"})


class HealthReadyView(HealthLiveView):
    def get(self, request):
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return Response({"status": "ready"})


class IsPlatformAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        claims = getattr(request, "platform_claims", {})
        return request.user.is_superuser or "platform:users:admin" in claims.get("permissions", [])


class AdminUsersView(APIView):
    permission_classes = [IsPlatformAdmin]

    def get(self, request): return Response(UserSerializer(User.objects.order_by("email"), many=True).data)

    def post(self, request):
        serializer = CreateLocalUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(UserSerializer(serializer.save()).data, status=201)


class AdminUserDetailView(APIView):
    permission_classes = [IsPlatformAdmin]

    def get(self, request, user_id):
        return Response(UserSerializer(User.objects.get(id=user_id)).data)

    def patch(self, request, user_id):
        user = User.objects.get(id=user_id)
        requested_status = request.data.get("status")
        if requested_status not in AccountStatus.values:
            return Response({"error": {"code": "invalid_status", "message": "Unsupported account status."}}, status=400)
        user.status = requested_status
        user.save(update_fields=("status", "is_active", "updated_at"))
        if requested_status != AccountStatus.ACTIVE:
            user.refresh_sessions.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        audit(request, "account_status_changed", "success", user)
        return Response(UserSerializer(user).data)


class AdminRolesView(APIView):
    permission_classes = [IsPlatformAdmin]

    def get(self, request): return Response(RoleSerializer(Role.objects.prefetch_related("permissions"), many=True).data)


class AdminUserRolesView(APIView):
    permission_classes = [IsPlatformAdmin]

    def post(self, request, user_id):
        user = User.objects.get(id=user_id)
        role = Role.objects.get(id=request.data.get("roleId"))
        UserRole.objects.get_or_create(user=user, role=role, defaults={"assigned_by": request.user})
        audit(request, "role_assigned", "success", user)
        return Response(MeSerializer(user).data)

    def delete(self, request, user_id, role_id):
        UserRole.objects.filter(user_id=user_id, role_id=role_id).delete()
        audit(request, "role_removed", "success", User.objects.get(id=user_id))
        return Response(status=204)


def saml_login_redirect(request):
    return redirect("/api/auth/saml/login/")
