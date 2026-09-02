from django.urls import path

from .views import (
    AdminRolesView, AdminUserDetailView, AdminUserRolesView, AdminUsersView, CsrfView, HealthLiveView,
    HealthReadyView, JwksView, LoginView, LogoutView, MeView, RefreshView,
    saml_login_redirect,
)

urlpatterns = [
    path("csrf", CsrfView.as_view()),
    path("login", LoginView.as_view()),
    path("refresh", RefreshView.as_view()),
    path("logout", LogoutView.as_view()),
    path("me", MeView.as_view()),
    path(".well-known/jwks.json", JwksView.as_view()),
    path("entra/login", saml_login_redirect),
    path("admin/users", AdminUsersView.as_view()),
    path("admin/users/<uuid:user_id>", AdminUserDetailView.as_view()),
    path("admin/roles", AdminRolesView.as_view()),
    path("admin/users/<uuid:user_id>/roles", AdminUserRolesView.as_view()),
    path("admin/users/<uuid:user_id>/roles/<uuid:role_id>", AdminUserRolesView.as_view()),
    path("health/live", HealthLiveView.as_view()),
    path("health/ready", HealthReadyView.as_view()),
]
