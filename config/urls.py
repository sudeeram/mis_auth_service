from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
]

if settings.SAML_ENABLED:
    urlpatterns.append(path("api/auth/saml/", include("djangosaml2.urls")))

