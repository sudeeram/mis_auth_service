import os
from pathlib import Path

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def env_bool(name: str, default: bool = False) -> bool:
    return env(name, str(default)).lower() in {"1", "true", "yes", "on"}


SECRET_KEY = env("DJANGO_SECRET_KEY", "unsafe-development-only-change-me")
DEBUG = env_bool("DJANGO_DEBUG", True)
ALLOWED_HOSTS = [item for item in env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,platform.local").split(",") if item]
CSRF_TRUSTED_ORIGINS = [item for item in env("CSRF_TRUSTED_ORIGINS", "http://platform.local").split(",") if item]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "djangosaml2",
    "accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "djangosaml2.middleware.SamlSessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "accounts.middleware.SamlSessionBridgeMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": env("POSTGRES_DB", "auth"),
    "USER": env("POSTGRES_USER", "auth"),
    "PASSWORD": env("POSTGRES_PASSWORD", "auth-dev-password"),
    "HOST": env("POSTGRES_HOST", "auth-postgres"),
    "PORT": env("POSTGRES_PORT", "5432"),
}}
if env_bool("USE_SQLITE_FOR_TESTS", False):
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "test.sqlite3"}}

AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = [
    "accounts.backends.LocalEmailBackend",
    "accounts.saml_backend.EntraSaml2Backend",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["accounts.authentication.PlatformJWTAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

PLATFORM_PUBLIC_ORIGIN = env("PLATFORM_PUBLIC_ORIGIN", "http://platform.local")
FRONTEND_AFTER_LOGIN = env("FRONTEND_AFTER_LOGIN", f"{PLATFORM_PUBLIC_ORIGIN}/dashboard")
FRONTEND_AFTER_LOGOUT = env("FRONTEND_AFTER_LOGOUT", f"{PLATFORM_PUBLIC_ORIGIN}/login")
ACCESS_TOKEN_TTL_SECONDS = int(env("ACCESS_TOKEN_TTL_SECONDS", "600"))
REFRESH_TOKEN_TTL_SECONDS = int(env("REFRESH_TOKEN_TTL_SECONDS", "604800"))
JWT_ISSUER = env("JWT_ISSUER", f"{PLATFORM_PUBLIC_ORIGIN}/api/auth")
JWT_AUDIENCE = env("JWT_AUDIENCE", "platform-api")
JWT_PRIVATE_KEY_FILE = env("JWT_PRIVATE_KEY_FILE", "/run/secrets/jwt-private.pem")
JWT_PUBLIC_KEY_FILE = env("JWT_PUBLIC_KEY_FILE", "/run/secrets/jwt-public.pem")
JWT_KEY_ID = env("JWT_KEY_ID", "platform-dev-1")
AUTH_COOKIE_SECURE = env_bool("AUTH_COOKIE_SECURE", False)
ACCESS_COOKIE_NAME = "platform_access"
REFRESH_COOKIE_NAME = "platform_refresh"

SAML_ENABLED = env_bool("SAML_ENABLED", False)
SAML_TENANT_ID = env("SAML_TENANT_ID")
SAML_IDP_ENTITY_ID = env("SAML_IDP_ENTITY_ID")
SAML_ENTRA_OBJECT_ID_ATTRIBUTE = env(
    "SAML_ENTRA_OBJECT_ID_ATTRIBUTE",
    "http://schemas.microsoft.com/identity/claims/objectidentifier",
)
SAML_ATTRIBUTE_MAPPING = {
    SAML_ENTRA_OBJECT_ID_ATTRIBUTE: ("username",),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ("email",),
    "http://schemas.microsoft.com/identity/claims/displayname": ("display_name",),
}
SAML_DJANGO_USER_MAIN_ATTRIBUTE = "username"
SAML_CREATE_UNKNOWN_USER = True
SAML_DEFAULT_BINDING = BINDING_HTTP_REDIRECT
SAML_SESSION_COOKIE_NAME = "platform_saml_session"
SAML_SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = AUTH_COOKIE_SECURE
SAML_IGNORE_LOGOUT_ERRORS = True
LOGIN_REDIRECT_URL = FRONTEND_AFTER_LOGIN
LOGOUT_REDIRECT_URL = FRONTEND_AFTER_LOGOUT

SAML_CONFIG = {
    "entityid": env("SAML_SP_ENTITY_ID", f"{PLATFORM_PUBLIC_ORIGIN}/api/auth/saml/metadata/"),
    "service": {
        "sp": {
            "name": "Platform Auth Service",
            "endpoints": {
                "assertion_consumer_service": [
                    (f"{PLATFORM_PUBLIC_ORIGIN}/api/auth/saml/acs/", BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    (f"{PLATFORM_PUBLIC_ORIGIN}/api/auth/saml/ls/", BINDING_HTTP_REDIRECT),
                    (f"{PLATFORM_PUBLIC_ORIGIN}/api/auth/saml/ls/post/", BINDING_HTTP_POST),
                ],
            },
            "allow_unsolicited": True,
            "authn_requests_signed": True,
            "logout_requests_signed": True,
            "want_assertions_signed": True,
            "want_response_signed": True,
        }
    },
    "metadata": {"local": [env("SAML_IDP_METADATA_FILE", "/run/secrets/entra-idp-metadata.xml")]},
    "key_file": env("SAML_SP_PRIVATE_KEY_FILE", "/run/secrets/saml-sp-key.pem"),
    "cert_file": env("SAML_SP_CERT_FILE", "/run/secrets/saml-sp-cert.pem"),
    "xmlsec_binary": env("XMLSEC_BINARY", "/usr/bin/xmlsec1"),
    "allow_unknown_attributes": False,
    "debug": DEBUG,
}
