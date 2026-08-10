"""Cloud.gov settings — Keycloak-based OIDC auth + AWS RDS."""

import json
import os

from .production import *  # noqa: F401, F403

env = environ.Env()

# Public route; Diego health checks originate from arbitrary cell IPs
ALLOWED_HOSTS = ["*"]
SECURE_SSL_REDIRECT = False
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# WhiteNoise serves collected static files (incl. Django admin) behind gunicorn.
if "whitenoise.middleware.WhiteNoiseMiddleware" not in MIDDLEWARE:
    _sec_idx = MIDDLEWARE.index("django.middleware.security.SecurityMiddleware")
    MIDDLEWARE.insert(_sec_idx + 1, "whitenoise.middleware.WhiteNoiseMiddleware")
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
WHITENOISE_MAX_AGE = 60 * 60 * 24 * 30
STATIC_URL = "/static/"

# ---- Keycloak OIDC ----
OIDC_OP_ISSUER = env("OIDC_OP_ISSUER", default="")
OIDC_OP_AUTHORIZATION_ENDPOINT = env("OIDC_OP_AUTHORIZATION_ENDPOINT", default="")
OIDC_OP_TOKEN_ENDPOINT = env("OIDC_OP_TOKEN_ENDPOINT", default="")
OIDC_OP_USER_ENDPOINT = env("OIDC_OP_USER_ENDPOINT", default="")
OIDC_OP_JWKS_ENDPOINT = env("OIDC_OP_JWKS_ENDPOINT", default="")
OIDC_RP_SIGN_ALGO = "RS256"
OIDC_RP_CLIENT_ID = env("OIDC_RP_CLIENT_ID", default="")
OIDC_RP_CLIENT_SECRET = env("OIDC_RP_CLIENT_SECRET", default="")
OIDC_RP_SCOPES = "openid email profile"
FRONTEND_URL = env("FRONTEND_URL", default="/")
# After Keycloak returns to /oidc/callback/, hand off to our token minter,
# which builds a redirect to the SPA including SimpleJWT tokens.
LOGIN_REDIRECT_URL = "/sso/handoff/"
LOGOUT_REDIRECT_URL = FRONTEND_URL
LOGIN_REDIRECT_URL_FAILURE = FRONTEND_URL.rstrip("/") + "/login?sso=error"
try:
    from urllib.parse import urlparse as _urlparse

    _fe = _urlparse(FRONTEND_URL)
    OIDC_REDIRECT_ALLOWED_HOSTS = [_fe.hostname] if _fe.hostname else []
except Exception:  # pragma: no cover
    OIDC_REDIRECT_ALLOWED_HOSTS = []
# Session cookie is set on the API host, so cross-origin SPA calls cannot
# rely on it. JWTs sent as Bearer headers remain the primary channel.

AUTHENTICATION_BACKENDS = [
    "apps.core.keycloak_auth.KeycloakOIDCBackend",
    "django.contrib.auth.backends.ModelBackend",
]

if "mozilla_django_oidc.middleware.SessionRefresh" not in MIDDLEWARE:
    MIDDLEWARE.append("mozilla_django_oidc.middleware.SessionRefresh")

_installed = list(globals().get("INSTALLED_APPS", []))
if "mozilla_django_oidc" not in _installed:
    _installed.append("mozilla_django_oidc")
INSTALLED_APPS = _installed

_rest = dict(globals().get("REST_FRAMEWORK", {}))
_rest["DEFAULT_AUTHENTICATION_CLASSES"] = (
    "rest_framework_simplejwt.authentication.JWTAuthentication",
    "apps.core.keycloak_auth.KeycloakBearerAuthentication",
    "rest_framework.authentication.SessionAuthentication",
)
REST_FRAMEWORK = _rest

# Sessions / CSRF
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
# SameSite=None so the Django session cookie set on the API host is not
# stripped when the SPA (different site) later triggers same-site requests.
SESSION_COOKIE_SAMESITE = "None"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "None"
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# ---- AWS RDS via VCAP_SERVICES ----
try:
    vcap_data = json.loads(os.environ.get("VCAP_SERVICES", "{}"))
    for label in ("aws-rds", "csb-aws-postgresql"):
        if label in vcap_data:
            creds = vcap_data[label][0].get("credentials", {})
            DATABASES["default"] = {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": creds.get("dbname") or creds.get("database") or creds.get("name"),
                "USER": creds.get("username") or creds.get("user"),
                "PASSWORD": creds.get("password"),
                "HOST": creds.get("host") or creds.get("hostname"),
                "PORT": creds.get("port") or "5432",
            }
            break
except (json.JSONDecodeError, KeyError, IndexError):
    pass

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {"format": "[{levelname}] {asctime} {module} | {message}", "style": "{"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}
