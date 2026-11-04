"""
Development settings for Precogly backend.
"""

from .base import *  # noqa: F403

DEBUG = True

# "0.0.0.0" is here so the container's runserver is reachable from the host;
# this settings module is never loaded in production, which uses production.py.
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0", "backend"]  # noqa: S104

# Default dev Fernet secret so saving an AIProviderConfig API key via
# Settings -> AI Providers works out of the box in local dev without editing .env.
AI_SECRET_KEY = env(  # noqa: F405
    "AI_SECRET_KEY", default="precogly-dev-ai-secret-key-change-in-production"
)

# Development-only apps
INSTALLED_APPS += ["django_extensions"]  # noqa: F405

# Set DEBUG_TOOLBAR=false in .env to turn it off for a machine.
DEBUG_TOOLBAR = env.bool("DEBUG_TOOLBAR", default=True)  # noqa: F405

if DEBUG_TOOLBAR:
    INSTALLED_APPS += ["debug_toolbar"]
    MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")  # noqa: F405
    INTERNAL_IPS = ["127.0.0.1"]

# More permissive CORS for development
CORS_ALLOW_ALL_ORIGINS = True

# Email backend for development (print to console)
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}
