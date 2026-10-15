"""Keycloak OIDC authentication for Django + DRF.

Uses mozilla-django-oidc for the browser flow and a lightweight JWT/JWKS
validator for DRF Bearer tokens from Keycloak.
"""

from __future__ import annotations

import logging

from django.contrib.auth import get_user_model
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from rest_framework import authentication, exceptions

try:
    import jwt
    from jwt import PyJWKClient
except ImportError:  # pragma: no cover
    jwt = None
    PyJWKClient = None

logger = logging.getLogger(__name__)
User = get_user_model()


class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    """Provision Django users from Keycloak `userinfo` claims."""

    def get_username(self, claims):
        return (claims.get("preferred_username") or claims.get("email") or "").lower()

    def create_user(self, claims):
        user = super().create_user(claims)
        self._apply_claims(user, claims)
        user.save()
        return user

    def update_user(self, user, claims):
        self._apply_claims(user, claims)
        user.save()
        return user

    @staticmethod
    def _apply_claims(user, claims):
        user.email = (claims.get("email") or user.email or "").lower()
        user.first_name = claims.get("given_name", user.first_name)
        user.last_name = claims.get("family_name", user.last_name)


class KeycloakBearerAuthentication(authentication.BaseAuthentication):
    """DRF authenticator that verifies Keycloak-issued JWT access tokens.

    Requires ``OIDC_OP_JWKS_ENDPOINT`` and ``OIDC_OP_ISSUER`` in settings.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        if jwt is None or PyJWKClient is None:
            return None

        header = authentication.get_authorization_header(request).decode("utf-8", "replace")
        if not header.lower().startswith(self.keyword.lower() + " "):
            return None
        token = header.split(" ", 1)[1].strip()
        if not token:
            return None

        from django.conf import settings

        jwks_url = getattr(settings, "OIDC_OP_JWKS_ENDPOINT", None)
        issuer = getattr(settings, "OIDC_OP_ISSUER", None)
        audience = getattr(settings, "OIDC_RP_CLIENT_ID", None)
        if not jwks_url or not issuer:
            raise exceptions.AuthenticationFailed("OIDC not configured")

        try:
            signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                issuer=issuer,
                audience=audience,
                options={"verify_aud": bool(audience)},
            )
        except jwt.PyJWTError:
            # Not a Keycloak-issued token (e.g. SimpleJWT HS256 from /sso/handoff/).
            # Return None so DRF continues to the next authenticator.
            return None

        username = (claims.get("preferred_username") or claims.get("email") or "").lower()
        if not username:
            raise exceptions.AuthenticationFailed("Token missing username claim")

        user, _ = User.objects.get_or_create(
            username=username,
            defaults={
                "email": (claims.get("email") or "").lower(),
                "first_name": claims.get("given_name", ""),
                "last_name": claims.get("family_name", ""),
            },
        )
        return (user, claims)

    def authenticate_header(self, request):
        return self.keyword
