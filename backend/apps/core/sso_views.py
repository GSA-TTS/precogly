"""SSO handoff view: mint SimpleJWT tokens after Keycloak OIDC login.

The SPA is cross-origin from the API, so a Django session cookie set on the
API host is invisible to the SPA host. This view runs after
``mozilla_django_oidc`` completes the code exchange and populates
``request.user``. It issues SimpleJWT access/refresh tokens matching the
``/api/auth/login/`` shape and redirects to the SPA with the tokens in the
URL fragment (fragment stays client-side; never hits logs).
"""

from __future__ import annotations

from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpResponseRedirect
from django.views import View
from rest_framework_simplejwt.tokens import RefreshToken


class SsoTokenHandoffView(View):
    """Mint JWTs for an authenticated user and redirect to the SPA."""

    def get(self, request):
        frontend = getattr(settings, "FRONTEND_URL", "/") or "/"
        if not request.user.is_authenticated:
            return HttpResponseRedirect(f"{frontend.rstrip('/')}/login?sso=error")

        refresh = RefreshToken.for_user(request.user)
        params = urlencode(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "email": request.user.email or "",
                "pk": request.user.pk,
            }
        )
        base = frontend.rstrip("/")
        # Land on SPA callback route; SPA reads tokens from the fragment.
        return HttpResponseRedirect(f"{base}/sso-callback#{params}")
