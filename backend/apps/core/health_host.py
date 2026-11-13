"""Let the cloud.gov Diego health check through ALLOWED_HOSTS.

Diego probes the instance's internal address, so its Host header is an IP and
ALLOWED_HOSTS rejects it. This rewrites the Host for the health path only, and
only for the Diego user agent. Every other request is validated as usual.
"""

from django.conf import settings

HEALTH_PATH = "/api/health/"
DIEGO_USER_AGENT = "diego-healthcheck"


class DiegoHealthCheckHostMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.path == HEALTH_PATH
            and request.META.get("HTTP_USER_AGENT") == DIEGO_USER_AGENT
            and settings.ALLOWED_HOSTS
        ):
            request.META["HTTP_HOST"] = settings.ALLOWED_HOSTS[0]
        return self.get_response(request)
