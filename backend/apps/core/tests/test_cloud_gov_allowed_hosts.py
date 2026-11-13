"""Cloud.gov host handling: the Diego health-check Host rewrite.

Driven through the middleware class directly, so the result does not depend on
which settings module pytest loads.
"""

from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.core.health_host import (
    DIEGO_USER_AGENT,
    HEALTH_PATH,
    DiegoHealthCheckHostMiddleware,
)

API_HOST = "precogly-api.app.cloud.gov"


def _seen_host(request_kwargs, path=HEALTH_PATH):
    seen = {}

    def get_response(request):
        seen["host"] = request.META.get("HTTP_HOST")
        return None

    request = RequestFactory().get(path, **request_kwargs)
    DiegoHealthCheckHostMiddleware(get_response)(request)
    return seen["host"]


@override_settings(ALLOWED_HOSTS=[API_HOST])
class DiegoHealthCheckHostTests(SimpleTestCase):
    def test_diego_probe_on_instance_ip_is_rewritten_to_public_host(self):
        host = _seen_host(
            {"HTTP_HOST": "10.10.2.5:8080", "HTTP_USER_AGENT": DIEGO_USER_AGENT}
        )
        self.assertEqual(host, API_HOST)

    def test_other_clients_keep_their_host(self):
        host = _seen_host(
            {"HTTP_HOST": "evil.example.com", "HTTP_USER_AGENT": "curl/8.0"}
        )
        self.assertEqual(host, "evil.example.com")

    def test_diego_user_agent_on_other_paths_keeps_its_host(self):
        host = _seen_host(
            {"HTTP_HOST": "10.10.2.5:8080", "HTTP_USER_AGENT": DIEGO_USER_AGENT},
            path="/api/dashboard/stats/",
        )
        self.assertEqual(host, "10.10.2.5:8080")
