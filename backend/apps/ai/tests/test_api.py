"""API tests for the per-tenant AI provider settings endpoint.

These need the database and the auth/permission stack, so they use DRF's
``APITestCase`` (the DB-integration convention in this repo) rather than the
``SimpleTestCase`` used for the pure provider/crypto logic in ``test_infra``.
The focus is the behavior the settings UI depends on and that the model's
constraints alone don't guarantee a *clean* response for:

* the API key is write-only — accepted on input, never echoed, surfaced only as
  a ``hasApiKey`` flag;
* a blank key on update keeps the stored one; a value replaces it;
* promoting a config to default demotes the previous default in one call;
* tenancy — a member can neither see nor create configs outside their orgs.
"""

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from apps.ai.models import AIProviderConfig
from apps.ai.providers.base import ProviderHealth
from apps.organizations.models import Organization, OrganizationMember

User = get_user_model()


@override_settings(AI_SECRET_KEY="api-test-secret")
class AIProviderConfigAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Acme")
        cls.other_org = Organization.objects.create(name="Globex")

        cls.member = User.objects.create_user(
            username="member", email="member@acme.test", password="pw"
        )
        OrganizationMember.objects.create(organization=cls.org, user=cls.member)

        cls.outsider = User.objects.create_user(
            username="outsider", email="out@globex.test", password="pw"
        )
        OrganizationMember.objects.create(organization=cls.other_org, user=cls.outsider)

    def setUp(self):
        self.client.force_authenticate(self.member)

    def _payload(self, **overrides):
        payload = {
            "organization": self.org.id,
            "name": "Local LM Studio",
            "providerType": "openai_compat",
            "baseUrl": "http://localhost:1234/v1",
            "model": "local-model",
        }
        payload.update(overrides)
        return payload

    def test_create_encrypts_key_and_never_echoes_it(self):
        response = self.client.post(
            "/api/ai-providers/", self._payload(apiKey="sk-secret"), format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        # The secret is neither rendered back nor stored in the clear.
        # (response.data is the serializer's native output — snake_case; the
        # CamelCase renderer only transforms the wire JSON, not .data.)
        self.assertNotIn("api_key", response.data)
        self.assertTrue(response.data["has_api_key"])

        config = AIProviderConfig.objects.get(id=response.data["id"])
        self.assertNotIn("sk-secret", config.api_key_encrypted)
        self.assertEqual(config.api_key, "sk-secret")

    def test_create_without_key_reports_no_key(self):
        response = self.client.post(
            "/api/ai-providers/", self._payload(), format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertFalse(response.data["has_api_key"])

    def test_blank_key_on_update_keeps_existing(self):
        config = AIProviderConfig.objects.create(organization=self.org, name="cfg")
        config.set_api_key("sk-keep")
        config.save()

        response = self.client.patch(
            f"/api/ai-providers/{config.id}/", {"apiKey": ""}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        config.refresh_from_db()
        self.assertEqual(config.api_key, "sk-keep")

    def test_value_on_update_replaces_key(self):
        config = AIProviderConfig.objects.create(organization=self.org, name="cfg")
        config.set_api_key("sk-old")
        config.save()

        response = self.client.patch(
            f"/api/ai-providers/{config.id}/", {"apiKey": "sk-new"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        config.refresh_from_db()
        self.assertEqual(config.api_key, "sk-new")

    def test_promoting_default_demotes_previous(self):
        first = AIProviderConfig.objects.create(
            organization=self.org, name="first", is_default=True
        )
        second = AIProviderConfig.objects.create(
            organization=self.org, name="second", is_default=False
        )

        response = self.client.patch(
            f"/api/ai-providers/{second.id}/", {"isDefault": True}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertFalse(first.is_default)
        self.assertTrue(second.is_default)

    def test_create_default_with_existing_default_demotes_in_one_call(self):
        AIProviderConfig.objects.create(
            organization=self.org, name="incumbent", is_default=True
        )
        response = self.client.post(
            "/api/ai-providers/",
            self._payload(name="challenger", isDefault=True),
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertEqual(
            AIProviderConfig.objects.filter(
                organization=self.org, is_default=True
            ).count(),
            1,
        )

    def test_duplicate_name_in_same_organization_is_rejected(self):
        AIProviderConfig.objects.create(organization=self.org, name="duplicate")

        response = self.client.post(
            "/api/ai-providers/", self._payload(name="duplicate"), format="json"
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("non_field_errors", response.data)

    def test_list_is_scoped_to_member_orgs(self):
        AIProviderConfig.objects.create(organization=self.org, name="mine")
        AIProviderConfig.objects.create(organization=self.other_org, name="theirs")

        response = self.client.get("/api/ai-providers/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data.get("results", response.data)
        names = {row["name"] for row in results}
        self.assertEqual(names, {"mine"})

    def test_cannot_create_for_non_member_org(self):
        response = self.client.post(
            "/api/ai-providers/",
            self._payload(organization=self.other_org.id),
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(
            AIProviderConfig.objects.filter(organization=self.other_org).exists()
        )

    @override_settings(AI_SECRET_KEY="")
    def test_saving_key_without_secret_returns_actionable_400(self):
        response = self.client.post(
            "/api/ai-providers/", self._payload(apiKey="sk-secret"), format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("api_key", response.data)
        # Nothing is persisted when the key could not be stored.
        self.assertFalse(
            AIProviderConfig.objects.filter(name="Local LM Studio").exists()
        )

    @mock.patch("apps.ai.views.build_provider")
    def test_connection_action_reports_health(self, build_provider):
        build_provider.return_value.test_connection.return_value = ProviderHealth(
            ok=True, detail="reachable, 3 models"
        )
        config = AIProviderConfig.objects.create(organization=self.org, name="cfg")

        response = self.client.post(f"/api/ai-providers/{config.id}/test-connection/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["ok"])
        self.assertEqual(response.data["detail"], "reachable, 3 models")
