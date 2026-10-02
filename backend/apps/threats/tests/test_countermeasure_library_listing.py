"""The countermeasure library list endpoint must return ``description``.

The list view searches against ``name`` and ``description``, but the list
serializer dropped ``description`` from its fields. A search match could
therefore never be seen in the results, and the listing was inconsistent
with its sibling ``ThreatLibraryListSerializer``.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import Organization, OrganizationMember
from apps.threats.models import CountermeasureLibrary

User = get_user_model()


class CountermeasureLibraryListTests(TestCase):
    """The ``/api/countermeasure-library/`` listing includes descriptions."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Counter Org", domain="counter.test")
        cls.user = User.objects.create_user(
            username="counteruser", email="counter@counter.test", password="testpass123"
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )
        cls.countermeasure = CountermeasureLibrary.objects.create(
            name="Encrypt Data at Rest",
            description="Apply encryption to data stored on disk.",
            control_functions=["preventive"],
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(self.user).access_token}"
        )

    def test_list_returns_description(self):
        """The list route must include each item's description."""
        response = self.client.get("/api/countermeasure-library/")
        self.assertEqual(response.status_code, 200)
        item = next(
            (c for c in response.data if c["name"] == "Encrypt Data at Rest"),
            None,
        )
        self.assertIsNotNone(item)
        self.assertEqual(
            item["description"], "Apply encryption to data stored on disk."
        )

    def test_search_matches_description_and_returns_it(self):
        """A search on description must surface the match with its text."""
        response = self.client.get("/api/countermeasure-library/?search=encryption")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["name"], "Encrypt Data at Rest")
        self.assertIn("description", response.data[0])
