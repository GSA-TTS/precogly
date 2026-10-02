"""A template pack's templates are offered without connecting the pack.

Templates are gated on their source pack being connected to the threat model so
that the `component_ref`s inside them resolve — inserting an AWS template
without the AWS pack yields components pointing at nothing. A template pack
ships no components, so there is nothing for a connection to supply, and gating
it would make a facilitator connect a STRIDE worksheet to their threat model as
though it described their stack.
"""

from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from apps.diagrams.models import DFDTemplatesLibrary
from apps.organizations.models import Organization, OrganizationMember
from apps.packs.models import LibraryPack
from apps.threat_models.models import ThreatModel

User = get_user_model()


class TemplatePackVisibilityTests(APITestCase):
    """Neither pack is connected to the threat model; only one should be hidden."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Org")
        cls.user = User.objects.create_user(
            username="facilitator", email="f@org.test", password="pw"
        )
        OrganizationMember.objects.create(organization=cls.org, user=cls.user)
        cls.threat_model = ThreatModel.objects.create(
            organization=cls.org, created_by=cls.user, name="TM"
        )

        cls.worksheets = LibraryPack.objects.create(
            slug="worksheets",
            name="Worksheets",
            pack_type=LibraryPack.PackType.TEMPLATE,
            version="1.0.0",
            author="Precogly",
        )
        cls.technology = LibraryPack.objects.create(
            slug="technology",
            name="Technology",
            pack_type=LibraryPack.PackType.FULL,
            version="1.0.0",
            author="Precogly",
        )

        DFDTemplatesLibrary.objects.create(
            qualified_slug="worksheets/stride-grid",
            slug="stride-grid",
            name="STRIDE Grid",
            source_pack=cls.worksheets,
            category="worksheet",
            diagram_type="level1",
            canvas_data={"nodes": [], "edges": []},
        )
        DFDTemplatesLibrary.objects.create(
            qualified_slug="technology/three-tier",
            slug="three-tier",
            name="Three Tier",
            source_pack=cls.technology,
            category="webapp",
            diagram_type="level1",
            canvas_data={"nodes": [], "edges": []},
        )

    def _template_names(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(
            "/api/dfd-templates/", {"threat_model": self.threat_model.id}
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        rows = payload["results"] if isinstance(payload, dict) else payload
        return {row["name"] for row in rows}

    def test_template_pack_is_offered_unconnected(self):
        self.assertIn("STRIDE Grid", self._template_names())

    def test_other_packs_are_still_gated(self):
        # The guard this relaxes has to keep holding for everything else, or a
        # technology template arrives with components that resolve to nothing.
        self.assertNotIn("Three Tier", self._template_names())
