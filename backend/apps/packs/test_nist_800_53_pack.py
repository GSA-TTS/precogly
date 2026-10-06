"""End-to-end tests for the generated NIST SP 800-53 Rev. 5 pack."""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.compliance.matrix import build_matrix
from apps.compliance.models import StandardFramework, StandardRequirement
from apps.organizations.models import Organization, OrganizationMember
from apps.packs.services import import_pack_from_path
from apps.threat_models.adapters import CycloneDxAdapter
from apps.threats.models import InstanceCountermeasureStandard

User = get_user_model()


class Nist80053PackTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.pack_path = (
            Path(__file__).resolve().parents[3]
            / "libraries/packs/standards/nist-800-53-r5"
        )
        result = import_pack_from_path(cls.pack_path, force=True)
        if not result.success:
            raise RuntimeError(result.errors)

        cls.organization = Organization.objects.create(name="NIST Pack Test")
        cls.user = User.objects.create_user(
            username="nist-pack-test",
            email="nist-pack@example.test",
            password=None,
        )
        OrganizationMember.objects.create(
            organization=cls.organization,
            user=cls.user,
            role="security_team",
        )

    def test_pack_import_is_idempotent_and_preserves_hierarchy(self):
        ac2_before = StandardRequirement.objects.get(
            framework__slug="nist-800-53-r5", section_code="AC-2"
        )
        updated_at = ac2_before.updated_at

        second = import_pack_from_path(self.pack_path)

        self.assertTrue(second.success, second.errors)
        framework = StandardFramework.objects.get(slug="nist-800-53-r5")
        self.assertEqual(framework.requirements.count(), 1196)
        ac2 = framework.requirements.get(section_code="AC-2")
        ac2_1 = framework.requirements.get(section_code="AC-2(1)")
        self.assertEqual(ac2.name, "Account Management")
        self.assertEqual(ac2.requirement_type, "control")
        self.assertEqual(ac2_1.name, "Automated System Account Management")
        self.assertEqual(ac2_1.requirement_type, "enhancement")
        self.assertEqual(ac2_1.parent, ac2)
        self.assertEqual(ac2_1.format_metadata["oscal_id"], "ac-2.1")
        self.assertEqual(ac2.updated_at, updated_at)
        self.assertIn("already exists", second.message)

    def test_cyclonedx_compact_mappings_are_native_and_visible_in_matrix(self):
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "blueprints": [{"name": "NIST Mapping Test"}],
            "controls": [
                {
                    "bom-ref": "control-ac-2",
                    "name": "Account Management",
                    "satisfies": [{"framework": "nist-800-53-r5", "reference": "AC-2"}],
                },
                {
                    "bom-ref": "control-ac-2-1",
                    "name": "Automated Account Management",
                    "satisfies": [
                        {"framework": "nist-800-53-r5", "reference": "AC-02.01"}
                    ],
                },
            ],
        }

        threat_model, summary = CycloneDxAdapter().import_data(
            document, self.organization, self.user
        )

        self.assertEqual(summary.get("warnings", []), [])
        mappings = InstanceCountermeasureStandard.objects.filter(
            countermeasure__threat_model=threat_model
        )
        self.assertEqual(
            set(mappings.values_list("section_code", flat=True)),
            {"AC-2", "AC-2(1)"},
        )

        matrix = build_matrix(
            threat_model,
            framework_name="NIST SP 800-53 Rev. 5",
            include_empty=False,
        )
        ac_requirements = {
            requirement["section_code"]: requirement
            for family in matrix["families"]
            if family["family"] == "AC"
            for requirement in family["requirements"]
        }
        self.assertEqual(set(ac_requirements), {"AC-2", "AC-2(1)"})
        self.assertEqual(
            ac_requirements["AC-2"]["countermeasures"][0]["name"],
            "Account Management",
        )

    def test_withdrawn_control_is_explicitly_marked(self):
        requirement = StandardRequirement.objects.get(
            framework__slug="nist-800-53-r5", section_code="AC-13"
        )

        self.assertEqual(requirement.status, "withdrawn")
        self.assertEqual(requirement.description, "")
        self.assertEqual(
            requirement.format_metadata["disposition_links"][0]["rel"],
            "incorporated-into",
        )
