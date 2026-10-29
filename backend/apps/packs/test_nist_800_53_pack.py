"""End-to-end tests for the generated NIST SP 800-53 Rev. 5 pack.

Ported from the fork's pre-#598 suite. The original drove the retired
``apps.compliance.matrix.build_matrix`` and ``adapters.CycloneDxAdapter``;
this version drives their upstream successors, ``threat_models.
compliance_matrix.build_compliance_matrix`` and ``tmbom.TmBomAdapter``, so
the pack's identity contract (canonical control IDs, enhancement hierarchy,
withdrawn dispositions) stays covered on the TM-BOM model.
"""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.compliance.models import StandardFramework, StandardRequirement
from apps.organizations.models import Organization, OrganizationMember
from apps.packs.services import import_pack_from_path
from apps.threat_models.compliance_matrix import build_compliance_matrix
from apps.threat_models.tmbom import TmBomAdapter
from apps.threats.models import InstanceCountermeasureStandard

User = get_user_model()

PACK_PATH = (
    Path(__file__).resolve().parents[3] / "libraries/packs/standards/nist-800-53-r5"
)


class Nist80053PackTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.pack_path = PACK_PATH
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

    def test_tmbom_satisfies_resolves_natively_and_shows_in_the_matrix(self):
        # TM-BOM 2.0 allows only references in `satisfies`; the identifiers
        # live under definitions.standards[].requirements, which is the shape
        # this repository's generated SSPP artifacts already emit.
        document = {
            "specFormat": "CycloneDX",
            "specVersion": "2.0",
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": "sys",
                    "name": "NIST Mapping Test",
                }
            },
            "blueprints": [{"name": "NIST Mapping Test", "modelTypes": ["data-flow"]}],
            "definitions": {
                "standards": [
                    {
                        "bom-ref": "standard-nist-800-53-r5",
                        "name": "nist-800-53-r5",
                        "version": "5.2.0",
                        "requirements": [
                            {
                                "bom-ref": "requirement-nist-800-53-r5-ac-2",
                                "identifier": "AC-2",
                                "title": "Account Management",
                            },
                            {
                                "bom-ref": "requirement-nist-800-53-r5-ac-2-1",
                                "identifier": "AC-2(1)",
                                "title": "Automated System Account Management",
                            },
                        ],
                    }
                ]
            },
            "controls": [
                {
                    "bom-ref": "control-ac-2",
                    "name": "Account Management",
                    "satisfies": ["requirement-nist-800-53-r5-ac-2"],
                    "properties": [
                        {
                            "name": "precogly:sufficiency",
                            "value": (
                                '[{"requirement":'
                                '"requirement-nist-800-53-r5-ac-2",'
                                '"sufficiency":"full"}]'
                            ),
                        }
                    ],
                },
                {
                    "bom-ref": "control-ac-2-1",
                    "name": "Automated Account Management",
                    "satisfies": ["requirement-nist-800-53-r5-ac-2-1"],
                },
            ],
        }

        threat_model, summary = TmBomAdapter().import_data(
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
        # Resolved against the installed pack, not stored as a snapshot.
        self.assertFalse(mappings.filter(requirement__isnull=True).exists())

        matrix = build_compliance_matrix(threat_model)
        entry = next(item for item in matrix if item["name"] == "NIST SP 800-53 Rev. 5")
        self.assertTrue(entry["installed"])
        self.assertEqual(entry["mapped_requirement_count"], 2)
        # Rows are the pack's requirements minus the families that no control
        # maps to directly (those are group headings). AC-2 is a family and is
        # mapped, so it stays a row; every unmapped family drops out.
        unmapped_families = (
            StandardRequirement.objects.filter(
                framework__slug="nist-800-53-r5", children__isnull=False
            )
            .exclude(section_code="AC-2")
            .distinct()
            .count()
        )
        self.assertEqual(entry["pack_requirement_count"], 1196 - unmapped_families)

        rows = {
            row["section_code"]: row
            for group in entry["groups"]
            for row in group["rows"]
        }
        # A full mapping whose control is not yet verified/platform is
        # "covered"; the AC-2(1) mapping defaults to partial.
        self.assertEqual(rows["AC-2"]["state"], "covered")
        self.assertEqual(rows["AC-2(1)"]["state"], "partial_only")
        self.assertEqual(rows["AC-2"]["controls"][0]["name"], "Account Management")
        self.assertEqual(
            rows["AC-2(1)"]["controls"][0]["name"], "Automated Account Management"
        )

    def test_withdrawn_control_is_explicitly_marked(self):
        requirement = StandardRequirement.objects.get(
            framework__slug="nist-800-53-r5", section_code="AC-13"
        )

        self.assertEqual(requirement.status, "withdrawn")
        self.assertEqual(
            requirement.description,
            "Withdrawn in NIST SP 800-53 Rev. 5; incorporated into AC-2; "
            "incorporated into AU-6.",
        )
        self.assertEqual(
            requirement.format_metadata["disposition_links"][0]["rel"],
            "incorporated-into",
        )
