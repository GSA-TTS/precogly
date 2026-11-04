"""Import parity restored from the removed CycloneDX adapter (GSA-TTS/TTSE #31).

Covers: library matching by satisfied NIST requirement, priority validation,
the legacy singular scenario ``threat`` relation, and replace-on-import.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.compliance.models import (
    CountermeasureLibraryStandard,
    StandardFramework,
    StandardRequirement,
)
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threat_models.tmbom import TmBomAdapter
from apps.threats.models import (
    CountermeasureLibrary,
    InstanceCountermeasure,
    InstanceThreatStandard,
)

User = get_user_model()


def _document(controls=None, standards=None, threats=None, name="Import"):
    document = {
        "specFormat": "CycloneDX",
        "specVersion": "2.0",
        "metadata": {
            "component": {"type": "application", "bom-ref": "sys", "name": name}
        },
        "blueprints": [{"name": name, "modelTypes": ["data-flow"]}],
    }
    if standards is not None:
        document["definitions"] = {"standards": standards}
    if controls is not None:
        document["controls"] = controls
    if threats is not None:
        document["threats"] = threats
    return document


def _nist(*codes):
    return [
        {
            "bom-ref": "std",
            "name": "NIST SP 800-53 Rev. 5",
            "requirements": [
                {"bom-ref": f"req-{code.lower()}", "identifier": code} for code in codes
            ],
        }
    ]


class ParityTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Org", domain="org.test")
        cls.user = User.objects.create_user(
            username="sec", email="sec@org.test", password="x"
        )
        OrganizationMember.objects.create(
            organization=cls.organization, user=cls.user, role="security_team"
        )
        cls.framework = StandardFramework.objects.create(
            name="NIST SP 800-53 Rev. 5",
            slug="nist-800-53-r5",
            version="5",
            issuer="NIST",
        )
        cls.ac2 = StandardRequirement.objects.create(
            framework=cls.framework, section_code="AC-2", description="Accounts"
        )
        cls.sc8 = StandardRequirement.objects.create(
            framework=cls.framework, section_code="SC-8", description="Transit"
        )
        cls.accounts = cls._library("accounts", cls.ac2)
        cls.tls_a = cls._library("tls-a", cls.sc8)
        cls.tls_b = cls._library("tls-b", cls.sc8)

    @classmethod
    def _library(cls, slug, requirement):
        library = CountermeasureLibrary.objects.create(
            name=slug, description=slug, slug=slug, qualified_slug=f"demo/{slug}"
        )
        CountermeasureLibraryStandard.objects.create(
            countermeasure_library=library, requirement=requirement
        )
        return library

    def _import(self, document):
        return TmBomAdapter().import_data(document, self.organization, self.user)

    def _control(self, threat_model):
        return InstanceCountermeasure.objects.get(threat_model=threat_model)


class LibraryMatchTests(ParityTestCase):
    def test_unique_nist_match_sets_the_library(self):
        model, _ = self._import(
            _document(
                standards=_nist("AC-2"),
                controls=[{"bom-ref": "c", "name": "AC-2", "satisfies": ["req-ac-2"]}],
            )
        )
        self.assertEqual(self._control(model).countermeasure_library, self.accounts)

    def test_ambiguous_match_leaves_the_library_empty(self):
        model, _ = self._import(
            _document(
                standards=_nist("SC-8"),
                controls=[{"bom-ref": "c", "name": "SC-8", "satisfies": ["req-sc-8"]}],
            )
        )
        self.assertIsNone(self._control(model).countermeasure_library)

    def test_explicit_library_property_wins(self):
        model, _ = self._import(
            _document(
                standards=_nist("AC-2"),
                controls=[
                    {
                        "bom-ref": "c",
                        "name": "AC-2",
                        "satisfies": ["req-ac-2"],
                        "properties": [
                            {"name": "precogly:library", "value": "demo/tls-a"}
                        ],
                    }
                ],
            )
        )
        self.assertEqual(self._control(model).countermeasure_library, self.tls_a)


class PriorityTests(ParityTestCase):
    def _with_priority(self, value):
        model, summary = self._import(
            _document(
                controls=[
                    {
                        "bom-ref": "c",
                        "name": "C",
                        "properties": [{"name": "precogly:priority", "value": value}],
                    }
                ]
            )
        )
        return self._control(model).priority, summary

    def test_valid_priority_is_kept(self):
        self.assertEqual(self._with_priority("High")[0], "high")

    def test_invalid_priority_warns_and_defaults(self):
        priority, summary = self._with_priority("urgent!!")
        self.assertEqual(priority, "none")
        self.assertTrue(any("priority" in w for w in summary.get("warnings", [])))


class LegacyScenarioThreatTests(ParityTestCase):
    def test_singular_threat_relation_links_the_abstract_threat(self):
        model, summary = self._import(
            _document(
                threats={
                    "threats": [
                        {
                            "bom-ref": "t-1",
                            "name": "Spoofing",
                            "properties": [{"name": "ctrl:id", "value": "AC-2"}],
                        }
                    ],
                    "scenarios": [{"bom-ref": "s-1", "threat": "t-1"}],
                }
            )
        )
        warnings = summary.get("warnings", [])
        self.assertFalse(any("realizes no threat" in w for w in warnings))
        threat = model.threats.get()
        self.assertEqual(threat.threat_name, "Spoofing")
        mapping = InstanceThreatStandard.objects.get(threat=threat)
        self.assertEqual(mapping.requirement, self.ac2)
        self.assertEqual(mapping.section_code, "AC-2")


class ReplaceOnImportTests(ParityTestCase):
    def setUp(self):
        self.client = APIClient()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    def _post(self, document, replace=None):
        url = "/api/threat-models/import/cyclonedx/"
        if replace is not None:
            url += f"?replace={replace}"
        response = self.client.post(url, document, format="json")
        return response

    def test_replace_deletes_the_old_model_after_import(self):
        created = self._post(_document(name="Sys"))
        self.assertEqual(created.status_code, 201, created.content[:500])
        first = created.json()["threatModel"]["id"]
        response = self._post(_document(name="Sys"), replace=first)
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["summary"]["replacedThreatModel"], first)
        self.assertFalse(ThreatModel.objects.filter(pk=first).exists())
        self.assertEqual(ThreatModel.objects.filter(name="Sys").count(), 1)

    def test_rejected_document_keeps_the_old_model(self):
        first = self._post(_document(name="Sys")).json()["threatModel"]["id"]
        response = self._post({"specFormat": "nope"}, replace=first)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(ThreatModel.objects.filter(pk=first).exists())

    def test_unknown_replace_target_is_404(self):
        self.assertEqual(self._post(_document(), replace=999999).status_code, 404)

    def test_replace_needs_write_access(self):
        other = Organization.objects.create(name="Other", domain="other.test")
        foreign = ThreatModel.objects.create(
            name="Foreign", organization=other, created_by=self.user
        )
        self.assertEqual(self._post(_document(), replace=foreign.pk).status_code, 404)
        self.assertTrue(ThreatModel.objects.filter(pk=foreign.pk).exists())


class ComponentIconImportTests(ParityTestCase):
    def test_crm_icon_property_is_stored_on_format_metadata(self):
        doc = _document()
        doc["blueprints"][0]["assets"] = [
            {
                "bom-ref": "asset-1",
                "name": "App",
                "type": "process",
                "properties": [{"name": "crm:icon", "value": "cloud"}],
            }
        ]
        model, _ = self._import(doc)
        comp = OrgsystemComponent.objects.get(blueprint=model.default_blueprint)
        self.assertEqual(comp.format_metadata.get("icon"), "cloud")

    def test_pack_icon_map_resolves_fallback_token_svg(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        from apps.packs.models import LibraryPack
        from apps.packs.services import _load_components
        from apps.systems.models import ComponentLibrary

        pack = LibraryPack.objects.create(
            slug="cloudgov-paas", name="Cloud.gov PaaS", version="1.0.0"
        )
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pack.yaml").write_text(
                "pack:\n  slug: cloudgov-paas\n  icon_map:\n    - component: cloudgov-apps\n      icon: application\n",
                encoding="utf-8",
            )
            comp_file = root / "components.yaml"
            comp_file.write_text(
                "components:\n"
                "  - id: cloudgov-apps\n"
                "    name: Cloud.gov Apps\n"
                "    category: process\n"
                "    type: compute\n",
                encoding="utf-8",
            )
            _load_components(pack, comp_file)
        lib = ComponentLibrary.objects.get(qualified_slug="cloudgov-paas/cloudgov-apps")
        self.assertIn("<svg", lib.icon_svg)
