"""Tests for the read-only threat-model fidelity coverage endpoint.

See issue GSA-TTS/TTSE-petrified-forest-sspp#82 (item 6): external CI
scripts need a stable, server-computed coverage report rather than
re-deriving the same metrics from a raw CycloneDX export.
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.organizations.models import Organization, OrganizationMember
from apps.threat_models.models import ThreatModel
from apps.threats.models import CountermeasureLibrary, InstanceCountermeasure

User = get_user_model()


class ThreatModelFidelityEndpointTests(APITestCase):
    """Verify GET /api/threat-models/{id}/fidelity/ coverage math."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Fidelity Test Org")
        cls.user = User.objects.create_user(
            username="fidelity_user", email="fidelity@example.com", password="pw"
        )
        OrganizationMember.objects.create(organization=cls.org, user=cls.user)
        cls.tm = ThreatModel.objects.create(
            organization=cls.org, created_by=cls.user, name="Fidelity TM"
        )

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def _get(self):
        return self.client.get(f"/api/threat-models/{self.tm.id}/fidelity/")

    def test_empty_threat_model_reports_zero_without_dividing_by_zero(self):
        response = self._get()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["countermeasures"], 0)
        for key in (
            "nistIdCoverage",
            "proseCoverage",
            "evidenceUrlCoverage",
            "complianceStandardCoverage",
            "inheritedFlagCoverage",
            "componentLibraryLinked",
        ):
            self.assertEqual(data[key], 0.0)
        self.assertEqual(data["schemaVersion"], "2")
        self.assertEqual(
            data["transportCoverage"],
            {
                "controlId": 0.0,
                "implementationProse": 0.0,
                "evidenceUrl": 0.0,
                "originationMarker": 0.0,
            },
        )
        self.assertEqual(data["nativeCoverage"]["requirementMapping"], 0.0)
        self.assertIsNone(data["nativeCoverage"]["editableScope"])
        self.assertFalse(data["authorizationReadiness"]["supported"])
        self.assertFalse(data["authorizationReadiness"]["ready"])

    def test_partial_coverage_computed_correctly(self):
        library_entry = CountermeasureLibrary.objects.create(
            name="Encryption at Rest", description="Template"
        )

        # Fully covered instance.
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            countermeasure_name="Full coverage",
            countermeasure_description="Has prose",
            evidence_url="https://example.gov/evidence",
            is_inherited=False,
            countermeasure_library=library_entry,
            format_metadata={
                "cyclonedx": {
                    "nist_control_id": "SC-28",
                    "origination_present": True,
                }
            },
        )
        # Bare instance: no NIST id, no evidence, not inherited, no library link.
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            countermeasure_name="Bare",
            countermeasure_description="",
        )

        response = self._get()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["countermeasures"], 2)
        self.assertEqual(data["nistIdCoverage"], 0.5)
        self.assertEqual(data["proseCoverage"], 0.5)
        self.assertEqual(data["evidenceUrlCoverage"], 0.5)
        self.assertEqual(data["inheritedFlagCoverage"], 0.5)
        self.assertEqual(data["componentLibraryLinked"], 0.5)
        self.assertEqual(data["complianceStandardCoverage"], 0.0)
        self.assertEqual(data["transportCoverage"]["controlId"], 0.5)
        self.assertEqual(data["transportCoverage"]["originationMarker"], 0.5)
        self.assertEqual(data["nativeCoverage"]["requirementMapping"], 0.0)
        self.assertEqual(data["nativeCoverage"]["libraryLink"], 0.5)

    def test_transport_id_does_not_imply_native_requirement_mapping(self):
        InstanceCountermeasure.objects.create(
            threat_model=self.tm,
            countermeasure_name="Transport-only NIST control",
            countermeasure_description="Imported prose",
            format_metadata={
                "cyclonedx": {
                    "nist_control_id": "AC-2",
                    "origination_present": True,
                }
            },
        )

        data = self._get().json()

        self.assertEqual(data["transportCoverage"]["controlId"], 1.0)
        self.assertEqual(data["nativeCoverage"]["requirementMapping"], 0.0)
        self.assertFalse(data["authorizationReadiness"]["ready"])

    def test_fidelity_scoped_to_requested_threat_model_only(self):
        other_tm = ThreatModel.objects.create(
            organization=self.org, created_by=self.user, name="Other TM"
        )
        InstanceCountermeasure.objects.create(
            threat_model=other_tm,
            countermeasure_name="Should not count",
            countermeasure_description="x",
            evidence_url="https://example.gov/x",
        )

        response = self._get()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["countermeasures"], 0)

    def test_query_count_is_constant_as_countermeasures_grow(self):
        for index in range(10):
            InstanceCountermeasure.objects.create(
                threat_model=self.tm,
                countermeasure_name=f"Control {index}",
                countermeasure_description="Documented",
            )

        with self.assertNumQueries(3):
            response = self._get()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["countermeasures"], 10)
