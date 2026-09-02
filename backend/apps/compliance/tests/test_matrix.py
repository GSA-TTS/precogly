"""Tests for the compliance-matrix endpoint."""

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase

from apps.compliance.models import StandardFramework, StandardRequirement
from apps.organizations.models import Organization, OrganizationMember
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ComponentInstanceThreat,
    CountermeasureThreatLink,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
)

User = get_user_model()


class ComplianceMatrixTests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.other_org = Organization.objects.create(
            name="Contoso", domain="contoso.test"
        )
        cls.user = User.objects.create_user(
            username="matrix@kestrel.test",
            email="matrix@kestrel.test",
            password="pw",
        )
        OrganizationMember.objects.create(
            organization=cls.org, user=cls.user, role="security_team"
        )

        cls.tm = ThreatModel.objects.create(name="TM-A", organization=cls.org)
        cls.other_tm = ThreatModel.objects.create(
            name="TM-B", organization=cls.other_org
        )

        cls.framework = StandardFramework.objects.create(
            name="NIST 800-53 Rev 5", slug="nist-800-53-r5"
        )
        cls.req_ac3 = StandardRequirement.objects.create(
            framework=cls.framework,
            section_code="AC-3",
            description="Access enforcement",
        )
        cls.req_au6 = StandardRequirement.objects.create(
            framework=cls.framework, section_code="AU-6", description="Audit review"
        )

        cls.component = OrgsystemComponent.objects.create(
            threat_model=cls.tm, name="API"
        )
        cls.threat = ComponentInstanceThreat.objects.create(
            component=cls.component,
            threat_name="Spoofing",
            inherent_severity="high",
        )

        # Countermeasure mapped via instance_standard_mappings to AC-3.
        cls.cm_ac3 = InstanceCountermeasure.objects.create(
            threat_model=cls.tm,
            countermeasure_name="MFA everywhere",
            status="implemented",
        )
        InstanceCountermeasureStandard.objects.create(
            countermeasure=cls.cm_ac3,
            requirement=cls.req_ac3,
            section_code="AC-3",
            sufficiency="full",
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=cls.cm_ac3, component_threat=cls.threat
        )

        # Countermeasure with only the CycloneDX fallback ctrl_id.
        cls.cm_au6 = InstanceCountermeasure.objects.create(
            threat_model=cls.tm,
            countermeasure_name="Centralised logging",
            status="planned",
            format_metadata={"cyclonedx": {"ctrl_id": "AU-6"}},
        )

    def test_matrix_lists_families_and_countermeasures(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url)
        assert response.status_code == 200
        data = response.json()
        assert data["framework"]["name"] == "NIST 800-53 Rev 5"

        families = {fam["family"]: fam for fam in data["families"]}
        assert set(families) == {"AC", "AU"}

        ac3 = families["AC"]["requirements"][0]
        assert ac3["section_code"] == "AC-3"
        assert [cm["name"] for cm in ac3["countermeasures"]] == ["MFA everywhere"]
        assert ac3["countermeasures"][0]["sufficiency"] == "full"
        assert [t["name"] for t in ac3["threats"]] == ["Spoofing"]

        au6 = families["AU"]["requirements"][0]
        assert au6["section_code"] == "AU-6"
        assert [cm["name"] for cm in au6["countermeasures"]] == ["Centralised logging"]
        assert au6["threats"] == []

    def test_matrix_requires_authentication(self):
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url)
        assert response.status_code in (401, 403)

    def test_matrix_hides_threat_models_in_other_orgs(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.other_tm.id})
        response = self.client.get(url)
        assert response.status_code == 404

    def test_matrix_returns_warning_for_unknown_framework(self):
        self.client.force_authenticate(self.user)
        url = reverse("compliance-matrix", kwargs={"tm_id": self.tm.id})
        response = self.client.get(url, {"framework": "does-not-exist"})
        assert response.status_code == 200
        assert response.json()["framework"] is None
        assert "warning" in response.json()
