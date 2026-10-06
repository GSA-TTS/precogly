"""API tests for server-enforced countermeasure lifecycle transitions."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.systems.models import OrgsystemComponent
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ComponentInstanceThreat,
    CountermeasureComment,
    CountermeasureThreatLink,
    InstanceCountermeasure,
    InstanceCountermeasureTest,
    VerificationTest,
)

User = get_user_model()


class CountermeasureTransitionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.organization = Organization.objects.create(name="Transition Org")
        cls.team = Team.objects.create(
            organization=cls.organization, name="Transition Team"
        )
        cls.reviewer = cls._user("reviewer", "security_team", None)
        cls.member = cls._user("member", "member", "member")
        cls.viewer = cls._user("viewer", "member", "viewer")
        cls.outsider_org = Organization.objects.create(name="Outside Org")
        cls.outsider = User.objects.create_user(username="outsider", password=None)
        OrganizationMember.objects.create(
            organization=cls.outsider_org,
            user=cls.outsider,
            role="security_team",
        )
        cls.threat_model = ThreatModel.objects.create(
            name="Transition Model",
            organization=cls.organization,
            owning_team=cls.team,
        )
        component = OrgsystemComponent.objects.create(
            threat_model=cls.threat_model, name="Application"
        )
        cls.threat = ComponentInstanceThreat.objects.create(
            component=component, threat_name="Misuse", inherent_severity="high"
        )

    @classmethod
    def _user(cls, username, org_role, team_role):
        user = User.objects.create_user(username=username, password=None)
        OrganizationMember.objects.create(
            organization=cls.organization, user=user, role=org_role
        )
        if team_role:
            TeamMembership.objects.create(team=cls.team, user=user, role=team_role)
        return user

    def setUp(self):
        self.countermeasure = InstanceCountermeasure.objects.create(
            threat_model=self.threat_model,
            countermeasure_name="Account control",
            countermeasure_description="Implemented through account automation.",
            status="gap",
        )
        CountermeasureThreatLink.objects.create(
            countermeasure=self.countermeasure, component_threat=self.threat
        )

    def _client(self, user):
        client = APIClient()
        token = str(RefreshToken.for_user(user).access_token)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        return client

    def _transition(self, user, target, **data):
        return self._client(user).post(
            f"/api/countermeasures/{self.countermeasure.pk}/transition/",
            {"status": target, **data},
            format="json",
        )

    def test_member_transitions_to_planned_with_owner_and_audit_comment(self):
        response = self._transition(
            self.member, "planned", assignedOwner=self.member.pk, note="Accepted work."
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "planned")
        self.assertEqual(self.countermeasure.assigned_owner, self.member)
        comment = CountermeasureComment.objects.get(countermeasure=self.countermeasure)
        self.assertEqual(comment.change_summary, "status: gap -> planned")
        self.assertEqual(comment.body, "Accepted work.")

    def test_planned_requires_owner_and_failure_is_atomic(self):
        response = self._transition(self.member, "planned")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "gap")
        self.assertFalse(self.countermeasure.comments.exists())

    def test_verified_requires_security_reviewer_and_evidence(self):
        self.countermeasure.status = "implemented"
        self.countermeasure.save(update_fields=["status"])

        member_response = self._transition(self.member, "verified")
        reviewer_response = self._transition(self.reviewer, "verified")

        self.assertEqual(member_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(reviewer_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "implemented")
        self.assertIsNone(self.countermeasure.verified_by)
        self.assertFalse(self.countermeasure.comments.exists())

    def test_security_reviewer_verifies_with_evidence_and_server_owned_identity(self):
        self.countermeasure.status = "implemented"
        self.countermeasure.save(update_fields=["status"])

        response = self._transition(
            self.reviewer,
            "verified",
            evidenceUrl="http://localhost/evidence/control",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "verified")
        self.assertEqual(self.countermeasure.verified_by, self.reviewer)
        self.assertEqual(
            self.countermeasure.evidence_url, "http://localhost/evidence/control"
        )

    def test_passing_linked_test_with_evidence_allows_verification(self):
        self.countermeasure.status = "implemented"
        self.countermeasure.save(update_fields=["status"])
        verification = VerificationTest.objects.create(
            name="Control test",
            method="auto",
            passed=True,
            evidence="Test result reference",
        )
        InstanceCountermeasureTest.objects.create(
            countermeasure=self.countermeasure,
            verification_test=verification,
        )

        response = self._transition(self.reviewer, "verified")

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_leaving_verified_clears_verifier(self):
        self.countermeasure.status = "verified"
        self.countermeasure.verified_by = self.reviewer
        self.countermeasure.save(update_fields=["status", "verified_by"])

        response = self._transition(self.member, "implemented")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.countermeasure.refresh_from_db()
        self.assertIsNone(self.countermeasure.verified_by)

    def test_security_decisions_are_scoped_to_same_organization(self):
        response = self._transition(self.outsider, "waived")

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "gap")

    def test_waived_requires_security_reviewer_and_rationale(self):
        without_note = self._transition(self.reviewer, "waived")
        member_response = self._transition(self.member, "waived", note="Accepted risk.")
        success = self._transition(self.reviewer, "waived", note="Accepted risk.")

        self.assertEqual(without_note.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(member_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(success.status_code, status.HTTP_200_OK)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "waived")
        self.assertEqual(self.countermeasure.comments.get().body, "Accepted risk.")

    def test_viewer_cannot_transition(self):
        response = self._transition(
            self.viewer, "planned", assignedOwner=self.member.pk
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_generic_patch_cannot_change_status_or_verifier(self):
        response = self._client(self.reviewer).patch(
            f"/api/countermeasures/{self.countermeasure.pk}/",
            {"status": "verified", "verifiedBy": self.reviewer.pk},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.countermeasure.refresh_from_db()
        self.assertEqual(self.countermeasure.status, "gap")
        self.assertIsNone(self.countermeasure.verified_by)

    def test_invalid_transition_is_atomic(self):
        response = self._transition(self.member, "verified")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(self.countermeasure.comments.exists())

    def test_successful_transition_recalculates_linked_threat(self):
        self.threat.status = "exposed"
        self.threat.save(update_fields=["status"])
        self.countermeasure.status = "planned"
        self.countermeasure.assigned_owner = self.member
        self.countermeasure.save(update_fields=["status", "assigned_owner"])

        response = self._transition(self.member, "implemented")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.threat.refresh_from_db()
        self.assertEqual(self.threat.status, "mitigated")
