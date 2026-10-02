"""What the MCP endpoint reads, and as whom.

`ORMReader` is Precogly's half of the data-access protocol `precogly_mcp` defines: a
tool never fetches for itself, and mounted in this process it cannot, since the
caller's token is audience-bound to /mcp and django-oauth-toolkit refuses it at
/api/. What crosses into the data is the user the verifier resolved.

The rows are handed to the pydantic models the tools validate them with, which is the
strongest thing pinned here. Those models live in the other repository, so a
serializer change that would break a tool has nothing else to fail against — it would
otherwise surface as a validation error inside an agent's answer, or as a field
quietly missing from one.

Async methods are driven with `async_to_sync`. The ORM work inside them runs under
`sync_to_async(thread_sensitive=True)`, which keeps it on the calling thread, so it
sees the data this TestCase has created inside its transaction. Without that it would
run on another thread, outside the transaction, and every fixture below would look
absent.
"""

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.test import TestCase
from mcp.server.auth.provider import AccessToken
from precogly_mcp.models import (
    LibraryComponent,
    LibraryCountermeasure,
    LibraryThreat,
    ThreatModelSummary,
)

from apps.core.mcp import ORMReader, reader_for
from apps.organizations.models import Organization, OrganizationMember, Team
from apps.systems.models import ComponentLibrary
from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    CountermeasureLibrary,
    ExternalTaxonomy,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
)

User = get_user_model()


def account(email, organization, role="security_team"):
    """A user in one organization and nothing else.

    The memberships are cleared first because `create_personal_workspace`
    (`apps/organizations/signals.py`) gives every new account a workspace of its own,
    as security team, whenever no primary organization exists — which is every test
    database. Left in place it would widen what `visible_to` returns.
    """
    user = User.objects.create_user(username=email, email=email, password="testpass123")
    user.organization_memberships.all().delete()
    user.team_memberships.all().delete()
    OrganizationMember.objects.create(organization=organization, user=user, role=role)
    return user


class ThreatModelReadingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.other = Organization.objects.create(name="Contoso", domain="contoso.test")
        cls.team = Team.objects.create(organization=cls.org, name="Platform")

        # Created oldest first, so "most recently updated" is the last one written.
        cls.older = ThreatModel.objects.create(
            organization=cls.org, name="Ingest pipeline", owning_team=cls.team
        )
        cls.newer = ThreatModel.objects.create(
            organization=cls.org, name="Card vault", owning_team=cls.team
        )
        cls.elsewhere = ThreatModel.objects.create(
            organization=cls.other, name="Contoso ledger", owning_team=None
        )

        cls.insider = account("appsec@kestrel.test", cls.org)
        cls.outsider = account("appsec@contoso.test", cls.other)

    def read(self, user, organization_id=None):
        return async_to_sync(ORMReader(user.pk).threat_models)(organization_id)

    def test_the_rows_are_the_ones_that_user_may_read(self):
        assert [row["name"] for row in self.read(self.insider).rows] == [
            "Card vault",
            "Ingest pipeline",
        ]
        assert [row["name"] for row in self.read(self.outsider).rows] == [
            "Contoso ledger"
        ]

    def test_most_recently_updated_comes_first(self):
        # The tool's description promises this order. Two things supply it — the
        # reader's `order_by` and `ThreatModel.Meta.ordering` — and this cannot tell
        # them apart: dropping either one on its own leaves the test passing, and
        # dropping both fails it. Measured, not assumed. The promise is what is
        # pinned here; the redundancy is deliberate and belongs to the reader.
        self.older.save()

        assert [row["name"] for row in self.read(self.insider).rows] == [
            "Ingest pipeline",
            "Card vault",
        ]

    def test_total_counts_what_came_back(self):
        listing = self.read(self.insider)

        assert listing.total == len(listing.rows) == 2

    def test_an_organization_id_narrows_to_that_organization(self):
        listing = self.read(self.insider, organization_id=self.org.pk)

        assert [row["name"] for row in listing.rows] == [
            "Card vault",
            "Ingest pipeline",
        ]

    def test_an_organization_the_caller_cannot_read_comes_back_empty(self):
        # Narrowing an already-scoped queryset, so this is empty rather than an error.
        # The REST filter answers differently — it validates against every
        # organization, which tells a caller the difference between "not yours" and
        # "no such id" (precogly/precogly#259). Empty is the better of the two.
        listing = self.read(self.insider, organization_id=self.other.pk)

        assert listing.rows == []
        assert listing.total == 0

    def test_every_row_validates_as_the_tool_returns_it(self):
        for row in self.read(self.insider).rows:
            ThreatModelSummary.model_validate(row)


class CatalogReadingTests(TestCase):
    """The three shared catalogs, which belong to no organization."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.user = account("appsec@kestrel.test", cls.org)

        cwe = ExternalTaxonomy.objects.create(slug="cwe", name="CWE")
        improper_input = TaxonomyEntry.objects.create(
            taxonomy=cwe,
            external_id="CWE-20",
            title="Improper Input Validation",
            reference_url="https://cwe.mitre.org/data/definitions/20.html",
        )

        # Named out of alphabetical order, so name ordering is measured rather than
        # inherited from insertion.
        injection = ThreatLibrary.objects.create(
            name="SQL injection", description="Untrusted input reaches a query."
        )
        ThreatLibrary.objects.create(
            name="Broken authentication", description="Credentials are guessable."
        )
        ThreatLibraryTaxonomyEntry.objects.create(
            threat_library=injection, taxonomy_entry=improper_input
        )

        CountermeasureLibrary.objects.create(
            name="Parameterised queries",
            description="Bind values instead of concatenating.",
            control_functions=["preventive"],
            cost="low",
            default_status="gap",
        )
        ComponentLibrary.objects.create(
            name="Amazon S3",
            category=ComponentLibrary.Category.DATASTORE,
            component_type="object-store",
            provider="aws",
            slug="s3",
            qualified_slug="aws/s3",
        )

    def reader(self):
        return ORMReader(self.user.pk)

    def test_the_threat_catalog_comes_back_whole_and_in_name_order(self):
        rows = async_to_sync(self.reader().threat_library)()

        assert [row["name"] for row in rows] == [
            "Broken authentication",
            "SQL injection",
        ]

    def test_a_threat_keeps_its_taxonomy_mappings(self):
        # The tool matches an identifier like CWE-20 against these, so a projection
        # that dropped them would leave the search silently answering nothing.
        rows = async_to_sync(self.reader().threat_library)()
        threats = [LibraryThreat.model_validate(row) for row in rows]
        injection = next(t for t in threats if t.name == "SQL injection")

        assert [entry.external_id for entry in injection.taxonomy_entries] == ["CWE-20"]
        assert injection.taxonomy_entries[0].taxonomy_slug == "cwe"

    def test_every_catalog_row_validates_as_the_tool_returns_it(self):
        reader = self.reader()

        for row in async_to_sync(reader.threat_library)():
            LibraryThreat.model_validate(row)
        for row in async_to_sync(reader.countermeasure_library)():
            LibraryCountermeasure.model_validate(row)
        for row in async_to_sync(reader.component_library)():
            LibraryComponent.model_validate(row)

    def test_a_catalog_reads_the_same_for_anyone(self):
        # Not scoped to the caller: the rows carry no organization, and reads are open
        # to any authenticated user. A plain member of another organization sees the
        # same catalog.
        elsewhere = Organization.objects.create(name="Contoso", domain="contoso.test")
        stranger = account("member@contoso.test", elsewhere, role="member")

        assert async_to_sync(ORMReader(stranger.pk).component_library)() == (
            async_to_sync(self.reader().component_library)()
        )


class ReaderForTests(TestCase):
    """The factory the lifespan hands every tool call."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.user = account("appsec@kestrel.test", cls.org)
        ThreatModel.objects.create(
            organization=cls.org, name="Ingest pipeline", owning_team=None
        )

    def test_the_reader_acts_as_the_account_the_token_names(self):
        token = AccessToken(
            token="opaque",
            client_id="probe",
            scopes=["read"],
            subject=str(self.user.pk),
        )

        listing = async_to_sync(reader_for(token).threat_models)()

        assert [row["name"] for row in listing.rows] == ["Ingest pipeline"]

    def test_a_call_with_no_resolved_user_is_refused(self):
        # Unreachable through the endpoint, which authenticates first. Raising names
        # the wiring mistake; returning an empty reader would surface it as an empty
        # listing, which reads like an answer.
        with self.assertRaises(RuntimeError):
            reader_for(None)

        with self.assertRaises(RuntimeError):
            reader_for(AccessToken(token="opaque", client_id="probe", scopes=["read"]))
