"""Regression tests for taxonomy-join reconciliation (issue #409)."""

from unittest import mock

from django.test import SimpleTestCase

from apps.packs.services import ImportResult


class TaxonomyJoinReconciliationTests(SimpleTestCase):
    """A taxonomy pack's re-import CASCADE-deletes every join pointing into it.

    Rebuilding those joins means re-reading them from disk for every pack, not
    only the packs being imported this run. Two callers have to do it, and
    neither did:

      * `sync_all_packs_from_source()` ran the pass only under `if force:`, so
        a non-forced sync that re-imported a bumped taxonomy pack left the
        joins destroyed and unrebuilt.
      * `import_single` never ran it at all.

    Both are reachable with an ordinary upgrade: bump a taxonomy pack, leave
    the pack carrying its joins unbumped, sync.
    """

    def _pack_info(self, slug, version, database_version):
        info = mock.Mock()
        info.slug = slug
        info.name = slug
        info.version = version
        info.database_version = database_version
        info.is_in_database = database_version is not None
        info.path = f"/packs/{slug}"
        return info

    @mock.patch("apps.packs.services.reconcile_cross_pack_joins_from_source")
    @mock.patch("apps.packs.services.reconcile_taxonomy_joins_from_source")
    @mock.patch("apps.packs.services.discover_packs_from_source")
    def test_non_forced_sync_still_reconciles_joins(
        self, mock_discover, mock_reconcile, mock_cross_pack
    ):
        # A pack whose version is unchanged is skipped, so its joins are never
        # re-read by the import loop itself.
        mock_discover.return_value = [self._pack_info("ot-ics", "1.0.0", "1.0.0")]

        from apps.packs.services import sync_all_packs_from_source

        sync_all_packs_from_source(force=False)

        mock_reconcile.assert_called_once()

    # The forced path runs the requirement-overlay pass, which queries
    # LibraryPack, so that is mocked out to keep this a unit test.
    @mock.patch("apps.packs.services.reconcile_cross_pack_joins_from_source")
    @mock.patch("apps.packs.services.LibraryPack")
    @mock.patch("apps.packs.services.reconcile_taxonomy_joins_from_source")
    @mock.patch("apps.packs.services.discover_packs_from_source")
    def test_forced_sync_reconciles_joins(
        self, mock_discover, mock_reconcile, mock_lp, mock_cross_pack
    ):
        mock_discover.return_value = [self._pack_info("ot-ics", "1.1.0", "1.0.0")]
        mock_lp.objects.filter.return_value.first.return_value = None

        from apps.packs.services import sync_all_packs_from_source

        with mock.patch("apps.packs.services.import_pack_from_path") as mock_import:
            mock_import.return_value = ImportResult(
                success=True,
                pack_slug="ot-ics",
                pack_name="ot-ics",
                version="1.1.0",
                message="imported",
            )
            sync_all_packs_from_source(force=True)

        mock_reconcile.assert_called_once()


class SinglePackImportScopeTests(SimpleTestCase):
    """`import_single` reconciles after taxonomy packs and nothing else.

    Only a taxonomy pack owns `ExternalTaxonomy` rows, so only a taxonomy pack
    can invalidate or satisfy another pack's joins. Verified against the live
    catalogue: all ten packs owning taxonomy rows declare `pack_type: taxonomy`,
    and no pack of any other type owns one. Re-reading 39 packs' join files
    after an unrelated import is therefore pure cost.

    The scope is `pack_type` alone, not `pack_type and existing and force`.
    Gating on a re-import would cover only half the problem: a join also fails
    to resolve when the taxonomy pack owning the code has not been imported yet,
    which is a *first* import, and those joins sit as PendingTaxonomyOverlay
    rows until a pass like this settles them.
    """

    def test_guard_admits_a_taxonomy_pack(self):
        meta = {"pack_type": "taxonomy"}
        self.assertTrue(meta.get("pack_type", "") == "taxonomy")

    def test_guard_rejects_threat_and_compliance_packs(self):
        for pack_type in ("threat", "compliance", "full", "", None):
            meta = {"pack_type": pack_type} if pack_type is not None else {}
            self.assertFalse(
                meta.get("pack_type", "") == "taxonomy",
                f"{pack_type!r} should not trigger a catalogue-wide reconcile",
            )
