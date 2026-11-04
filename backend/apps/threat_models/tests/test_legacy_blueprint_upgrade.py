"""Legacy database upgrade across the #598 blueprint migrations (issue #44).

`threat_models.0005` and `diagrams.0003` turn the pre-blueprint schema, where
a DFD and an out-of-scope item pointed straight at a threat model, into the
blueprint model.  The first version of those migrations added the new foreign
key with `default=1`, so every upgraded row was attached to whichever blueprint
happened to be first -- or the migration failed outright when no such row
existed.

This exercises the real upgrade path: reset the test schema, migrate *forward*
only as far as the last pre-blueprint migration, write rows the way the old
schema did, then migrate the rest of the way and check that each threat model
kept its own data.  It is the regression guard for the defect reported in
GSA-TTS/precogly#44.

Two deliberate choices:

- Forward-only.  Unapplying the graph to reach the legacy state trips a
  separate reversibility problem in the `threats` check constraints, which
  would fail this test for a reason that has nothing to do with blueprints.
- Raw SQL for the legacy rows.  A partial migration leaves a project state
  that only renders the apps it reached, so a historical model registry is not
  available for the apps around it.  SQL is also closer to what an existing
  database actually holds.
"""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

# The last migration in each app before blueprints existed.
PRE_BLUEPRINT = [
    ("diagrams", "0002_initial"),
    ("threat_models", "0004_cyclonedx_schema_enrichment"),
]


def _migrate(targets):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(targets)
    executor.loader.build_graph()


def _migrate_to_latest():
    # Not `[(app, None)]`: a None target means *unapply* that app.
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    targets = executor.loader.graph.leaf_nodes()
    executor.migrate(targets)


def _reset_schema():
    """Empty the test database so the graph can be replayed from zero."""
    name = connection.settings_dict["NAME"]
    if "test" not in name.lower():
        raise RuntimeError(
            f"refusing to reset a database that is not a test database: {name}"
        )
    with connection.cursor() as cursor:
        cursor.execute("DROP SCHEMA public CASCADE")
        cursor.execute("CREATE SCHEMA public")


def _insert(table: str, **columns) -> int:
    names = ", ".join(f'"{name}"' for name in columns)
    holders = ", ".join(["%s"] * len(columns))
    # The table and column names are literals from this module, never caller
    # input; every value is a bound parameter.
    statement = f'INSERT INTO "{table}" ({names}) VALUES ({holders}) RETURNING id'  # noqa: S608
    with connection.cursor() as cursor:
        cursor.execute(statement, list(columns.values()))
        return cursor.fetchone()[0]


def _rows(sql: str, *params) -> list[tuple]:
    with connection.cursor() as cursor:
        cursor.execute(sql, list(params))
        return cursor.fetchall()


def _scalar(sql: str, *params):
    return _rows(sql, *params)[0][0]


class LegacyBlueprintUpgradeTests(TransactionTestCase):
    def setUp(self):
        _reset_schema()
        # Cleanups run before the flush in Django's _post_teardown, so the
        # schema is whole again by the time the test runner touches it.
        self.addCleanup(self._restore)
        _migrate(PRE_BLUEPRINT)

    def _restore(self):
        _reset_schema()
        _migrate_to_latest()

    def _legacy_organization(self) -> int:
        return _insert(
            "organizations_organization",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            name="Legacy Upgrade",
            domain="",
            plan="free",
            business_unit_label="",
            is_primary=False,
        )

    def _legacy_threat_model(self, organization_id: int, name: str) -> int:
        return _insert(
            "threat_models_threatmodel",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            name=name,
            description="",
            criticality="medium",
            risk_scoring_method="qualitative_matrix",
            format_metadata="{}",
            workspace_data="{}",
            assumptions="[]",
            scope_locked=False,
            organization_id=organization_id,
        )

    def _legacy_dfd(self, threat_model_id, name: str, *, is_primary=True) -> int:
        return _insert(
            "diagrams_dfd",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            name=name,
            diagram_type="data-flow",
            canvas_data="{}",
            is_primary=is_primary,
            threat_model_id=threat_model_id,
        )

    def _legacy_scope_item(self, threat_model_id: int, name: str) -> int:
        return _insert(
            "threat_models_outofscopeitem",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            name=name,
            reason="",
            threat_model_id=threat_model_id,
        )

    def test_each_legacy_threat_model_keeps_its_own_dfd_and_scope_items(self):
        organization = self._legacy_organization()
        first = self._legacy_threat_model(organization, "First")
        second = self._legacy_threat_model(organization, "Second")
        first_dfd = self._legacy_dfd(first, "First DFD")
        second_dfd = self._legacy_dfd(second, "Second DFD")
        first_scope = self._legacy_scope_item(first, "First exclusion")
        second_scope = self._legacy_scope_item(second, "Second exclusion")

        _migrate_to_latest()

        # One blueprint per legacy threat model, with no hard-coded id.
        blueprints = dict(
            _rows("SELECT threat_model_id, id FROM threat_models_blueprint")
        )
        self.assertEqual(set(blueprints), {first, second})

        # Rows moved to their own model's blueprint, not a shared first one.
        self.assertEqual(
            _scalar("SELECT blueprint_id FROM diagrams_dfd WHERE id = %s", first_dfd),
            blueprints[first],
        )
        self.assertEqual(
            _scalar("SELECT blueprint_id FROM diagrams_dfd WHERE id = %s", second_dfd),
            blueprints[second],
        )
        self.assertEqual(
            _scalar(
                "SELECT blueprint_id FROM threat_models_outofscopeitem WHERE id = %s",
                first_scope,
            ),
            blueprints[first],
        )
        self.assertEqual(
            _scalar(
                "SELECT blueprint_id FROM threat_models_outofscopeitem WHERE id = %s",
                second_scope,
            ),
            blueprints[second],
        )

        # Nothing was left unassigned, and the primary designation survived.
        self.assertEqual(
            _scalar("SELECT count(*) FROM diagrams_dfd WHERE blueprint_id IS NULL"), 0
        )
        self.assertEqual(
            _scalar(
                "SELECT count(*) FROM threat_models_outofscopeitem "
                "WHERE blueprint_id IS NULL"
            ),
            0,
        )
        self.assertTrue(
            _scalar("SELECT is_primary FROM diagrams_dfd WHERE id = %s", first_dfd)
        )

        # The legacy threat-model link is gone, replaced by the blueprint.
        self.assertEqual(
            _scalar(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_name = 'diagrams_dfd' AND column_name = 'threat_model_id'"
            ),
            0,
        )

    def test_upgrade_refuses_to_misassign_a_dfd_with_no_threat_model(self):
        organization = self._legacy_organization()
        self._legacy_threat_model(organization, "First")
        orphan = self._legacy_dfd(None, "Orphan", is_primary=False)

        with self.assertRaises(RuntimeError) as caught:
            _migrate_to_latest()

        self.assertIn(str(orphan), str(caught.exception))
