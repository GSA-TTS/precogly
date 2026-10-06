"""Tests for read-only live database schema drift detection."""

from types import SimpleNamespace
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.core.schema_drift import inspect_schema_drift


class SchemaDriftTests(TestCase):
    def test_current_migrated_database_has_no_drift(self):
        self.assertEqual(inspect_schema_drift(), [])

    def test_unexpected_non_null_column_is_reported(self):
        from django.db import connection

        original = connection.introspection.get_table_description

        def description(cursor, table_name):
            columns = original(cursor, table_name)
            if table_name == "threats_instancecountermeasure":
                return [*columns, SimpleNamespace(name="source", null_ok=False)]
            return columns

        with patch.object(
            connection.introspection,
            "get_table_description",
            side_effect=description,
        ):
            findings = inspect_schema_drift()

        self.assertIn(
            {
                "code": "unexpected-column",
                "table": "threats_instancecountermeasure",
                "column": "source",
            },
            findings,
        )

    def test_command_exits_nonzero_when_drift_exists(self):
        finding = {
            "code": "unexpected-column",
            "table": "example",
            "column": "stale",
        }
        with (
            patch(
                "apps.core.management.commands.check_schema_drift.inspect_schema_drift",
                return_value=[finding],
            ),
            self.assertRaises(CommandError),
        ):
            call_command("check_schema_drift", "--json")
