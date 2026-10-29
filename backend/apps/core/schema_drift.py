"""Read-only comparison of Django's managed models with the live database."""

from django.apps import apps
from django.db import connection


def inspect_schema_drift():
    """Return deterministic model/database schema differences."""
    findings = []
    with connection.cursor() as cursor:
        tables = set(connection.introspection.table_names(cursor))
        for model in sorted(
            apps.get_models(),
            key=lambda item: item._meta.db_table,
        ):
            options = model._meta
            if not options.managed or options.proxy:
                continue

            table = options.db_table
            if table not in tables:
                findings.append({"code": "missing-table", "table": table})
                continue

            description = connection.introspection.get_table_description(cursor, table)
            actual = {column.name: column for column in description}
            expected = {
                field.column: field
                for field in options.local_concrete_fields
                if field.column
            }

            for column in sorted(expected.keys() - actual.keys()):
                findings.append(
                    {"code": "missing-column", "table": table, "column": column}
                )
            for column in sorted(actual.keys() - expected.keys()):
                findings.append(
                    {"code": "unexpected-column", "table": table, "column": column}
                )
            for column in sorted(expected.keys() & actual.keys()):
                nullable = actual[column].null_ok
                if nullable is not None and nullable != expected[column].null:
                    findings.append(
                        {
                            "code": "nullability-mismatch",
                            "table": table,
                            "column": column,
                            "model_nullable": expected[column].null,
                            "database_nullable": nullable,
                        }
                    )

    return findings
