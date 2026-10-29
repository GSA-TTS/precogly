"""Report differences between managed Django models and the live database."""

import json

from django.core.management.base import BaseCommand, CommandError

from apps.core.schema_drift import inspect_schema_drift


class Command(BaseCommand):
    help = "Detect unexpected, missing, or nullability-drifted database columns"

    def add_arguments(self, parser):
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Emit a machine-readable report",
        )

    def handle(self, *args, **options):
        findings = inspect_schema_drift()
        report = {
            "ok": not findings,
            "finding_count": len(findings),
            "findings": findings,
        }
        if options["as_json"]:
            self.stdout.write(json.dumps(report, sort_keys=True))
        elif not findings:
            self.stdout.write(
                self.style.SUCCESS("Database schema matches managed models.")
            )
        else:
            for finding in findings:
                location = finding["table"]
                if finding.get("column"):
                    location += f".{finding['column']}"
                self.stdout.write(f"{finding['code']}: {location}")

        if findings:
            raise CommandError(
                f"Database schema drift detected ({len(findings)} finding(s))."
            )
