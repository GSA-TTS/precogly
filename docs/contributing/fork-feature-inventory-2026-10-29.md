# Fork feature inventory across the upstream TM-BOM (#598) reconciliation

**Branch:** `restore/fork-regressions-2026-10-29` (from `reconcile/upstream-2026-10-28`)
**Baselines compared:** fork `main` (`1a09af4`) vs this branch
**Date:** 2026-10-29

Reconciling the fork onto upstream `precogly/precogly#598` replaced the whole
pre-TM-BOM model layer. 30 non-frontend files that exist on fork `main` are
absent from the reconciled branch. Most are genuinely superseded. Three were
plain regressions, and those are restored on this branch.

Every file below was checked against `upstream/main` as well as the reconciled
branch, so "superseded" means upstream really does carry a successor — not that
the capability was simply dropped.

## Restored — no upstream equivalent exists

| Files | Why it had to come back |
| --- | --- |
| `backend/apps/core/schema_drift.py`, `.../management/commands/check_schema_drift.py`, `.../tests/test_schema_drift.py`, plus the `backend/Dockerfile` startup gate | A read-only model-vs-database comparison that both container entrypoints run before serving. Upstream has no equivalent, so the reconciled branch would start the app over a drifted schema. This is the live safety regression of the three. The test's drift probe had to change: it injected a phantom `source` column, and upstream promoted `source` to a real `InstanceCountermeasure` field, so the injection stopped being drift. It now uses a name that is not a model field. |
| `backend/apps/packs/generate_nist_800_53_pack.py`, `backend/apps/packs/test_nist_800_53_pack.py`, `libraries/packs/standards/nist-800-53-r5/{pack.yaml,PROVENANCE.md}` | The governed NIST SP 800-53 Rev. 5 pack: 1196 requirements generated from a pinned, digest-verified OSCAL catalog. It is the framework every FPDF control maps to. Upstream ships `nist-csf` and others but not 800-53. Restoring the pack alone was not enough — see the loader repairs below. |
| `backend/apps/threats/zone_protections.py` (**not yet restored** — see below) | Zone-based countermeasure inheritance. Upstream has no `zone_protections`, no `is_inherited` field, and no component→trust-zone relation; the data model it reads no longer exists. Tracked as follow-up rather than mechanically restored. |

### Loader repairs the pack restore exposed

Dropping the pack file back in was not sufficient; the upstream pack loader
silently discarded most of its content.

1. `_load_frameworks` wrote only `description` on each requirement, so
   `name`, `requirement_type`, `status`, `priority`, `acceptance_criteria`,
   and `format_metadata` were dropped and parent links were never built. The
   enhancement hierarchy (AC-2(1) under AC-2) and the withdrawn-control
   dispositions existed in the YAML but not in the database. Fork `main`
   already had this; the reconcile lost it. Restored, including the
   second-pass parent resolution so YAML ordering stays insignificant.
2. `import_pack_from_path` decided a pack was "empty" by counting components,
   threats, countermeasures, taxonomies, and templates. A compliance pack
   ships *frameworks* and none of those, so every reimport looked empty and
   rewrote all 1196 rows. Added `existing.frameworks.exists()` to the
   has-active-items test.

The restored pack test was rewritten rather than copied: the original drove
`apps.compliance.matrix.build_matrix` and `adapters.CycloneDxAdapter`, both
retired. It now drives their upstream successors,
`threat_models.compliance_matrix.build_compliance_matrix` and
`tmbom.TmBomAdapter`, and uses TM-BOM 2.0 reference-form `satisfies` — the
shape this repository's generated artifacts already emit (verified: 1214
identifiers across `build/systems/*`, zero zero-padded or dotted forms).

## Superseded — upstream carries a successor

| Fork file(s) | Upstream successor |
| --- | --- |
| `threat_models/adapters/cyclonedx.py` and its `cyclonedx_bom_ref.py`, `cyclonedx_enum_maps.py`, `symbolic_name.py`, `tm_library.py`, fixtures and tests | `threat_models/tmbom/` — `importer/`, `exporter/`, `refs.py`, `spec_values.py`, `kept_values.py`, `passthrough.py`, `validation.py`, with its own slice tests |
| `compliance/matrix.py`, `matrix.html`, `tests/test_matrix.py`, `tests/test_section_338_cascade_fix.py`, `tests/fixtures/matrix_snapshot.json` | `threat_models/compliance_matrix.py` + `tests/test_compliance_matrix.py`. Upstream's own docstring credits the fork's PR #561. Note the shape changed: it returns one entry per mapped framework and is consumed by `report_service`, with no standalone HTTP route. |
| `threat_models/tests/test_fidelity_endpoint.py` | `tmbom/coverage.py` with `FIELD_HOMES`, which fails on any snapshot field that has no documented home |
| `threat_models/tests/test_write_capability.py` | `core/permissions.py::CanWrite`, applied as a `permission_class` across `threat_models/views.py` and `threats/views.py` rather than serialized as a `can_write` field |
| `threats/tests/test_countermeasure_action_scoping.py` | Upstream scopes countermeasure actions through `CanWrite` + the native target model |
| `threats/scoring/tm_library.py` | `threats/scoring/` registry with `manual.py`, `owasp_risk_rating.py`, `qualitative_matrix.py` |

## Open regressions — tracked, not restored

| Item | Reason it is not a mechanical restore |
| --- | --- |
| `threats/zone_protections.py` + the two `ThreatModelViewSet` actions that call it | Reads `component_threat__component__trust_zone` and writes `is_inherited` / `inherited_from_component_name` / `inherited_from_zone_name`. None of those exist upstream: threats target components through `InstanceThreatTarget`, zones hang off blueprints, and there is no inheritance field. Needs a port onto the native model, not a file copy. |
| `threats/services.py::transition_countermeasure` + `ALLOWED_STATUS_TRANSITIONS` and `test_countermeasure_transitions.py` | Upstream keeps the same eight `InstanceCountermeasure.Status` values but gates only `platform` (via `check_platform_status`). The fork's full transition matrix, owner/evidence/waiver preconditions, and `CountermeasureComment` history entry have no upstream equivalent. The model pieces it needs (`CountermeasureComment.change_summary`, `countermeasure.tests` → `verification_test`) do still exist, so this is a portable feature — just not a blind restore. |
| `systems/management/commands/cleanup_orphaned_components.py`, `trust_zone_owners.py` | Operational commands written against the pre-blueprint component/zone ownership shape. |
| Fork-only docs and frontend (`docs/concepts/zone-protections.md`, `docs/planning/precogly-roadmap.md`, `frontend/src/features/compliance/*`, the zone-protection and taxonomy dialogs, `Project-TM-Library` fixtures) | Follow whichever backend decision is made above. |

## Separate defect found while testing the restore

`threat_models.0010` adds `serial_number` as a unique `UUIDField` with
`default=uuid.uuid4`. Django evaluates a callable default **once** per
`AddField` and writes that single value to every existing row, so the unique
index build fails on any database holding more than one threat model:

```
UniqueViolation: could not create unique index
  "threat_models_threatmodel_serial_number_key"
DETAIL: Key (serial_number)=(144163dd-…) is duplicated.
```

This is an upstream migration, present in `upstream/main`, and it is a second
legacy-upgrade blocker of exactly the same class as issue #44. The local
database escaped it only because it was migrated while empty and the threat
models were imported afterwards. Repaired here: add the column nullable, fill
it per row in a `RunPython` step, then apply uniqueness.

## Verification

Run against the live dev container on the restore branch.

| Check | Result |
| --- | --- |
| `pytest` (whole backend suite) | **672 passed**, 49 subtests, 224.52s |
| `pytest apps/packs apps/core/tests/test_schema_drift.py apps/threat_models/tests/test_legacy_blueprint_upgrade.py` | **56 passed** |
| `manage.py makemigrations --check --dry-run` | No changes detected |
| `manage.py migrate --check` | clean |
| `manage.py check_schema_drift --json` | `{"finding_count": 0, "findings": [], "ok": true}` |
| `ruff check` on every touched file | All checks passed |
| `ruff format --check` on every touched file | 7 files already formatted |
| `uv run pip-audit` | No known vulnerabilities found |

This change was AI-assisted and requires human review before merge. In
particular a reviewer should confirm the supersede verdicts above, since
accepting them is accepting the permanent loss of those fork files.
