# Precogly Roadmap: SSPP-Driven Feature Plan & Maintainability Assessment

_Draft, 2026-09-15. Source: open issues in [GSA-TTS/TTSE-petrified-forest-sspp](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp) that request Precogly changes: #227, #226, #96, #95, #82, #81, #31, #28._

This fork (`JJediny/precogly`) is a downstream consumer of `precogly/precogly`, used as the threat-modeling backend for the SSPP pipeline. `main` was just reconciled with `upstream/main` (merge `453f931`, 79 commits, through the `v0.4.0` release) and `feat/cloudgov-keycloak-sso` / `feat/compliance-matrix-view` were rebased/fast-forwarded onto it and pushed. This document plans the SSPP-driven feature work on top of that clean base and assesses whether to build features in the fork or upstream them.

## 1. Issue Review Summary

| Issue | Title | Ask | Current state in Precogly |
|---|---|---|---|
| [#31](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/31) | Bulk-import enhancements for oscal-vault CDX | Consume `satisfies[]` on CDX controls → `InstanceCountermeasureStandard`; map `vault:origination`/`vault:providing-system` → `is_inherited`/`inherited_from_component_name`; evidence URL from `externalReferences` | **Mostly implemented already.** `cyclonedx.py` adapter reads `satisfies` (line ~852), `vault:origination`/`nist:control-id`/`crm:control-id` (line ~1270), sets `is_inherited`/`inherited_from_component_name` (line ~1284). Verify evidence-URL mapping and whether `StandardRequirement` FK-miss fallback (store `section_code`/`framework_name` even when unresolved) is handled. |
| [#82](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/82) | U1–U6 data model improvements for POA&M/provenance | Add `poam_id`, `scheduled_completion`, `days_overdue` property, `source` field | **Not implemented.** `InstanceCountermeasure` (`backend/apps/threats/models.py`) has `due_date`, `external_ticket_url`, `format_metadata` but no `poam_id` column, no `scheduled_completion`, no `days_overdue` property, no `source` field. |
| [#81](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/81) | POA&M = InstanceCountermeasure with due_date, not a new model | Clarifies #82; also asks SSPP-side `bulk_import_to_precogly.py`/`generate_poam_augment.py` changes (out of Precogly's scope) | Confirms #82's approach is correct; the Precogly-side ask is the same as #82 U1/U2. |
| [#96](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/96) | Guest-mode guided walkthrough (FIPS 199 → baseline arch → control baseline) | New 3-step wizard producing a downloadable CDX, no login | **Partially implemented.** `frontend/src/features/guest-editor/` and `/guest` route already exist (DFD editor + threat analysis, no auth). The FIPS 199 categorization step and baseline-architecture-pack-selection step are new. |
| [#95](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/95) | SVG/React icons for library-pack components | `icons.yaml` per pack, SVG bundling, React Flow icon rendering, `crm:icon` CDX property | **Superseded/partially done.** Upstream merged `ComponentLibrary.icon_svg` (migration `0006_componentlibrary_icon_svg.py`) with a stored-XSS fix (`#516`) that renders icons via `<img>` base64 data URI. The pack-level `icons.yaml` + `crm:icon` CDX property + `make pack-install-<pack>` SVG copy step are still missing. |
| [#227](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/227) | Nested projects / hierarchical sub-diagrams | New component type linking to a child threat model; breadcrumb drill-down; boundary port mapping; rolled-up threat metrics | **Not implemented for cross-threat-model nesting.** `OrgsystemComponent.parent` already supports a 3-level *process* hierarchy within one diagram (`backend/apps/systems/models.py:252`), and `ThreatModelRelationship` links two threat models, but there is no "nested project" component type, no cross-TM breadcrumb navigation, no boundary-port mapping, no metric roll-up. This is the largest ask in the batch. |
| [#226](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/226) | Platform right-sizing pitch (cloud.gov / FCS / sandbox) | Not a Precogly code change — a methodology/process proposal for choosing platform tier per workload, using SSPP as the evidence layer | **Out of scope for Precogly code.** No action item translates to a Precogly PR; it's a GSA-internal architecture decision framework that *consumes* SSPP+Precogly data. Track as informational only. |
| [#28](https://github.com/GSA-TTS/TTSE-petrified-forest-sspp/issues/28) | Bulk-import 25 vault systems + seed NIST 800-53r5 pack | Operational backlog (run import script, fix CF pack bundling) | **Operational, not a code feature.** The blocker is that `libraries/packs/` isn't bundled at `cf push` time — confirmed by repo memory notes; already tracked as a deploy/ops issue, not a code change. |

## 2. Implementation Plan

Ordered by dependency and risk, not issue number. Each phase assumes the previous phase's branch has merged to `main` first — this backlog touches shared model files (`backend/apps/threats/models.py`, `cyclonedx.py`) repeatedly, so serializing avoids compounding merge conflicts.

### Phase 1 — POA&M data model fields (issues #82, #81)
**Branch:** `feat/poam-fields`. **Size:** small, additive migration.
- Add to `InstanceCountermeasure` (`backend/apps/threats/models.py`): `poam_id` (indexed `CharField`), `scheduled_completion` (`DateField`), `days_overdue` (computed `@property`, not a DB column). Decide on `source` field (enum: `manual`, `vault-import`, `pentest`) — needs a short design note since it overlaps conceptually with `PentestFinding`; recommend a `CharField` with choices rather than a new model, per the issue's own recommendation.
- Migration + `InstanceCountermeasureSerializer` field additions (`backend/apps/threats/serializers.py`).
- Add `?has_poam=true` / `?overdue=true` filter params to the relevant list view.
- Update `cyclonedx.py` `_import_control` to populate `poam_id`/`scheduled_completion` from `poam:*` CDX properties (mirrors what `bulk_import_to_precogly.py` in the SSPP repo already assumes).
- Tests: extend `backend/apps/threats/tests/` (or add one) for the new property and filter; extend `backend/apps/compliance/tests/test_matrix.py` since `matrix.py` already reads `poam.get("poam_id", ...)` from `format_metadata` — once the column exists, `matrix.py` should read the column instead and this is a one-line change plus a test update.
- **Risk:** low. No breaking changes to existing `format_metadata["poam"]` consumers if the column is populated *alongside* the existing JSON key during a transition period.

### Phase 2 — CDX import completeness audit (issue #31 remainder)
**Branch:** `feat/cdx-import-audit`. **Size:** small, mostly test-writing.
- Most of #31 is already implemented (`satisfies[]`, `vault:origination`, `nist:control-id`). Write characterization tests in `backend/apps/threat_models/tests/` against a CDX fixture with `satisfies[]` present but the referenced `StandardRequirement` missing, to confirm the fallback (`section_code`/`framework_name` stored even when FK unresolved) actually works — the issue calls this out as a requirement, not yet confirmed by a test.
- Confirm evidence-URL mapping from CDX `externalReferences` → `InstanceCountermeasure.evidence_url` exists; add if missing.
- **Risk:** very low — this phase is verification, not new behavior.

### Phase 3 — Pack icon manifest (issue #95, scoped down)
**Branch:** `feat/pack-icon-manifest`. **Size:** medium.
- Upstream already solved *component-instance* icon storage/rendering safely (`ComponentLibrary.icon_svg`, base64 `<img>` rendering, XSS-fixed in `#516`). Do **not** reintroduce `dangerouslySetInnerHTML` — reuse the existing safe pattern.
- Remaining scope: a pack-level `icons.yaml` (`libraries/packs/<pack>/icons.yaml`) mapping component-name → icon key, consumed by the pack install/seed pipeline (`backend/apps/packs/services.py`) to populate `ComponentLibrary.icon_svg` at pack-install time instead of per-component manual upload.
- Add `crm:icon` CDX property passthrough in `cyclonedx.py` import as an interim signal when a pack isn't installed locally.
- **Risk:** medium — touches the pack install pipeline; needs a security review pass on any new SVG ingestion path (validate/sanitize SVG content before storing in `icon_svg`, same as the fix in `#516`).

### Phase 4 — Guest-mode FIPS 199 + baseline architecture wizard (issue #96)
**Branch:** `feat/guest-onboarding-wizard`. **Size:** large, frontend-heavy.
- Extends the existing `/guest` route and `frontend/src/features/guest-editor/`.
- Step 1 (FIPS 199): new form component computing high-water-mark categorization client-side, writing `fips199:*` properties into the in-memory CDX draft — no backend change needed since guest mode already works off exported CDX.
- Step 2 (baseline pack selection): reuse `frontend/src/features/dfd-editor/api/component-library.ts` to pre-populate canvas nodes from a selected pack's components; needs a public (unauthenticated) read endpoint for pack component lists if one doesn't already exist for guest mode — check `frontend/src/features/libraries/api/libraries.ts` auth requirements first.
- Step 3: existing guest DFD editor + export.
- **Risk:** medium — new unauthenticated read surface must be scoped carefully (read-only, no tenant data) to avoid the pattern that caused the XSS fix in `#516` and the `ComponentLibraryViewSet` read-only restriction; any new guest-facing endpoint should default to read-only and explicitly exclude tenant-scoped data.

### Phase 5 — Nested projects / hierarchical decomposition (issue #227)
**Branch:** `feat/nested-projects` (expect multiple sub-branches). **Size:** large, multi-milestone; propose as its own EPIC rather than one PR.
- **Data model:** add a "nested project" component subtype or a `linked_threat_model` FK on `OrgsystemComponent`/a new `NestedProjectComponent` proxy, distinct from the existing intra-diagram `parent` process hierarchy (`backend/apps/systems/models.py:252`) and from `ThreatModelRelationship` (which links TMs but has no diagram-canvas semantics).
- **Boundary port mapping:** external flows into the nested component need a mapping table to entry/exit points on the child diagram — new model, e.g. `NestedProjectBoundaryPort`.
- **Frontend:** breadcrumb navigation component (partial precedent exists: `ComponentView.tsx` already has ancestry-path breadcrumbs for process nodes, `hierarchy-utils.ts`) — extend that pattern across threat-model boundaries rather than building parallel breadcrumb logic.
- **Metric roll-up:** aggregate threat counts/completion status from child TM up to parent node; likely a computed serializer field with caching, given `ThreatModel` completion status is already computed elsewhere (`concepts/completion-status.md`).
- **Risk:** high — this changes core diagram semantics and cross-TM permission boundaries (a nested component may reference a TM the current user can't see). Needs an explicit ADR before implementation given the scope; do not start coding without a design doc reviewed by a Precogly maintainer, since this is the kind of "single wrong decision causes downstream effects" case called out in `CONTRIBUTING.md`.

### Not code work
- **#226** (platform right-sizing): no Precogly PR. Track as a cross-repo methodology doc in the SSPP repo; Precogly's role is limited to being a data source (via the compliance-matrix endpoint from `feat/compliance-matrix-view`).
- **#28** (bulk import + pack seeding): operational task against the live cloud.gov deployment (fix `cf push` to bundle `libraries/packs/`, then run the import script). Track in repo memory / ops runbook, not as a feature branch.

## 3. Long-Term Maintainability Assessment

**Upstream velocity is high and the fork is falling behind fast.** `upstream/main` had 336 commits in the last 60 days and was 79 commits ahead of this fork before today's merge. At that pace, a fork left unsynced for a month accumulates enough drift that every future merge risks conflicts like the two hit in this sync (`cyclonedx.py`, `package.json`) — both in files this fork also modifies for its own features (compliance matrix, CDX import). **Recommendation: sync `main` from upstream at least every 1–2 weeks**, not opportunistically, to keep conflict surface small.

**Bus factor / contributor concentration.** Two contributors (Vikram/Vikramaditya Narayan) account for the large majority of the last 90 days' commits, with `AlvinKuruvilla`, `sidd190`, and `navesecurity` as secondary contributors, several of them clearly focused on security fixes (self-escalation vulnerability, XSS in icon rendering, org-scoping bugs). This is a healthy sign for review quality (security issues are being caught and fixed) but a risk if the primary maintainer's velocity changes — the fork's continued viability depends on upstream staying active.

**CI/CD posture.** Upstream has a real quality gate: `ci.yml` runs lint (pre-commit, diff-scoped), backend pytest via `docker compose`, and a separate MCP-package job; `security.yml` runs secret scanning (gitleaks) as a distinct gate from correctness CI. This fork's own feature branches (`feat/compliance-matrix-view`) have tests that **cannot run in this workstation's environment** (no local Postgres, rootless podman broken) — per repo memory, `test_matrix.py` was never actually executed locally and relies entirely on upstream CI to validate. This is a maintainability risk specific to this environment, not to the project.

**Fork-specific technical debt.**
- `podman-compose.yml`/local dev setup requires manual bind-mount workarounds because the local container image predates several now-required dependencies (`django-oauth-toolkit`, `mozilla-django-oidc`, `django-csp`, `whitenoise`, `PyJWT[crypto]`) — this is drift between the fork's Docker image and its own `pyproject.toml`, not an upstream problem, and should be fixed by rebuilding the base image rather than perpetuating the bind-mount workaround.
- The cloud.gov/Keycloak SSO branch and the compliance-matrix branch are fork-only features with no upstream PR yet. As shown by this sync, they are cheap to carry today (both were trivial fast-forwards/rebases) specifically *because* they were kept small and touched few files. Larger fork-only features (e.g. Phase 5 nested projects) will not stay this cheap — the risk compounds with feature size, not just time.

**Security posture of planned work.** Two of the planned phases touch areas upstream has already had to patch for security bugs: icon rendering (stored XSS, `#516`) and any new unauthenticated/guest-facing endpoint (self-escalation vulnerability precedent, `#066dfb6`). Phase 3 and Phase 4 above call out reusing the already-fixed-safe patterns explicitly to avoid regressing those fixes.

## 4. Upstream Contribution Assessment

| Planned work | Contribute upstream? | Rationale |
|---|---|---|
| Phase 1 (POA&M fields) | **Yes — upstream first.** | Issue #82 explicitly frames this as an "Upstream Precogly model suggestions" ask. It's a small, additive, non-breaking schema change with clear value to any Precogly user doing compliance tracking, not just this SSPP use case. Low conflict risk, high reuse value. |
| Phase 2 (import audit) | **Yes, if gaps found.** | If the fallback-storage test in Phase 2 reveals an actual bug (not just missing test coverage), fix and PR it upstream — issue #31 originated as an upstream-facing request and the submitter (per the issue) already offered to open a PR. Coordinate to avoid duplicate work. |
| Phase 3 (pack icon manifest) | **Partially — core icon safety already upstreamed by others; the pack-manifest layer is more fork/SSPP-specific.** | The general `icon_svg` + safe-rendering mechanism is already upstream. A `libraries/packs/<pack>/icons.yaml` convention is closer to this fork's specific pack pipeline (`libraries/packs/`) and the SSPP repo's `data/packs/`. Propose upstream only if the pack-install flow (`backend/apps/packs/services.py`) is itself upstream code shared by all Precogly users — confirm this before committing to an upstream PR. |
| Phase 4 (guest wizard) | **Yes, with a design review first.** | Guest mode already exists upstream (`/guest` route, `GuestOnlyNotice`), so this extends an existing upstream feature rather than forking it. Any new unauthenticated endpoint needs upstream maintainer sign-off given the project's security-conscious CI/review culture (`CONTRIBUTING.md`'s "Owl's Orders": human review non-negotiable, screenshots required for UI PRs). |
| Phase 5 (nested projects) | **No — start with an upstream design discussion (ADR/RFC issue), not a fork branch.** | This is the highest-risk, highest-scope item (new diagram semantics, cross-TM permission model). Given upstream's commit velocity and active maintainership, building this in isolation in the fork risks either (a) permanent unmergeable drift, or (b) duplicating work upstream does independently. Open a design-discussion issue against `precogly/precogly` first (issue #227 already exists as the tracking issue in the SSPP repo — cross-link or move the design conversation to the Precogly repo where the maintainers can weigh in before code is written). |
| #226, #28 | **N/A.** | Not Precogly code changes; no upstream PR applicable. |

### Overall recommendation
Given upstream's activity level, this fork's long-term health depends on minimizing fork-only surface area. Concretely:
1. Keep the sync cadence tight (biweekly) — already recorded in repo memory as a process to repeat.
2. Land Phases 1–2 as upstream PRs directly rather than fork-only commits; they were explicitly requested by the issue author as upstream suggestions.
3. Treat Phase 5 as an upstream RFC, not a fork feature branch, given its size and the project's active, review-heavy maintainer culture.
4. Reserve fork-only branches (`feat/cloudgov-keycloak-sso` pattern) for genuinely deployment-specific concerns (SSO provider choice, cloud.gov manifest) that have no generic upstream value — that is the correct use of a fork, and this sync confirms it stays cheap to maintain when scoped that way.
