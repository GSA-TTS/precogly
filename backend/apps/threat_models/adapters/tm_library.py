"""TM-Library format adapter — import and export."""

import logging

from django.db import transaction
from rest_framework.exceptions import ValidationError

from .base import BaseAdapter
from .symbolic_name import SymbolicNameResolver

logger = logging.getLogger(__name__)

# --- Enum mappings ---

BUSINESS_CRITICALITY_MAP = {
    "minimal": "low",
    "low": "low",
    "moderate": "medium",
    "high": "high",
    "maximal": "critical",
}
BUSINESS_CRITICALITY_REVERSE = {
    "low": "low",
    "medium": "moderate",
    "high": "high",
    "critical": "maximal",
}

ACTOR_TYPE_TO_CATEGORY = {
    "user": "external_human_actor",
    "power_user": "external_human_actor",
    "administrator": "external_human_actor",
    "engineer": "external_human_actor",
    "third_party": "external_human_actor",
    "customer": "external_human_actor",
    "system": "external_system_actor",
    "api": "external_system_actor",
    "legacy": "external_system_actor",
    "partner": "external_system_actor",
    "saas": "external_system_actor",
}
CATEGORY_TO_ACTOR_TYPE = {
    "external_human_actor": "user",
    "external_system_actor": "system",
}

CONTROL_STATUS_MAP = {
    "active": "verified",
    "assumed": "platform",
    "suggested": "planned",
    "under_review": "planned",
    "approved": "planned",
    "scheduled": "planned",
    "retired": "waived",
    "wont_do": "waived",
    "unknown": "gap",
}
CONTROL_STATUS_REVERSE = {
    "verified": "active",
    "platform": "assumed",
    "planned": "suggested",
    "waived": "retired",
    "gap": "unknown",
}

CONTROL_PRIORITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# TM-Library JSON enum → DB slug (NIST SP 800-30r1 category names)
SOURCE_SLUG_MAP = {
    "adversary": "adversarial",
    "human_error": "accidental",
    "failure": "structural",
    "events_beyond_org_control": "environmental",
}
SOURCE_SLUG_REVERSE = {v: k for k, v in SOURCE_SLUG_MAP.items()}


def _resolve_flow_endpoint(resolver, endpoint):
    """Resolve a data flow source/destination to an OrgsystemComponent.

    Supports both {type, name} and {type, object} properties.
    """
    entity_type = endpoint.get("type", "")
    symbolic_name = endpoint.get("name") or endpoint.get("object", "")

    type_mapping = {
        "actor": "actor",
        "component": "component",
        "data_store": "data_store",
        "datastore": "data_store",
    }
    resolved_type = type_mapping.get(entity_type, entity_type)
    return resolver.resolve(resolved_type, symbolic_name)


class TmLibraryAdapter(BaseAdapter):
    """Import/export for OWASP TM-Library JSON format."""

    def validate(self, json_data):
        """Validate TM-Library JSON structure before import.

        Structural issues (wrong types, missing required fields) raise
        ValidationError. Cross-reference mismatches are collected as
        warnings and returned — the import handles missing refs gracefully.
        """
        errors = []
        warnings = []

        # --- Top-level structure ---
        if not isinstance(json_data, dict):
            raise ValidationError({"detail": "Input must be a JSON object."})
        if "scope" not in json_data:
            raise ValidationError({"detail": "Missing required 'scope' field."})
        scope = json_data["scope"]
        if not isinstance(scope, dict) or "title" not in scope:
            raise ValidationError({"detail": "scope.title is required."})
        if not scope["title"].strip():
            errors.append("scope.title must not be empty.")

        # --- Collect all symbolic names for cross-reference validation ---
        duplicates = []  # (entity_type, symbolic_name)

        entity_lists = {
            "trust_zones": json_data.get("trust_zones", []),
            "actors": json_data.get("actors", []),
            "components": json_data.get("components", []),
            "data_stores": json_data.get("data_stores", []),
            "data_sets": json_data.get("data_sets", []),
            "data_flows": json_data.get("data_flows", []),
            "threats": json_data.get("threats", []),
            "controls": json_data.get("controls", []),
            "risks": json_data.get("risks", []),
        }

        # Validate each entity list is actually a list
        for list_name, entity_list in entity_lists.items():
            if not isinstance(entity_list, list):
                errors.append(
                    f"'{list_name}' must be an array, got {type(entity_list).__name__}."
                )

        if errors:
            raise ValidationError({"detail": errors})

        # --- Per-entity validation (structural) ---

        for entity_type, entity_list in entity_lists.items():
            seen_in_type = set()
            for idx, item in enumerate(entity_list):
                if not isinstance(item, dict):
                    errors.append(f"{entity_type}[{idx}]: must be an object.")
                    continue

                sym = item.get("symbolic_name")
                if not sym:
                    errors.append(
                        f"{entity_type}[{idx}]: missing 'symbolic_name' "
                        f"(title: '{item.get('title', '?')}')."
                    )
                    continue

                if not isinstance(sym, str):
                    errors.append(
                        f"{entity_type}[{idx}]: 'symbolic_name' must be a string."
                    )
                    continue

                # Duplicate within same entity type
                if sym in seen_in_type:
                    duplicates.append((entity_type, sym))
                seen_in_type.add(sym)

        if duplicates:
            for entity_type, sym in duplicates:
                errors.append(f"Duplicate symbolic_name '{sym}' in {entity_type}.")

        # Data flows → source/destination must be objects
        for idx, df in enumerate(entity_lists["data_flows"]):
            if not isinstance(df, dict):
                continue
            for endpoint_key in ("source", "destination"):
                endpoint = df.get(endpoint_key, {})
                if endpoint and not isinstance(endpoint, dict):
                    errors.append(
                        f"data_flows[{idx}] '{df.get('symbolic_name', '?')}': "
                        f"{endpoint_key} must be an object."
                    )

        # Assumptions must be objects with description
        for idx, assumption in enumerate(json_data.get("assumptions", [])):
            if not isinstance(assumption, dict):
                errors.append(f"assumptions[{idx}]: must be an object.")
            elif not assumption.get("description", "").strip():
                warnings.append(f"assumptions[{idx}]: empty description.")

        # Trust boundaries must be objects
        for idx, tb in enumerate(json_data.get("trust_boundaries", [])):
            if not isinstance(tb, dict):
                errors.append(f"trust_boundaries[{idx}]: must be an object.")

        if errors:
            raise ValidationError({"detail": errors})

        # --- Cross-reference validation (warnings only) ---

        resolvable_names = set()
        for entity_type in (
            "trust_zones",
            "actors",
            "components",
            "data_stores",
            "data_sets",
        ):
            for item in entity_lists[entity_type]:
                if isinstance(item, dict) and item.get("symbolic_name"):
                    resolvable_names.add(item["symbolic_name"])

        trust_zone_names = {
            item.get("symbolic_name")
            for item in entity_lists["trust_zones"]
            if isinstance(item, dict) and item.get("symbolic_name")
        }
        component_names = {
            item.get("symbolic_name")
            for item in entity_lists["components"]
            if isinstance(item, dict) and item.get("symbolic_name")
        }
        threat_names = {
            item.get("symbolic_name")
            for item in entity_lists["threats"]
            if isinstance(item, dict) and item.get("symbolic_name")
        }
        data_store_names = {
            item.get("symbolic_name")
            for item in entity_lists["data_stores"]
            if isinstance(item, dict) and item.get("symbolic_name")
        }

        # Trust boundaries → trust zone references
        for idx, tb in enumerate(json_data.get("trust_boundaries", [])):
            if not isinstance(tb, dict):
                continue
            for side in ("trust_zone_a", "trust_zone_b"):
                ref = tb.get(side)
                if ref and ref not in trust_zone_names:
                    warnings.append(
                        f"trust_boundaries[{idx}].{side}: "
                        f"'{ref}' not found in trust_zones."
                    )

        # Components → trust_zone and parent_component references
        for idx, comp in enumerate(entity_lists["components"]):
            if not isinstance(comp, dict):
                continue
            tz_ref = comp.get("trust_zone")
            if tz_ref and tz_ref not in trust_zone_names:
                warnings.append(
                    f"components[{idx}] '{comp.get('symbolic_name', '?')}': "
                    f"trust_zone '{tz_ref}' not found."
                )
            parent_ref = comp.get("parent_component")
            if parent_ref and parent_ref not in component_names:
                warnings.append(
                    f"components[{idx}] '{comp.get('symbolic_name', '?')}': "
                    f"parent_component '{parent_ref}' not found."
                )

        # Data flows → source/destination references
        for idx, df in enumerate(entity_lists["data_flows"]):
            if not isinstance(df, dict):
                continue
            for endpoint_key in ("source", "destination"):
                endpoint = df.get(endpoint_key, {})
                if not isinstance(endpoint, dict):
                    continue
                ref = endpoint.get("name") or endpoint.get("object")
                if ref and ref not in resolvable_names:
                    warnings.append(
                        f"data_flows[{idx}] '{df.get('symbolic_name', '?')}': "
                        f"{endpoint_key} '{ref}' not found in "
                        f"actors/components/data_stores."
                    )

        # Threats → components_affected references
        for idx, threat in enumerate(entity_lists["threats"]):
            if not isinstance(threat, dict):
                continue
            for comp_ref in threat.get("components_affected", []):
                if comp_ref not in resolvable_names:
                    warnings.append(
                        f"threats[{idx}] '{threat.get('symbolic_name', '?')}': "
                        f"components_affected '{comp_ref}' not found."
                    )

        # Controls → threat references
        for idx, ctrl in enumerate(entity_lists["controls"]):
            if not isinstance(ctrl, dict):
                continue
            for threat_ref in ctrl.get("threats", []):
                if threat_ref not in threat_names:
                    warnings.append(
                        f"controls[{idx}] '{ctrl.get('symbolic_name', '?')}': "
                        f"threat '{threat_ref}' not found in threats."
                    )

        # Data set placements → data_store references
        for idx, ds in enumerate(entity_lists["data_sets"]):
            if not isinstance(ds, dict):
                continue
            for placement in ds.get("placements", []):
                if not isinstance(placement, dict):
                    continue
                store_ref = placement.get("data_store")
                if store_ref and store_ref not in data_store_names:
                    warnings.append(
                        f"data_sets[{idx}] '{ds.get('symbolic_name', '?')}': "
                        f"placement data_store '{store_ref}' not found."
                    )

        # Threats → threat_persona cross-reference check
        persona_names = {
            item.get("symbolic_name")
            for item in json_data.get("threat_personas", [])
            if isinstance(item, dict) and item.get("symbolic_name")
        }
        for idx, threat in enumerate(entity_lists["threats"]):
            if not isinstance(threat, dict):
                continue
            persona_ref = threat.get("threat_persona")
            if persona_ref and persona_ref not in persona_names:
                warnings.append(
                    f"threats[{idx}] '{threat.get('symbolic_name', '?')}': "
                    f"threat_persona '{persona_ref}' not found in threat_personas."
                )

        return warnings

    @staticmethod
    def _apply_instance_detail(threat_instance, detail, persona_map):
        """Apply per-instance fields from an instance_details entry to a threat instance."""
        from apps.threats.models import ThreatPersonaLink

        update_fields = []

        scoring_meta = detail.get("severity_scoring_metadata")
        if scoring_meta:
            threat_instance.severity_scoring_metadata = scoring_meta
            update_fields.append("severity_scoring_metadata")

        inherent_severity = detail.get("inherent_severity")
        if inherent_severity:
            threat_instance.inherent_severity = inherent_severity
            update_fields.append("inherent_severity")

        residual_severity = detail.get("residual_severity")
        if residual_severity:
            threat_instance.residual_severity = residual_severity
            update_fields.append("residual_severity")

        impact_description = detail.get("event")
        if impact_description:
            threat_instance.impact_description = impact_description
            update_fields.append("impact_description")

        # New format: triage_status / decision_rationale
        triage_status = detail.get("triage_status")
        if triage_status:
            threat_instance.triage_status = triage_status
            update_fields.append("triage_status")
            decision_rationale = detail.get("decision_rationale", "")
            if decision_rationale:
                threat_instance.decision_rationale = decision_rationale
                update_fields.append("decision_rationale")

        if update_fields:
            threat_instance.save(update_fields=update_fields)

        # Restore per-instance persona link (replaces any top-level default)
        persona_ref = detail.get("threat_persona")
        if persona_ref and persona_ref in persona_map:
            persona = persona_map[persona_ref]
            if hasattr(threat_instance, "component_id"):
                # Remove any existing links from top-level default
                ThreatPersonaLink.objects.filter(
                    component_threat=threat_instance,
                ).exclude(persona=persona).delete()
                ThreatPersonaLink.objects.get_or_create(
                    persona=persona,
                    component_threat=threat_instance,
                )
            elif hasattr(threat_instance, "data_flow_id"):
                ThreatPersonaLink.objects.filter(
                    flow_threat=threat_instance,
                ).exclude(persona=persona).delete()
                ThreatPersonaLink.objects.get_or_create(
                    persona=persona,
                    flow_threat=threat_instance,
                )

    def import_data(self, json_data, organization, created_by):
        validation_warnings = self.validate(json_data) or []

        from apps.organizations.models import TeamMembership
        from apps.systems.models import (
            ComponentDataAsset,
            DataAsset,
            DataFlow,
            OrgsystemComponent,
            TrustBoundary,
            TrustZone,
        )
        from apps.threats.models import (
            ComponentInstanceThreat,
            CountermeasureLibrary,
            CountermeasureThreatLink,
            DataFlowInstanceThreat,
            InstanceCountermeasure,
            Risk,
            RiskThreat,
            ThreatLibrary,
            ThreatPersona,
            ThreatPersonaLink,
            ThreatSource,
            ThreatSourceLink,
            build_taxonomy_snapshot,
        )
        from apps.threats.services import calculate_inherent_score, recalculate_risk

        from ..models import ThreatModel

        resolver = SymbolicNameResolver()
        scope = json_data["scope"]
        summary = {
            "trust_zones": 0,
            "trust_boundaries": 0,
            "actors": 0,
            "components": 0,
            "data_stores": 0,
            "data_assets": 0,
            "data_flows": 0,
            "threat_personas": 0,
            "threats": 0,
            "controls": 0,
            "risks": 0,
            "warnings": list(validation_warnings),
        }

        with transaction.atomic():
            # 1. ThreatModel
            criticality = BUSINESS_CRITICALITY_MAP.get(
                scope.get("business_criticality", "moderate"), "medium"
            )
            threat_model = ThreatModel.objects.create(
                organization=organization,
                created_by=created_by,
                name=scope["title"],
                description=scope.get("description", json_data.get("description", "")),
                risk_scoring_method="tm_library",
                criticality=criticality,
                format_metadata={
                    "tm_library": {
                        "version": json_data.get("version"),
                        "scope": scope,
                        "frozen": json_data.get("frozen", False),
                        "release_docs_link": json_data.get("release_docs_link", ""),
                        "repo_link": json_data.get("repo_link", ""),
                    }
                },
            )

            # Auto-assign team
            user_team_memberships = TeamMembership.objects.filter(
                user=created_by,
                team__organization=organization,
            ).select_related("team")
            if user_team_memberships.count() == 1:
                threat_model.owning_team = user_team_memberships.first().team
                threat_model.save(update_fields=["owning_team"])

            # 2. Trust Zones
            for tz_data in json_data.get("trust_zones", []):
                tz = TrustZone.objects.create(
                    organization=organization,
                    name=tz_data.get("title", tz_data["symbolic_name"]),
                    description=tz_data.get("description", ""),
                    format_metadata={
                        "tm_library": {
                            "symbolic_name": tz_data["symbolic_name"],
                        }
                    },
                )
                resolver.register("trust_zone", tz_data["symbolic_name"], tz)
                summary["trust_zones"] += 1

            # Store zone IDs in threat model for export retrieval
            all_zone_ids = [obj.pk for obj in resolver.get_all("trust_zone").values()]
            if all_zone_ids:
                fm = threat_model.format_metadata
                fm.setdefault("tm_library", {})["zone_ids"] = all_zone_ids
                threat_model.save(update_fields=["format_metadata"])

            # 3. Trust Boundaries
            for tb_data in json_data.get("trust_boundaries", []):
                zone_a = resolver.resolve("trust_zone", tb_data.get("trust_zone_a", ""))
                zone_b = resolver.resolve("trust_zone", tb_data.get("trust_zone_b", ""))
                if zone_a and zone_b:
                    TrustBoundary.objects.create(
                        organization=organization,
                        zone_a=zone_a,
                        zone_b=zone_b,
                        format_metadata={
                            "tm_library": {
                                "access_control_methods": tb_data.get(
                                    "access_control_methods", []
                                ),
                                "authentication_methods": tb_data.get(
                                    "authentication_methods", []
                                ),
                            }
                        },
                    )
                    summary["trust_boundaries"] += 1
                else:
                    summary["warnings"].append(
                        f"Trust boundary skipped: could not resolve zones "
                        f"'{tb_data.get('trust_zone_a')}' / '{tb_data.get('trust_zone_b')}'"
                    )

            # 4. Actors → OrgsystemComponent
            for actor_data in json_data.get("actors", []):
                actor_type = actor_data.get("type", "user")
                category = None  # Users classify post-import via UI
                trust_zone = resolver.resolve(
                    "trust_zone", actor_data.get("trust_zone", "")
                )

                comp = OrgsystemComponent.objects.create(
                    name=actor_data.get("title", actor_data["symbolic_name"]),
                    description=actor_data.get("description", ""),
                    category=category,
                    actor_type=actor_type,
                    trust_zone=trust_zone,
                    threat_model=threat_model,
                    format_metadata={
                        "tm_library": {
                            "symbolic_name": actor_data["symbolic_name"],
                            "permissions": actor_data.get("permissions", ""),
                            "original_type": actor_type,
                        }
                    },
                )
                resolver.register("actor", actor_data["symbolic_name"], comp)
                summary["actors"] += 1

            # 5. Components → OrgsystemComponent (two-pass for parent_component)
            component_entries = json_data.get("components", [])
            # First pass: create all components
            for comp_data in component_entries:
                trust_zone = resolver.resolve(
                    "trust_zone", comp_data.get("trust_zone", "")
                )
                comp = OrgsystemComponent.objects.create(
                    name=comp_data.get("title", comp_data["symbolic_name"]),
                    description=comp_data.get("description", ""),
                    category="process",
                    trust_zone=trust_zone,
                    threat_model=threat_model,
                    format_metadata={
                        "tm_library": {
                            "symbolic_name": comp_data["symbolic_name"],
                            "repo_link": comp_data.get("repo_link", ""),
                        }
                    },
                )
                resolver.register("component", comp_data["symbolic_name"], comp)
                summary["components"] += 1

            # Second pass: resolve parent_component
            for comp_data in component_entries:
                parent_name = comp_data.get("parent_component")
                if parent_name:
                    parent = resolver.resolve("component", parent_name)
                    child = resolver.resolve("component", comp_data["symbolic_name"])
                    if parent and child:
                        child.parent_component = parent
                        child.save(update_fields=["parent_component"])

            # 6. Data Stores → OrgsystemComponent
            for ds_data in json_data.get("data_stores", []):
                trust_zone = resolver.resolve(
                    "trust_zone", ds_data.get("trust_zone", "")
                )
                comp = OrgsystemComponent.objects.create(
                    name=ds_data.get("title", ds_data["symbolic_name"]),
                    description=ds_data.get("description", ""),
                    category="datastore",
                    data_store_type=ds_data.get("type", ""),
                    trust_zone=trust_zone,
                    threat_model=threat_model,
                    format_metadata={
                        "tm_library": {
                            "symbolic_name": ds_data["symbolic_name"],
                            "vendor": ds_data.get("vendor", ""),
                            "product": ds_data.get("product", ""),
                        }
                    },
                )
                resolver.register("data_store", ds_data["symbolic_name"], comp)
                summary["data_stores"] += 1

            # 7. Data Assets (data_sets) + ComponentDataAsset joins
            for da_data in json_data.get("data_sets", []):
                data_asset = DataAsset.objects.create(
                    threat_model=threat_model,
                    name=da_data.get("title", da_data["symbolic_name"]),
                    description=da_data.get("description", ""),
                    classification=",".join(da_data.get("data_sensitivity", []))
                    or "general",
                    data_sensitivity=da_data.get("data_sensitivity", []),
                    format_metadata={
                        "tm_library": {
                            "symbolic_name": da_data["symbolic_name"],
                            "record_count": da_data.get("record_count"),
                            "access_control_methods": da_data.get(
                                "access_control_methods", []
                            ),
                        }
                    },
                )
                resolver.register("data_asset", da_data["symbolic_name"], data_asset)
                summary["data_assets"] += 1

                # Create placements
                for placement in da_data.get("placements", []):
                    store_name = placement.get("data_store", "")
                    store_comp = resolver.resolve("data_store", store_name)
                    if store_comp:
                        ComponentDataAsset.objects.create(
                            component=store_comp,
                            data_asset=data_asset,
                            encrypted=placement.get("encrypted", False),
                        )

            # 8. Data Flows
            for df_data in json_data.get("data_flows", []):
                source = _resolve_flow_endpoint(resolver, df_data.get("source", {}))
                destination = _resolve_flow_endpoint(
                    resolver, df_data.get("destination", {})
                )

                if source and destination:
                    flow = DataFlow.objects.create(
                        source_component=source,
                        dest_component=destination,
                        label=df_data.get("title", df_data.get("symbolic_name", "")),
                        description=df_data.get("description", ""),
                        encrypted=df_data.get("encrypted", False),
                        has_sensitive_data=df_data.get("has_sensitive_data", False),
                        format_metadata={
                            "tm_library": {
                                "symbolic_name": df_data["symbolic_name"],
                            }
                        },
                    )
                    resolver.register("data_flow", df_data["symbolic_name"], flow)
                    summary["data_flows"] += 1
                else:
                    summary["warnings"].append(
                        f"Data flow '{df_data.get('symbolic_name')}' skipped: "
                        f"could not resolve source or destination"
                    )

            # 9. Threat Personas → create ThreatPersona records
            persona_map = {}  # symbolic_name → ThreatPersona
            for persona_data in json_data.get("threat_personas", []):
                symbolic_name = persona_data.get("symbolic_name", "")
                if not symbolic_name:
                    summary["warnings"].append(
                        "Threat persona missing symbolic_name, skipped."
                    )
                    continue

                # Extract known fields; store extras in format_metadata
                known_fields = {
                    "symbolic_name",
                    "title",
                    "description",
                    "is_person",
                    "malicious_intent",
                    "skill_level",
                    "motivation",
                    "resources",
                    "objectives",
                }
                extra_fields = {
                    k: v for k, v in persona_data.items() if k not in known_fields
                }

                persona = ThreatPersona.objects.create(
                    threat_model=threat_model,
                    symbolic_name=symbolic_name,
                    name=persona_data.get("title", symbolic_name),
                    description=persona_data.get("description", ""),
                    is_person=persona_data.get("is_person", True),
                    malicious_intent=persona_data.get("malicious_intent", True),
                    skill_level=persona_data.get("skill_level", ""),
                    motivation=persona_data.get("motivation", ""),
                    resources=persona_data.get("resources", ""),
                    objectives=persona_data.get("objectives", ""),
                    format_metadata=extra_fields,
                )
                persona_map[symbolic_name] = persona
                summary["threat_personas"] += 1

            # 10. Assumptions
            raw_assumptions = json_data.get("assumptions", [])
            if raw_assumptions:
                assumptions = []
                for idx, assumption in enumerate(raw_assumptions):
                    if not isinstance(assumption, dict):
                        summary["warnings"].append(
                            f"assumptions[{idx}]: not an object, skipped."
                        )
                        continue
                    assumptions.append(
                        {
                            "id": assumption.get("id", f"assumption-{idx}"),
                            "description": assumption.get("description", ""),
                            "validity": assumption.get("validity", "unconfirmed"),
                            "topics": assumption.get("topics", []),
                        }
                    )
                threat_model.assumptions = assumptions
                threat_model.save(update_fields=["assumptions"])

            # 11. Threats
            threat_component_map = {}  # symbolic_name → list of threat instances
            system_component = (
                None  # Lazy-created for threats without components_affected
            )
            for threat_data in json_data.get("threats", []):
                symbolic_name = threat_data["symbolic_name"]
                title = threat_data.get("title", symbolic_name)
                description = threat_data.get("description", "")

                # Skip duplicate threats (same symbolic name already imported)
                if symbolic_name in threat_component_map:
                    summary["warnings"].append(
                        f"Duplicate threat '{symbolic_name}' skipped"
                    )
                    continue

                # Create a ThreatLibrary entry for each imported threat
                slug = symbolic_name[:100]
                # Ensure slug uniqueness by appending suffix if needed
                base_slug = slug
                counter = 1
                while ThreatLibrary.objects.filter(
                    qualified_slug=f"custom/{slug}"
                ).exists():
                    slug = f"{base_slug[:95]}-{counter}"
                    counter += 1
                threat_lib = ThreatLibrary.objects.create(
                    name=title,
                    description=description,
                    slug=slug,
                )

                # Find which components this threat affects
                components_affected = threat_data.get("components_affected", [])
                if not components_affected:
                    # Default: create as component threat on the threat model
                    # (no specific component targeted)
                    components_affected = []

                # Import severity from JSON or default to medium
                inherent_severity = threat_data.get("inherent_severity", "medium")
                if inherent_severity not in ("low", "medium", "high", "critical"):
                    inherent_severity = "medium"

                severity_metadata = {
                    "rationale": "severity imported from TM-Library JSON",
                }

                # Map event → impact_description
                impact_description = threat_data.get("event", "")

                format_meta = {
                    "tm_library": {
                        "symbolic_name": symbolic_name,
                        "threat_persona": threat_data.get("threat_persona", ""),
                        "event": threat_data.get("event", ""),
                        "sources": threat_data.get("sources", []),
                        "attack_mechanisms": threat_data.get("attack_mechanisms", {}),
                        "weaknesses": threat_data.get("weaknesses", []),
                    }
                }

                # Also check for data_flows_affected
                data_flows_affected = threat_data.get("data_flows_affected", [])

                instances = []

                # Shared defaults for threat instance creation
                instance_defaults = {
                    "threat_library": threat_lib,
                    "threat_description": description,
                    "inherent_severity": inherent_severity,
                    "status": "exposed",
                    "severity_scoring_metadata": severity_metadata,
                    "format_metadata": format_meta,
                    "taxonomy_snapshot": build_taxonomy_snapshot(threat_lib),
                    "impact_description": impact_description,
                }

                # Create ComponentInstanceThreat for each component affected
                if components_affected:
                    for comp_ref in components_affected:
                        # Resolve against component types only (not trust zones)
                        comp = (
                            resolver.resolve("component", comp_ref)
                            or resolver.resolve("actor", comp_ref)
                            or resolver.resolve("data_store", comp_ref)
                        )
                        if comp:
                            instance, created = (
                                ComponentInstanceThreat.objects.get_or_create(
                                    component=comp,
                                    threat_name=title,
                                    defaults=instance_defaults,
                                )
                            )
                            if not created and not instance.threat_library:
                                instance.threat_library = threat_lib
                                instance.format_metadata = format_meta
                                instance.save(
                                    update_fields=["threat_library", "format_metadata"]
                                )
                            instances.append(("component", instance))
                            if created:
                                summary["threats"] += 1

                # Create DataFlowInstanceThreat for each flow affected
                if data_flows_affected:
                    for flow_ref in data_flows_affected:
                        flow = resolver.resolve("data_flow", flow_ref)
                        if flow:
                            instance, created = (
                                DataFlowInstanceThreat.objects.get_or_create(
                                    data_flow=flow,
                                    threat_name=title,
                                    defaults=instance_defaults,
                                )
                            )
                            if not created and not instance.threat_library:
                                instance.threat_library = threat_lib
                                instance.format_metadata = format_meta
                                instance.save(
                                    update_fields=["threat_library", "format_metadata"]
                                )
                            instances.append(("flow", instance))
                            if created:
                                summary["threats"] += 1

                # If neither components nor flows affected, create system-level
                if not components_affected and not data_flows_affected:
                    if system_component is None:
                        system_component = OrgsystemComponent.objects.create(
                            name=f"{threat_model.name} (System)",
                            category="process",
                            threat_model=threat_model,
                            format_metadata={"tm_library": {"synthetic": True}},
                        )
                    instance, created = ComponentInstanceThreat.objects.get_or_create(
                        component=system_component,
                        threat_name=title,
                        defaults=instance_defaults,
                    )
                    if not created and not instance.threat_library:
                        instance.threat_library = threat_lib
                        instance.format_metadata = format_meta
                        instance.save(
                            update_fields=["threat_library", "format_metadata"]
                        )
                    instances.append(("component", instance))
                    if created:
                        summary["threats"] += 1

                # Link personas to threat instances
                persona_ref = threat_data.get("threat_persona", "")
                if persona_ref and persona_ref in persona_map:
                    persona = persona_map[persona_ref]
                    for threat_type, threat_instance in instances:
                        if threat_type == "component":
                            ThreatPersonaLink.objects.get_or_create(
                                persona=persona,
                                component_threat=threat_instance,
                            )
                        elif threat_type == "flow":
                            ThreatPersonaLink.objects.get_or_create(
                                persona=persona,
                                flow_threat=threat_instance,
                            )
                elif persona_ref:
                    summary["warnings"].append(
                        f"Threat '{symbolic_name}': persona '{persona_ref}' "
                        f"not found in threat_personas."
                    )

                # Link sources to threat instances
                source_refs = threat_data.get("sources", [])
                for source_ref in source_refs:
                    raw_value = source_ref if isinstance(source_ref, str) else ""
                    if not raw_value:
                        continue
                    source_slug = SOURCE_SLUG_MAP.get(raw_value, raw_value)
                    try:
                        source_obj = ThreatSource.objects.get(slug=source_slug)
                    except ThreatSource.DoesNotExist:
                        summary["warnings"].append(
                            f"Threat '{symbolic_name}': source '{source_slug}' "
                            f"not found in ThreatSource table."
                        )
                        continue
                    for threat_type, threat_instance in instances:
                        if threat_type == "component":
                            ThreatSourceLink.objects.get_or_create(
                                source=source_obj,
                                component_threat=threat_instance,
                            )
                        elif threat_type == "flow":
                            ThreatSourceLink.objects.get_or_create(
                                source=source_obj,
                                flow_threat=threat_instance,
                            )

                threat_component_map[symbolic_name] = instances
                resolver.register("threat", symbolic_name, threat_lib)

            # 11. Controls → Countermeasures (duplicate per referenced threat)
            for ctrl_data in json_data.get("controls", []):
                symbolic_name = ctrl_data["symbolic_name"]
                title = ctrl_data.get("title", symbolic_name)
                description = ctrl_data.get("description", "")
                original_status = ctrl_data.get("status", "unknown")
                mapped_status = CONTROL_STATUS_MAP.get(original_status, "gap")
                priority = CONTROL_PRIORITY_MAP.get(
                    ctrl_data.get("priority", ""), "none"
                )

                # Create a CountermeasureLibrary entry
                cm_lib = CountermeasureLibrary.objects.create(
                    name=title,
                    description=description,
                    default_status=mapped_status,
                )

                referenced_threats = ctrl_data.get("threats", [])
                # Create one countermeasure instance per library item (shared across threats)
                cm_instance = None
                cm_created = False
                for threat_ref in referenced_threats:
                    instances = threat_component_map.get(threat_ref, [])
                    for threat_type, threat_instance in instances:
                        format_meta_cm = {
                            "tm_library": {
                                "symbolic_name": symbolic_name,
                                "original_status": original_status,
                            }
                        }
                        if cm_instance is None:
                            # Create one unified countermeasure instance, scoped to threat_model
                            cm_instance, cm_created = (
                                InstanceCountermeasure.objects.get_or_create(
                                    threat_model=threat_model,
                                    countermeasure_name=title,
                                    countermeasure_library=cm_lib,
                                    defaults={
                                        "countermeasure_description": description,
                                        "status": mapped_status,
                                        "priority": priority,
                                        "format_metadata": format_meta_cm,
                                    },
                                )
                            )
                            if cm_created:
                                summary["controls"] += 1

                        # Create junction link for each threat
                        if threat_type == "component":
                            CountermeasureThreatLink.objects.get_or_create(
                                countermeasure=cm_instance,
                                component_threat=threat_instance,
                            )
                        elif threat_type == "flow":
                            CountermeasureThreatLink.objects.get_or_create(
                                countermeasure=cm_instance,
                                flow_threat=threat_instance,
                            )

                resolver.register("control", symbolic_name, cm_lib)

            # 12. Risks
            for risk_data in json_data.get("risks", []):
                scoring_metadata = {
                    "likelihood": risk_data.get("likelihood", "possible"),
                    "impact": risk_data.get("impact", "moderate"),
                    "impact_description": risk_data.get("impact_description", ""),
                }

                try:
                    score, level = calculate_inherent_score(
                        "tm_library", scoring_metadata
                    )
                except Exception:
                    # Fallback: use file score if engine fails
                    score = min(100, max(0, int(risk_data.get("score", 50)) * 4))
                    level = risk_data.get("level", "medium")

                risk = Risk.objects.create(
                    threat_model=threat_model,
                    name=risk_data.get("title", risk_data.get("symbolic_name", "")),
                    description=risk_data.get("description", ""),
                    scoring_metadata=scoring_metadata,
                    inherent_score=score,
                    inherent_level=level,
                    format_metadata={
                        "tm_library": {
                            "symbolic_name": risk_data.get("symbolic_name", ""),
                            "original_score": risk_data.get("score"),
                            "original_level": risk_data.get("level"),
                        }
                    },
                )

                # Create RiskThreat rows
                for threat_ref in risk_data.get("threats", []):
                    instances = threat_component_map.get(threat_ref, [])
                    for threat_type, threat_instance in instances:
                        if threat_type == "component":
                            RiskThreat.objects.get_or_create(
                                risk=risk,
                                component_threat=threat_instance,
                            )
                        elif threat_type == "flow":
                            RiskThreat.objects.get_or_create(
                                risk=risk,
                                flow_threat=threat_instance,
                            )

                recalculate_risk(risk)
                summary["risks"] += 1

            # 14. Consume Precogly extensions (round-trip restore)
            extensions = json_data.get("extensions", {})

            # 14a. precogly.org/threat-details → restore per-instance fields
            threat_details_ext = extensions.get("precogly.org/threat-details", {})
            if threat_details_ext:
                for threat_sym, detail_data in threat_details_ext.items():
                    instances = threat_component_map.get(threat_sym, [])
                    instance_details = detail_data.get("instance_details")
                    if instance_details:
                        # Per-instance format: match by affected name
                        for detail in instance_details:
                            affected_name = detail.get("affected")
                            affected_type = detail.get("affected_type")
                            if not affected_name or not affected_type:
                                continue
                            # Resolve the symbolic name to a DB object
                            if affected_type == "component":
                                affected_obj = (
                                    resolver.resolve("component", affected_name)
                                    or resolver.resolve("actor", affected_name)
                                    or resolver.resolve("data_store", affected_name)
                                )
                                if not affected_obj:
                                    continue
                                for threat_type, threat_instance in instances:
                                    if (
                                        threat_type == "component"
                                        and threat_instance.component_id
                                        == affected_obj.pk
                                    ):
                                        self._apply_instance_detail(
                                            threat_instance, detail, persona_map
                                        )
                            elif affected_type == "flow":
                                affected_obj = resolver.resolve(
                                    "data_flow", affected_name
                                )
                                if not affected_obj:
                                    continue
                                for threat_type, threat_instance in instances:
                                    if (
                                        threat_type == "flow"
                                        and threat_instance.data_flow_id
                                        == affected_obj.pk
                                    ):
                                        self._apply_instance_detail(
                                            threat_instance, detail, persona_map
                                        )
                    else:
                        # Legacy flat format: apply to all instances
                        scoring_meta = detail_data.get("severity_scoring_metadata")
                        if not scoring_meta:
                            continue
                        for _threat_type, threat_instance in instances:
                            threat_instance.severity_scoring_metadata = scoring_meta
                            threat_instance.save(
                                update_fields=["severity_scoring_metadata"]
                            )

            # 14b. precogly.org/taxonomy-references → create ThreatLibraryTaxonomyEntry
            from apps.threats.models import (
                ExternalTaxonomy,
                TaxonomyEntry,
                ThreatLibraryTaxonomyEntry,
            )

            taxonomy_ext = extensions.get("precogly.org/taxonomy-references", {})
            if taxonomy_ext:
                for threat_sym, tax_data in taxonomy_ext.items():
                    instances = threat_component_map.get(threat_sym, [])
                    if not instances:
                        continue
                    # Get the threat_library from the first instance
                    first_instance = instances[0][1]
                    threat_lib_obj = first_instance.threat_library
                    if not threat_lib_obj:
                        continue
                    for taxonomy_slug, entries in tax_data.items():
                        # Map slug to ExternalTaxonomy
                        db_slug = taxonomy_slug.replace(
                            "_", "-"
                        )  # mitre_attack → mitre-attack
                        taxonomy = ExternalTaxonomy.objects.filter(slug=db_slug).first()
                        if not taxonomy:
                            continue
                        for entry_data in entries:
                            ext_id = entry_data.get("id", "")
                            tax_entry = TaxonomyEntry.objects.filter(
                                taxonomy=taxonomy, external_id=ext_id
                            ).first()
                            if tax_entry:
                                ThreatLibraryTaxonomyEntry.objects.get_or_create(
                                    threat_library=threat_lib_obj,
                                    taxonomy_entry=tax_entry,
                                )

            # 14c. precogly.org/compliance-mappings → restore instance standards
            from apps.compliance.models import StandardRequirement
            from apps.threats.models import InstanceCountermeasureStandard

            compliance_ext = extensions.get("precogly.org/compliance-mappings", {})
            if compliance_ext:
                # Build reverse lookup: control symbolic_name → countermeasure instances
                for ctrl_sym, mappings in compliance_ext.items():
                    for mapping in mappings:
                        req_id = mapping.get("requirement_id", "")
                        framework_name = mapping.get("framework", "")
                        sufficiency = mapping.get("sufficiency", "partial")
                        if not req_id or not framework_name:
                            continue
                        requirement = StandardRequirement.objects.filter(
                            framework__name=framework_name,
                            section_code=req_id,
                        ).first()
                        if not requirement:
                            summary["warnings"].append(
                                f"Compliance mapping: requirement '{req_id}' "
                                f"in framework '{framework_name}' not found."
                            )
                            continue
                        # Find countermeasure instances matching this control sym
                        countermeasure_instances = (
                            InstanceCountermeasure.objects.filter(
                                threat_model=threat_model,
                                format_metadata__tm_library__symbolic_name=ctrl_sym,
                            )
                        )
                        for cm in countermeasure_instances:
                            InstanceCountermeasureStandard.objects.get_or_create(
                                countermeasure=cm,
                                requirement=requirement,
                                defaults={"sufficiency": sufficiency},
                            )

            # 14d. precogly.org/pack-lineage → reconnect to library packs
            from apps.packs.models import LibraryPack
            from apps.systems.models import ComponentLibrary

            pack_lineage_ext = extensions.get("precogly.org/pack-lineage", {})
            if pack_lineage_ext:
                for lineage_type, lineage_map in pack_lineage_ext.items():
                    if lineage_type == "components":
                        for comp_sym, lineage in lineage_map.items():
                            lib_slug = lineage.get("library_slug", "")
                            pack_slug = lineage.get("pack_slug", "")
                            pack_version = lineage.get("pack_version", "")
                            if not lib_slug:
                                continue
                            # Check if the pack is installed
                            pack = LibraryPack.objects.filter(
                                slug=pack_slug, version=pack_version
                            ).first()
                            if not pack:
                                summary["warnings"].append(
                                    f"Pack lineage: pack '{pack_slug}' v{pack_version} "
                                    f"not installed, component '{comp_sym}' remains standalone."
                                )
                                continue
                            comp_lib = ComponentLibrary.objects.filter(
                                qualified_slug=lib_slug
                            ).first()
                            if not comp_lib:
                                comp_lib = ComponentLibrary.objects.filter(
                                    slug=lib_slug.split("/")[-1]
                                    if "/" in lib_slug
                                    else lib_slug,
                                    source_pack=pack,
                                ).first()
                            if comp_lib:
                                comp = resolver.resolve("component", comp_sym)
                                if comp:
                                    comp.component_library = comp_lib
                                    comp.save(update_fields=["component_library"])

        return threat_model, summary

    def export_data(self, threat_model):
        from apps.systems.models import (
            ComponentDataAsset,
            DataAsset,
            DataFlow,
            OrgsystemComponent,
            TrustBoundary,
            TrustZone,
        )
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
            Risk,
            ThreatLibraryTaxonomyEntry,
            ThreatPersona,
            ThreatPersonaLink,
            ThreatSourceLink,
        )

        result = {
            "version": "1.0",
            "scope": {},
            "trust_zones": [],
            "trust_boundaries": [],
            "actors": [],
            "components": [],
            "data_stores": [],
            "data_sets": [],
            "data_flows": [],
            "threats": [],
            "controls": [],
            "risks": [],
        }

        # Build symbolic name resolver from stored format_metadata
        resolver = SymbolicNameResolver()

        def _get_symbolic_name(obj, entity_type):
            """Get symbolic name from format_metadata or generate one."""
            fm = getattr(obj, "format_metadata", {}) or {}
            tm_lib = fm.get("tm_library", {})
            if tm_lib.get("symbolic_name"):
                return tm_lib["symbolic_name"]
            return f"{entity_type}_{obj.pk}"

        # Scope
        fm = threat_model.format_metadata or {}
        tm_lib_meta = fm.get("tm_library", {})
        stored_scope = tm_lib_meta.get("scope", {})
        result["scope"] = {
            "title": threat_model.name,
            "description": threat_model.description,
            "business_criticality": BUSINESS_CRITICALITY_REVERSE.get(
                threat_model.criticality, "moderate"
            ),
            **{
                k: v
                for k, v in stored_scope.items()
                if k not in ("title", "description", "business_criticality")
            },
        }
        if tm_lib_meta.get("version"):
            result["version"] = tm_lib_meta["version"]
        if tm_lib_meta.get("release_docs_link"):
            result["release_docs_link"] = tm_lib_meta["release_docs_link"]
        if tm_lib_meta.get("repo_link"):
            result["repo_link"] = tm_lib_meta["repo_link"]

        # Assumptions
        if threat_model.assumptions:
            result["assumptions"] = threat_model.assumptions

        # Collect all components for this threat model
        components = OrgsystemComponent.objects.filter(threat_model=threat_model)

        # Trust Zones — use stored zone IDs if available, else gather from components
        stored_zone_ids = tm_lib_meta.get("zone_ids", [])
        if stored_zone_ids:
            zone_ids = set(stored_zone_ids)
        else:
            zone_ids = set(
                components.exclude(trust_zone__isnull=True).values_list(
                    "trust_zone_id", flat=True
                )
            )
        trust_zones = TrustZone.objects.filter(id__in=zone_ids)
        for tz in trust_zones:
            sym = _get_symbolic_name(tz, "zone")
            resolver.register("trust_zone", sym, tz)
            result["trust_zones"].append(
                {
                    "symbolic_name": sym,
                    "title": tz.name,
                    "description": tz.description,
                }
            )

        # Trust Boundaries
        boundaries = TrustBoundary.objects.filter(
            zone_a__in=trust_zones
        ) | TrustBoundary.objects.filter(zone_b__in=trust_zones)
        for tb in boundaries.distinct():
            zone_a_sym = _get_symbolic_name(tb.zone_a, "zone")
            zone_b_sym = _get_symbolic_name(tb.zone_b, "zone")
            tb_fm = (tb.format_metadata or {}).get("tm_library", {})
            result["trust_boundaries"].append(
                {
                    "trust_zone_a": zone_a_sym,
                    "trust_zone_b": zone_b_sym,
                    "access_control_methods": tb_fm.get("access_control_methods", []),
                    "authentication_methods": tb_fm.get("authentication_methods", []),
                }
            )

        # Components by category (skip synthetic system component)
        for comp in components:
            comp_fm = (comp.format_metadata or {}).get("tm_library", {})
            if comp_fm.get("synthetic"):
                continue

            sym = _get_symbolic_name(comp, comp.category or "component")
            resolver.register(comp.category or "component", sym, comp)

            trust_zone_sym = ""
            if comp.trust_zone:
                trust_zone_sym = _get_symbolic_name(comp.trust_zone, "zone")

            if comp.category in ("external_human_actor", "external_system_actor") or (
                comp.category is None and comp_fm.get("original_type")
            ):
                original_type = comp_fm.get(
                    "original_type"
                ) or CATEGORY_TO_ACTOR_TYPE.get(comp.category or "", "user")
                result["actors"].append(
                    {
                        "symbolic_name": sym,
                        "title": comp.name,
                        "description": comp.description,
                        "type": original_type,
                        "permissions": comp_fm.get("permissions", ""),
                    }
                )
                # Also register as "actor" for flow resolution
                resolver.register("actor", sym, comp)
            elif comp.category == "datastore":
                result["data_stores"].append(
                    {
                        "symbolic_name": sym,
                        "title": comp.name,
                        "description": comp.description,
                        "type": comp.data_store_type or "",
                        "vendor": comp_fm.get("vendor", ""),
                        "product": comp_fm.get("product", ""),
                    }
                )
                resolver.register("data_store", sym, comp)
            else:
                entry = {
                    "symbolic_name": sym,
                    "title": comp.name,
                    "description": comp.description,
                    "trust_zone": trust_zone_sym,
                }
                if comp_fm.get("repo_link"):
                    entry["repo_link"] = comp_fm["repo_link"]
                if comp.parent_component:
                    parent_sym = _get_symbolic_name(comp.parent_component, "component")
                    entry["parent_component"] = parent_sym
                result["components"].append(entry)
                resolver.register("component", sym, comp)

        # Data Assets
        data_assets = DataAsset.objects.filter(threat_model=threat_model)
        for da in data_assets:
            da_sym = _get_symbolic_name(da, "data_asset")
            da_fm = (da.format_metadata or {}).get("tm_library", {})

            placements = []
            for cda in ComponentDataAsset.objects.filter(data_asset=da).select_related(
                "component"
            ):
                store_sym = _get_symbolic_name(cda.component, "data_store")
                placements.append(
                    {
                        "data_store": store_sym,
                        "encrypted": cda.encrypted,
                    }
                )

            result["data_sets"].append(
                {
                    "symbolic_name": da_sym,
                    "title": da.name,
                    "description": da.description,
                    "placements": placements,
                    "record_count": da_fm.get("record_count"),
                    "data_sensitivity": da.data_sensitivity or [],
                    "access_control_methods": da_fm.get("access_control_methods", []),
                }
            )

        # Data Flows
        comp_reverse = {}
        for entity_type in ("actor", "component", "data_store"):
            for sym, obj in resolver.get_all(entity_type).items():
                comp_reverse[obj.pk] = (entity_type, sym)

        flows = DataFlow.objects.filter(
            source_component__in=components
        ) | DataFlow.objects.filter(dest_component__in=components)
        for flow in flows.distinct():
            flow_sym = _get_symbolic_name(flow, "flow")
            source_type, source_sym = comp_reverse.get(
                flow.source_component_id,
                ("component", f"component_{flow.source_component_id}"),
            )
            dest_type, dest_sym = comp_reverse.get(
                flow.dest_component_id,
                ("component", f"component_{flow.dest_component_id}"),
            )

            result["data_flows"].append(
                {
                    "symbolic_name": flow_sym,
                    "title": flow.label,
                    "description": flow.description,
                    "source": {"type": source_type, "name": source_sym},
                    "destination": {"type": dest_type, "name": dest_sym},
                    "has_sensitive_data": flow.has_sensitive_data,
                    "encrypted": flow.encrypted,
                }
            )

        # Threat Personas (from DB)
        db_personas = ThreatPersona.objects.filter(threat_model=threat_model)
        if db_personas.exists():
            result["threat_personas"] = []
            for persona in db_personas:
                persona_entry = {
                    "symbolic_name": persona.symbolic_name,
                    "title": persona.name,
                    "description": persona.description,
                    "is_person": persona.is_person,
                    "malicious_intent": persona.malicious_intent,
                }
                if persona.skill_level:
                    persona_entry["skill_level"] = persona.skill_level
                if persona.motivation:
                    persona_entry["motivation"] = persona.motivation
                if persona.resources:
                    persona_entry["resources"] = persona.resources
                if persona.objectives:
                    persona_entry["objectives"] = persona.objectives
                # Merge back any extra fields from format_metadata
                if persona.format_metadata:
                    persona_entry.update(persona.format_metadata)
                result["threat_personas"].append(persona_entry)

        # Threats — collect from component and flow threats, grouped by library
        component_threat_ids = set(components.values_list("id", flat=True))
        comp_threats = (
            ComponentInstanceThreat.objects.filter(
                component_id__in=component_threat_ids
            )
            .select_related("threat_library")
            .prefetch_related("countermeasure_links__countermeasure")
        )

        flow_ids = set(
            DataFlow.objects.filter(source_component__in=components).values_list(
                "id", flat=True
            )
        ) | set(
            DataFlow.objects.filter(dest_component__in=components).values_list(
                "id", flat=True
            )
        )
        flow_threats = (
            DataFlowInstanceThreat.objects.filter(data_flow_id__in=flow_ids)
            .select_related("threat_library")
            .prefetch_related("countermeasure_links__countermeasure")
        )

        # Build flow reverse lookup for data_flows_affected
        flow_reverse = {}
        for flow_sym, flow_obj in resolver.get_all("data_flow").items():
            flow_reverse[flow_obj.pk] = flow_sym
        # Also handle flows not yet in resolver (non-imported models)
        for flow in flows.distinct():
            if flow.pk not in flow_reverse:
                flow_reverse[flow.pk] = _get_symbolic_name(flow, "flow")

        # Group threats by threat_library_id (or by name+desc for custom)
        # Each group becomes one threat entry in the export
        # group_key -> { symbolic_name, title, desc, ..., instances }
        threat_groups = {}

        def _threat_group_key(threat_instance):
            """Determine grouping key for a threat instance."""
            if threat_instance.threat_library_id:
                return f"lib_{threat_instance.threat_library_id}"
            # Custom threat: group by stored symbolic name or name+desc
            fm = (threat_instance.format_metadata or {}).get("tm_library", {})
            if fm.get("symbolic_name"):
                return fm["symbolic_name"]
            return f"custom_{threat_instance.threat_name}_{hash(threat_instance.threat_description or '')}"

        # Track used symbolic names to detect and resolve collisions
        used_threat_syms = set()

        def _unique_threat_sym(base_sym):
            """Ensure symbolic name uniqueness by appending a suffix if needed."""
            if base_sym not in used_threat_syms:
                used_threat_syms.add(base_sym)
                return base_sym
            counter = 2
            while f"{base_sym}_{counter}" in used_threat_syms:
                counter += 1
            unique_sym = f"{base_sym}_{counter}"
            used_threat_syms.add(unique_sym)
            return unique_sym

        for threat in comp_threats:
            group_key = _threat_group_key(threat)
            threat_fm = (threat.format_metadata or {}).get("tm_library", {})

            if group_key not in threat_groups:
                base_sym = (
                    threat_fm.get("symbolic_name")
                    or f"threat_{threat.threat_library_id or f'c{threat.pk}'}"
                )
                threat_sym = _unique_threat_sym(base_sym)
                threat_groups[group_key] = {
                    "symbolic_name": threat_sym,
                    "title": threat.threat_name
                    or (threat.threat_library.name if threat.threat_library else ""),
                    "description": threat.threat_description
                    or (
                        threat.threat_library.description
                        if threat.threat_library
                        else ""
                    ),
                    "tm_library_fields": {
                        field: threat_fm[field]
                        for field in ("attack_mechanisms", "weaknesses")
                        if threat_fm.get(field)
                    },
                    "components_affected": [],
                    "data_flows_affected": [],
                    "instances": [],
                }

            comp_sym = comp_reverse.get(threat.component_id)
            if comp_sym:
                entity_sym = comp_sym[1]
                if entity_sym not in threat_groups[group_key]["components_affected"]:
                    threat_groups[group_key]["components_affected"].append(entity_sym)
            threat_groups[group_key]["instances"].append(("component", threat))

        for threat in flow_threats:
            group_key = _threat_group_key(threat)
            threat_fm = (threat.format_metadata or {}).get("tm_library", {})

            if group_key not in threat_groups:
                base_sym = (
                    threat_fm.get("symbolic_name")
                    or f"threat_{threat.threat_library_id or f'f{threat.pk}'}"
                )
                threat_sym = _unique_threat_sym(base_sym)
                threat_groups[group_key] = {
                    "symbolic_name": threat_sym,
                    "title": threat.threat_name
                    or (threat.threat_library.name if threat.threat_library else ""),
                    "description": threat.threat_description
                    or (
                        threat.threat_library.description
                        if threat.threat_library
                        else ""
                    ),
                    "tm_library_fields": {
                        field: threat_fm[field]
                        for field in ("attack_mechanisms", "weaknesses")
                        if threat_fm.get(field)
                    },
                    "components_affected": [],
                    "data_flows_affected": [],
                    "instances": [],
                }

            flow_sym = flow_reverse.get(
                threat.data_flow_id, f"flow_{threat.data_flow_id}"
            )
            if flow_sym not in threat_groups[group_key]["data_flows_affected"]:
                threat_groups[group_key]["data_flows_affected"].append(flow_sym)
            threat_groups[group_key]["instances"].append(("flow", threat))

        # Emit grouped threats and collect countermeasures
        control_groups = {}  # control_symbolic_name → {data, threat_symbolic_names}
        extensions = {}  # Precogly extensions block

        for group in threat_groups.values():
            threat_sym = group["symbolic_name"]
            threat_entry = {
                "symbolic_name": threat_sym,
                "title": group["title"],
                "description": group["description"],
            }
            if group["components_affected"]:
                threat_entry["components_affected"] = group["components_affected"]
            if group["data_flows_affected"]:
                threat_entry["data_flows_affected"] = group["data_flows_affected"]
            threat_entry.update(group["tm_library_fields"])

            # Use first instance for top-level threat entry fields and taxonomy
            first_instance = group["instances"][0][1] if group["instances"] else None
            if first_instance:
                if first_instance.impact_description:
                    threat_entry["event"] = first_instance.impact_description

                # Export threat_persona from first instance (top-level default)
                first_type, first_inst = group["instances"][0]
                if first_type == "component":
                    persona_link = (
                        ThreatPersonaLink.objects.filter(
                            component_threat=first_inst,
                        )
                        .select_related("persona")
                        .first()
                    )
                else:
                    persona_link = (
                        ThreatPersonaLink.objects.filter(
                            flow_threat=first_inst,
                        )
                        .select_related("persona")
                        .first()
                    )
                if persona_link:
                    threat_entry["threat_persona"] = persona_link.persona.symbolic_name

                # Export severity (top-level default from first instance)
                threat_entry["inherent_severity"] = first_instance.inherent_severity
                if first_instance.residual_severity:
                    threat_entry["residual_severity"] = first_instance.residual_severity

                # Export CAPEC/CWE from DB via ThreatLibraryTaxonomyEntry
                if first_instance.threat_library_id:
                    taxonomy_joins = ThreatLibraryTaxonomyEntry.objects.filter(
                        threat_library_id=first_instance.threat_library_id,
                    ).select_related("taxonomy_entry__taxonomy")
                    capec_entries = []
                    cwe_entries = []
                    stride_entries = []
                    attack_entries = []
                    for join in taxonomy_joins:
                        entry = join.taxonomy_entry
                        slug = entry.taxonomy.slug if entry.taxonomy else ""
                        if slug == "capec":
                            capec_entries.append(
                                {
                                    "id": entry.external_id,
                                    "title": entry.title,
                                }
                            )
                        elif slug == "cwe":
                            cwe_entries.append(
                                {
                                    "id": entry.external_id,
                                    "title": entry.title,
                                }
                            )
                        elif slug == "stride":
                            stride_entries.append(
                                {
                                    "id": entry.external_id,
                                    "title": entry.title,
                                }
                            )
                        elif slug == "mitre-attack":
                            attack_entries.append(
                                {
                                    "id": entry.external_id,
                                    "title": entry.title,
                                }
                            )
                    if capec_entries:
                        threat_entry["attack_mechanisms"] = {
                            "capec": [e["id"] for e in capec_entries]
                        }
                    if cwe_entries:
                        threat_entry["weaknesses"] = [e["id"] for e in cwe_entries]

                    # Extensions: taxonomy references (STRIDE, ATT&CK)
                    if stride_entries or attack_entries:
                        ext_taxonomy = extensions.setdefault(
                            "precogly.org/taxonomy-references", {}
                        )
                        threat_tax = {}
                        if stride_entries:
                            threat_tax["stride"] = stride_entries
                        if attack_entries:
                            threat_tax["mitre_attack"] = attack_entries
                        ext_taxonomy[threat_sym] = threat_tax

                # Extensions: per-instance threat details
                instance_details = []
                for threat_type, threat_instance in group["instances"]:
                    if threat_type == "component":
                        affected_sym = comp_reverse.get(threat_instance.component_id)
                        affected_name = affected_sym[1] if affected_sym else None
                    else:
                        affected_name = flow_reverse.get(threat_instance.data_flow_id)
                    if not affected_name:
                        continue

                    detail_entry = {
                        "affected": affected_name,
                        "affected_type": threat_type,
                    }

                    # Per-instance severity
                    detail_entry["inherent_severity"] = (
                        threat_instance.inherent_severity
                    )
                    if threat_instance.residual_severity:
                        detail_entry["residual_severity"] = (
                            threat_instance.residual_severity
                        )

                    # Per-instance impact description
                    if threat_instance.impact_description:
                        detail_entry["event"] = threat_instance.impact_description

                    # Per-instance severity scoring metadata
                    if threat_instance.severity_scoring_metadata:
                        detail_entry["severity_scoring_metadata"] = (
                            threat_instance.severity_scoring_metadata
                        )

                    # Per-instance triage state
                    if threat_instance.triage_status != "open":
                        detail_entry["triage_status"] = threat_instance.triage_status
                        if threat_instance.decision_rationale:
                            detail_entry["decision_rationale"] = (
                                threat_instance.decision_rationale
                            )

                    # Per-instance threat persona
                    if threat_type == "component":
                        inst_persona_link = (
                            ThreatPersonaLink.objects.filter(
                                component_threat=threat_instance,
                            )
                            .select_related("persona")
                            .first()
                        )
                    else:
                        inst_persona_link = (
                            ThreatPersonaLink.objects.filter(
                                flow_threat=threat_instance,
                            )
                            .select_related("persona")
                            .first()
                        )
                    if inst_persona_link:
                        detail_entry["threat_persona"] = (
                            inst_persona_link.persona.symbolic_name
                        )

                    instance_details.append(detail_entry)

                if instance_details:
                    ext_details = extensions.setdefault(
                        "precogly.org/threat-details", {}
                    )
                    ext_details[threat_sym] = {
                        "instance_details": instance_details,
                    }

            # Export sources from DB (ThreatSourceLink records)
            source_slugs = set()
            for threat_type, threat_instance in group["instances"]:
                if threat_type == "component":
                    links = ThreatSourceLink.objects.filter(
                        component_threat=threat_instance,
                    ).select_related("source")
                else:
                    links = ThreatSourceLink.objects.filter(
                        flow_threat=threat_instance,
                    ).select_related("source")
                for link in links:
                    source_slugs.add(link.source.slug)
            if source_slugs:
                threat_entry["sources"] = [
                    SOURCE_SLUG_REVERSE.get(slug, slug) for slug in sorted(source_slugs)
                ]

            result["threats"].append(threat_entry)

            # Collect countermeasures from all instances in the group (via junction table)
            for _threat_type, threat_instance in group["instances"]:
                from apps.threats.services import get_countermeasures_for_threat

                countermeasures = get_countermeasures_for_threat(threat_instance)
                for cm in countermeasures:
                    cm_fm = (cm.format_metadata or {}).get("tm_library", {})
                    cm_sym = cm_fm.get("symbolic_name") or f"control_{cm.pk}"

                    if cm_sym not in control_groups:
                        original_status = cm_fm.get(
                            "original_status"
                        ) or CONTROL_STATUS_REVERSE.get(cm.status, cm.status)
                        control_groups[cm_sym] = {
                            "data": {
                                "symbolic_name": cm_sym,
                                "title": cm.countermeasure_name or "",
                                "description": cm.countermeasure_description or "",
                                "status": original_status,
                                "priority": cm.priority or "medium",
                            },
                            "threat_symbolic_names": set(),
                        }
                    control_groups[cm_sym]["threat_symbolic_names"].add(threat_sym)

        # Re-merge controls
        for group in control_groups.values():
            ctrl = group["data"].copy()
            ctrl["threats"] = sorted(group["threat_symbolic_names"])
            result["controls"].append(ctrl)

        # Risks
        risks = Risk.objects.filter(threat_model=threat_model).prefetch_related(
            "risk_threats__component_threat", "risk_threats__flow_threat"
        )
        for risk in risks:
            risk_fm = (risk.format_metadata or {}).get("tm_library", {})
            risk_sym = risk_fm.get("symbolic_name") or f"risk_{risk.pk}"

            scoring = risk.scoring_metadata or {}
            risk_threats_syms_seen = set()
            risk_threats_syms = []
            for rt in risk.risk_threats.all():
                threat = rt.component_threat or rt.flow_threat
                if threat:
                    t_fm = (threat.format_metadata or {}).get("tm_library", {})
                    sym = t_fm.get("symbolic_name") or f"threat_{threat.pk}"
                    if sym not in risk_threats_syms_seen:
                        risk_threats_syms.append(sym)
                        risk_threats_syms_seen.add(sym)

            risk_entry = {
                "symbolic_name": risk_sym,
                "title": risk.name,
                "description": risk.description,
                "threats": risk_threats_syms,
                "likelihood": scoring.get("likelihood", ""),
                "impact": scoring.get("impact", ""),
                "impact_description": scoring.get("impact_description", ""),
                "score": round(risk.inherent_score / 100 * 25),
                "level": risk.inherent_level,
            }
            result["risks"].append(risk_entry)

        # Compliance mappings extension
        from apps.threats.models import InstanceCountermeasureStandard

        compliance_data = {}
        countermeasure_standards = InstanceCountermeasureStandard.objects.filter(
            countermeasure__threat_model=threat_model,
        ).select_related(
            "countermeasure",
            "requirement",
            "requirement__framework",
        )
        for standard in countermeasure_standards:
            cm = standard.countermeasure
            cm_fm = (cm.format_metadata or {}).get("tm_library", {})
            cm_sym = cm_fm.get("symbolic_name") or f"control_{cm.pk}"
            compliance_data.setdefault(cm_sym, []).append(
                {
                    "framework": standard.requirement.framework.name
                    if standard.requirement.framework
                    else "",
                    "requirement_id": standard.requirement.section_code
                    if standard.requirement
                    else "",
                    "sufficiency": standard.sufficiency,
                }
            )
        if compliance_data:
            extensions["precogly.org/compliance-mappings"] = compliance_data

        # Pack lineage extension
        pack_lineage = {}
        for comp in components:
            if comp.component_library and comp.component_library.source_pack:
                comp_sym = _get_symbolic_name(comp, comp.category or "component")
                pack = comp.component_library.source_pack
                pack_lineage.setdefault("components", {})[comp_sym] = {
                    "library_slug": comp.component_library.qualified_slug
                    or comp.component_library.slug,
                    "pack_slug": pack.slug,
                    "pack_version": pack.version,
                }
        if pack_lineage:
            extensions["precogly.org/pack-lineage"] = pack_lineage

        # Add extensions block to result if any data
        if extensions:
            result["extensions"] = extensions

        return result
