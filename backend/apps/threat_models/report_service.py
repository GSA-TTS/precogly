"""
Report data assembly service.

Builds a comprehensive dataset for threat model reporting by gathering data
from all related models in optimized query batches.
"""

from collections import defaultdict

from django.db.models import Q

from apps.compliance.models import StandardFramework, StandardRequirementMapping
from apps.systems.models import (
    ComponentDataAsset,
    DataFlow,
    DataFlowAsset,
    OrgsystemComponent,
    TrustBoundary,
    TrustZone,
)
from apps.threats.models import (
    ACTIVE_TRIAGE_STATUSES,
    ComponentInstanceThreat,
    CountermeasureThreatLink,
    DataFlowInstanceThreat,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
    Risk,
)


def _get_scoped_ids(threat_model):
    """
    Extract component_ids and dataflow_ids from DFD canvas data,
    including analysis-only components and their flows.
    """
    dfds = threat_model.dfds.filter(is_primary=True)
    component_ids = set()
    dataflow_ids = set()

    for dfd in dfds:
        canvas_data = dfd.canvas_data or {}
        for node in canvas_data.get("nodes", []):
            component_id = node.get("data", {}).get("component_id")
            if component_id:
                component_ids.add(component_id)
        for edge in canvas_data.get("edges", []):
            dataflow_id = edge.get("data", {}).get("dataflow_id")
            if dataflow_id:
                dataflow_ids.add(dataflow_id)

    # Include analysis-only components
    analysis_only_ids = (
        OrgsystemComponent.objects.filter(threat_model=threat_model)
        .exclude(id__in=component_ids)
        .values_list("id", flat=True)
    )
    component_ids.update(analysis_only_ids)

    # Include data flows connected to analysis-only components
    extra_flow_ids = (
        DataFlow.objects.filter(
            Q(source_component_id__in=component_ids)
            | Q(dest_component_id__in=component_ids)
        )
        .exclude(id__in=dataflow_ids)
        .values_list("id", flat=True)
    )
    dataflow_ids.update(extra_flow_ids)

    return list(component_ids), list(dataflow_ids)


def _build_metadata(threat_model):
    """Build metadata section."""
    frameworks = []
    for assoc in threat_model.framework_associations.select_related("framework").all():
        frameworks.append(
            {
                "name": assoc.framework.name,
                "slug": assoc.framework.slug,
                "version": assoc.framework.version,
            }
        )

    return {
        "name": threat_model.name,
        "description": threat_model.description,
        "criticality": threat_model.criticality,
        "risk_scoring_method": threat_model.risk_scoring_method,
        "owning_team": threat_model.owning_team.name
        if threat_model.owning_team
        else None,
        "created_by": threat_model.created_by.email
        if threat_model.created_by
        else None,
        "created_at": threat_model.created_at.isoformat()
        if threat_model.created_at
        else None,
        "updated_at": threat_model.updated_at.isoformat()
        if threat_model.updated_at
        else None,
        "frameworks": frameworks,
    }


def _build_scope(threat_model):
    """Build scope section."""
    out_of_scope = list(threat_model.out_of_scope_items.values("id", "name", "reason"))

    referenced_models = []
    for rel in threat_model.outgoing_relationships.select_related(
        "target_threat_model"
    ).all():
        referenced_models.append(
            {
                "id": str(rel.target_threat_model.id),
                "name": rel.target_threat_model.name,
                "relation_type": rel.relation_type,
            }
        )

    return {
        "description": threat_model.description,
        "scope_locked": threat_model.scope_locked,
        "assumptions": threat_model.assumptions or [],
        "out_of_scope_items": out_of_scope,
        "referenced_models": referenced_models,
    }


def _build_architecture(threat_model, component_ids):
    """Build architecture section."""
    dfds = []
    for dfd in threat_model.dfds.all():
        canvas_data = dfd.canvas_data or {}
        dfds.append(
            {
                "id": str(dfd.id),
                "name": dfd.name,
                "diagram_type": dfd.diagram_type,
                "is_primary": dfd.is_primary,
                "node_count": len(canvas_data.get("nodes", [])),
                "edge_count": len(canvas_data.get("edges", [])),
                "canvas_data": canvas_data,
            }
        )

    reference_images = []
    for img in threat_model.reference_images.all():
        reference_images.append(
            {
                "id": img.id,
                "filename": img.filename,
                "description": img.description,
            }
        )

    # Trust zones from components in scope
    zone_ids = (
        OrgsystemComponent.objects.filter(
            id__in=component_ids,
            trust_zone__isnull=False,
        )
        .values_list("trust_zone_id", flat=True)
        .distinct()
    )

    trust_zones = []
    for zone in TrustZone.objects.filter(id__in=zone_ids):
        trust_zones.append(
            {
                "id": zone.id,
                "name": zone.name,
                "trust_level": zone.trust_level,
                "description": zone.description,
            }
        )

    zone_id_set = set(zone_ids)
    trust_boundaries = []
    for boundary in TrustBoundary.objects.filter(
        Q(zone_a_id__in=zone_id_set) | Q(zone_b_id__in=zone_id_set)
    ).select_related("zone_a", "zone_b"):
        trust_boundaries.append(
            {
                "id": boundary.id,
                "label": boundary.label,
                "zone_a": boundary.zone_a.name,
                "zone_b": boundary.zone_b.name,
                "description": boundary.description,
            }
        )

    return {
        "dfds": dfds,
        "reference_images": reference_images,
        "trust_zones": trust_zones,
        "trust_boundaries": trust_boundaries,
    }


def _build_data_assets(threat_model, component_ids, dataflow_ids):
    """Build data assets section."""
    assets = []
    for asset in threat_model.data_assets.all():
        placements = list(
            ComponentDataAsset.objects.filter(
                data_asset=asset,
                component_id__in=component_ids,
            )
            .select_related("component")
            .values("component__name", "data_state", "volume", "encrypted")
        )
        in_transit = list(
            DataFlowAsset.objects.filter(
                data_asset=asset,
                data_flow_id__in=dataflow_ids,
            )
            .select_related("data_flow")
            .values("data_flow__label", "protection_method", "encryption_type")
        )
        assets.append(
            {
                "id": asset.id,
                "name": asset.name,
                "description": asset.description,
                "classification": asset.classification,
                "confidentiality": asset.confidentiality,
                "integrity": asset.integrity,
                "availability": asset.availability,
                "placements": [
                    {
                        "component_name": p["component__name"],
                        "data_state": p["data_state"],
                        "volume": p["volume"],
                        "encrypted": p["encrypted"],
                    }
                    for p in placements
                ],
                "in_transit": [
                    {
                        "data_flow_label": t["data_flow__label"],
                        "protection_method": t["protection_method"],
                        "encryption_type": t["encryption_type"],
                    }
                    for t in in_transit
                ],
            }
        )

    return assets


def _build_components(component_ids):
    """Build components section grouped by category."""
    components = OrgsystemComponent.objects.filter(id__in=component_ids).select_related(
        "trust_zone"
    )

    grouped = {
        "processes": [],
        "data_stores": [],
        "human_actors": [],
        "system_actors": [],
    }

    for comp in components:
        entry = {
            "id": comp.id,
            "name": comp.name,
            "category": comp.category,
            "component_type": comp.component_type,
            "actor_type": comp.actor_type,
            "provider": comp.provider,
            "trust_zone": comp.trust_zone.name if comp.trust_zone else None,
            "description": comp.description,
        }
        category = comp.category or ""
        if category == "process":
            grouped["processes"].append(entry)
        elif category == "datastore":
            grouped["data_stores"].append(entry)
        elif category == "external_human_actor":
            grouped["human_actors"].append(entry)
        elif category == "external_system_actor":
            grouped["system_actors"].append(entry)
        else:
            grouped["processes"].append(entry)

    return grouped


def _build_data_flows(dataflow_ids):
    """Build data flows section."""
    flows = DataFlow.objects.filter(id__in=dataflow_ids).select_related(
        "source_component", "dest_component"
    )

    result = []
    for flow in flows:
        result.append(
            {
                "id": flow.id,
                "label": flow.label,
                "source": flow.source_component.name if flow.source_component else None,
                "destination": flow.dest_component.name
                if flow.dest_component
                else None,
                "protocol": flow.protocol,
                "encrypted": flow.encrypted,
                "authenticated": flow.authenticated,
                "crosses_trust_zone": flow.crosses_trust_zone,
                "has_sensitive_data": flow.has_sensitive_data,
            }
        )

    return result


def _get_stride_category(threat_instance):
    """Extract STRIDE category from library or instance taxonomy entries."""
    if threat_instance.threat_library:
        for join in threat_instance.threat_library.taxonomy_entries.all():
            entry = join.taxonomy_entry
            if entry.taxonomy and entry.taxonomy.slug == "stride":
                return entry.external_id

    for link in threat_instance.instance_taxonomy_links.all():
        entry = link.taxonomy_entry
        if entry.taxonomy and entry.taxonomy.slug == "stride":
            return entry.external_id

    return "unknown"


def _get_taxonomy_entries(threat_instance):
    """Return merged taxonomy entries (library + instance), falling back to snapshot."""
    seen = {}

    if threat_instance.threat_library:
        for join in threat_instance.threat_library.taxonomy_entries.all():
            entry = join.taxonomy_entry
            if entry.taxonomy:
                key = (entry.taxonomy.slug, entry.external_id)
                seen[key] = {
                    "taxonomy_slug": entry.taxonomy.slug,
                    "external_id": entry.external_id,
                    "title": entry.title,
                    "reference_url": entry.reference_url or "",
                    "source": "library",
                }

    for link in threat_instance.instance_taxonomy_links.all():
        entry = link.taxonomy_entry
        if entry.taxonomy:
            key = (entry.taxonomy.slug, entry.external_id)
            if key not in seen:
                seen[key] = {
                    "taxonomy_slug": entry.taxonomy.slug,
                    "external_id": entry.external_id,
                    "title": entry.title,
                    "reference_url": entry.reference_url or "",
                    "source": "instance",
                }

    if not seen:
        return threat_instance.taxonomy_snapshot or []

    return list(seen.values())


def _serialize_compliance_standards(cm):
    """Serialize compliance standard mappings for a countermeasure.

    Merges library-level and instance-level mappings, with instance
    entries overriding library entries for the same requirement.
    """
    seen = {}

    if cm.countermeasure_library:
        for mapping in cm.countermeasure_library.standard_mappings.all():
            if mapping.requirement and mapping.requirement.framework:
                seen[mapping.requirement_id] = {
                    "framework_name": mapping.requirement.framework.name,
                    "section_code": mapping.requirement.section_code,
                    "sufficiency": mapping.sufficiency,
                }

    for mapping in cm.instance_standard_mappings.all():
        if mapping.requirement and mapping.requirement.framework:
            seen[mapping.requirement_id] = {
                "framework_name": mapping.requirement.framework.name,
                "section_code": mapping.requirement.section_code,
                "sufficiency": mapping.sufficiency,
            }
        elif not mapping.requirement:
            seen[f"snapshot-{mapping.id}"] = {
                "framework_name": mapping.framework_name,
                "section_code": mapping.section_code,
                "sufficiency": mapping.sufficiency,
            }

    return list(seen.values())


def _serialize_countermeasure(cm):
    """Serialize a countermeasure instance to dict."""
    return {
        "id": cm.id,
        "countermeasure_name": (
            cm.countermeasure_library.name if cm.countermeasure_library else None
        )
        or cm.countermeasure_name,
        "control_functions": (
            cm.countermeasure_library.control_functions
            if cm.countermeasure_library
            else None
        )
        or cm.control_functions,
        "control_nature": (
            cm.countermeasure_library.control_nature
            if cm.countermeasure_library
            else None
        )
        or cm.control_nature,
        "status": cm.status,
        "priority": cm.priority,
        "assigned_owner_email": cm.assigned_owner.email if cm.assigned_owner else None,
        "verified_by_email": cm.verified_by.email if cm.verified_by else None,
        "evidence_url": cm.evidence_url,
        "is_inherited": cm.is_inherited,
        "inherited_from_component_name": cm.inherited_from_component_name,
        "inherited_from_zone_name": cm.inherited_from_zone_name,
        "compliance_standards": _serialize_compliance_standards(cm),
    }


def _build_threat_analysis(component_ids, dataflow_ids):
    """Build threat analysis section with STRIDE summary and detailed threats."""
    from django.db.models import Prefetch

    countermeasure_links_prefetch = Prefetch(
        "countermeasure_links",
        queryset=CountermeasureThreatLink.objects.select_related(
            "countermeasure",
            "countermeasure__countermeasure_library",
            "countermeasure__assigned_owner",
            "countermeasure__verified_by",
        )
        .prefetch_related(
            "countermeasure__countermeasure_library__standard_mappings__requirement__framework",
            "countermeasure__instance_standard_mappings__requirement__framework",
        )
        .order_by("display_order"),
    )

    # Component threats
    component_threats = (
        ComponentInstanceThreat.objects.filter(component_id__in=component_ids)
        .select_related("component", "threat_library")
        .prefetch_related(
            "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
            "instance_taxonomy_links__taxonomy_entry__taxonomy",
            countermeasure_links_prefetch,
        )
    )

    # Data flow threats
    flow_threats = (
        DataFlowInstanceThreat.objects.filter(data_flow_id__in=dataflow_ids)
        .select_related("data_flow", "threat_library")
        .prefetch_related(
            "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
            "instance_taxonomy_links__taxonomy_entry__taxonomy",
            countermeasure_links_prefetch,
        )
    )

    # STRIDE category counts
    stride_counts = defaultdict(int)
    active_component_threats = []
    triaged_component_threats = []

    for threat in component_threats:
        category = _get_stride_category(threat)
        if threat.triage_status in ACTIVE_TRIAGE_STATUSES:
            stride_counts[category] += 1
            active_component_threats.append(threat)
        else:
            triaged_component_threats.append(threat)

    active_flow_threats = []
    triaged_flow_threats = []
    for threat in flow_threats:
        category = _get_stride_category(threat)
        if threat.triage_status in ACTIVE_TRIAGE_STATUSES:
            stride_counts[category] += 1
            active_flow_threats.append(threat)
        else:
            triaged_flow_threats.append(threat)

    # Group component threats by component
    threats_by_component = defaultdict(list)
    for threat in active_component_threats:
        component_name = threat.component.name if threat.component else "Unknown"
        threats_by_component[component_name].append(
            {
                "id": threat.id,
                "threat_name": threat.threat_name
                or (threat.threat_library.name if threat.threat_library else None),
                "threat_description": threat.threat_description
                or (
                    threat.threat_library.description if threat.threat_library else None
                ),
                "stride_category": _get_stride_category(threat),
                "taxonomy_entries": _get_taxonomy_entries(threat),
                "inherent_severity": threat.inherent_severity,
                "residual_severity": threat.residual_severity,
                "status": threat.status,
                "impact_description": threat.impact_description,
                "threat_actor_text": threat.threat_actor_text,
                "countermeasures": [
                    _serialize_countermeasure(link.countermeasure)
                    for link in threat.countermeasure_links.all()
                ],
            }
        )

    # Group flow threats
    threats_by_flow = defaultdict(list)
    for threat in active_flow_threats:
        flow_label = threat.data_flow.label if threat.data_flow else "Unknown"
        threats_by_flow[flow_label].append(
            {
                "id": threat.id,
                "threat_name": threat.threat_name
                or (threat.threat_library.name if threat.threat_library else None),
                "threat_description": threat.threat_description
                or (
                    threat.threat_library.description if threat.threat_library else None
                ),
                "stride_category": _get_stride_category(threat),
                "taxonomy_entries": _get_taxonomy_entries(threat),
                "inherent_severity": threat.inherent_severity,
                "residual_severity": threat.residual_severity,
                "status": threat.status,
                "impact_description": threat.impact_description,
                "threat_actor_text": threat.threat_actor_text,
                "countermeasures": [
                    _serialize_countermeasure(link.countermeasure)
                    for link in threat.countermeasure_links.all()
                ],
            }
        )

    # Triaged threats (simple list)
    triaged_threats = []
    for threat in triaged_component_threats:
        triaged_threats.append(
            {
                "id": threat.id,
                "type": "component",
                "threat_name": threat.threat_name
                or (threat.threat_library.name if threat.threat_library else None),
                "component_name": threat.component.name if threat.component else None,
                "triage_status": threat.triage_status,
                "decision_rationale": threat.decision_rationale,
            }
        )
    for threat in triaged_flow_threats:
        triaged_threats.append(
            {
                "id": threat.id,
                "type": "dataflow",
                "threat_name": threat.threat_name
                or (threat.threat_library.name if threat.threat_library else None),
                "flow_label": threat.data_flow.label if threat.data_flow else None,
                "triage_status": threat.triage_status,
                "decision_rationale": threat.decision_rationale,
            }
        )

    return {
        "stride_summary": dict(stride_counts),
        "component_threats": dict(threats_by_component),
        "data_flow_threats": dict(threats_by_flow),
        "triaged_threats": triaged_threats,
    }


def _build_countermeasure_summary(threat_model):
    """Build countermeasure summary with status breakdown.

    Uses direct threat_model FK — each countermeasure counted once even if shared.
    """
    all_countermeasures = (
        InstanceCountermeasure.objects.filter(threat_model=threat_model)
        .select_related(
            "countermeasure_library",
            "assigned_owner",
        )
        .prefetch_related(
            "threat_links__component_threat__component",
            "threat_links__flow_threat__data_flow",
        )
    )

    status_counts = defaultdict(int)
    gaps = []
    waived = []
    inherited = []

    for cm in all_countermeasures:
        status_counts[cm.status] += 1
        cm_name = (
            cm.countermeasure_library.name if cm.countermeasure_library else None
        ) or cm.countermeasure_name

        # Determine the display context from the first threat link
        first_link = cm.threat_links.all()[:1]
        component_name = None
        flow_label = None
        if first_link:
            link = first_link[0]
            if link.component_threat and link.component_threat.component:
                component_name = link.component_threat.component.name
            elif link.flow_threat and link.flow_threat.data_flow:
                flow_label = link.flow_threat.data_flow.label

        entry_id = str(cm.id)

        if cm.status == "gap":
            gap_entry = {
                "id": entry_id,
                "countermeasure_name": cm_name,
                "priority": cm.priority,
                "assigned_owner_email": cm.assigned_owner.email
                if cm.assigned_owner
                else None,
            }
            if component_name:
                gap_entry["component_name"] = component_name
            if flow_label:
                gap_entry["flow_label"] = flow_label
            gaps.append(gap_entry)

        elif cm.status == "waived":
            waived_entry = {
                "id": entry_id,
                "countermeasure_name": cm_name,
            }
            if component_name:
                waived_entry["component_name"] = component_name
            if flow_label:
                waived_entry["flow_label"] = flow_label
            waived.append(waived_entry)

        if cm.is_inherited:
            inherited_entry = {
                "id": entry_id,
                "countermeasure_name": cm_name,
                "inherited_from_component_name": cm.inherited_from_component_name,
                "inherited_from_zone_name": cm.inherited_from_zone_name,
            }
            if component_name:
                inherited_entry["component_name"] = component_name
            if flow_label:
                inherited_entry["flow_label"] = flow_label
            inherited.append(inherited_entry)

    return {
        "status_breakdown": dict(status_counts),
        "gaps": gaps,
        "waived": waived,
        "inherited": inherited,
    }


def _build_risks(threat_model):
    """Build risk register section."""
    risks = Risk.objects.filter(threat_model=threat_model).prefetch_related(
        "risk_threats__component_threat__threat_library",
        "risk_threats__flow_threat__threat_library",
    )

    result = []
    for risk in risks:
        contributing_threats = []
        for rt in risk.risk_threats.all():
            if rt.component_threat:
                threat = rt.component_threat
                contributing_threats.append(
                    {
                        "type": "component",
                        "threat_name": threat.threat_name
                        or (
                            threat.threat_library.name
                            if threat.threat_library
                            else None
                        ),
                        "status": threat.status,
                    }
                )
            elif rt.flow_threat:
                threat = rt.flow_threat
                contributing_threats.append(
                    {
                        "type": "dataflow",
                        "threat_name": threat.threat_name
                        or (
                            threat.threat_library.name
                            if threat.threat_library
                            else None
                        ),
                        "status": threat.status,
                    }
                )

        result.append(
            {
                "id": risk.id,
                "name": risk.name,
                "description": risk.description,
                "inherent_score": risk.inherent_score,
                "inherent_level": risk.inherent_level,
                "residual_score": risk.residual_score,
                "residual_level": risk.residual_level,
                "owner_email": risk.owner.email if risk.owner else None,
                "contributing_threats": contributing_threats,
            }
        )

    return result


def _build_compliance(threat_model, component_ids, dataflow_ids):
    """Build compliance section with framework coverage and satisfaction.

    Derives frameworks from instance-level compliance mappings rather than
    requiring explicit ThreatModelFramework associations.

    Coverage: requirement has at least one countermeasure mapped to it.
    Satisfaction: requirement has at least one countermeasure with status
    "verified" or "platform".
    """
    satisfied_statuses = {"verified", "platform"}

    # Collect all covered and satisfied (framework_id, requirement_id) pairs
    framework_coverage = defaultdict(set)
    framework_satisfied = defaultdict(set)

    # From unified countermeasure instance mappings (using threat_model FK)
    instance_standards = InstanceCountermeasureStandard.objects.filter(
        countermeasure__threat_model=threat_model,
        requirement__isnull=False,
    ).select_related("requirement__framework", "countermeasure")

    for mapping in instance_standards:
        fw_id = mapping.requirement.framework_id
        req_id = mapping.requirement_id
        framework_coverage[fw_id].add(req_id)
        if mapping.countermeasure.status in satisfied_statuses:
            framework_satisfied[fw_id].add(req_id)

    # Build framework summaries
    frameworks = []
    if framework_coverage:
        for framework in StandardFramework.objects.filter(
            id__in=framework_coverage.keys()
        ):
            covered_ids = framework_coverage[framework.id]
            satisfied_ids = framework_satisfied.get(framework.id, set())
            total_requirements = framework.requirements.count()
            frameworks.append(
                {
                    "name": framework.name,
                    "slug": framework.slug,
                    "total_requirements": total_requirements,
                    "covered_requirements": len(covered_ids),
                    "coverage_percentage": (
                        round(len(covered_ids) / total_requirements * 100, 1)
                        if total_requirements > 0
                        else 0
                    ),
                    "satisfied_requirements": len(satisfied_ids),
                    "satisfaction_percentage": (
                        round(len(satisfied_ids) / total_requirements * 100, 1)
                        if total_requirements > 0
                        else 0
                    ),
                }
            )

    # Build cross-framework requirement mappings
    cross_framework_mappings = []
    framework_slugs = {fw["slug"] for fw in frameworks}

    if len(framework_slugs) >= 2:
        relevant_mappings = StandardRequirementMapping.objects.filter(
            from_requirement__framework__slug__in=framework_slugs,
            to_requirement__framework__slug__in=framework_slugs,
        ).select_related(
            "from_requirement__framework",
            "to_requirement__framework",
        )

        # Group by (source_framework_slug, target_framework_slug)
        groups = defaultdict(list)
        for mapping in relevant_mappings:
            key = (
                mapping.from_requirement.framework.slug,
                mapping.to_requirement.framework.slug,
            )
            groups[key].append(
                {
                    "from_section_code": mapping.from_requirement.section_code,
                    "from_description": mapping.from_requirement.description,
                    "to_section_code": mapping.to_requirement.section_code,
                    "to_description": mapping.to_requirement.description,
                    "sufficiency": mapping.sufficiency,
                }
            )

        # Build display names from frameworks already computed above
        framework_name_by_slug = {fw["slug"]: fw["name"] for fw in frameworks}

        for (source_slug, target_slug), mappings_list in groups.items():
            cross_framework_mappings.append(
                {
                    "source_framework": framework_name_by_slug.get(
                        source_slug, source_slug
                    ),
                    "target_framework": framework_name_by_slug.get(
                        target_slug, target_slug
                    ),
                    "mappings": mappings_list,
                }
            )

    return {
        "frameworks": frameworks,
        "cross_framework_mappings": cross_framework_mappings,
    }


def _build_summary_metrics(threat_analysis, countermeasure_summary, risks):
    """Build summary metrics for dashboard."""
    # Count active threats
    total_active_threats = sum(
        len(threats) for threats in threat_analysis["component_threats"].values()
    ) + sum(len(threats) for threats in threat_analysis["data_flow_threats"].values())
    total_triaged = len(threat_analysis["triaged_threats"])

    # Count threats by status
    threat_status_counts = defaultdict(int)
    for threats in threat_analysis["component_threats"].values():
        for threat in threats:
            threat_status_counts[threat["status"]] += 1
    for threats in threat_analysis["data_flow_threats"].values():
        for threat in threats:
            threat_status_counts[threat["status"]] += 1

    cm_breakdown = countermeasure_summary["status_breakdown"]
    total_cms = sum(cm_breakdown.values())

    risk_level_counts = defaultdict(int)
    for risk in risks:
        risk_level_counts[risk["residual_level"]] += 1

    return {
        "total_active_threats": total_active_threats,
        "total_triaged_threats": total_triaged,
        "threats_by_status": dict(threat_status_counts),
        "total_countermeasures": total_cms,
        "countermeasures_by_status": cm_breakdown,
        "total_gaps": len(countermeasure_summary["gaps"]),
        "total_waived": len(countermeasure_summary["waived"]),
        "total_inherited": len(countermeasure_summary["inherited"]),
        "total_risks": len(risks),
        "risks_by_level": dict(risk_level_counts),
    }


def build_report_data(threat_model):
    """
    Assemble complete report dataset for a threat model.

    Returns a dict with all sections needed for any report type.
    """
    component_ids, dataflow_ids = _get_scoped_ids(threat_model)

    metadata = _build_metadata(threat_model)
    scope = _build_scope(threat_model)
    architecture = _build_architecture(threat_model, component_ids)
    data_assets = _build_data_assets(threat_model, component_ids, dataflow_ids)
    components = _build_components(component_ids)
    data_flows = _build_data_flows(dataflow_ids)
    threat_analysis = _build_threat_analysis(component_ids, dataflow_ids)
    countermeasure_summary = _build_countermeasure_summary(threat_model)
    risks = _build_risks(threat_model)
    compliance = _build_compliance(threat_model, component_ids, dataflow_ids)
    summary_metrics = _build_summary_metrics(
        threat_analysis, countermeasure_summary, risks
    )

    # Reuse completion status from serializer
    from apps.threat_models.serializers import ThreatModelSerializer

    serializer = ThreatModelSerializer()
    completion_status = serializer._compute_completion_status(threat_model)
    progress_checklist = serializer._flatten_to_legacy_checklist(completion_status)

    return {
        "metadata": metadata,
        "scope": scope,
        "architecture": architecture,
        "data_assets": data_assets,
        "components": components,
        "data_flows": data_flows,
        "threat_analysis": threat_analysis,
        "countermeasure_summary": countermeasure_summary,
        "risks": risks,
        "compliance": compliance,
        "summary_metrics": summary_metrics,
        "progress_checklist": progress_checklist,
        "completion_status": completion_status,
    }
