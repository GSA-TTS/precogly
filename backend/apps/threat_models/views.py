"""
Views for threat_models app.
"""

import json
import logging

from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.core.permissions import CanWrite

from .models import (
    OutOfScopeItem,
    ThreatModel,
    ThreatModelLibraryPack,
    ThreatModelReferenceImage,
)
from .serializers import (
    OutOfScopeItemSerializer,
    ThreatModelCreateSerializer,
    ThreatModelListSerializer,
    ThreatModelReferenceImageSerializer,
    ThreatModelReferenceImageUploadSerializer,
    ThreatModelSerializer,
)

logger = logging.getLogger(__name__)


class ThreatModelViewSet(viewsets.ModelViewSet):
    """ViewSet for ThreatModel CRUD operations."""

    permission_classes = [IsAuthenticated, CanWrite]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["organization"]
    search_fields = ["name", "description"]
    ordering_fields = ["name", "created_at", "updated_at"]
    ordering = ["-updated_at"]

    def get_queryset(self):
        """Filter threat models by user's team memberships within their orgs.
        Security team members see all threat models in their org.

        Who may read what is `ThreatModelQuerySet.visible_to`, which the MCP endpoint
        calls as well — it has no request and no permission classes, so the rule has to
        live somewhere both can reach.
        """
        queryset = ThreatModel.objects.visible_to(self.request.user).select_related(
            "created_by", "organization", "owning_team", "owning_team__business_unit"
        )

        # Optional further filter by specific team
        owning_team_id = self.request.query_params.get("owning_team")
        if owning_team_id:
            queryset = queryset.filter(
                Q(owning_team_id=owning_team_id) | Q(owning_team__isnull=True)
            )

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == "list":
            return ThreatModelListSerializer
        elif self.action == "create":
            return ThreatModelCreateSerializer
        return ThreatModelSerializer

    def perform_create(self, serializer):
        """Set created_by to current user."""
        serializer.save(created_by=self.request.user)

    def perform_destroy(self, instance):
        """
        Delete the threat model. DFDs cascade-delete via FK.
        Also clean up components linked to this threat model.
        """
        from apps.systems.models import OrgsystemComponent

        with transaction.atomic():
            # Delete components linked to this threat model (cascades to threats/CMs)
            OrgsystemComponent.objects.filter(threat_model=instance).delete()

            # Delete the threat model (DFDs cascade via FK)
            instance.delete()

    @action(detail=True, methods=["get"])
    def delete_preview(self, request, pk=None):
        """
        Preview what will be deleted when this threat model is deleted.

        Returns information about DFDs, components, threats, and countermeasures
        that will be deleted.
        """
        from apps.systems.models import DataFlow, OrgsystemComponent
        from apps.threats.models import (
            ComponentInstanceThreat,
            DataFlowInstanceThreat,
            InstanceCountermeasure,
        )

        threat_model = self.get_object()

        # Get all DFDs for this threat model (direct FK)
        dfds = threat_model.dfds.all()
        dfds_to_delete = []
        component_ids_to_delete = set()

        for dfd in dfds:
            canvas_data = dfd.canvas_data or {}
            node_count = len(canvas_data.get("nodes", []))

            dfds_to_delete.append(
                {
                    "id": str(dfd.id),
                    "name": dfd.name,
                    "node_count": node_count,
                }
            )

            for node in canvas_data.get("nodes", []):
                component_id = node.get("data", {}).get("component_id")
                if component_id:
                    component_ids_to_delete.add(component_id)

        # Also include analysis-only components
        analysis_component_ids = OrgsystemComponent.objects.filter(
            threat_model=threat_model
        ).values_list("id", flat=True)
        component_ids_to_delete.update(analysis_component_ids)

        # Count data flows that will be deleted
        dataflow_count = DataFlow.objects.filter(
            Q(source_component_id__in=component_ids_to_delete)
            | Q(dest_component_id__in=component_ids_to_delete)
        ).count()

        # Count component threats and countermeasures
        component_threat_count = ComponentInstanceThreat.objects.filter(
            component_id__in=component_ids_to_delete
        ).count()

        # Count flow threats and countermeasures
        flow_threat_count = DataFlowInstanceThreat.objects.filter(
            Q(data_flow__source_component_id__in=component_ids_to_delete)
            | Q(data_flow__dest_component_id__in=component_ids_to_delete)
        ).count()

        # Count all countermeasures in this threat model
        countermeasure_count = InstanceCountermeasure.objects.filter(
            threat_model=threat_model
        ).count()

        return Response(
            {
                "threat_model": {
                    "id": str(threat_model.id),
                    "name": threat_model.name,
                },
                "dfds_to_delete": dfds_to_delete,
                "total_dfds": len(dfds_to_delete),
                "components_to_delete": len(component_ids_to_delete),
                "dataflows_to_delete": dataflow_count,
                "threats_to_delete": component_threat_count + flow_threat_count,
                "countermeasures_to_delete": countermeasure_count,
            }
        )

    @action(detail=True, methods=["post"])
    def add_system(self, request, pk=None):
        """Add a system to this threat model."""
        from apps.systems.models import Orgsystem

        threat_model = self.get_object()
        system_id = request.data.get("system_id")

        if not system_id:
            return Response(
                {"error": "system_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            orgsystem = Orgsystem.objects.get(
                id=system_id,
                organization=threat_model.organization,
            )
        except Orgsystem.DoesNotExist:
            return Response(
                {"error": "System not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        from .models import ThreatModelOrgsystem

        ThreatModelOrgsystem.objects.get_or_create(
            threat_model=threat_model, orgsystem=orgsystem
        )
        return Response({"status": "system added"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def remove_system(self, request, pk=None):
        """Remove a system from this threat model."""
        from .models import ThreatModelOrgsystem

        threat_model = self.get_object()
        system_id = request.data.get("system_id")

        if not system_id:
            return Response(
                {"error": "system_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        deleted, _ = ThreatModelOrgsystem.objects.filter(
            threat_model=threat_model, orgsystem_id=system_id
        ).delete()

        if deleted:
            return Response({"status": "system removed"}, status=status.HTTP_200_OK)
        return Response(
            {"error": "System not associated with this threat model"},
            status=status.HTTP_404_NOT_FOUND,
        )

    @action(detail=True, methods=["post"])
    def remove_pack(self, request, pk=None):
        """Remove a pack from this threat model."""
        from apps.packs.models import LibraryPack, LibraryPackDependency

        threat_model = self.get_object()
        pack_id = request.data.get("pack_id")

        if not pack_id:
            return Response(
                {"error": "pack_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        deleted, _ = ThreatModelLibraryPack.objects.filter(
            threat_model=threat_model, library_pack_id=pack_id
        ).delete()

        if not deleted:
            return Response(
                {"error": "Pack not associated with this threat model"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Build dependency warnings
        dependency_warnings = []
        try:
            removed_pack = LibraryPack.objects.get(id=pack_id)
        except LibraryPack.DoesNotExist:
            removed_pack = None

        if removed_pack:
            connected_pack_ids = set(
                ThreatModelLibraryPack.objects.filter(
                    threat_model=threat_model
                ).values_list("library_pack_id", flat=True)
            )

            # Packs that depend on the removed pack
            dependent_deps = LibraryPackDependency.objects.filter(
                depends_on_pack=removed_pack,
                pack_id__in=connected_pack_ids,
            ).select_related("pack")
            for dep in dependent_deps:
                dependency_warnings.append(
                    {
                        "pack": dep.pack.name,
                        "message": (
                            f"{dep.pack.name} (still connected) depends on {removed_pack.name}. "
                            f"Threat and countermeasure generation from {removed_pack.name} "
                            f"will no longer apply to this threat model."
                        ),
                    }
                )

            # Packs the removed pack depends on: check if any other connected
            # pack also depends on them
            child_deps = LibraryPackDependency.objects.filter(
                pack=removed_pack,
            ).select_related("depends_on_pack")
            for dep in child_deps:
                child_pack = dep.depends_on_pack
                other_dependents = LibraryPackDependency.objects.filter(
                    depends_on_pack=child_pack,
                    pack_id__in=connected_pack_ids,
                ).exists()
                if not other_dependents:
                    dependency_warnings.append(
                        {
                            "pack": child_pack.name,
                            "message": (
                                f"{child_pack.name} was a dependency of {removed_pack.name} "
                                f"and no other connected pack uses it. "
                                f"Consider removing it too if it is no longer needed."
                            ),
                        }
                    )

        return Response(
            {
                "status": "pack removed",
                "dependency_warnings": dependency_warnings,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def add_pack(self, request, pk=None):
        """Add a pack to this threat model.

        After connecting the pack, scans existing components on the TM
        whose component_library belongs to the newly connected pack and
        generates threats and countermeasures for each.
        """
        from apps.diagrams.services import _generate_threats_for_component
        from apps.packs.models import LibraryPack
        from apps.systems.models import OrgsystemComponent

        threat_model = self.get_object()
        pack_id = request.data.get("pack_id")

        if not pack_id:
            return Response(
                {"error": "pack_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            library_pack = LibraryPack.objects.get(id=pack_id)
        except LibraryPack.DoesNotExist:
            return Response(
                {"error": "Pack not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        _, created = ThreatModelLibraryPack.objects.get_or_create(
            threat_model=threat_model, library_pack=library_pack
        )

        # Auto-materialize threats for existing components from this pack
        threats_created = 0
        components_matched = 0
        if created:
            matching_components = OrgsystemComponent.objects.filter(
                threat_model=threat_model,
                component_library__source_pack=library_pack,
            )
            with transaction.atomic():
                for component in matching_components:
                    components_matched += 1
                    threats_created += _generate_threats_for_component(component)

        return Response(
            {
                "status": "pack added",
                "components_matched": components_matched,
                "threats_created": threats_created,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def add_referenced_model(self, request, pk=None):
        """Add a referenced threat model relationship."""
        threat_model = self.get_object()
        target_model_id = request.data.get("target_model_id")

        if not target_model_id:
            return Response(
                {"error": "target_model_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(target_model_id) == str(threat_model.id):
            return Response(
                {"error": "A threat model cannot reference itself"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            target_model = ThreatModel.objects.get(
                id=target_model_id,
                organization=threat_model.organization,
            )
        except ThreatModel.DoesNotExist:
            return Response(
                {"error": "Target threat model not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        from .models import ThreatModelRelationship

        ThreatModelRelationship.objects.get_or_create(
            source_threat_model=threat_model,
            target_threat_model=target_model,
            relation_type=ThreatModelRelationship.RelationType.RELATED_TO,
        )
        return Response({"status": "reference added"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def remove_referenced_model(self, request, pk=None):
        """Remove a referenced threat model relationship."""
        from .models import ThreatModelRelationship

        threat_model = self.get_object()
        target_model_id = request.data.get("target_model_id")

        if not target_model_id:
            return Response(
                {"error": "target_model_id is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        deleted, _ = ThreatModelRelationship.objects.filter(
            source_threat_model=threat_model,
            target_threat_model_id=target_model_id,
            relation_type=ThreatModelRelationship.RelationType.RELATED_TO,
        ).delete()

        if deleted:
            return Response({"status": "reference removed"}, status=status.HTTP_200_OK)
        return Response(
            {"error": "Reference not found"},
            status=status.HTTP_404_NOT_FOUND,
        )

    def _serialize_taxonomy_entries(self, threat_instance):
        """Serialize taxonomy entries for a threat instance.

        Merges library-level and instance-level entries, deduplicating by
        (taxonomy_slug, external_id). Falls back to taxonomy_snapshot when
        no live entries exist.
        """
        seen = {}

        if threat_instance.threat_library:
            for join in threat_instance.threat_library.taxonomy_entries.select_related(
                "taxonomy_entry__taxonomy"
            ).all():
                entry = join.taxonomy_entry
                key = (entry.taxonomy.slug, entry.external_id)
                seen[key] = {
                    "taxonomy_slug": entry.taxonomy.slug,
                    "taxonomy_name": entry.taxonomy.name,
                    "external_id": entry.external_id,
                    "title": entry.title,
                    "reference_url": entry.reference_url,
                    "source": "library",
                }

        for link in threat_instance.instance_taxonomy_links.select_related(
            "taxonomy_entry__taxonomy"
        ).all():
            entry = link.taxonomy_entry
            key = (entry.taxonomy.slug, entry.external_id)
            if key not in seen:
                seen[key] = {
                    "taxonomy_slug": entry.taxonomy.slug,
                    "taxonomy_name": entry.taxonomy.name,
                    "external_id": entry.external_id,
                    "title": entry.title,
                    "reference_url": entry.reference_url,
                    "source": "instance",
                }

        if not seen:
            return threat_instance.taxonomy_snapshot

        return list(seen.values())

    def _serialize_standard_mappings(self, countermeasure_instance):
        """Serialize standard mappings for a countermeasure instance.

        Merges library-level and instance-level mappings. Instance mappings
        override library mappings for the same requirement.
        """
        seen = {}

        if countermeasure_instance.countermeasure_library:
            for (
                mapping
            ) in countermeasure_instance.countermeasure_library.standard_mappings.all():
                if mapping.requirement and mapping.requirement.framework:
                    req_id = mapping.requirement_id
                    seen[req_id] = {
                        "id": mapping.id,
                        "framework_name": mapping.requirement.framework.name,
                        "framework_slug": mapping.requirement.framework.slug,
                        "section_code": mapping.requirement.section_code,
                        "requirement_description": mapping.requirement.description,
                        "sufficiency": mapping.sufficiency,
                    }

        for mapping in countermeasure_instance.instance_standard_mappings.all():
            if mapping.requirement and mapping.requirement.framework:
                req_id = mapping.requirement_id
                seen[req_id] = {
                    "id": mapping.id,
                    "framework_name": mapping.requirement.framework.name,
                    "framework_slug": mapping.requirement.framework.slug,
                    "section_code": mapping.requirement.section_code,
                    "requirement_description": mapping.requirement.description,
                    "sufficiency": mapping.sufficiency,
                }
            else:
                seen[f"snapshot_{mapping.id}"] = {
                    "id": mapping.id,
                    "framework_name": mapping.framework_name,
                    "framework_slug": "",
                    "section_code": mapping.section_code,
                    "requirement_description": mapping.requirement_description,
                    "sufficiency": mapping.sufficiency,
                }

        return list(seen.values())

    def _serialize_countermeasures_from_links(self, links, current_threat):
        """Serialize countermeasures from junction table links, including also_mitigates."""
        from apps.threats.models import CountermeasureThreatLink

        result = []
        for link in links:
            cm = link.countermeasure
            # Find other threats this countermeasure also mitigates (across both types)
            other_links = (
                CountermeasureThreatLink.objects.filter(countermeasure=cm)
                .exclude(id=link.id)
                .select_related(
                    "component_threat__component",
                    "component_threat__threat_library",
                    "flow_threat__data_flow__source_component",
                    "flow_threat__data_flow__dest_component",
                    "flow_threat__threat_library",
                )
            )

            also_mitigates = []
            for other_link in other_links:
                other_threat = other_link.component_threat or other_link.flow_threat
                if not other_threat:
                    continue

                # Build display name: component name for component threats,
                # flow label (or "source → dest" fallback) for flow threats
                if hasattr(other_threat, "component") and other_threat.component:
                    display_name = other_threat.component.name
                elif hasattr(other_threat, "data_flow") and other_threat.data_flow:
                    df = other_threat.data_flow
                    if df.label:
                        display_name = df.label
                    else:
                        source = (
                            df.source_component.name if df.source_component else "?"
                        )
                        dest = df.dest_component.name if df.dest_component else "?"
                        display_name = f"{source} \u2192 {dest}"
                else:
                    display_name = None

                also_mitigates.append(
                    {
                        "threat_id": other_threat.id,
                        "threat_type": "component"
                        if other_link.component_threat
                        else "flow",
                        "threat_name": other_threat.threat_name
                        or (
                            other_threat.threat_library.name
                            if other_threat.threat_library
                            else None
                        ),
                        "component_name": display_name,
                    }
                )

            result.append(
                {
                    "id": cm.id,
                    "countermeasure_library_id": cm.countermeasure_library_id,
                    "countermeasure_name": (
                        cm.countermeasure_library.name
                        if cm.countermeasure_library
                        else None
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
                    "due_date": cm.due_date,
                    "external_ticket_url": cm.external_ticket_url,
                    "evidence_url": cm.evidence_url,
                    "assigned_owner_email": cm.assigned_owner.email
                    if cm.assigned_owner
                    else None,
                    "verified_by_email": cm.verified_by.email
                    if cm.verified_by
                    else None,
                    "standard_mappings": self._serialize_standard_mappings(cm),
                    "display_order": link.display_order,
                    "is_inherited": cm.is_inherited,
                    "inherited_from_component_name": cm.inherited_from_component_name,
                    "inherited_from_zone_name": cm.inherited_from_zone_name,
                    "also_mitigates": also_mitigates,
                }
            )
        return result

    @action(detail=True, methods=["get"], url_path="countermeasures-in-use")
    def countermeasures_in_use(self, request, pk=None):
        """List all countermeasure instances active in this threat model."""
        from apps.threats.models import InstanceCountermeasure

        threat_model = self.get_object()
        countermeasures = (
            InstanceCountermeasure.objects.filter(threat_model=threat_model)
            .select_related("countermeasure_library", "assigned_owner")
            .prefetch_related(
                "threat_links__component_threat__component",
                "threat_links__component_threat__threat_library",
                "threat_links__flow_threat__data_flow",
                "threat_links__flow_threat__threat_library",
            )
        )

        result = []
        for cm in countermeasures:
            linked_threats = []
            for link in cm.threat_links.all():
                threat = link.component_threat or link.flow_threat
                if not threat:
                    continue
                linked_threats.append(
                    {
                        "threat_id": threat.id,
                        "threat_name": threat.threat_name
                        or (
                            threat.threat_library.name
                            if threat.threat_library
                            else None
                        ),
                        "component_name": (
                            threat.component.name
                            if hasattr(threat, "component") and threat.component
                            else None
                        ),
                        "flow_label": (
                            threat.data_flow.label
                            if hasattr(threat, "data_flow") and threat.data_flow
                            else None
                        ),
                    }
                )
            result.append(
                {
                    "id": cm.id,
                    "countermeasure_name": (
                        cm.countermeasure_library.name
                        if cm.countermeasure_library
                        else None
                    )
                    or cm.countermeasure_name,
                    "countermeasure_library_id": cm.countermeasure_library_id,
                    "status": cm.status,
                    "assigned_owner_email": cm.assigned_owner.email
                    if cm.assigned_owner
                    else None,
                    "linked_threats": linked_threats,
                }
            )

        return Response(
            {
                "threat_model_id": str(threat_model.id),
                "countermeasures": result,
                "total_count": len(result),
            }
        )

    @action(detail=True, methods=["get"])
    def threats(self, request, pk=None):
        """
        Get all threats for this threat model, aggregated from all DFDs.

        Returns both component threats and data flow threats with their countermeasures.
        """
        from apps.systems.models import DataFlow, OrgsystemComponent
        from apps.threats.models import (
            ComponentInstanceThreat,
            CountermeasureThreatLink,
            DataFlowInstanceThreat,
        )

        threat_model = self.get_object()

        # Get all DFDs for this threat model (direct FK)
        dfds = threat_model.dfds.all()

        # Build node_id -> component_id mapping and edge_id -> dataflow_id mapping from all DFDs
        node_component_map = {}
        edge_dataflow_map = {}
        for dfd in dfds:
            canvas_data = dfd.canvas_data or {}
            for node in canvas_data.get("nodes", []):
                node_id = node.get("id")
                node_data = node.get("data", {})
                component_id = node_data.get("component_id")
                if node_id and component_id:
                    node_component_map[node_id] = {
                        "component_id": component_id,
                        "dfd_id": str(dfd.id),
                        "dfd_name": dfd.name,
                    }
            for edge in canvas_data.get("edges", []):
                edge_id = edge.get("id")
                dataflow_id = edge.get("data", {}).get("dataflow_id")
                if edge_id and dataflow_id:
                    edge_dataflow_map[edge_id] = {
                        "dataflow_id": dataflow_id,
                        "dfd_id": str(dfd.id),
                        "dfd_name": dfd.name,
                    }

        # Get all component IDs and dataflow IDs from canvas nodes
        component_ids = [v["component_id"] for v in node_component_map.values()]
        dataflow_ids = [v["dataflow_id"] for v in edge_dataflow_map.values()]

        # Also include analysis-only components (linked directly to threat model, not via DFD canvas)
        analysis_only_components = OrgsystemComponent.objects.filter(
            threat_model=threat_model
        ).exclude(
            id__in=component_ids  # Exclude components already on canvas
        )

        # Add analysis-only components to the node_component_map with synthetic node IDs
        for comp in analysis_only_components:
            synthetic_node_id = f"analysis-{comp.id}"
            node_component_map[synthetic_node_id] = {
                "component_id": comp.id,
                "dfd_id": None,
                "dfd_name": None,
                "is_analysis_only": True,
            }
            component_ids.append(comp.id)

        # Also include data flows connected to analysis-only components
        analysis_flows = (
            DataFlow.objects.filter(
                Q(source_component_id__in=component_ids)
                | Q(dest_component_id__in=component_ids)
            )
            .exclude(id__in=dataflow_ids)
            .select_related("source_component", "dest_component")
            .distinct()
        )

        for flow in analysis_flows:
            synthetic_edge_id = f"analysis-flow-{flow.id}"
            edge_dataflow_map[synthetic_edge_id] = {
                "dataflow_id": flow.id,
                "dfd_id": None,
                "dfd_name": None,
                "is_analysis_only": True,
                "label": flow.label,
                "source_component_name": flow.source_component.name
                if flow.source_component
                else "",
                "dest_component_name": flow.dest_component.name
                if flow.dest_component
                else "",
            }
            dataflow_ids.append(flow.id)

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

        # Fetch all component threats with countermeasures via junction table
        component_threats = (
            ComponentInstanceThreat.objects.filter(component_id__in=component_ids)
            .select_related("component", "threat_library")
            .prefetch_related(
                "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
                "instance_taxonomy_links__taxonomy_entry__taxonomy",
                countermeasure_links_prefetch,
            )
        )

        # Fetch all data flow threats with countermeasures via junction table
        flow_threats = (
            DataFlowInstanceThreat.objects.filter(data_flow_id__in=dataflow_ids)
            .select_related(
                "data_flow",
                "data_flow__source_component",
                "data_flow__dest_component",
                "threat_library",
            )
            .prefetch_related(
                "threat_library__taxonomy_entries__taxonomy_entry__taxonomy",
                "instance_taxonomy_links__taxonomy_entry__taxonomy",
                countermeasure_links_prefetch,
            )
        )

        # Build response with component threats
        result = []
        for threat in component_threats:
            # Find which node this component corresponds to
            node_info = None
            for node_id, info in node_component_map.items():
                if info["component_id"] == threat.component_id:
                    node_info = {"node_id": node_id, **info}
                    break

            threat_data = {
                "id": threat.id,
                "type": "component",
                "component_id": threat.component_id,
                "component_name": threat.component.name if threat.component else None,
                "node_id": node_info["node_id"] if node_info else None,
                "dfd_id": node_info["dfd_id"] if node_info else None,
                "dfd_name": node_info["dfd_name"] if node_info else None,
                "threat_library_id": threat.threat_library_id,
                "threat_name": threat.threat_name
                or (threat.threat_library.name if threat.threat_library else None),
                "threat_description": threat.threat_description
                or (
                    threat.threat_library.description if threat.threat_library else None
                ),
                "taxonomy_entries": self._serialize_taxonomy_entries(threat),
                "inherent_severity": threat.inherent_severity,
                "residual_severity": threat.residual_severity,
                "status": threat.status,
                "severity_scoring_metadata": threat.severity_scoring_metadata,
                "triage_status": threat.triage_status,
                "decision_rationale": threat.decision_rationale,
                "display_order": threat.display_order,
                "impact_description": threat.impact_description,
                "threat_actor_text": threat.threat_actor_text,
                "countermeasures": self._serialize_countermeasures_from_links(
                    threat.countermeasure_links.all(), threat
                ),
            }
            result.append(threat_data)

        # Add data flow threats to the response
        for threat in flow_threats:
            edge_info = None
            for edge_id, info in edge_dataflow_map.items():
                if info["dataflow_id"] == threat.data_flow_id:
                    edge_info = {"edge_id": edge_id, **info}
                    break

            # Build a descriptive label for the data flow
            flow = threat.data_flow
            if flow and flow.label:
                flow_display_label = flow.label
            elif flow and flow.source_component and flow.dest_component:
                flow_display_label = (
                    f"{flow.source_component.name} \u2192 {flow.dest_component.name}"
                )
            else:
                flow_display_label = None

            threat_data = {
                "id": threat.id,
                "type": "dataflow",
                "dataflow_id": threat.data_flow_id,
                "dataflow_label": flow_display_label,
                "edge_id": edge_info["edge_id"] if edge_info else None,
                "node_id": edge_info["edge_id"] if edge_info else None,
                "component_id": threat.data_flow_id,
                "component_name": flow_display_label,
                "dfd_id": edge_info["dfd_id"] if edge_info else None,
                "dfd_name": edge_info["dfd_name"] if edge_info else None,
                "threat_library_id": threat.threat_library_id,
                "threat_name": threat.threat_name
                or (threat.threat_library.name if threat.threat_library else None),
                "threat_description": threat.threat_description
                or (
                    threat.threat_library.description if threat.threat_library else None
                ),
                "taxonomy_entries": self._serialize_taxonomy_entries(threat),
                "inherent_severity": threat.inherent_severity,
                "residual_severity": threat.residual_severity,
                "status": threat.status,
                "severity_scoring_metadata": threat.severity_scoring_metadata,
                "triage_status": threat.triage_status,
                "decision_rationale": threat.decision_rationale,
                "display_order": threat.display_order,
                "impact_description": threat.impact_description,
                "threat_actor_text": threat.threat_actor_text,
                "countermeasures": self._serialize_countermeasures_from_links(
                    threat.countermeasure_links.all(), threat
                ),
            }
            result.append(threat_data)

        return Response(
            {
                "threat_model_id": str(threat_model.id),
                "threats": result,
                "total_count": len(result),
                "node_component_map": node_component_map,
                "edge_dataflow_map": edge_dataflow_map,
            }
        )

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """Get complete report data for this threat model."""
        from .report_service import build_report_data

        threat_model = self.get_object()
        data = build_report_data(threat_model)
        return Response(data)

    @action(detail=True, methods=["get"])
    def zone_protections(self, request, pk=None):
        """Analyze zone topology and return inheritance suggestions."""
        from apps.threats.zone_protections import analyze_zone_protections

        threat_model = self.get_object()
        suggestions = analyze_zone_protections(threat_model)
        return Response(
            {
                "suggestions": suggestions,
                "total_count": len(suggestions),
            }
        )

    @action(detail=True, methods=["post"])
    def apply_zone_protections(self, request, pk=None):
        """Apply selected zone inheritance suggestions."""
        from apps.threats.zone_protections import apply_zone_protections

        self.get_object()  # Permission check
        items = request.data.get("items", [])
        result = apply_zone_protections(items)
        return Response(result)

    @action(detail=True, methods=["get"])
    def compliance_drift(self, request, pk=None):
        """Check for compliance drift between instance and library mappings."""
        from apps.threat_models.compliance_service import check_compliance_drift

        threat_model = self.get_object()
        result = check_compliance_drift(threat_model)
        return Response(result)

    @action(detail=True, methods=["post"])
    def refresh_compliance(self, request, pk=None):
        """Sync instance compliance mappings with library sources."""
        from apps.threat_models.compliance_service import refresh_compliance_standards

        threat_model = self.get_object()
        result = refresh_compliance_standards(threat_model)
        return Response(result)

    @action(
        detail=False,
        methods=["post"],
        url_path="import/tm-library",
        parser_classes=[MultiPartParser, JSONParser],
    )
    def import_tm_library(self, request):
        """Import a TM-Library format JSON file as a new threat model."""
        from .adapters import TmLibraryAdapter

        # Get organization from user's membership
        first_membership = request.user.organization_memberships.first()
        if not first_membership:
            return Response(
                {"detail": "User has no organization membership."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        organization = first_membership.organization

        # Accept either file upload or JSON body
        if "file" in request.FILES:
            uploaded_file = request.FILES["file"]
            try:
                json_data = json.loads(uploaded_file.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return Response(
                    {
                        "detail": (
                            "Could not parse the uploaded file as JSON. "
                            "Check that it is a valid JSON file and try again."
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif request.content_type and "json" in request.content_type:
            json_data = request.data
        else:
            return Response(
                {
                    "detail": "Provide a JSON file upload (field: 'file') or a JSON body."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        adapter = TmLibraryAdapter()
        try:
            threat_model, summary = adapter.import_data(
                json_data, organization, request.user
            )
        except ValidationError as e:
            detail = str(e)
            if hasattr(e, "detail"):
                detail = (
                    e.detail.get("detail", str(e.detail))
                    if isinstance(e.detail, dict)
                    else str(e.detail)
                )
            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("Unexpected error during TM-Library import")
            return Response(
                {
                    "detail": (
                        "An unexpected error occurred during import. "
                        "This is likely a bug. Please try again or contact support."
                    ),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "threat_model": {
                    "id": str(threat_model.id),
                    "name": threat_model.name,
                },
                "summary": summary,
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"], url_path="export/tm-library")
    def export_tm_library(self, request, pk=None):
        """Export a threat model as TM-Library format JSON."""
        from .adapters import TmLibraryAdapter

        threat_model = self.get_object()
        adapter = TmLibraryAdapter()
        export_data = adapter.export_data(threat_model)

        import re

        response = JsonResponse(export_data, json_dumps_params={"indent": 2})
        safe_name = re.sub(r"[^a-z0-9\-]", "-", threat_model.name.lower())
        safe_name = re.sub(r"-{2,}", "-", safe_name).strip("-")
        suffix = "" if safe_name.endswith("-threat-model") else "-threat-model"
        filename = f"{safe_name}{suffix}.json"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @action(
        detail=False,
        methods=["post"],
        url_path="import/cyclonedx",
        parser_classes=[MultiPartParser, JSONParser],
    )
    def import_cyclonedx(self, request):
        """Import a CycloneDX 2.0 TM-BOM JSON file as a new threat model."""
        from .adapters import CycloneDxAdapter

        first_membership = request.user.organization_memberships.first()
        if not first_membership:
            return Response(
                {"detail": "User has no organization membership."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        organization = first_membership.organization

        if "file" in request.FILES:
            uploaded_file = request.FILES["file"]
            try:
                json_data = json.loads(uploaded_file.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return Response(
                    {
                        "detail": (
                            "Could not parse the uploaded file as JSON. "
                            "Check that it is a valid JSON file and try again."
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif request.content_type and "json" in request.content_type:
            json_data = request.data
        else:
            return Response(
                {
                    "detail": "Provide a JSON file upload (field: 'file') or a JSON body."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        from .adapters.cyclonedx import TmBomImportError

        adapter = CycloneDxAdapter()
        try:
            threat_model, summary = adapter.import_data(
                json_data, organization, request.user
            )
        except (TmBomImportError, ValidationError) as e:
            detail = str(e)
            if hasattr(e, "detail"):
                detail = (
                    e.detail.get("detail", str(e.detail))
                    if isinstance(e.detail, dict)
                    else str(e.detail)
                )
            return Response(
                {"detail": detail},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception:
            logger.exception("Unexpected error during CycloneDX import")
            return Response(
                {
                    "detail": (
                        "An unexpected error occurred during import. "
                        "This is likely a bug. Please try again or contact support."
                    ),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "threat_model": {
                    "id": str(threat_model.id),
                    "name": threat_model.name,
                },
                "summary": summary,
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"], url_path="export/cyclonedx")
    def export_cyclonedx(self, request, pk=None):
        """Export a threat model as CycloneDX 2.0 TM-BOM JSON."""
        from .adapters import CycloneDxAdapter

        threat_model = self.get_object()
        adapter = CycloneDxAdapter()
        export_data = adapter.export_data(threat_model)

        import re

        response = JsonResponse(export_data, json_dumps_params={"indent": 2})
        safe_name = re.sub(r"[^a-z0-9\-]", "-", threat_model.name.lower())
        safe_name = re.sub(r"-{2,}", "-", safe_name).strip("-")
        filename = f"{safe_name}-cyclonedx-tm-bom.cdx.json"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


class ThreatModelReferenceImageViewSet(viewsets.ModelViewSet):
    """ViewSet for managing threat model reference images."""

    permission_classes = [IsAuthenticated, CanWrite]
    serializer_class = ThreatModelReferenceImageSerializer

    def get_queryset(self):
        """Filter by user's organization access and specific threat model."""
        user = self.request.user
        user_orgs = user.organization_memberships.values_list(
            "organization_id", flat=True
        )

        queryset = ThreatModelReferenceImage.objects.filter(
            threat_model__organization_id__in=user_orgs
        ).select_related("threat_model", "uploaded_by")

        # Filter by threat_model if accessed via nested route
        threat_model_id = self.kwargs.get("threat_model_pk")
        if threat_model_id:
            queryset = queryset.filter(threat_model_id=threat_model_id)

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action in ["create", "upload_for_threat_model"]:
            return ThreatModelReferenceImageUploadSerializer
        return ThreatModelReferenceImageSerializer

    def perform_create(self, serializer):
        """Set uploaded_by to current user."""
        serializer.save(uploaded_by=self.request.user)

    @action(detail=False, methods=["post"], url_path="upload")
    def upload_for_threat_model(self, request, threat_model_pk=None):
        """Upload a reference image for a specific threat model."""
        from django.shortcuts import get_object_or_404

        threat_model = get_object_or_404(ThreatModel, pk=threat_model_pk)

        # Verify user has access to this threat model's organization
        user_orgs = request.user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        if threat_model.organization_id not in user_orgs:
            return Response(
                {"detail": "Not authorized"}, status=status.HTTP_403_FORBIDDEN
            )

        serializer = ThreatModelReferenceImageUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        image = serializer.save(
            threat_model=threat_model,
            uploaded_by=request.user,
        )

        return Response(
            ThreatModelReferenceImageSerializer(
                image, context={"request": request}
            ).data,
            status=status.HTTP_201_CREATED,
        )


class OutOfScopeItemViewSet(viewsets.ModelViewSet):
    """ViewSet for OutOfScopeItem CRUD, nested under threat models."""

    serializer_class = OutOfScopeItemSerializer
    permission_classes = [IsAuthenticated, CanWrite]

    def get_queryset(self):
        """Filter by threat model and user's organization."""
        user = self.request.user
        org_ids = user.organization_memberships.values_list(
            "organization_id", flat=True
        )
        return OutOfScopeItem.objects.filter(
            threat_model_id=self.kwargs["threat_model_pk"],
            threat_model__organization_id__in=org_ids,
        )

    def perform_create(self, serializer):
        """Set threat_model from URL kwargs."""
        serializer.save(threat_model_id=self.kwargs["threat_model_pk"])
