"""Compliance matrix endpoint.

Renders one row per StandardRequirement, showing every InstanceCountermeasure
and every ComponentInstanceThreat/DataFlowInstanceThreat linked to that
requirement inside a single ThreatModel, grouped by control family
(AC, AU, CM, ...).

Ported from ``TTSE-petrified-forest-sspp/scripts/prototypes/compliance_matrix/``
and adapted to the real Precogly model surface:

* Countermeasure -> requirement linkage lives on
  ``InstanceCountermeasureStandard`` (reverse manager
  ``instance_standard_mappings`` on ``InstanceCountermeasure``), not
  ``ic.standards``.
* Threat -> countermeasure linkage lives on ``CountermeasureThreatLink``
  (reverse manager ``countermeasure_links`` on the threat, ``threat_links``
  on the CM), not ``threat_countermeasures``.
* Fallback control ID is read from
  ``InstanceCountermeasure.format_metadata['cyclonedx']['ctrl_id']`` (matches
  the CycloneDX importer).

Access control uses ``ThreatModel.objects.visible_to(user)`` so the endpoint
respects the read boundary already enforced by threat-model viewsets, and any
tenant crossing the boundary receives a 404.
"""

from __future__ import annotations

from collections import defaultdict

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.threat_models.models import ThreatModel
from apps.threats.models import (
    ComponentInstanceThreat,
    CountermeasureThreatLink,
    DataFlowInstanceThreat,
    InstanceCountermeasure,
)

from .models import StandardFramework

DEFAULT_FRAMEWORK_NAME = "NIST 800-53 Rev 5"


def _family(section_code: str) -> str:
    return section_code.split("-", 1)[0] if "-" in section_code else section_code


def _resolve_framework(name_query: str) -> StandardFramework | None:
    return StandardFramework.objects.filter(name__icontains=name_query).first()


def _index_countermeasures(
    tm: ThreatModel,
) -> dict[str, list[InstanceCountermeasure]]:
    """Return ``{section_code: [InstanceCountermeasure, ...]}`` for one TM.

    Uses the instance-level mapping table when present, and falls back to the
    ``format_metadata['cyclonedx']['ctrl_id']`` value written by the CycloneDX
    importer.
    """
    idx: dict[str, list[InstanceCountermeasure]] = defaultdict(list)
    cms = (
        tm.countermeasures.all()
        .prefetch_related("instance_standard_mappings")
        .order_by("countermeasure_name")
    )
    for ic in cms:
        seen: set[str] = set()
        for mapping in ic.instance_standard_mappings.all():
            code = mapping.section_code
            if code and code not in seen:
                idx[code].append(ic)
                seen.add(code)
        fm = ic.format_metadata or {}
        cdx = fm.get("cyclonedx") or {}
        cid = cdx.get("ctrl_id") or cdx.get("ctrlId")
        if cid and cid not in seen:
            idx[cid].append(ic)
            base = cid.split("(", 1)[0]
            if base != cid and base not in seen:
                idx[base].append(ic)
    return idx


def _index_threats(
    tm: ThreatModel,
) -> dict[str, list[ComponentInstanceThreat | DataFlowInstanceThreat]]:
    """Return ``{section_code: [threat, ...]}`` for one TM.

    A threat is linked to a countermeasure through ``CountermeasureThreatLink``;
    the countermeasure carries the requirement via
    ``instance_standard_mappings``. Component-scoped and data-flow-scoped
    threats are collected together, deduped per section code.
    """
    idx: dict[str, list[ComponentInstanceThreat | DataFlowInstanceThreat]] = (
        defaultdict(list)
    )
    seen_per_section: dict[str, set[tuple[str, int]]] = defaultdict(set)

    links = (
        CountermeasureThreatLink.objects.filter(countermeasure__threat_model=tm)
        .select_related(
            "countermeasure",
            "component_threat",
            "flow_threat",
        )
        .prefetch_related("countermeasure__instance_standard_mappings")
    )
    for link in links:
        threat = link.component_threat or link.flow_threat
        if threat is None:
            continue
        kind = "component" if link.component_threat else "flow"
        key = (kind, threat.pk)
        for mapping in link.countermeasure.instance_standard_mappings.all():
            code = mapping.section_code
            if not code:
                continue
            if key in seen_per_section[code]:
                continue
            idx[code].append(threat)
            seen_per_section[code].add(key)
    return idx


def _threat_name(threat) -> str:
    name = getattr(threat, "threat_name", None)
    return name or str(threat)


def build_matrix(tm: ThreatModel, framework_name: str) -> dict:
    fw = _resolve_framework(framework_name)
    if fw is None:
        return {
            "threat_model": {"id": tm.id, "name": tm.name},
            "framework": None,
            "families": [],
            "warning": f"No compliance framework matches {framework_name!r}",
        }

    cm_index = _index_countermeasures(tm)
    threat_index = _index_threats(tm)

    families: dict[str, list[dict]] = defaultdict(list)
    for req in fw.requirements.all().order_by("section_code"):
        cms = cm_index.get(req.section_code, [])
        threats = threat_index.get(req.section_code, [])
        if not cms and not threats:
            continue

        cm_payload = []
        for ic in cms:
            sufficiency = (
                ic.instance_standard_mappings.filter(section_code=req.section_code)
                .values_list("sufficiency", flat=True)
                .first()
            )
            cm_payload.append(
                {
                    "id": ic.id,
                    "name": ic.countermeasure_name,
                    "status": ic.status,
                    "sufficiency": sufficiency,
                }
            )

        threat_payload = [
            {
                "id": t.id,
                "kind": (
                    "component" if isinstance(t, ComponentInstanceThreat) else "flow"
                ),
                "name": _threat_name(t),
            }
            for t in threats
        ]

        families[_family(req.section_code)].append(
            {
                "section_code": req.section_code,
                "description": req.description,
                "countermeasures": cm_payload,
                "threats": threat_payload,
            }
        )

    return {
        "threat_model": {"id": tm.id, "name": tm.name},
        "framework": {"id": fw.id, "name": fw.name},
        "families": [
            {"family": fam, "requirements": reqs}
            for fam, reqs in sorted(families.items())
        ],
    }


class ComplianceMatrixApiView(APIView):
    """JSON compliance matrix for a single threat model.

    ``GET /api/threat-models/<tm_id>/compliance-matrix/[?framework=<name>]``
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, tm_id: int):
        tm = get_object_or_404(ThreatModel.objects.visible_to(request.user), pk=tm_id)
        fw_name = request.query_params.get("framework", DEFAULT_FRAMEWORK_NAME)
        return Response(build_matrix(tm, framework_name=fw_name))
