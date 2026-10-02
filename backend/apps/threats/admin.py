from django.contrib import admin

from .models import (
    ComponentInstanceThreat,
    ComponentLibraryThreat,
    CountermeasureLibrary,
    DataFlowInstanceThreat,
    ExternalTaxonomy,
    InstanceCountermeasure,
    InstanceThreatTaxonomyEntry,
    PentestFinding,
    Risk,
    RiskThreat,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatLibraryTaxonomyEntry,
    ThreatPersona,
    ThreatPersonaLink,
    ThreatSource,
    ThreatSourceLink,
    VerificationTest,
)


@admin.register(ThreatLibrary)
class ThreatLibraryAdmin(admin.ModelAdmin):
    list_display = ["name", "source_pack"]
    list_filter = ["source_pack"]
    search_fields = ["name", "description"]


@admin.register(ComponentLibraryThreat)
class ComponentLibraryThreatAdmin(admin.ModelAdmin):
    list_display = [
        "component_library",
        "threat_library",
        "default_severity",
        "applies_to",
    ]
    list_filter = ["applies_to", "default_severity"]


@admin.register(CountermeasureLibrary)
class CountermeasureLibraryAdmin(admin.ModelAdmin):
    list_display = ["name", "control_nature", "cost"]
    list_filter = ["control_nature", "cost"]
    search_fields = ["name", "description"]


@admin.register(ComponentInstanceThreat)
class ComponentInstanceThreatAdmin(admin.ModelAdmin):
    list_display = [
        "component",
        "threat_name",
        "threat_library",
        "status",
        "inherent_severity",
        "residual_severity",
    ]
    list_filter = ["status", "inherent_severity"]


@admin.register(DataFlowInstanceThreat)
class DataFlowInstanceThreatAdmin(admin.ModelAdmin):
    list_display = [
        "data_flow",
        "threat_name",
        "threat_library",
        "status",
        "inherent_severity",
    ]
    list_filter = ["status", "inherent_severity"]


@admin.register(InstanceCountermeasure)
class InstanceCountermeasureAdmin(admin.ModelAdmin):
    list_display = [
        "threat_model",
        "countermeasure_library",
        "status",
        "assigned_owner",
    ]
    list_filter = ["status", "required_for_release"]


@admin.register(VerificationTest)
class VerificationTestAdmin(admin.ModelAdmin):
    list_display = ["name", "method", "passed", "last_run_at"]
    list_filter = ["method", "passed"]


@admin.register(ExternalTaxonomy)
class ExternalTaxonomyAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "version"]
    search_fields = ["name", "slug"]


@admin.register(TaxonomyEntry)
class TaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ["taxonomy", "external_id", "title"]
    list_filter = ["taxonomy"]
    search_fields = ["external_id", "title"]


@admin.register(ThreatLibraryTaxonomyEntry)
class ThreatLibraryTaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ["threat_library", "taxonomy_entry"]
    list_filter = ["taxonomy_entry__taxonomy"]


@admin.register(PentestFinding)
class PentestFindingAdmin(admin.ModelAdmin):
    list_display = [
        "finding_description",
        "severity",
        "reconciliation_status",
        "threat_model",
    ]
    list_filter = ["reconciliation_status", "severity"]


@admin.register(Risk)
class RiskAdmin(admin.ModelAdmin):
    list_display = ["name", "threat_model", "inherent_level", "residual_level", "owner"]
    list_filter = ["inherent_level", "residual_level"]
    search_fields = ["name", "description"]


@admin.register(RiskThreat)
class RiskThreatAdmin(admin.ModelAdmin):
    list_display = ["risk", "component_threat", "flow_threat"]
    list_filter = ["risk__threat_model"]


@admin.register(ThreatPersona)
class ThreatPersonaAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "symbolic_name",
        "threat_model",
        "is_person",
        "malicious_intent",
    ]
    list_filter = ["is_person", "malicious_intent"]
    search_fields = ["name", "symbolic_name"]


@admin.register(ThreatPersonaLink)
class ThreatPersonaLinkAdmin(admin.ModelAdmin):
    list_display = ["persona", "component_threat", "flow_threat"]


@admin.register(ThreatSource)
class ThreatSourceAdmin(admin.ModelAdmin):
    list_display = ["name", "slug"]
    search_fields = ["name", "slug"]


@admin.register(ThreatSourceLink)
class ThreatSourceLinkAdmin(admin.ModelAdmin):
    list_display = ["source", "component_threat", "flow_threat"]


@admin.register(InstanceThreatTaxonomyEntry)
class InstanceThreatTaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ["taxonomy_entry", "component_threat", "flow_threat"]
    list_filter = ["taxonomy_entry__taxonomy"]
