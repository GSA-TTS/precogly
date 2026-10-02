"""Enum conversion tables for CycloneDX 2.0 TM-BOM <-> Precogly mappings."""

# ---------------------------------------------------------------------------
# Asset type  <->  Precogly component category
# ---------------------------------------------------------------------------

ASSET_TYPE_TO_CATEGORY = {
    "component": "process",
    "process": "process",
    "function": "process",
    "container": "process",
    "service": "process",
    "subsystem": "process",
    "system": "external_system_actor",
    "gateway": "process",
    "api": "process",
    "device": "process",
    "infrastructure": "process",
    "model": "process",
    "data-store": "datastore",
    "cache": "datastore",
    "queue": "datastore",
    "stream": "datastore",
    "actor": "external_human_actor",
    "agent": "external_system_actor",
}

CATEGORY_TO_ASSET_TYPE = {
    "process": "component",
    "datastore": "data-store",
    "external_human_actor": "actor",
    "external_system_actor": "system",
}

# ---------------------------------------------------------------------------
# Control status
# ---------------------------------------------------------------------------

CONTROL_STATUS_TO_CDX = {
    "gap": "recommended",
    "planned": "planned",
    "in_progress": "in-progress",
    "implemented": "implemented",
    "verified": "verified",
    "waived": "rejected",
    "platform": "implemented",
    "decommissioned": "decommissioned",
}

CDX_STATUS_TO_CONTROL = {
    "recommended": "gap",
    "planned": "planned",
    "proposed": "planned",
    "approved": "planned",
    "in-progress": "in_progress",
    "implemented": "implemented",
    "verified": "verified",
    "rejected": "waived",
    "decommissioned": "decommissioned",
}

# ---------------------------------------------------------------------------
# Risk response strategy
# ---------------------------------------------------------------------------

RESPONSE_TO_CDX = {
    "accept": "accept",
    "mitigate": "reduce",
    "reduce": "reduce",
    "transfer": "transfer",
    "avoid": "avoid",
}

CDX_TO_RESPONSE = {
    "accept": "accept",
    "reduce": "reduce",
    "transfer": "transfer",
    "avoid": "avoid",
}

# ---------------------------------------------------------------------------
# Risk / severity levels
# ---------------------------------------------------------------------------

LEVEL_TO_CDX = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

CDX_TO_LEVEL = {
    "none": "low",
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

SEVERITY_TO_CDX_RISK_LEVEL = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# ---------------------------------------------------------------------------
# Data store type
# ---------------------------------------------------------------------------

DATA_STORE_TYPE_TO_CDX = {
    "relational": "relational-database",
    "document": "document-store",
    "key_value": "key-value-store",
    "graph": "graph-database",
    "file": "file-system",
    "object": "object-storage",
    "cache": "cache",
    "queue": "message-queue",
}

CDX_TO_DATA_STORE_TYPE = {v: k for k, v in DATA_STORE_TYPE_TO_CDX.items()}
