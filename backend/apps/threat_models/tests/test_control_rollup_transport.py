"""Rollup metadata is preserved for authenticated readers, not recomputed."""

from types import SimpleNamespace

from apps.threat_models.tmbom.passthrough import (
    keep_document_level,
    restore_document_level,
)


def test_rollup_metadata_transport_preserves_current_and_legacy_keys():
    for name in ("resp:control-rollup", "crm:control-rollup"):
        properties = [
            {
                "name": name,
                "value": '[{"control_id":"AC-1","aggregate_status":"recommended","cm_count":2}]',
            }
        ]
        model = SimpleNamespace(format_metadata={})
        keep_document_level(model, {"metadata": {"properties": properties}})
        assert (
            model.format_metadata["cyclonedx"]["passthrough"]["metadata"]["properties"]
            == properties
        )
        exported = {"metadata": {}}
        restore_document_level(exported, model, stale=set(), warnings=[])
        assert exported["metadata"]["properties"] == properties
