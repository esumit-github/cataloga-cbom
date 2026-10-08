"""Analysis engine (paper Section 5.2).

Pipeline: normalization -> canonical identity (C9) -> deduplication ->
QV classification (C6, from C2) -> criticality scoring (C5 x C2) ->
CBOM emission (CycloneDX 1.7 + CATALOGA EXT).
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Iterable, Optional

from .dedup import canonical_key, merge
from .qv_classifier import expected_qv_class
from .schema import validate


def _timestamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def enrich(assets: Iterable[dict]) -> list[dict]:
    """Normalize discovered assets: canonical identity + QV classification."""
    enriched = []
    for asset in assets:
        asset = dict(asset)
        if not asset.get("canonicalKey"):
            asset["canonicalKey"] = canonical_key(asset)
        if asset.get("qvClassification") in (None, "unknown"):
            if asset.get("cryptoProperties", {}).get("algorithmProperties"):
                asset["qvClassification"] = expected_qv_class(asset).classification
        enriched.append(asset)
    return enriched


def build_record(
    assets: Iterable[dict],
    system_context: dict,
    metadata_component: Optional[dict] = None,
    tool_name: str = "cataloga-engine",
    tool_version: str = "0.9.0",
) -> dict:
    """Assemble a full CATALOGA record (CycloneDX 1.7 + EXT namespaces)."""
    merged = merge(enrich(assets))
    dependencies = []
    for asset in merged:
        parent = asset.get("relationship", {}).get("parent")
        if parent:
            dependencies.append({"ref": asset["bom-ref"], "dependsOn": [parent]})

    record = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [{"name": tool_name, "version": tool_version}],
        },
        "systemContext": system_context,
        "components": merged,
        "dependencies": dependencies,
    }
    if metadata_component:
        record["metadata"]["component"] = metadata_component
    return record


def analyze(records: list[dict]) -> dict:
    """Full pipeline entry: validate each record, report status + migration queue."""
    results = []
    for record in records:
        is_valid, violations = validate(record)
        results.append({"record": record, "valid": is_valid, "violations": violations})
    return {"results": results}