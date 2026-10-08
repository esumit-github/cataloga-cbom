"""CATALOGA schema validator — JSON Schema (CycloneDX 1.7 superset) plus the
cross-element rules of paper Section 4.4:

  * structural conformance to cataloga-schema-v0.9.json (C1-C9 presence, shapes);
  * C6 must be derivable from C2 via the QV classifier;
  * every bom-ref referenced in dependencies must resolve;
  * canonicalKeys must be collision-free within the record;
  * bom-refs must be unique.
"""

from __future__ import annotations

import json
import pathlib
from typing import Optional

import jsonschema

from .qv_classifier import expected_qv_class

SCHEMA_PATH = pathlib.Path(__file__).resolve().parent.parent / "schemas" / "cataloga-schema-v0.9.json"

_schema_cache: Optional[dict] = None


def load_schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        with SCHEMA_PATH.open() as fh:
            _schema_cache = json.load(fh)
    return _schema_cache


def validate_record(record: dict) -> None:
    """Raise jsonschema.ValidationError if the record is structurally invalid."""
    jsonschema.validate(instance=record, schema=load_schema())


def validate_cross_elements(record: dict) -> list[str]:
    """Return a list of cross-element rule violations (empty == compliant)."""
    violations: list[str] = []

    components = record.get("components", [])
    bom_refs = [c.get("bom-ref") for c in components]
    # The system root (metadata.component.bom-ref) is a valid resolution target.
    root_ref = record.get("metadata", {}).get("component", {}).get("bom-ref")
    resolvable = set(bom_refs) | ({root_ref} if root_ref else set())

    # Unique bom-refs (C1).
    seen = set()
    for ref in bom_refs:
        if ref in seen:
            violations.append(f"duplicate bom-ref: {ref}")
        seen.add(ref)

    # Unique canonicalKeys (C9).
    keys = [c.get("canonicalKey") for c in components if c.get("canonicalKey")]
    if len(keys) != len(set(keys)):
        violations.append("duplicate canonicalKey within record")

    # C6 derivable from C2.
    for c in components:
        if c.get("qvClassification") and c.get("cryptoProperties", {}).get("algorithmProperties"):
            expected = expected_qv_class(c).classification
            if expected != c["qvClassification"]:
                violations.append(
                    f"{c.get('bom-ref')}: qvClassification '{c['qvClassification']}' "
                    f"not derivable from C2 (expected '{expected}')"
                )

    # dependencies resolve.
    for dep in record.get("dependencies", []):
        for ref in dep.get("dependsOn", []):
            if ref not in resolvable and ref != dep.get("ref"):
                violations.append(f"dependencies: unresolved bom-ref '{ref}'")

    # relationship.parent resolves where present.
    for c in components:
        parent = c.get("relationship", {}).get("parent")
        if parent and parent not in resolvable and parent != c.get("bom-ref"):
            violations.append(f"{c.get('bom-ref')}: relationship.parent '{parent}' unresolved")

    return violations


def validate(record: dict) -> tuple[bool, list[str]]:
    """Full validation: schema + cross-element rules.

    Returns (is_valid, violations). Raises nothing.
    """
    try:
        validate_record(record)
    except jsonschema.ValidationError as exc:
        return False, [f"schema: {exc.message}"]
    violations = validate_cross_elements(record)
    return (len(violations) == 0, violations)