"""Schema + cross-element validation tests (paper Section 4.4)."""

import json
import pathlib

import pytest

from cataloga.engine import build_record
from cataloga.schema import validate, validate_cross_elements, load_schema
from cataloga.dedup import canonical_key

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _alg_asset(ref, family, algorithm, params, usage):
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": f"{algorithm}-{params or ''}",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "algorithmFamily": family,
                "algorithm": algorithm,
                "parameterSetIdentifier": params,
            },
            "usage": usage,
        },
        "locationProvenance": {"method": "test", "confidence": 1.0, "timestamp": "2026-10-06T00:00:00Z"},
        "lifecycleState": "active",
    }


def _record():
    assets = [
        _alg_asset("alg-rsa2048-1", "RSA", "RSA", "2048", "tls"),
        _alg_asset("alg-mlkem768-2", "PQC", "ML-KEM", "768", "tls-pqc"),
    ]
    return build_record(assets, {"systemClass": "enterprise", "criticality": "high"},
                        tool_name="cataloga-test")


def test_schema_loads():
    schema = load_schema()
    assert schema["$id"].endswith("cataloga-schema-v0.9.json")
    assert "systemContext" in schema["$defs"]
    assert "cryptoAsset" in schema["$defs"]


def test_built_record_is_valid():
    record = _record()
    is_valid, violations = validate(record)
    assert is_valid, violations


def test_qv_classifications_filled_by_engine():
    record = _record()
    by_ref = {c["bom-ref"]: c["qvClassification"] for c in record["components"]}
    assert by_ref["alg-rsa2048-1"] == "classical-112"
    assert by_ref["alg-mlkem768-2"] == "PQC-ready"


def test_wrong_qv_classification_is_rejected():
    record = _record()
    record["components"][0]["qvClassification"] = "PQC-ready"  # not derivable from RSA-2048
    is_valid, violations = validate(record)
    assert not is_valid
    assert any("not derivable from C2" in v for v in violations)


def test_missing_required_field_is_rejected():
    record = _record()
    del record["components"][0]["qvClassification"]
    is_valid, violations = validate(record)
    assert not is_valid
    assert any(v.startswith("schema:") for v in violations)


def test_duplicate_canonical_key_is_rejected():
    record = _record()
    record["components"][1]["canonicalKey"] = record["components"][0]["canonicalKey"]
    violations = validate_cross_elements(record)
    assert any("duplicate canonicalKey" in v for v in violations)


def test_unresolved_dependency_is_rejected():
    record = _record()
    record["dependencies"].append({"ref": "x", "dependsOn": ["does-not-exist"]})
    violations = validate_cross_elements(record)
    assert any("unresolved bom-ref" in v for v in violations)


def test_canonical_key_matches_schema_pattern():
    asset = _alg_asset("a", "RSA", "RSA", "2048", "tls")
    key = canonical_key(asset)
    assert len(key.split(":", 1)[1]) == 64
    import re
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", key)


def test_shipped_examples_are_valid():
    """The corpus artifacts shipped in examples/ must validate end-to-end."""
    examples = ROOT / "examples"
    if not examples.exists():
        pytest.skip("examples/ not generated yet")
    for path in sorted(examples.glob("*-cbom.json")):
        record = json.loads(path.read_text())
        is_valid, violations = validate(record)
        assert is_valid, f"{path.name}: {violations}"