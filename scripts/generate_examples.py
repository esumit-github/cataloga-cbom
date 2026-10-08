"""Generate the CATALOGA example corpus with the SAME engine that validates it.

Guarantees the shipped examples are always conformant (schema + cross-element):
canonicalKeys and qvClassifications are produced by cataloga.dedup /
cataloga.qv_classifier, then written to examples/ as static JSON artifacts.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cataloga.engine import build_record
from cataloga.schema import validate

OUT = pathlib.Path(__file__).resolve().parent.parent / "examples"
OUT.mkdir(exist_ok=True)
(OUT / "ground-truth").mkdir(exist_ok=True)


def _alg_asset(ref, name, family, algorithm, params, usage, method="example-corpus",
               confidence=1.0, bits=None):
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "algorithmFamily": family,
                "algorithm": algorithm,
                "parameterSetIdentifier": params,
                "securityLevel": bits,
            },
            "usage": usage,
        },
        "locationProvenance": {"method": method, "confidence": confidence,
                               "timestamp": "2026-10-06T00:00:00Z"},
        "lifecycleState": "active",
    }


def _cert_asset(ref, name, family, algorithm, params, issuer, subject, usage="tls"):
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": {
            "assetType": "certificate",
            "algorithmProperties": {
                "algorithmFamily": family,
                "algorithm": algorithm,
                "parameterSetIdentifier": params,
            },
            "usage": usage,
            "certificateProperties": {
                "issuer": issuer, "subject": subject, "notValidAfter": "2027-03-01",
                "renewal": {"mechanism": "ACME", "renewBeforeDays": 30},
            },
        },
        "locationProvenance": {"method": "example-corpus", "confidence": 1.0,
                               "timestamp": "2026-10-06T00:00:00Z"},
        "lifecycleState": "active",
    }


def build_vran_edge() -> dict:
    """The paper Section 4.3 worked example, as a fully conformant record."""
    assets = [
        _alg_asset("alg-rsa2048-0001", "RSA-2048", "RSA", "RSA", "2048",
                   "TLS-1.2-key-establishment", bits=2048),
        _cert_asset("cert-edge1-0002", "TLS Server Cert (edge-1)", "RSA", "RSA", "2048",
                    "CN=Edge CA", "CN=edge-1"),
        _alg_asset("alg-mlkem768-0003", "ML-KEM-768", "PQC", "ML-KEM", "768",
                   "TLS-1.3-pqc-key-establishment", bits=0),
        _alg_asset("alg-x25519mlkem-0004", "X25519MLKEM768", "PQC", "X25519MLKEM768", "768",
                   "hybrid-key-agreement", bits=0),
        _alg_asset("alg-aes256-0005", "AES-256-GCM", "AES", "AES-256-GCM", "256",
                   "record-protection", bits=256),
    ]
    # Hierarchy: cert -> alg; alg assets -> system.
    assets[1]["relationship"] = {"parent": "system-vran-edge-1"}
    record = build_record(
        assets,
        system_context={"systemClass": "telecom", "criticality": "high",
                        "boundary": "enterprise-edge", "migrationWindow": "2028-2030"},
        metadata_component={"type": "application", "bom-ref": "system-vran-edge-1",
                            "name": "vRAN Edge Cluster A"},
        tool_name="cataloga-example-generator",
    )
    record["vulnerabilities"] = [{
        "bom-ref": "vuln-rsa2048-0001",
        "id": "PQC-MIGRATION-RSA2048",
        "analysis": {
            "state": "exploitable",
            "detail": "key establishment vulnerable post-2030 (NIST IR 8547: 112-bit deprecated after 2030, disallowed after 2035)",
            "remediation": {"recommendation": "migrate to ML-KEM-768 hybrid by 2030",
                            "priority": "high", "window": "2028-2030"},
        },
    }]
    return record


def build_enterprise_web() -> dict:
    assets = [
        _alg_asset("alg-rsa3072-0101", "RSA-3072", "RSA", "RSA", "3072",
                   "TLS-1.2-key-establishment", bits=3072),
        _cert_asset("cert-web01-0102", "TLS Server Cert (web-01)", "RSA", "RSA", "3072",
                    "CN=WebRoot CA", "CN=web-01"),
        _alg_asset("alg-ed25519-0103", "Ed25519", "EdDSA", "Ed25519", "256",
                   "code-signing", bits=256),
        _alg_asset("alg-mldsa65-0104", "ML-DSA-65", "PQC", "ML-DSA", "65",
                   "signature-pqc-pilot", bits=0),
        _alg_asset("alg-aes128-0105", "AES-128-GCM", "AES", "AES-128-GCM", "128",
                   "record-protection", bits=128),
    ]
    assets[1]["relationship"] = {"parent": "system-web-farm-1"}
    return build_record(
        assets,
        system_context={"systemClass": "enterprise", "criticality": "medium",
                        "boundary": "dmz", "migrationWindow": "2028-2030"},
        metadata_component={"type": "application", "bom-ref": "system-web-farm-1",
                            "name": "Public Web Farm"},
        tool_name="cataloga-example-generator",
    )


def build_ground_truth() -> dict:
    """Ground-truth corpus (paper Section 5.4): the assets every generator MUST find."""
    records = [build_vran_edge(), build_enterprise_web()]
    assets = []
    for record in records:
        for component in record["components"]:
            assets.append({
                "bom-ref": component["bom-ref"],
                "name": component["name"],
                "canonicalKey": component["canonicalKey"],
                "qvClassification": component["qvClassification"],
                "cryptoProperties": {"assetType": component["cryptoProperties"]["assetType"]},
                "present": True,
            })
    return {"corpus": "corpus-v1", "description": "CATALOGA ground-truth corpus v1",
            "assets": assets}


def main():
    examples = {
        "vran-edge-cbom.json": build_vran_edge(),
        "enterprise-web-cbom.json": build_enterprise_web(),
    }
    for name, record in examples.items():
        is_valid, violations = validate(record)
        assert is_valid, f"{name} failed validation: {violations}"
        (OUT / name).write_text(json.dumps(record, indent=2))
        print(f"{name}: VALID ({len(record['components'])} components)")

    gt = build_ground_truth()
    (OUT / "ground-truth" / "corpus-v1.json").write_text(json.dumps(gt, indent=2))
    print(f"ground-truth/corpus-v1.json: {len(gt['assets'])} ground-truth assets")


if __name__ == "__main__":
    main()