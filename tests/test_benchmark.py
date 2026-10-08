"""Benchmarking protocol tests (paper Section 5.4) — precision/recall vs ground
truth and cross-generator agreement.

Canonical identities must be computed from the SAME fingerprint structure in
both ground truth and generator output, or matching is meaningless — this is
itself a finding (it is exactly why BF-CBOM observed discrepancies).
"""

import pytest

from cataloga.benchmark import precision_recall, cross_generator_agreement
from cataloga.dedup import canonical_key


def _asset(name, family, algo, params, asset_type="algorithm"):
    fingerprint = {
        "name": name,
        "cryptoProperties": {
            "assetType": asset_type,
            "algorithmProperties": {
                "algorithmFamily": family, "algorithm": algo, "parameterSetIdentifier": params,
            },
            "usage": "tls",
        },
    }
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"ref-{name}",
        "name": name,
        "cryptoProperties": fingerprint["cryptoProperties"],
        "locationProvenance": {"method": "test", "confidence": 1.0, "timestamp": "2026-10-06T00:00:00Z"},
        "lifecycleState": "active",
        "canonicalKey": canonical_key(fingerprint),
    }


def _gt_from(assets):
    """Ground-truth corpus derived from canonical identities (same canonicalization)."""
    return [
        {"canonicalKey": a["canonicalKey"],
         "cryptoProperties": {"assetType": a["cryptoProperties"]["assetType"]},
         "present": True}
        for a in assets
    ]


A1 = _asset("a1", "RSA", "RSA", "2048")
A2 = _asset("a2", "RSA", "RSA", "2048", asset_type="certificate")
A3 = _asset("a3", "ECDSA", "ECDSA", "P-256")


def test_precision_recall_perfect_generator():
    gen = [A1, A2, A3]
    report = precision_recall(_gt_from(gen), gen)
    assert report["overall"] == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_precision_recall_with_false_positive_and_miss():
    gt = _gt_from([A1, A2, A3])          # ground truth has 3 assets
    ghost = _asset("ghost", "RSA", "RSA", "3072")
    gen = [A1, ghost]                    # generator finds A1 + one false positive
    report = precision_recall(gt, gen)
    assert report["counts"] == {"tp": 1, "fp": 1, "fn": 2, "ground_truth": 3, "generated": 2}
    assert report["overall"]["precision"] == 0.5
    assert report["overall"]["recall"] == pytest.approx(0.333, abs=0.001)


def test_per_class_breakdown():
    gt = _gt_from([A1, A2])
    gen = [A1, _asset("a4", "AES", "AES-256", "256")]
    report = precision_recall(gt, gen)
    assert "algorithm" in report["per_class"]
    assert "certificate" in report["per_class"]
    cert = report["per_class"]["certificate"]
    assert cert["recall"] == 0.0  # A2 missed


def test_cross_generator_agreement():
    a = [_asset("x1", "RSA", "RSA", "2048"), _asset("x2", "AES", "AES-256", "256")]
    b = [_asset("x1", "RSA", "RSA", "2048"), _asset("x3", "PQC", "ML-KEM", "768")]
    report = cross_generator_agreement(a, b)
    assert report["jaccard"] == pytest.approx(0.333, abs=0.001)
    assert a[1]["canonicalKey"] in report["a_only"]   # x2 only in generator A
    assert b[1]["canonicalKey"] in report["b_only"]   # x3 only in generator B
    assert report["discrepancy_a"] == pytest.approx(0.5)
    assert report["discrepancy_b"] == pytest.approx(0.5)