"""Benchmarking protocol (paper Section 5.4) — grounded in the BF-CBOM finding
of "striking discrepancies" between generators.

Separates "a generator produced a CBOM" from "a generator produced a correct
CBOM": precision/recall/F1 of a generator's output against a ground-truth corpus,
plus cross-generator agreement metrics.
"""

from __future__ import annotations

from typing import Iterable


def _canonical_keys(records: Iterable[dict]) -> set[str]:
    return {r.get("canonicalKey") for r in records if r.get("canonicalKey")}


def precision_recall(ground_truth: Iterable[dict], generated: Iterable[dict]) -> dict:
    """Precision / recall / F1 of generated assets vs the ground-truth corpus.

    Matching is by canonical identity (C9). Returns per-class and overall metrics.
    """
    gt = list(ground_truth)
    gen = list(generated)

    gt_keys = _canonical_keys(gt)
    gen_keys = _canonical_keys(gen)
    tp = len(gt_keys & gen_keys)
    fp = len(gen_keys - gt_keys)
    fn = len(gt_keys - gen_keys)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # Per-asset-class breakdown (C3).
    by_class: dict[str, dict] = {}
    for asset in gt:
        cls = asset.get("cryptoProperties", {}).get("assetType", "unknown")
        by_class.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})
    for asset in gen:
        cls = asset.get("cryptoProperties", {}).get("assetType", "unknown")
        by_class.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})

    for asset in gt:
        cls = asset.get("cryptoProperties", {}).get("assetType", "unknown")
        if asset.get("canonicalKey") in gen_keys:
            by_class[cls]["tp"] += 1
        else:
            by_class[cls]["fn"] += 1
    for asset in gen:
        cls = asset.get("cryptoProperties", {}).get("assetType", "unknown")
        if asset.get("canonicalKey") not in gt_keys:
            by_class[cls]["fp"] += 1

    per_class = {}
    for cls, counts in by_class.items():
        p = counts["tp"] / (counts["tp"] + counts["fp"]) if (counts["tp"] + counts["fp"]) else 0.0
        r = counts["tp"] / (counts["tp"] + counts["fn"]) if (counts["tp"] + counts["fn"]) else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        per_class[cls] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3)}

    return {
        "overall": {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)},
        "counts": {"tp": tp, "fp": fp, "fn": fn, "ground_truth": len(gt_keys), "generated": len(gen_keys)},
        "per_class": per_class,
    }


def cross_generator_agreement(gen_a: Iterable[dict], gen_b: Iterable[dict]) -> dict:
    """Overlap between two generators' output, measured on canonical identity.

    Returns Jaccard similarity and the BF-CBOM-style "striking discrepancy"
    indicator (the fraction of each generator's output NOT agreed by the other).
    """
    a = _canonical_keys(gen_a)
    b = _canonical_keys(gen_b)
    union = a | b
    intersection = a & b
    jaccard = len(intersection) / len(union) if union else 1.0
    return {
        "jaccard": round(jaccard, 3),
        "a_only": sorted(a - b),
        "b_only": sorted(b - a),
        "discrepancy_a": round(len(a - b) / len(a), 3) if a else 0.0,
        "discrepancy_b": round(len(b - a) / len(b), 3) if b else 0.0,
    }