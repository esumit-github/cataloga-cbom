"""C5 x C2 — criticality scoring and migration queue (paper Section 3.3).

score = asset_criticality (C5, from system context) x crypto_sensitivity (C2/C6).
The score drives the remediation queue: the highest-score assets migrate first
under OMB M-26-15 Phase 3 and EO 14412 Section 4(b) HVA deadlines.
"""

from __future__ import annotations

from typing import Iterable

# Crypto sensitivity by QV class (C6). Higher = more urgent.
CRYPTO_SENSITIVITY = {
    "PQC-ready": 0.2,
    "hybrid": 0.4,
    "classical-128+": 0.7,
    "classical-112": 0.9,
    "unknown": 1.0,
}

# Asset criticality by C5 system-context criticality rating.
ASSET_CRITICALITY = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
}


def score_asset(asset: dict, system_criticality: str = "medium") -> float:
    """Compute the CATALOGA migration score for one asset."""
    qv = asset.get("qvClassification", "unknown")
    sensitivity = CRYPTO_SENSITIVITY.get(qv, CRYPTO_SENSITIVITY["unknown"])
    criticality = ASSET_CRITICALITY.get(system_criticality, 0.5)
    return round(criticality * sensitivity, 3)


def build_migration_queue(records: Iterable[dict], system_criticality: str = "medium") -> list[dict]:
    """Return records ranked by migration urgency (highest first)."""
    ranked = []
    for asset in records:
        ranked.append(
            {
                "asset": asset,
                "score": score_asset(asset, system_criticality),
                "qv_classification": asset.get("qvClassification", "unknown"),
            }
        )
    return sorted(ranked, key=lambda r: r["score"], reverse=True)