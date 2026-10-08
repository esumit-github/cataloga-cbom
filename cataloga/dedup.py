"""C9 — canonical identity and deduplication.

Answers the Comcast IETF-draft duplication gap: the same RSA-2048 key discovered
by a source scanner, a TLS scanner, and a cloud scanner must collapse to one
record with provenance retained per source.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable


def _stable_fingerprint(asset: dict) -> str:
    """Normalize an asset to its stable identity fields (excludes volatile
    provenance/timestamp/confidence so re-discovery does not create dupes)."""
    props = asset.get("cryptoProperties", {})
    algo_props = props.get("algorithmProperties", {})
    stable = {
        "assetType": props.get("assetType"),
        "name": asset.get("name"),
        "algorithmFamily": algo_props.get("algorithmFamily"),
        "algorithm": algo_props.get("algorithm"),
        "parameterSetIdentifier": algo_props.get("parameterSetIdentifier"),
        "usage": props.get("usage"),
    }
    # Serialize with sorted keys for determinism.
    return json.dumps(stable, sort_keys=True, separators=(",", ":"))


def canonical_key(asset: dict) -> str:
    """Compute the C9 canonical identity for a CBOM component.

    Canonical form: sha256:<64 hex> (schema pattern).
    """
    digest = hashlib.sha256(_stable_fingerprint(asset).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def merge(records: Iterable[dict]) -> list[dict]:
    """Merge a stream of discovered assets by canonical identity.

    Returns a list of merged records. Each merged record carries:
      * merged provenance (one entry per source),
      * highest-confidence provenance as the primary,
      * a duplicate count.
    """
    groups: dict[str, dict] = {}
    for asset in records:
        if "canonicalKey" not in asset or not asset.get("canonicalKey"):
            asset = {**asset, "canonicalKey": canonical_key(asset)}
        key = asset["canonicalKey"]
        if key not in groups:
            merged = dict(asset)
            merged["_provenance_sources"] = [asset.get("locationProvenance", {})]
            merged["_duplicate_count"] = 1
            groups[key] = merged
            continue
        target = groups[key]
        prov = asset.get("locationProvenance", {})
        target.setdefault("_provenance_sources", []).append(prov)
        target["_duplicate_count"] += 1
        # Highest confidence wins as primary provenance.
        cur_conf = target.get("locationProvenance", {}).get("confidence", 0)
        new_conf = prov.get("confidence", 0)
        if new_conf > cur_conf:
            target["locationProvenance"] = prov
    return list(groups.values())