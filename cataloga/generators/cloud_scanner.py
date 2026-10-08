"""Cloud discovery connector (paper Section 5.1 — cloud). Accepts a provider
inventory snapshot (services + their algorithms) and emits CBOM components.
The provider adapter itself (KMS/cert-manager/ALB APIs) is an integration point
for production deployments; this connector models the emitted shape.
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib

from ..dedup import canonical_key


def _timestamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def scan_cloud_inventory(inventory: dict) -> list[dict]:
    """Emit CBOM assets from a cloud inventory snapshot.

    inventory shape:
      {"provider": "aws", "region": "ap-south-1",
       "services": [{"name": "alb-prod-1", "algorithms": [
           {"family": "RSA", "algorithm": "RSA", "parameterSetIdentifier": "2048", "usage": "tls-cert"}]}]}
    """
    assets: list[dict] = []
    for svc in inventory.get("services", []):
        for algo in svc.get("algorithms", []):
            family = algo.get("family", "unknown")
            algorithm = algo.get("algorithm", "unknown")
            params = algo.get("parameterSetIdentifier")
            asset = {
                "type": "cryptographic-asset",
                "bom-ref": f"cloud-{svc['name']}-{algorithm.lower()}-{params or 'x'}",
                "name": f"{algorithm} ({svc['name']})",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "algorithmFamily": family,
                        "algorithm": algorithm,
                        "parameterSetIdentifier": params,
                    },
                    "usage": algo.get("usage", "key-establishment"),
                },
                "qvClassification": "unknown",
                "locationProvenance": {
                    "method": "cloud-api",
                    "confidence": 0.9,
                    "timestamp": _timestamp(),
                    "provider": inventory.get("provider"),
                    "region": inventory.get("region"),
                    "service": svc["name"],
                },
                "lifecycleState": "active",
            }
            asset["canonicalKey"] = canonical_key(asset)
            assets.append(asset)
    return assets


def load_inventory(path: str | pathlib.Path) -> dict:
    return json.loads(pathlib.Path(path).read_text())