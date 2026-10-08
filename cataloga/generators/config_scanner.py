"""Config / IaC discovery connector (paper Section 5.1 — configs and IaC, the
C8 agility source). Heuristic parser for YAML/JSON configs that references TLS,
keys, and certificates. Honest-stage: heuristic, confidence-weighted.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import yaml

from ..dedup import canonical_key

_CONFIG_KEYS = {
    "tls_version": "tls-version",
    "tls_min_version": "tls-version",
    "tls_max_version": "tls-version",
    "ssl_protocols": "tls-version",
    "ciphers": "cipher",
    "ssl_ciphers": "cipher",
    "cipher_suites": "cipher",
    "certificate": "certificate-ref",
    "cert_file": "certificate-ref",
    "ssl_cert": "certificate-ref",
    "cert_path": "certificate-ref",
    "key": "key-ref",
    "key_file": "key-ref",
    "signing_algorithm": "signing-algorithm",
    "signature_algorithm": "signing-algorithm",
}

_TLS_112 = {"TLSv1", "TLSv1.0", "TLS1", "TLSv1.1", "TLS1.1"}
_TLS_128 = {"TLSv1.2", "TLSv1.3", "TLS1.2", "TLS1.3", "TLS"}


def _walk(node: Any, path: str, found: dict[str, list[tuple[Any, str]]]):
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(value, (dict, list)):
                _walk(value, child, found)
            else:
                matched = None
                for cfg_key, kind in _CONFIG_KEYS.items():
                    if key.lower().replace("-", "_") == cfg_key:
                        matched = kind
                        break
                if matched:
                    found.setdefault(matched, []).append((value, child))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk(item, f"{path}[{i}]", found)


def _timestamp() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def scan_config(path: str | pathlib.Path) -> list[dict]:
    """Parse a YAML/JSON config file and emit CBOM components for crypto config."""
    raw = pathlib.Path(path).read_text()
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        data = json.loads(raw)

    found: dict[str, list[tuple[Any, str]]] = {}
    _walk(data, "", found)

    assets: list[dict] = []

    for tls_value, loc in found.get("tls-version", []):
        family = "TLS"
        value = str(tls_value)
        qv = "classical-128+" if any(v in value.upper() for v in _TLS_128) else "classical-112"
        asset = {
            "type": "cryptographic-asset",
            "bom-ref": f"tls-{value.lower().replace('.', '')}",
            "name": f"TLS {value}",
            "cryptoProperties": {
                "assetType": "protocol",
                "algorithmProperties": {"algorithmFamily": family, "algorithm": "TLS", "parameterSetIdentifier": value},
                "usage": "transport-security",
                "agility": {"configurationSource": "config-file", "changeMechanism": "runtime-config"},
            },
            "qvClassification": qv,
            "locationProvenance": {"method": "config-scan", "confidence": 0.85, "timestamp": _timestamp(), "path": loc},
            "lifecycleState": "active",
        }
        asset["canonicalKey"] = canonical_key(asset)
        assets.append(asset)

    for sign_value, loc in found.get("signing-algorithm", []):
        value = str(sign_value)
        qv = "classical-112" if "sha1" in value.lower() or "md5" in value.lower() else "classical-128+"
        asset = {
            "type": "cryptographic-asset",
            "bom-ref": f"sig-{value.lower().replace(' ', '')}",
            "name": f"signing {value}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"algorithmFamily": "hash-signature", "algorithm": value},
                "usage": "signing",
            },
            "qvClassification": qv,
            "locationProvenance": {"method": "config-scan", "confidence": 0.8, "timestamp": _timestamp(), "path": loc},
            "lifecycleState": "active",
        }
        asset["canonicalKey"] = canonical_key(asset)
        assets.append(asset)

    return assets