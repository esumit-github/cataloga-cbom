"""C9 canonical identity and deduplication tests."""

from cataloga.dedup import canonical_key, merge


def _asset(name, family, algo, params, method, confidence):
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"ref-{name}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "algorithmFamily": family,
                "algorithm": algo,
                "parameterSetIdentifier": params,
            },
            "usage": "tls",
        },
        "locationProvenance": {"method": method, "confidence": confidence},
        "lifecycleState": "active",
    }


def test_canonical_key_deterministic():
    a = _asset("x", "RSA", "RSA", "2048", "source-scan", 0.8)
    b = _asset("x", "RSA", "RSA", "2048", "network-scan", 0.9)
    assert canonical_key(a) == canonical_key(b)


def test_canonical_key_differs_by_algorithm():
    a = _asset("x", "RSA", "RSA", "2048", "src", 0.8)
    b = _asset("x", "RSA", "RSA", "3072", "src", 0.8)
    assert canonical_key(a) != canonical_key(b)


def test_merge_collapses_duplicates_and_keeps_provenance():
    records = [
        _asset("k1", "RSA", "RSA", "2048", "source-scan", 0.8),
        _asset("k1", "RSA", "RSA", "2048", "network-scan", 0.95),
        _asset("k1", "RSA", "RSA", "2048", "cloud-api", 0.7),
        _asset("k2", "ECDSA", "ECDSA", "P-256", "source-scan", 0.8),
    ]
    merged = merge(records)
    assert len(merged) == 2
    dup = [m for m in merged if m["_duplicate_count"] == 3][0]
    assert len(dup["_provenance_sources"]) == 3
    # Highest confidence wins as primary provenance.
    assert dup["locationProvenance"]["confidence"] == 0.95


def test_merge_assigns_missing_canonical_keys():
    asset = _asset("k3", "AES", "AES-256-GCM", "256", "src", 0.9)
    assert "canonicalKey" not in asset
    merged = merge([asset])
    assert merged[0]["canonicalKey"].startswith("sha256:")