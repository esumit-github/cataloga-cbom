"""C5 x C2 criticality scoring and migration queue tests (paper Section 3.3)."""

from cataloga.criticality import score_asset, build_migration_queue, CRYPTO_SENSITIVITY


def _asset(qv, name="a"):
    return {"name": name, "qvClassification": qv}


def test_sensitivity_ordering():
    # unknown > classical-112 > classical-128+ > hybrid > PQC-ready
    assert CRYPTO_SENSITIVITY["unknown"] > CRYPTO_SENSITIVITY["classical-112"]
    assert CRYPTO_SENSITIVITY["classical-112"] > CRYPTO_SENSITIVITY["classical-128+"]
    assert CRYPTO_SENSITIVITY["classical-128+"] > CRYPTO_SENSITIVITY["hybrid"]
    assert CRYPTO_SENSITIVITY["hybrid"] > CRYPTO_SENSITIVITY["PQC-ready"]


def test_score_reflects_criticality():
    a = score_asset(_asset("classical-112"), "critical")
    b = score_asset(_asset("classical-112"), "low")
    assert a > b


def test_queue_orders_by_score_desc():
    records = [_asset("PQC-ready", "pqc"), _asset("classical-112", "rsa"), _asset("unknown", "unk")]
    queue = build_migration_queue(records, "high")
    assert [q["asset"]["name"] for q in queue] == ["unk", "rsa", "pqc"]


def test_queue_scores_are_in_range():
    for qv in CRYPTO_SENSITIVITY:
        score = score_asset(_asset(qv), "high")
        assert 0 <= score <= 1.0