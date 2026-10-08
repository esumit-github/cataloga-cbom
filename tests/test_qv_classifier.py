"""QV classification engine tests (C6 — paper Section 3.3)."""

import pytest

from cataloga.qv_classifier import classify


@pytest.mark.parametrize("family,algo,params,expected", [
    ("RSA", "RSA", "2048", "classical-112"),
    ("RSA", "RSA", "3072", "classical-128+"),
    ("RSA", "RSA", "4096", "classical-128+"),
    ("DSA", "DSA", "1024", "classical-112"),
    ("DSA", "DSA", "2048", "classical-128+"),
    ("ECDSA", "ECDSA", "P-256", "classical-128+"),
    ("ECDSA", "ECDSA", "P-384", "classical-128+"),
    ("EdDSA", "Ed25519", "256", "classical-128+"),
    ("AES", "AES-256-GCM", "256", "classical-128+"),
    ("PQC", "ML-KEM", "768", "PQC-ready"),
    ("PQC", "ML-DSA", "65", "PQC-ready"),
    ("PQC", "SLH-DSA", "128", "PQC-ready"),
    ("PQC", "FN-DSA", "512", "PQC-ready"),
    ("PQC", "HQC", "128", "PQC-ready"),
    ("SHA", "SHA-1", None, "classical-112"),
    ("MD5", "MD5", None, "classical-112"),
    ("", "X25519MLKEM768", "768", "hybrid"),
])
def test_classify_table(family, algo, params, expected):
    result = classify(family, algo, params)
    assert result.classification == expected, (algo, result.rationale)


def test_classify_unknown():
    result = classify("", "WEIRD-ALGO", None)
    assert result.classification == "unknown"


def test_nist_notes_present_for_112():
    result = classify("RSA", "RSA", "2048")
    assert "2030" in result.nist_notes and "2035" in result.nist_notes


def test_pqc_notes_reference_fips():
    result = classify("PQC", "ML-KEM", "768")
    assert "FIPS 203" in result.rationale


def test_fips_206_draft_status_flagged():
    result = classify("PQC", "FN-DSA", "512")
    assert "draft" in result.rationale.lower()