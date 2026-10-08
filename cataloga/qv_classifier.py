"""C6 — quantum-vulnerability (QV) classification engine.

Maps an asset's algorithm family + algorithm + parameter set onto a QV class per
NIST IR 8547 timeframes (paper Section 3.3):

  classical-112    deprecated after 2030, disallowed after 2035
  classical-128+   disallowed after 2035
  PQC-ready        FIPS 203/204/205 (+ FIPS 206 when final), or a standardized
                   hybrid construction
  hybrid           explicit PQC + classical hybrid (e.g. X25519MLKEM768)
  unknown          cannot be determined

The classification is machine-readable and is the direct bridge from inventory
(CBOM) to migration schedule (EO 14412 / OMB M-26-15 / BSI / CNSA 2.0).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# FIPS 203/204/205 final 2024-08-13; FIPS 206 (FN-DSA) still in draft (2026).
PQC_READY_ALGORITHMS = {
    "ML-KEM": {"variants": {"768", "1024"}, "note": "FIPS 203"},
    "ML-DSA": {"variants": {"44", "65", "87"}, "note": "FIPS 204"},
    "SLH-DSA": {"variants": {"128", "192", "256"}, "note": "FIPS 205"},
    "FN-DSA": {"variants": {"512", "1024"}, "note": "FIPS 206 (draft; OIDs TBD in LAMPS)"},
    "HQC": {"variants": {"128", "192", "256"}, "note": "NIST IR 8545 selected; no final FIPS/OID yet"},
}

HYBRID_ALGORITHMS = {
    "X25519MLKEM768": "TLS 1.3 hybrid (ML-KEM-768 + X25519)",
    "X25519KYBER768": "deprecated draft hybrid",
    "P256MLKEM768": "hybrid ECDHE P-256 + ML-KEM-768",
}

# RSA / DSA bit-strength thresholds per NIST SP 800-57.
_RSA_112_MAX = 2048          # RSA-2048 -> 112-bit security
_RSA_128_MIN = 3072          # RSA-3072 -> 128-bit security


@dataclass
class QVClassResult:
    classification: str
    rationale: str
    nist_notes: str = ""
    confidence: float = 1.0


def _parameter_bits(parameter_set: Optional[str]) -> Optional[int]:
    """Extract a numeric bit length from a parameter set identifier."""
    if not parameter_set:
        return None
    digits = "".join(ch for ch in parameter_set if ch.isdigit())
    return int(digits) if digits else None


def classify(
    algorithm_family: str,
    algorithm: str,
    parameter_set_identifier: Optional[str] = None,
    oid: Optional[str] = None,
    usage: Optional[str] = None,
) -> QVClassResult:
    """Classify an algorithm asset into a QV class (C6)."""
    fam = (algorithm_family or "").upper()
    algo = (algorithm or "").upper()
    params = parameter_set_identifier or ""

    # --- PQC-ready (FIPS 203/204/205, hybrids handled separately) -------------
    for pqc, spec in PQC_READY_ALGORITHMS.items():
        if algo == pqc or (fam == "PQC" and pqc in f"{algo} {params}".upper()):
            return QVClassResult(
                "PQC-ready",
                f"{algo} is a finalized (or selected) NIST PQC algorithm ({spec['note']}).",
                nist_notes="No migration required for the algorithm itself.",
            )

    # --- Hybrid constructions --------------------------------------------------
    for hyb, desc in HYBRID_ALGORITHMS.items():
        if hyb.upper() in f"{algo} {params}".upper():
            return QVClassResult(
                "hybrid",
                f"{desc} — combines classical and PQC components.",
                nist_notes="Classical leg still subject to classical deprecation timeframes.",
                confidence=0.95,
            )

    # --- RSA -------------------------------------------------------------------
    if fam == "RSA" or algo.startswith("RSA"):
        bits = _parameter_bits(params) or _parameter_bits(algo)
        if bits is None:
            return QVClassResult("unknown", "RSA key length not determinable.", confidence=0.7)
        if bits <= _RSA_112_MAX:
            return QVClassResult(
                "classical-112",
                f"RSA-{bits} provides 112-bit security.",
                nist_notes="NIST IR 8547: 112-bit deprecated after 2030, disallowed after 2035.",
            )
        return QVClassResult(
            "classical-128+",
            f"RSA-{bits} provides >=128-bit security.",
            nist_notes="NIST IR 8547: >=128-bit classical disallowed after 2035.",
        )

    # --- DSA -------------------------------------------------------------------
    if fam == "DSA" or algo.startswith("DSA"):
        bits = _parameter_bits(params) or _parameter_bits(algo)
        if bits and bits <= 1024:
            return QVClassResult("classical-112", f"DSA-{bits} is 112-bit-equivalent.",
                                 nist_notes="NIST IR 8547: 112-bit deprecated after 2030, disallowed after 2035.")
        return QVClassResult("classical-128+", f"DSA (>=128-bit equivalent).",
                             nist_notes="NIST IR 8547: >=128-bit classical disallowed after 2035.")

    # --- Elliptic curves ---------------------------------------------------------
    if fam in ("ECDSA", "ECDH", "EC") or algo.startswith(("ECDSA", "ECDH", "P-", "SECP")):
        return QVClassResult(
            "classical-128+",
            f"{algo or fam} elliptic-curve key agreement/signature — 128-bit-class family.",
            nist_notes="NIST IR 8547: >=128-bit classical disallowed after 2035.",
            confidence=0.9,
        )
    if fam in ("EDDSA", "ED25519", "ED448") or algo.startswith(("ED25519", "ED448")):
        return QVClassResult(
            "classical-128+", f"{algo or fam} — 128-bit-class signature.",
            nist_notes="NIST IR 8547: >=128-bit classical disallowed after 2035.", confidence=0.9,
        )

    # --- Symmetric / hashes -------------------------------------------------------
    if fam == "AES" or algo.startswith("AES"):
        return QVClassResult(
            "classical-128+", f"{algo or 'AES'} symmetric encryption.",
            nist_notes="Symmetric crypto is only marginally affected by Shor; key sizes already quantum-safe at 256-bit.",
            confidence=0.95,
        )
    if algo in ("SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA384", "SHA512", "HMAC-SHA256"):
        return QVClassResult(
            "classical-128+", f"{algo} — hash/MAC above Grover's practical bound.",
            nist_notes="Hash/MAC doubling of output length required only for long-term commitments.", confidence=0.95,
        )
    if algo in ("SHA-1", "SHA1", "MD5", "3DES", "DES"):
        return QVClassResult(
            "classical-112", f"{algo} — legacy/weak cryptographic primitive.",
            nist_notes="Deprecated; migration urgent.", confidence=0.95,
        )

    # --- OID-based fallback -------------------------------------------------------
    if oid and oid.startswith("2.16.840.1.101.3.4"):
        return QVClassResult("PQC-ready", f"NIST CSOR PQC OID {oid}.",
                             nist_notes="FIPS 203/204/205 OID namespace.")
    if oid:
        return QVClassResult("classical-128+", f"Classical OID {oid}.",
                             nist_notes="NIST IR 8547 applies.", confidence=0.8)

    return QVClassResult(
        "unknown", f"Algorithm '{algo or algorithm_family}' not recognized.",
        nist_notes="Operator must resolve manually.", confidence=0.5,
    )


def expected_qv_class(asset: dict) -> QVClassResult:
    """Classify a CBOM component dict (C2 -> C6 derivability check)."""
    props = asset.get("cryptoProperties", {})
    algo_props = props.get("algorithmProperties", {})
    return classify(
        algo_props.get("algorithmFamily", ""),
        algo_props.get("algorithm", ""),
        algo_props.get("parameterSetIdentifier"),
        usage=props.get("usage"),
    )