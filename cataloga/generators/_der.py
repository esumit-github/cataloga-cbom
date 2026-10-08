"""Minimal DER/TLV parser sufficient to extract SubjectPublicKeyInfo from an
X.509 certificate — no third-party crypto dependencies (stdlib-only).

Only what CATALOGA's TLS connector needs:
  * RSA modulus bit length,
  * EC curve OID -> name + bit length,
  * Ed25519 / Ed448 detection.
"""

from __future__ import annotations

from typing import Optional

# SPKI algorithm OIDs.
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"

EC_CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
}


def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return (tag, value, next_offset) for the TLV at offset."""
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x81:
        length = data[offset]
        offset += 1
    elif first == 0x82:
        length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
    else:
        raise ValueError("unsupported DER length encoding")
    return tag, data[offset : offset + length], offset + length


def iter_children(seq_bytes: bytes):
    """Yield (tag, value) of the direct children of a DER SEQUENCE value."""
    offset = 0
    while offset < len(seq_bytes):
        tag, value, offset = read_tlv(seq_bytes, offset)
        yield tag, value


def parse_oid(raw: bytes) -> str:
    parts = []
    first = raw[0]
    parts.append(str(first // 40))
    parts.append(str(first % 40))
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _leading_oid(seq_value: bytes, depth: int = 3) -> Optional[str]:
    """The OID that leads a SEQUENCE, descending through wrapper SEQUENCEs
    (e.g. SPKI = SEQUENCE { SEQUENCE { OID, params }, BIT STRING })."""
    if depth <= 0:
        return None
    for t, v in iter_children(seq_value):
        if t == 0x06:
            return parse_oid(v)
        if t == 0x30:  # SEQUENCE wrapper (algorithm identifier)
            return _leading_oid(v, depth - 1)
        return None
    return None


def _find_spki(tbs: bytes) -> Optional[tuple[str, bytes]]:
    """Find the SPKI (algorithm OID + full SPKI SEQUENCE value)."""
    for _tag, value in iter_children(tbs):
        if _tag != 0x30:
            continue
        for t2, v2 in iter_children(value):
            if t2 != 0x30:  # only SEQUENCE children can carry the SPKI
                continue
            try:
                oid = _leading_oid(v2)
            except (ValueError, IndexError):
                continue
            if oid in (OID_RSA, OID_EC, OID_ED25519, OID_ED448):
                return oid, v2
    return None


def public_key_info(der_cert: bytes) -> tuple[str, str, int]:
    """Return (algorithm_family, algorithm, bits) from a DER X.509 certificate."""
    try:
        _tag, tbs, _ = read_tlv(der_cert, 0)
        found = _find_spki(tbs)
    except (ValueError, IndexError):
        return "unknown", "unknown", 0
    if found is None:
        return "unknown", "unknown", 0

    oid, spki_seq = found

    if oid == OID_RSA:
        # SPKI: SEQUENCE{ SEQUENCE{OID,NULL}, BITSTRING{ SEQUENCE{INTEGER modulus,...} } }
        for t, v in iter_children(spki_seq):
            if t == 0x03:  # BIT STRING
                rsa_pub = v[1:]  # skip unused-bits octet -> RSAPublicKey SEQUENCE
                for t3, v3 in iter_children(rsa_pub):
                    if t3 == 0x30:  # RSAPublicKey
                        for t4, v4 in iter_children(v3):
                            if t4 == 0x02:  # INTEGER modulus
                                if v4 and v4[0] == 0x00:
                                    v4 = v4[1:]
                                return "RSA", "RSA", len(v4) * 8
        return "RSA", "RSA", 0

    if oid == OID_EC:
        # SPKI: SEQUENCE{ SEQUENCE{OID id-ecPublicKey, OID <curve>}, BITSTRING{...} }
        for t, v in iter_children(spki_seq):
            if t == 0x30:  # algorithm SEQUENCE
                for t2, v2 in iter_children(v):
                    if t2 == 0x06:
                        curve_oid = parse_oid(v2)
                        if curve_oid != OID_EC and curve_oid in EC_CURVES:
                            name, bits = EC_CURVES[curve_oid]
                            return "ECDSA", name, bits
        return "ECDSA", "unknown", 0

    if oid == OID_ED25519:
        return "EdDSA", "Ed25519", 256
    if oid == OID_ED448:
        return "EdDSA", "Ed448", 456

    return "unknown", "unknown", 0