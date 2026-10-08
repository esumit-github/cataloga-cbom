"""TLS / certificate discovery connector (paper Section 5.1 — network endpoints
and local certificate files). Stdlib-only: uses ssl for negotiation and the
bundled minimal DER parser for the public-key info.

Emits CBOM components with C4 locationProvenance, C3 assetType, C2
algorithmProperties, C7 lifecycleState, C8 agility (where derivable), and C9
canonicalKey.
"""

from __future__ import annotations

import datetime as _dt
import pathlib
import socket
import ssl
from typing import Iterable

from ..dedup import canonical_key
from ._der import public_key_info


def _timestamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _algorithm_asset(family: str, algorithm: str, bits: int, method: str, confidence: float,
                     usage: str) -> dict:
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"alg-{algorithm.lower()}-{bits}",
        "name": f"{algorithm}-{bits}",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "algorithmFamily": family,
                "algorithm": algorithm,
                "parameterSetIdentifier": str(bits) if bits else None,
                "securityLevel": bits,
            },
            "usage": usage,
        },
        "qvClassification": "unknown",  # filled by the analysis engine
        "locationProvenance": {"method": method, "confidence": confidence, "timestamp": _timestamp()},
        "lifecycleState": "active",
    }


def _certificate_asset(der: bytes, subject: str, issuer: str, not_valid_after: str,
                       method: str, confidence: float) -> dict:
    family, algorithm, bits = public_key_info(der)
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"cert-{subject.split('=')[-1].lower() or 'unknown'}",
        "name": subject,
        "cryptoProperties": {
            "assetType": "certificate",
            "algorithmProperties": {
                "algorithmFamily": family,
                "algorithm": algorithm,
                "parameterSetIdentifier": str(bits) if bits else None,
                "securityLevel": bits,
            },
            "usage": "certificate-signing-or-tls",
            "certificateProperties": {
                "issuer": issuer,
                "subject": subject,
                "notValidAfter": not_valid_after,
                "renewal": {"mechanism": "unknown", "renewBeforeDays": None},
            },
        },
        "qvClassification": "unknown",  # filled by the analysis engine
        "locationProvenance": {"method": method, "confidence": confidence, "timestamp": _timestamp()},
        "lifecycleState": "active",
    }


def scan_local_cert(pem_path: str | pathlib.Path) -> list[dict]:
    """Parse a PEM certificate file into CBOM components."""
    data = pathlib.Path(pem_path).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        pem = data.decode()
        body = pem.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
        import base64
        der = base64.b64decode("".join(body.split()))
    else:
        der = data

    # Minimal subject/issuer/notAfter extraction (best-effort; the DER parser
    # handles key-info independently, so failures here are non-fatal).
    try:
        sslobj = ssl._ssl._test_decode_cert(der) if hasattr(ssl._ssl, "_test_decode_cert") else {}
    except (ValueError, TypeError):
        sslobj = {}
    subject = sslobj.get("subject", ())
    issuer = sslobj.get("issuer", ())
    not_after = sslobj.get("notAfter", "")
    subject_str = ", ".join(f"{k}={v}" for k, v in subject) if subject else "unknown"
    issuer_str = ", ".join(f"{k}={v}" for k, v in issuer) if issuer else "unknown"
    asset = _certificate_asset(der, subject_str, issuer_str, not_after, "file-cert-parse", 0.99)
    asset["canonicalKey"] = canonical_key(asset)
    return [asset]


def scan_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> list[dict]:
    """Connect to a TLS endpoint, negotiate, and record cipher + certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cipher_name, proto, bits = tls.cipher()
            der = tls.getpeercert(binary_form=True)
            not_after = ""
            subject_str = issuer_str = "unknown"
            try:
                info = ssl._ssl._test_decode_cert(der)
                subject = info.get("subject", ())
                issuer = info.get("issuer", ())
                not_after = info.get("notAfter", "")
                subject_str = ", ".join(f"{k}={v}" for k, v in subject) or "unknown"
                issuer_str = ", ".join(f"{k}={v}" for k, v in issuer) or "unknown"
            except Exception:
                pass

    assets = []
    cert = _certificate_asset(der, subject_str, issuer_str, not_after, "network-tls-scan", 0.97)
    cert["canonicalKey"] = canonical_key(cert)
    assets.append(cert)

    fam, algo, alg_bits = public_key_info(der)
    if algo != "unknown":
        alg = _algorithm_asset(fam, algo, alg_bits, "network-tls-scan", 0.97,
                               f"tls-{proto}-key-establishment")
        alg["canonicalKey"] = canonical_key(alg)
        assets.append(alg)

    # Cipher asset (TLS protocol + cipher suite).
    cipher = _algorithm_asset("TLS", cipher_name, 0, "network-tls-scan", 0.9, f"{proto}-cipher")
    cipher["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] = proto
    cipher["canonicalKey"] = canonical_key(cipher)
    assets.append(cipher)
    return assets


def scan_endpoints(endpoints: Iterable[tuple[str, int]]) -> list[dict]:
    """Scan multiple endpoints, best-effort (unreachable endpoints are skipped)."""
    assets: list[dict] = []
    for host, port in endpoints:
        try:
            assets.extend(scan_endpoint(host, port))
        except (OSError, ssl.SSLError, ValueError):
            continue
    return assets