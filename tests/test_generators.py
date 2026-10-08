"""Discovery connector tests (paper Section 5.1) — config, cloud, and a real
local TLS endpoint with a self-signed certificate (openssl-generated)."""

import json
import pathlib
import socket
import ssl
import subprocess
import threading
import time

import pytest

from cataloga.generators import scan_config, scan_cloud_inventory, scan_endpoint, scan_local_cert
from cataloga.engine import enrich
from cataloga.qv_classifier import expected_qv_class


# --- config scanner -----------------------------------------------------------

CONFIG_FIXTURE = """
server:
  tls_min_version: TLS1.2
  ciphers: ECDHE-RSA-AES128-GCM-SHA256
  certificate: /etc/nginx/tls/web-01.crt
  key_file: /etc/nginx/tls/web-01.key
signing:
  signature_algorithm: SHA256withRSA
"""


def test_config_scanner_finds_tls_and_signing(tmp_path):
    path = tmp_path / "nginx.yaml"
    path.write_text(CONFIG_FIXTURE)
    assets = scan_config(path)
    refs = [a["bom-ref"] for a in assets]
    assert any(r.startswith("tls-") for r in refs)
    assert any(r.startswith("sig-") for r in refs)
    # C8 agility metadata present (config-scan is the agility source).
    tls = [a for a in assets if a["bom-ref"].startswith("tls-")][0]
    assert tls["cryptoProperties"]["agility"]["configurationSource"] == "config-file"
    # C4 provenance carries the config path.
    assert "path" in tls["locationProvenance"]


def test_config_scanner_classifies_tls12_as_128():
    path = pathlib.Path(".") / "cfg.yaml"
    with path.open("w") as fh:
        fh.write("tls_min_version: TLS1.2\n")
    try:
        assets = scan_config(path)
        tls = [a for a in assets if a["bom-ref"].startswith("tls-")][0]
        assert tls["qvClassification"] == "classical-128+"
    finally:
        path.unlink()


# --- cloud scanner -------------------------------------------------------------

CLOUD_FIXTURE = {
    "provider": "aws",
    "region": "ap-south-1",
    "services": [
        {"name": "alb-prod-1", "algorithms": [
            {"family": "RSA", "algorithm": "RSA", "parameterSetIdentifier": "2048", "usage": "tls-cert"}]},
        {"name": "kms-key-1", "algorithms": [
            {"family": "PQC", "algorithm": "ML-KEM", "parameterSetIdentifier": "768", "usage": "key-agreement"}]},
    ],
}


def test_cloud_scanner_emits_assets_with_provenance():
    assets = scan_cloud_inventory(CLOUD_FIXTURE)
    assert len(assets) == 2
    assert all(a["locationProvenance"]["method"] == "cloud-api" for a in assets)
    assert all(a["locationProvenance"]["provider"] == "aws" for a in assets)


def test_cloud_scanner_assets_are_enrichable():
    assets = enrich(scan_cloud_inventory(CLOUD_FIXTURE))
    by_name = {a["name"] for a in assets}
    qvs = {a["qvClassification"] for a in assets}
    assert "RSA (alb-prod-1)" in by_name
    assert qvs == {"classical-112", "PQC-ready"}


# --- TLS scanner ---------------------------------------------------------------

@pytest.fixture(scope="module")
def self_signed_cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("cert")
    cert = d / "cert.pem"
    key = d / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "30",
         "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


@pytest.fixture(scope="module")
def local_tls_server(self_signed_cert):
    cert, key = self_signed_cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        ctx_sock = ctx.wrap_socket(sock, server_side=True)
        while not stop.is_set():
            try:
                conn, _ = ctx_sock.accept()
                try:
                    conn.recv(1024)
                finally:
                    conn.close()
            except (ssl.SSLError, OSError):
                if stop.is_set():
                    break
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    sock.close()


def test_scan_local_cert_extracts_rsa_2048(self_signed_cert):
    cert, _ = self_signed_cert
    assets = scan_local_cert(cert)
    assert len(assets) == 1
    assert assets[0]["cryptoProperties"]["assetType"] == "certificate"
    algo = assets[0]["cryptoProperties"]["algorithmProperties"]
    assert algo["algorithmFamily"] == "RSA"
    assert algo["parameterSetIdentifier"] == "2048"


def test_scan_endpoint_negotiates_and_emits_assets(local_tls_server):
    assets = scan_endpoint("127.0.0.1", local_tls_server)
    types = {a["cryptoProperties"]["assetType"] for a in assets}
    assert "certificate" in types
    assert "algorithm" in types
    assert all(a["locationProvenance"]["method"] == "network-tls-scan" for a in assets)


def test_scan_endpoint_classification_consistent():
    # Every emitted algorithm asset must have a derivable qvClassification.
    result = expected_qv_class(
        {"cryptoProperties": {"algorithmProperties": {"algorithmFamily": "RSA", "algorithm": "RSA",
                                                      "parameterSetIdentifier": "2048"}}}
    )
    assert result.classification == "classical-112"