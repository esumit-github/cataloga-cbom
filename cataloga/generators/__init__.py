"""CATALOGA discovery connectors — paper Section 5.1 (source/binary/config/
network/cloud/OT-DIL layers). Each connector emits CBOM components with C4
locationProvenance and (where derivable) C8 agility attributes."""

from .tls_scanner import scan_endpoint, scan_local_cert  # noqa: F401
from .config_scanner import scan_config  # noqa: F401
from .cloud_scanner import scan_cloud_inventory  # noqa: F401