"""CATALOGA — reference implementation of a normative CBOM minimum-elements model.

Implements the C1-C9 model, JSON schema (CycloneDX 1.7 superset), discovery
connectors, and the benchmarking protocol from the CATALOGA paper.
"""

__version__ = "0.9.0"

from .schema import validate, validate_record, validate_cross_elements  # noqa: F401
from .qv_classifier import classify, QVClassResult  # noqa: F401
from .dedup import canonical_key, merge  # noqa: F401
from .criticality import score_asset, build_migration_queue  # noqa: F401