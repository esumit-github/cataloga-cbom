"""CATALOGA CLI — validate, classify, dedup, scan, benchmark."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from cataloga.schema import validate
from cataloga.qv_classifier import classify, expected_qv_class
from cataloga.dedup import canonical_key, merge
from cataloga.criticality import build_migration_queue
from cataloga.engine import build_record
from cataloga.benchmark import precision_recall, cross_generator_agreement
from cataloga.generators import scan_endpoint, scan_config, scan_cloud_inventory


def _load(path: str) -> dict:
    return json.loads(pathlib.Path(path).read_text())


def cmd_validate(args):
    record = _load(args.record)
    is_valid, violations = validate(record)
    if is_valid:
        print(f"VALID: {args.record}")
        return 0
    print(f"INVALID: {args.record}")
    for v in violations:
        print(f"  - {v}")
    return 1


def cmd_classify(args):
    result = classify(args.family, args.algorithm, args.params, oid=args.oid, usage=args.usage)
    print(json.dumps(
        {"classification": result.classification, "rationale": result.rationale,
         "nist_notes": result.nist_notes, "confidence": result.confidence},
        indent=2))


def cmd_dedup(args):
    record = _load(args.record)
    merged = merge(record.get("components", []))
    for m in merged:
        print(f"{m.get('bom-ref')}  {m.get('canonicalKey')}  sources={m.get('_duplicate_count')}")


def cmd_queue(args):
    record = _load(args.record)
    queue = build_migration_queue(record.get("components", []), args.criticality)
    for item in queue:
        print(f"{item['score']:.3f}  {item['qv_classification']:>14}  {item['asset'].get('name')}")


def cmd_scan_tls(args):
    assets = scan_endpoint(args.host, args.port, args.timeout)
    record = build_record(assets, {"systemClass": "enterprise", "criticality": "medium"},
                          tool_name="cataloga-tls-scanner")
    print(json.dumps(record, indent=2))
    return 0


def cmd_scan_config(args):
    assets = scan_config(args.config)
    record = build_record(assets, {"systemClass": "enterprise", "criticality": "medium"},
                          tool_name="cataloga-config-scanner")
    print(json.dumps(record, indent=2))


def cmd_scan_cloud(args):
    assets = scan_cloud_inventory(_load(args.inventory))
    record = build_record(assets, {"systemClass": "cloud", "criticality": "high"},
                          tool_name="cataloga-cloud-scanner")
    print(json.dumps(record, indent=2))


def cmd_benchmark(args):
    gt = json.loads(pathlib.Path(args.ground_truth).read_text()).get("assets", [])
    gen = _load(args.generated).get("components", [])
    report = precision_recall(gt, gen)
    print(json.dumps(report, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cataloga", description="CATALOGA CBOM toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate a CATALOGA record")
    p.add_argument("record")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("classify", help="QV-classify an algorithm (e.g. 'cataloga classify RSA RSA 2048')")
    p.add_argument("family")
    p.add_argument("algorithm")
    p.add_argument("params", nargs="?", default=None, help="parameter set identifier (optional positional)")
    p.add_argument("--oid", default=None)
    p.add_argument("--usage", default=None)
    p.set_defaults(func=cmd_classify)

    p = sub.add_parser("dedup", help="show merged canonical identities")
    p.add_argument("record")
    p.set_defaults(func=cmd_dedup)

    p = sub.add_parser("queue", help="build the migration queue (C5 x C2)")
    p.add_argument("record")
    p.add_argument("--criticality", default="medium")
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("scan-tls", help="scan a TLS endpoint")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_scan_tls)

    p = sub.add_parser("scan-config", help="scan a YAML/JSON config")
    p.add_argument("config")
    p.set_defaults(func=cmd_scan_config)

    p = sub.add_parser("scan-cloud", help="scan a cloud inventory snapshot")
    p.add_argument("inventory")
    p.set_defaults(func=cmd_scan_cloud)

    p = sub.add_parser("benchmark", help="precision/recall vs ground truth")
    p.add_argument("ground_truth")
    p.add_argument("generated")
    p.set_defaults(func=cmd_benchmark)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())