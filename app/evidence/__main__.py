from __future__ import annotations

import argparse
import json
import sys

from app.config import load_config
from app.evidence.generator import EvidenceOptions, generate_evidence_package, verify_evidence_package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate or verify an Amby MVP evidence package.")
    subparsers = parser.add_subparsers(dest="command")

    generate = subparsers.add_parser("generate", help="Generate an evidence package from the audit database.")
    generate.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    generate.add_argument("--db", default=None, help="Path to audit SQLite DB. Defaults to config audit.store.")
    generate.add_argument("--out", default="evidence", help="Output root directory.")
    generate.add_argument("--from", dest="start", default=None, help="Optional ISO8601 lower timestamp.")
    generate.add_argument("--to", dest="end", default=None, help="Optional ISO8601 upper timestamp.")
    generate.add_argument("--name", default=None, help="Optional package directory name.")

    verify = subparsers.add_parser("verify", help="Verify an existing evidence package.")
    verify.add_argument("package_dir", help="Evidence package directory.")

    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "generate"
        args.config = "config.yaml"
        args.db = None
        args.out = "evidence"
        args.start = None
        args.end = None
        args.name = None

    if args.command == "verify":
        result = verify_evidence_package(args.package_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1

    config = load_config(args.config)
    db_path = args.db or config.audit.store
    manifest = generate_evidence_package(
        EvidenceOptions(
            db_path=db_path,
            config_path=args.config,
            output_root=args.out,
            start=args.start,
            end=args.end,
            package_name=args.name,
        )
    )
    print(json.dumps({"package_dir": manifest["package_dir"], "manifest_hash": manifest["manifest_hash"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
