from __future__ import annotations

import argparse
import json
import sys

from app.audit.store import AuditStore
from app.config import load_config
from app.predeploy.runner import PredeployRunner, should_fail_ci


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Amby pre-deploy governance checks.")
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser("run", help="Run configured pre-deploy checks.")
    run.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    run.add_argument("--db", default=None, help="Path to audit SQLite DB. Defaults to config audit.store.")
    run.add_argument("--suite", default=None, help="Suite name. Defaults to predeploy.suite.")
    run.add_argument("--out", default=None, help="Output root directory. Defaults to predeploy.output_root.")
    run.add_argument("--use-fixtures", action="store_true", help="Use deterministic fixture scanner outputs.")
    run.add_argument("--no-ci-gate", action="store_true", help="Do not return a failing exit code for fail/error decisions.")

    args = parser.parse_args()
    if args.command is None:
        args.command = "run"
        args.config = "config.yaml"
        args.db = None
        args.suite = None
        args.out = None
        args.use_fixtures = False
        args.no_ci_gate = False
    if args.command != "run":
        parser.error(f"Unsupported command={args.command!r}")

    config = load_config(args.config)
    db_path = args.db or config.audit.store
    runner = PredeployRunner(config, audit_store=AuditStore(db_path))
    result = runner.run(suite=args.suite, output_root=args.out, use_fixtures=args.use_fixtures)
    payload = {
        "schema_version": "amby.predeploy.cli_result.v1",
        "run_id": result.run_id,
        "suite": result.suite,
        "decision": result.decision,
        "adapter_status": result.adapter_status,
        "finding_counts": result.finding_counts,
        "output_dir": result.output_dir,
        "error": result.error,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.no_ci_gate and should_fail_ci(result, config):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

