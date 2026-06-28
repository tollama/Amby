from __future__ import annotations

import argparse
import json
import sys

from app.audit.store import AuditStore
from app.config import load_config
from app.control_plane.service import (
    ControlPlaneError,
    activate_policy_bundle,
    build_local_heartbeat,
    create_policy_bundle,
    evaluate_drift,
)
from app.control_plane.store import ControlPlaneStore
from app.diagnostics import build_diagnostics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage local Amby control-plane evidence.")
    subparsers = parser.add_subparsers(dest="command")

    bundle = subparsers.add_parser("bundle", help="Create a signed policy bundle.")
    _add_common_args(bundle)
    bundle.add_argument("--activate", action="store_true", help="Mark the new bundle as active expected policy.")

    activate = subparsers.add_parser("activate", help="Activate an existing policy bundle.")
    _add_common_args(activate)
    activate.add_argument("bundle_id", help="Policy bundle id.")

    drift = subparsers.add_parser("drift", help="Check active bundle drift against runtime config.")
    _add_common_args(drift)
    drift.add_argument("--record-clean", action="store_true", help="Persist clean checks as drift events.")

    heartbeat = subparsers.add_parser("heartbeat", help="Record a local metadata-only fleet heartbeat.")
    _add_common_args(heartbeat)

    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("A command is required: bundle, activate, drift, or heartbeat.")

    try:
        config = load_config(args.config)
        db_path = args.db or config.audit.store
        store = ControlPlaneStore(db_path)
        store.initialize()

        if args.command == "bundle":
            row = create_policy_bundle(config, store)
            if args.activate:
                row = activate_policy_bundle(store, row["id"], config=config)
            print(json.dumps(row, indent=2, sort_keys=True))
            return 0

        if args.command == "activate":
            row = activate_policy_bundle(store, args.bundle_id, config=config)
            print(json.dumps(row, indent=2, sort_keys=True))
            return 0

        if args.command == "drift":
            result = evaluate_drift(config, store, record=args.record_clean)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 2 if result["drift"] else 0

        if args.command == "heartbeat":
            audit_store = AuditStore(db_path)
            audit_store.initialize()
            row = store.record_heartbeat(build_local_heartbeat(config, audit_store, diagnostics=build_diagnostics(config)))
            print(json.dumps(row, indent=2, sort_keys=True))
            return 0
    except ControlPlaneError as exc:
        print(json.dumps({"error": {"type": "control_plane_error", "message": str(exc)}}, indent=2), file=sys.stderr)
        return 1
    return 1


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    parser.add_argument("--db", default=None, help="Path to SQLite DB. Defaults to config audit.store.")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
