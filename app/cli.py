from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from app.config import load_config


_FORWARDING_COMMANDS = {"evidence", "predeploy", "control-plane", "release"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Amby security gateway CLI.")
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Run the Amby gateway.")
    serve.add_argument("--config", default="config.yaml", help="Path to config.yaml.")
    serve.add_argument("--host", default="0.0.0.0", help="Host interface to bind.")
    serve.add_argument("--port", type=int, default=None, help="Port to bind. Defaults to server.port.")
    serve.add_argument("--reload", action="store_true", help="Enable uvicorn reload.")

    subparsers.add_parser("demo", help="Inject the sample demo event.")
    subparsers.add_parser("evidence", help="Generate or verify evidence packages.")
    subparsers.add_parser("predeploy", help="Run pre-deploy governance checks.")
    subparsers.add_parser("control-plane", help="Manage policy bundles and drift evidence.")
    subparsers.add_parser("release", help="Generate release metadata.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if not raw_args:
        raw_args = ["serve"]
    if raw_args[0] in _FORWARDING_COMMANDS:
        return _run_forwarding_command(raw_args[0], raw_args[1:])

    args = build_parser().parse_args(raw_args)
    if args.command is None:
        args.command = "serve"
        args.config = "config.yaml"
        args.host = "0.0.0.0"
        args.port = None
        args.reload = False

    if args.command == "serve":
        os.environ["AMBY_CONFIG"] = args.config
        config = load_config(args.config)
        uvicorn.run("app.main:app", host=args.host, port=args.port or config.server.port, reload=args.reload)
        return 0
    if args.command == "demo":
        from app.demo.__main__ import main as demo_main

        return demo_main()
    return 2


def _run_forwarding_command(command: str, args: list[str]) -> int:
    if command == "evidence":
        from app.evidence.__main__ import main as evidence_main

        return evidence_main(args)
    if command == "predeploy":
        from app.predeploy.__main__ import main as predeploy_main

        old_argv = sys.argv
        sys.argv = ["amby predeploy", *args]
        try:
            return predeploy_main()
        finally:
            sys.argv = old_argv
    if command == "control-plane":
        from app.control_plane.__main__ import main as control_plane_main

        return control_plane_main(args)
    if command == "release":
        from app.release.__main__ import main as release_main

        return release_main(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
