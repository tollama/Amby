from __future__ import annotations

import argparse
import json
import sys

from app.release.metadata import evaluate_docker_smoke, write_release_candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate Amby release-candidate metadata.")
    subparsers = parser.add_subparsers(dest="command")

    candidate = subparsers.add_parser("candidate", help="Write release-candidate manifest, SBOM, security metadata, and README.")
    candidate.add_argument("--config", default="config.production.yaml", help="Release config path.")
    candidate.add_argument("--db", required=True, help="Release SQLite DB path.")
    candidate.add_argument("--out", required=True, help="Release candidate bundle directory.")
    candidate.add_argument("--evidence-package", required=True, help="Generated evidence package directory.")
    candidate.add_argument("--image-tag", default=None, help="Docker image tag, if built.")
    candidate.add_argument("--image-id", default=None, help="Docker image id, if built.")
    candidate.add_argument("--docker-smoke", default=None, help="Path to docker-smoke.json.")

    docker_smoke = subparsers.add_parser("docker-smoke", help="Normalize Docker smoke health and diagnostics JSON.")
    docker_smoke.add_argument("--healthz", required=True, help="Path to healthz JSON.")
    docker_smoke.add_argument("--diagnostics", required=True, help="Path to diagnostics JSON.")
    docker_smoke.add_argument("--out", required=True, help="Path to write docker-smoke.json.")
    docker_smoke.add_argument("--image-tag", default=None)
    docker_smoke.add_argument("--image-id", default=None)
    docker_smoke.add_argument("--container-id", default=None)
    docker_smoke.add_argument("--secret", action="append", default=[], help="Raw secret marker that must not appear in smoke output.")

    args = parser.parse_args(argv)
    if args.command == "candidate":
        result = write_release_candidate(
            config_path=args.config,
            db_path=args.db,
            bundle_dir=args.out,
            evidence_package=args.evidence_package,
            image_tag=args.image_tag,
            image_id=args.image_id,
            docker_smoke_path=args.docker_smoke,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["decision"] != "fail" else 2
    if args.command == "docker-smoke":
        with open(args.healthz, "r", encoding="utf-8") as handle:
            healthz = json.load(handle)
        with open(args.diagnostics, "r", encoding="utf-8") as handle:
            diagnostics = json.load(handle)
        result = evaluate_docker_smoke(
            healthz=healthz,
            diagnostics=diagnostics,
            image_tag=args.image_tag,
            image_id=args.image_id,
            container_id=args.container_id,
            raw_secret_values=args.secret,
        )
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["decision"] == "pass" else 2
    parser.error("A command is required.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
