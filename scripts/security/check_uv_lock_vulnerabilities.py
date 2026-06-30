#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Syft SBOM from uv.lock and scan it with Grype."
    )
    parser.add_argument(
        "--uv-lock-path",
        default=os.environ.get("UV_LOCK_PATH", "uv.lock"),
        help="Path to the uv.lock file to scan.",
    )
    parser.add_argument(
        "--fail-on",
        default=os.environ.get("GRYPE_FAIL_ON_SEVERITY", "high"),
        help=(
            "Severity threshold passed to grype --fail-on. "
            "Use 'none' to report vulnerabilities without failing."
        ),
    )
    parser.add_argument(
        "--no-db-update",
        action="store_true",
        help="Do not let Grype check for vulnerability database updates.",
    )
    return parser.parse_args()


SEVERITY_ORDER = {
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.lower(), -1)


def fixed_versions(match: dict) -> str:
    versions = match.get("vulnerability", {}).get("fix", {}).get("versions", [])
    if not versions:
        return ""
    return ", ".join(str(version) for version in versions)


def print_matches(matches: list[dict]) -> None:
    if not matches:
        print("Grype found no vulnerabilities.", flush=True)
        return

    print(f"Grype found {len(matches)} vulnerabilities:", flush=True)
    print(
        f"{'NAME':<24} {'INSTALLED':<16} {'FIXED IN':<20} "
        f"{'VULNERABILITY':<22} {'SEVERITY':<10}",
        flush=True,
    )
    for match in matches:
        artifact = match.get("artifact", {})
        vulnerability = match.get("vulnerability", {})
        print(
            f"{artifact.get('name', ''):<24.24} "
            f"{artifact.get('version', ''):<16.16} "
            f"{fixed_versions(match):<20.20} "
            f"{vulnerability.get('id', ''):<22.22} "
            f"{vulnerability.get('severity', ''):<10.10}",
            flush=True,
        )


def print_grype_db_status(env: dict[str, str]) -> None:
    result = subprocess.run(
        ["grype", "db", "status", "-o", "json"],
        capture_output=True,
        env=env,
        text=True,
    )
    if result.returncode != 0:
        print("Warning: could not read Grype DB status.", file=sys.stderr)
        return

    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Warning: could not parse Grype DB status.", file=sys.stderr)
        return

    built = status.get("built", "unknown")
    schema_version = status.get("schemaVersion", "unknown")
    valid = status.get("valid", "unknown")
    print(
        f"Using Grype DB {schema_version}, built {built}, valid={valid}.",
        flush=True,
    )


def failing_matches(matches: list[dict], fail_on_severity: str) -> list[dict]:
    if not fail_on_severity or fail_on_severity == "none":
        return []

    threshold = severity_rank(fail_on_severity)
    if threshold < 0:
        valid_values = ", ".join((*SEVERITY_ORDER.keys(), "none"))
        raise ValueError(
            f"Invalid --fail-on value: {fail_on_severity}. "
            f"Expected one of: {valid_values}."
        )

    return [
        match
        for match in matches
        if (
            severity_rank(match.get("vulnerability", {}).get("severity", ""))
            >= threshold
        )
    ]


def main() -> int:
    args = parse_args()
    uv_lock_path = Path(args.uv_lock_path)
    fail_on_severity = args.fail_on.strip().lower()

    if not uv_lock_path.is_file():
        print(f"Cannot scan dependencies: {uv_lock_path} not found.", file=sys.stderr)
        return 1

    missing_tools = [tool for tool in ("syft", "grype") if shutil.which(tool) is None]
    if missing_tools:
        print(f"Missing required tools: {', '.join(missing_tools)}", file=sys.stderr)
        print(
            f"Install Syft and Grype before committing changes to {uv_lock_path}.",
            file=sys.stderr,
        )
        return 1

    env = os.environ.copy()
    env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    env["GRYPE_DB_AUTO_UPDATE"] = "false" if args.no_db_update else "true"

    with tempfile.NamedTemporaryFile(
        prefix="uv-lock-sbom.",
        suffix=".syft.json",
        delete=False,
    ) as tmp_sbom:
        tmp_sbom_path = Path(tmp_sbom.name)

    try:
        print(f"Generating SBOM for {uv_lock_path} with Syft...", flush=True)
        subprocess.run(
            [
                "syft",
                "scan",
                f"file:{uv_lock_path}",
                "-q",
                "-o",
                f"syft-json={tmp_sbom_path}",
            ],
            check=True,
            env=env,
        )

        if fail_on_severity and fail_on_severity != "none":
            print(
                "Scanning SBOM with Grype "
                f"(failing on {fail_on_severity} or higher)...",
                flush=True,
            )
        else:
            print("Scanning SBOM with Grype...", flush=True)

        grype_result = subprocess.run(
            ["grype", f"sbom:{tmp_sbom_path}", "-o", "json"],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )
        report = json.loads(grype_result.stdout)
        print_grype_db_status(env)
        matches = report.get("matches", [])
        print_matches(matches)

        failed_matches = failing_matches(matches, fail_on_severity)
        if failed_matches:
            print(
                f"Failing because {len(failed_matches)} vulnerabilities are "
                f"at or above severity '{fail_on_severity}'.",
                file=sys.stderr,
                flush=True,
            )
            return 2
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    except json.JSONDecodeError as error:
        print(f"Could not parse Grype JSON output: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, file=sys.stdout)
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        return error.returncode
    finally:
        try:
            tmp_sbom_path.unlink(missing_ok=True)
        except OSError as error:
            print(
                f"Warning: could not remove temporary SBOM {tmp_sbom_path}: {error}",
                file=sys.stderr,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
