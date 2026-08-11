#!/usr/bin/env python3
"""Controller-owned build and OSV scan adapter for Candidate images."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_SUBJECT = re.compile(r"[a-f0-9]{64}")


def _write_evidence(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _containerfile(root: Path) -> Path:
    for relative in (
        "container/Containerfile",
        "Containerfile",
        "Dockerfile",
    ):
        candidate = root / relative
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise RuntimeError("container build file is missing")


def _validated_root(raw: str) -> Path:
    root = Path(raw).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("product root is not a directory")
    return root


def build(args: argparse.Namespace) -> int:
    root = _validated_root(args.root)
    if not _SUBJECT.fullmatch(args.subject_sha):
        raise RuntimeError("subject SHA is invalid")
    containerfile = _containerfile(root)
    with tempfile.TemporaryDirectory(prefix="hermes-image-build-") as directory:
        iidfile = Path(directory) / "iid"
        completed = subprocess.run(
            [
                args.builder,
                "build",
                "--iidfile",
                str(iidfile),
                "--tag",
                args.image_ref,
                "--file",
                str(containerfile),
                str(root),
            ],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=840,
            check=False,
        )
        if completed.returncode != 0 or not iidfile.is_file():
            raise RuntimeError(
                f"container build failed with exit code {completed.returncode}"
            )
        image_digest = iidfile.read_text(encoding="utf-8").strip().lower()
    if not _DIGEST.fullmatch(image_digest):
        raise RuntimeError("container builder returned a non-immutable image ID")
    _write_evidence(
        Path(args.output),
        {
            "status": "pass",
            "subject_sha": args.subject_sha,
            "image_ref": args.image_ref,
            "image_digest": image_digest,
            "immutable_image_ref": f"{args.image_ref}@{image_digest}",
        },
    )
    return 0


def _findings(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        raise TypeError("OSV image scan output is not an object")
    results = payload.get("results", [])
    if not isinstance(results, list):
        raise TypeError("OSV image scan results are malformed")
    findings: list[dict[str, str]] = []
    for result in results:
        if not isinstance(result, dict):
            raise TypeError("OSV image scan result is malformed")
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise TypeError("OSV image scan package list is malformed")
        for package_entry in packages:
            if not isinstance(package_entry, dict):
                raise TypeError("OSV image scan package entry is malformed")
            package = package_entry.get("package", {})
            package_name = (
                str(package.get("name") or "unknown")
                if isinstance(package, dict)
                else "unknown"
            )
            vulnerabilities = package_entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise TypeError("OSV vulnerability list is malformed")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise TypeError("OSV vulnerability entry is malformed")
                severities = vulnerability.get("severity", [])
                severity = "unknown"
                if isinstance(severities, list) and severities:
                    first = severities[0]
                    if isinstance(first, dict):
                        severity = str(first.get("score") or first.get("type") or severity)
                findings.append(
                    {
                        "id": str(vulnerability.get("id") or "unknown"),
                        "severity": severity,
                        "package": package_name,
                    }
                )
    return sorted(findings, key=lambda item: (item["id"], item["package"]))


def scan(args: argparse.Namespace) -> int:
    _validated_root(args.root)
    if not _SUBJECT.fullmatch(args.subject_sha):
        raise RuntimeError("subject SHA is invalid")
    match = re.search(r"(sha256:[a-f0-9]{64})$", args.image_digest)
    if match is None:
        raise RuntimeError("immutable image reference is invalid")
    completed = subprocess.run(
        [args.scanner, "scan", "image", "--format", "json", args.image_digest],
        text=True,
        capture_output=True,
        timeout=840,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(
            f"OSV image scanner failed with exit code {completed.returncode}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("OSV image scanner output is not valid JSON") from error
    findings = _findings(payload)
    image_digest = match.group(1)
    blocking = len(findings)
    _write_evidence(
        Path(args.output),
        {
            "status": "pass" if blocking == 0 and completed.returncode == 0 else "fail",
            "subject_sha": args.subject_sha,
            "image_ref": args.image_digest,
            "image_digest": image_digest,
            "scanner": str(Path(args.scanner).resolve(strict=True)),
            "evidence_valid": True,
            "scanner_exit_code": completed.returncode,
            "blocking_findings": blocking,
            "findings": findings,
        },
    )
    return 0 if blocking == 0 and completed.returncode == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--root", required=True)
    build_parser.add_argument("--image-ref", required=True)
    build_parser.add_argument("--subject-sha", required=True)
    build_parser.add_argument("--output", required=True)
    build_parser.add_argument("--builder", required=True)
    build_parser.set_defaults(handler=build)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--root", required=True)
    scan_parser.add_argument("--image-digest", required=True)
    scan_parser.add_argument("--subject-sha", required=True)
    scan_parser.add_argument("--output", required=True)
    scan_parser.add_argument("--scanner", required=True)
    scan_parser.add_argument("--builder", required=True)
    scan_parser.set_defaults(handler=scan)
    args = parser.parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
