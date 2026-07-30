#!/usr/bin/env python3
"""Fail closed when release version evidence disagrees."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
import zipfile
from collections.abc import Iterable, Mapping
from email.parser import Parser
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:[A-Za-z0-9.+-]*)$")
_CHANGELOG_VERSION = re.compile(r"^##\s+([^\s]+)", re.MULTILINE)


class VersionConsistencyError(ValueError):
    """Release metadata is missing, malformed, or inconsistent."""


def _valid(label: str, value: object) -> str:
    version = str(value).strip()
    if not _VERSION.fullmatch(version):
        raise VersionConsistencyError(f"{label} contains an invalid version")
    return version


def _canonical_project_name(value: object) -> str:
    return re.sub(r"[-_.]+", "-", str(value).strip().lower())


def _project_metadata(path: Path) -> tuple[str, str]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VersionConsistencyError("pyproject.toml is invalid") from error
    project = payload.get("project")
    if not isinstance(project, Mapping):
        raise VersionConsistencyError("pyproject.toml has no [project] table")
    name = _canonical_project_name(project.get("name", ""))
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        raise VersionConsistencyError("pyproject.toml project name is invalid")
    return name, _valid("pyproject.toml", project.get("version", ""))


def _changelog_version(path: Path) -> str:
    try:
        match = _CHANGELOG_VERSION.search(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise VersionConsistencyError("CHANGELOG.md cannot be read") from error
    if match is None:
        raise VersionConsistencyError("CHANGELOG.md has no release heading")
    return _valid("CHANGELOG.md", match.group(1))


def _sbom_version(path: Path, project_name: str) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VersionConsistencyError("SBOM is invalid") from error
    packages = payload.get("packages") if isinstance(payload, Mapping) else None
    if not isinstance(packages, list):
        raise VersionConsistencyError("SBOM has no packages list")
    matches = [
        package
        for package in packages
        if isinstance(package, Mapping)
        and _canonical_project_name(package.get("name", "")) == project_name
    ]
    if len(matches) != 1:
        raise VersionConsistencyError("SBOM must identify exactly one factory package")
    return _valid("SBOM", matches[0].get("versionInfo", ""))


def _wheel_version(path: Path, project_name: str) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise VersionConsistencyError(
                    "wheel must contain exactly one dist-info/METADATA"
                )
            metadata = Parser().parsestr(
                archive.read(metadata_names[0]).decode("utf-8")
            )
    except (OSError, UnicodeError, zipfile.BadZipFile, KeyError) as error:
        raise VersionConsistencyError("wheel metadata is invalid") from error
    if _canonical_project_name(metadata.get("Name", "")) != project_name:
        raise VersionConsistencyError("wheel contains an unexpected project")
    return _valid("wheel METADATA", metadata.get("Version", ""))


def _release_record_version(path: Path) -> str:
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VersionConsistencyError("release record is invalid") from error
    if not isinstance(payload, Mapping):
        raise VersionConsistencyError("release record must be an object")
    release = payload.get("release")
    value = release.get("version") if isinstance(release, Mapping) else payload.get("version")
    return _valid("release record", value or "")


def collect_version_evidence(
    root: Path,
    *,
    wheel: Path | None = None,
    sbom: Path | None = None,
    release_record: Path | None = None,
) -> dict[str, str]:
    """Collect every version source present in a release candidate."""

    evidence: dict[str, str] = {}
    project_name = "hermes-software-factory-spec"
    version_path = root / "VERSION"
    if version_path.is_file():
        try:
            version_value = version_path.read_text(encoding="utf-8")
        except OSError as error:
            raise VersionConsistencyError("VERSION cannot be read") from error
        evidence["VERSION"] = _valid("VERSION", version_value)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        project_name, evidence["pyproject.toml"] = _project_metadata(pyproject)
    changelog = root / "CHANGELOG.md"
    if changelog.is_file():
        evidence["CHANGELOG.md"] = _changelog_version(changelog)
    resolved_sbom = sbom or root / "evidence" / "sbom.spdx.json"
    if resolved_sbom.is_file():
        evidence["SBOM"] = _sbom_version(resolved_sbom, project_name)
    if wheel is not None:
        evidence["wheel METADATA"] = _wheel_version(wheel, project_name)
    if release_record is not None:
        evidence["release record"] = _release_record_version(release_record)
    return evidence


def verify_version_consistency(
    root: Path,
    *,
    wheel: Path | None = None,
    sbom: Path | None = None,
    release_record: Path | None = None,
    expected: str | None = None,
    required_labels: Iterable[str] = (),
) -> str:
    """Return the single release version or raise before side effects."""

    evidence = collect_version_evidence(
        root,
        wheel=wheel,
        sbom=sbom,
        release_record=release_record,
    )
    missing = sorted(set(required_labels) - evidence.keys())
    if missing:
        raise VersionConsistencyError(
            "missing version evidence: " + ", ".join(missing)
        )
    if not evidence:
        raise VersionConsistencyError("release candidate has no version evidence")
    versions = set(evidence.values())
    if expected is not None:
        versions.add(_valid("expected version", expected))
    if len(versions) != 1:
        coordinates = ", ".join(
            f"{label}={value}" for label, value in sorted(evidence.items())
        )
        raise VersionConsistencyError(
            f"release version mismatch: {coordinates}"
        )
    return next(iter(versions))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--release-record", type=Path)
    parser.add_argument("--expected")
    parser.add_argument("--factory-source", action="store_true")
    args = parser.parse_args()
    required = (
        ("VERSION", "pyproject.toml", "CHANGELOG.md", "SBOM")
        if args.factory_source
        else ()
    )
    try:
        version = verify_version_consistency(
            args.root.resolve(),
            wheel=args.wheel,
            sbom=args.sbom,
            release_record=args.release_record,
            expected=args.expected,
            required_labels=required,
        )
    except VersionConsistencyError as error:
        print(f"VERSION CONSISTENCY FAILED: {error}")
        return 1
    print(f"VERSION CONSISTENCY PASSED: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
