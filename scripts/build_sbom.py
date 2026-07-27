#!/usr/bin/env python3
"""Build a deterministic SPDX 2.3 SBOM from the pinned lockfile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "evidence" / "sbom.spdx.json"


def locked_packages() -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    for line in (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, version = line.split("==", 1)
        packages.append((name, version))
    return packages


def build() -> dict[str, object]:
    packages: list[dict[str, object]] = [
        {
            "SPDXID": "SPDXRef-Package-hermes-software-factory-spec",
            "name": "hermes-software-factory-spec",
            "versionInfo": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        },
        {
            "SPDXID": "SPDXRef-Package-hermes-agent",
            "name": "hermes-agent",
            "versionInfo": "0.19.0",
            "downloadLocation": "https://pypi.org/project/hermes-agent/0.19.0/",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "bd0bac012aee38a60894781f4597dc29ee7bedb3448540249921f10d3bef327f"}],
        },
    ]
    for name, version in locked_packages():
        safe_id = "".join(char if char.isalnum() else "-" for char in name)
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{safe_id}",
                "name": name,
                "versionInfo": version,
                "downloadLocation": f"https://pypi.org/project/{name}/{version}/",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "hermes-software-factory-2.0.0",
        "documentNamespace": "https://brullik.github.io/hermes-software-factory/sbom/2.0.0",
        "creationInfo": {
            "created": "2026-07-26T00:00:00Z",
            "creators": ["Tool: hermes-software-factory/scripts/build_sbom.py"],
        },
        "packages": packages,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = json.dumps(build(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != payload:
            print("SBOM CHECK FAILED")
            return 1
        print("SBOM CHECK PASSED")
        return 0
    OUTPUT.write_text(payload, encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
