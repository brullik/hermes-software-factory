"""Controller-owned execution of immutable, allowlisted quality gates."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from scripts.quality_gate import load_catalog, run_gate

from .artifacts import ArtifactStore
from .common import sha256_text
from .config import FactoryConfig


@dataclass(frozen=True)
class QualityGateRun:
    """Machine-readable results and evidence paths for one gate batch."""

    results: tuple[dict[str, str], ...]
    evidence_paths: tuple[Path, ...]
    mandatory_passed: bool


class QualityGateEngine:
    """Run only controller-selected catalog entries; model text cannot alter the catalog."""

    def __init__(self, config: FactoryConfig, artifacts: ArtifactStore | None = None) -> None:
        self.config = config
        self.artifacts = artifacts or ArtifactStore(config)
        self.catalog_path = config.source.parent / "quality-gates.yaml"

    def run(
        self,
        *,
        cwd: Path,
        subject_sha: str,
        task_id: str,
        attempt_id: str,
        gate_ids: list[str],
    ) -> QualityGateRun:
        if not gate_ids:
            return QualityGateRun((), (), True)
        if not self.catalog_path.is_file():
            raise FileNotFoundError(f"Quality gate catalog is missing: {self.catalog_path}")
        catalog = load_catalog(self.catalog_path)
        entries = catalog.get("gates")
        if not isinstance(entries, list):
            raise TypeError("Quality gate catalog must contain a gates list")
        by_id = {str(entry["id"]): entry for entry in entries if isinstance(entry, dict) and "id" in entry}
        unknown = sorted(set(gate_ids) - set(by_id))
        if unknown:
            raise ValueError(f"Unknown quality gates: {', '.join(unknown)}")

        results: list[dict[str, str]] = []
        evidence_paths: list[Path] = []
        mandatory_passed = True
        for gate_id in gate_ids:
            gate = by_id[gate_id]
            evidence = run_gate(
                gate,
                cwd,
                subject_sha,
                python_executable=sys.executable,
            )
            filename = f"gate-{task_id}-{attempt_id}-{gate_id}.json"
            evidence_path = self.artifacts.write("gate-evidence.schema.json", evidence, filename=filename)
            evidence_paths.append(evidence_path)
            status = str(evidence["status"])
            results.append(
                {
                    "gate_id": gate_id,
                    "status": "PASS" if status == "PASS" else "FAIL",
                    "evidence_ref": str(evidence_path),
                }
            )
            if bool(gate.get("mandatory", True)) and status != "PASS":
                mandatory_passed = False
        return QualityGateRun(tuple(results), tuple(evidence_paths), mandatory_passed)

    @staticmethod
    def batch_digest(run: QualityGateRun) -> str:
        """Return a stable digest for gate IDs/statuses, excluding timestamps."""
        return sha256_text("|".join(f"{item['gate_id']}:{item['status']}" for item in run.results))
