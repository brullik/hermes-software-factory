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


class UnknownQualityGatesError(ValueError):
    """Raised when a persisted task references gates outside the controller catalog."""

    def __init__(self, gate_ids: list[str]) -> None:
        self.gate_ids = tuple(gate_ids)
        super().__init__(f"Unknown quality gates: {', '.join(self.gate_ids)}")


class ControllerContainerScanHelperInvalid(RuntimeError):
    """The immutable controller-owned image verifier is missing or tampered."""


class QualityGateEngine:
    """Run only controller-selected catalog entries; model text cannot alter the catalog."""

    def __init__(self, config: FactoryConfig, artifacts: ArtifactStore | None = None) -> None:
        self.config = config
        self.artifacts = artifacts or ArtifactStore(config)
        packaged_catalog = Path(__file__).resolve().parents[1] / "config" / "quality-gates.yaml"
        configured = config.raw.get("paths", {}).get("quality_gates")
        self.catalog_path = Path(str(configured)) if configured else packaged_catalog
        self.temporary_root = config.state_dir / "tmp" / "quality-gates"

    @staticmethod
    def _python_executable(cwd: Path) -> str:
        candidates = (
            cwd.parent / "venv" / "bin" / "python",
            cwd.parent / "venv" / "Scripts" / "python.exe",
        )
        selected = next((path for path in candidates if path.is_file()), None)
        return str(selected) if selected is not None else sys.executable

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
            raise UnknownQualityGatesError(unknown)

        results: list[dict[str, str]] = []
        evidence_paths: list[Path] = []
        mandatory_passed = True
        for gate_id in gate_ids:
            gate = by_id[gate_id]
            evidence = run_gate(
                gate,
                cwd,
                subject_sha,
                python_executable=self._python_executable(cwd),
                temporary_root=self.temporary_root,
            )
            filename = f"gate-{task_id}-{attempt_id}-{gate_id}.json"
            evidence_path = self.artifacts.write("gate-evidence.schema.json", evidence, filename=filename)
            evidence_paths.append(evidence_path)
            status = str(evidence["status"])
            if "controller_container_scan_helper_invalid" in str(
                evidence.get("summary") or ""
            ):
                raise ControllerContainerScanHelperInvalid(
                    "controller_container_scan_helper_invalid"
                )
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
