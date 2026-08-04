"""Digest-bound, one-shot fault contracts for isolated clean canaries only."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .common import sha256_text, stable_json, utc_now
from .config import FactoryConfig
from .quality import QualityGateEngine, QualityGateRun


class CanaryFaultError(RuntimeError):
    """The qualification-only fault boundary is invalid or has been tampered with."""


class Runner(Protocol):
    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> Any: ...


@dataclass(frozen=True)
class CanaryFaultContract:
    scenario_id: str
    scenario_digest: str
    controller_release_digest: str
    candidate_digest: str
    faults: tuple[str, ...]
    receipt_root: Path
    isolated_target_root: Path

    @classmethod
    def from_config(cls, config: FactoryConfig) -> CanaryFaultContract:
        qualification = config.raw.get("qualification")
        if not isinstance(qualification, Mapping) or qualification.get("plane") != "CLEAN_CANARY":
            raise CanaryFaultError("fault injection is allowed only in CLEAN_CANARY")
        contract = cls(
            scenario_id=str(qualification["scenario_id"]),
            scenario_digest=str(qualification["scenario_digest"]),
            controller_release_digest=str(
                qualification["controller_release_digest"]
            ),
            candidate_digest=str(qualification["candidate_digest"]),
            faults=tuple(str(value) for value in qualification["faults"]),
            receipt_root=Path(str(qualification["fault_receipt_root"])),
            isolated_target_root=Path(str(qualification["isolated_target_root"])),
        )
        if not contract.receipt_root.is_absolute() or not contract.isolated_target_root.is_absolute():
            raise CanaryFaultError("clean canary fault roots must be absolute")
        return contract

    @property
    def digest(self) -> str:
        return sha256_text(
            stable_json(
                {
                    "scenario_id": self.scenario_id,
                    "scenario_digest": self.scenario_digest,
                    "controller_release_digest": self.controller_release_digest,
                    "candidate_digest": self.candidate_digest,
                    "faults": self.faults,
                    "receipt_root": str(self.receipt_root),
                    "isolated_target_root": str(self.isolated_target_root),
                }
            )
        )


class CanaryFaultJournal:
    """Write-once evidence that each declared fault was consumed at most once."""

    def __init__(self, contract: CanaryFaultContract) -> None:
        self.contract = contract
        self.root = contract.receipt_root

    def _path(self, fault: str) -> Path:
        if fault not in self.contract.faults:
            raise CanaryFaultError("fault is outside the signed scenario contract")
        return self.root / f"{fault}.json"

    def consumed(self, fault: str) -> bool:
        path = self._path(fault)
        if not path.exists():
            return False
        self.load(fault)
        return True

    def consume(
        self,
        fault: str,
        *,
        point: str,
        product_id: str | None = None,
        task_id: str | None = None,
        observed: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        path = self._path(fault)
        self.root.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "1.0",
            "scenario_id": self.contract.scenario_id,
            "scenario_digest": self.contract.scenario_digest,
            "candidate_digest": self.contract.candidate_digest,
            "controller_release_digest": self.contract.controller_release_digest,
            "fault_contract_digest": self.contract.digest,
            "fault": fault,
            "point": point,
            "product_id": product_id,
            "task_id": task_id,
            "observed": dict(observed or {}),
            "consumed_at": utc_now(),
        }
        receipt_digest = sha256_text(stable_json(payload))
        envelope = {**payload, "receipt_digest": receipt_digest}
        encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        except FileExistsError as error:
            raise CanaryFaultError("clean canary fault was consumed more than once") from error
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        try:
            path.chmod(0o440)
        except OSError:
            pass
        return envelope

    def load(self, fault: str) -> dict[str, Any]:
        path = self._path(fault)
        if not path.is_file() or path.is_symlink():
            raise CanaryFaultError("clean canary fault receipt is unavailable")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CanaryFaultError("clean canary fault receipt is unreadable") from error
        if not isinstance(payload, dict):
            raise CanaryFaultError("clean canary fault receipt is not an object")
        receipt_digest = str(payload.pop("receipt_digest", ""))
        if (
            sha256_text(stable_json(payload)) != receipt_digest
            or payload.get("scenario_id") != self.contract.scenario_id
            or payload.get("scenario_digest") != self.contract.scenario_digest
            or payload.get("candidate_digest") != self.contract.candidate_digest
            or payload.get("controller_release_digest")
            != self.contract.controller_release_digest
            or payload.get("fault_contract_digest") != self.contract.digest
            or payload.get("fault") != fault
        ):
            raise CanaryFaultError("clean canary fault receipt integrity failed")
        return {**payload, "receipt_digest": receipt_digest}


class FaultInjectingHermesRunner:
    """Inject transport boundaries before delegating all other calls to Hermes."""

    def __init__(self, delegate: Runner, journal: CanaryFaultJournal) -> None:
        self.delegate = delegate
        self.journal = journal

    def run(
        self,
        *,
        selection: Any,
        prompt: str,
        cwd: Path,
        usage_path: Path | None = None,
    ) -> Any:
        from .worker import HermesRunResult

        if prompt.strip() == 'Return exactly {"status":"PASS"} and no other text.':
            return self.delegate.run(
                selection=selection,
                prompt=prompt,
                cwd=cwd,
                usage_path=usage_path,
            )
        if (
            "BOUNDED_EXTERNAL_BLOCK" in self.journal.contract.faults
            and not self.journal.consumed("BOUNDED_EXTERNAL_BLOCK")
        ):
            self.journal.consume(
                "BOUNDED_EXTERNAL_BLOCK",
                point="provider_preflight",
                observed={"reason_code": "network_timeout"},
            )
            message = "The isolated external fixture is not ready yet."
            return HermesRunResult(
                "FAIL",
                message,
                sha256_text(message),
                "network_timeout",
            )
        if (
            "ONE_PROVIDER_TIMEOUT" in self.journal.contract.faults
            and not self.journal.consumed("ONE_PROVIDER_TIMEOUT")
        ):
            self.journal.consume(
                "ONE_PROVIDER_TIMEOUT",
                point="provider_transport",
                observed={"reason_code": "agent_execution_timeout"},
            )
            message = "The qualification transport timed out once before provider execution."
            return HermesRunResult(
                "TIMEOUT",
                message,
                sha256_text(message),
                "agent_execution_timeout",
            )
        return self.delegate.run(
            selection=selection,
            prompt=prompt,
            cwd=cwd,
            usage_path=usage_path,
        )


class FaultInjectingQualityGate:
    """Fail one product-test gate after every earlier gate passed normally."""

    def __init__(
        self,
        delegate: QualityGateEngine,
        journal: CanaryFaultJournal,
        *,
        task_lookup: Any,
    ) -> None:
        self.delegate = delegate
        self.journal = journal
        self.task_lookup = task_lookup

    def run(
        self,
        *,
        cwd: Path,
        subject_sha: str,
        task_id: str,
        attempt_id: str,
        gate_ids: list[str],
    ) -> QualityGateRun:
        task = self.task_lookup(task_id)
        stage = str((task or {}).get("lifecycle_stage") or (task or {}).get("stage_key") or "")
        should_inject = (
            stage == "test"
            and bool(gate_ids)
            and "ONE_PRODUCT_TEST_FAILURE" in self.journal.contract.faults
            and not self.journal.consumed("ONE_PRODUCT_TEST_FAILURE")
        )
        if not should_inject:
            return self.delegate.run(
                cwd=cwd,
                subject_sha=subject_sha,
                task_id=task_id,
                attempt_id=attempt_id,
                gate_ids=gate_ids,
            )
        receipt = self.journal.consume(
            "ONE_PRODUCT_TEST_FAILURE",
            point="mandatory_product_test",
            task_id=task_id,
            observed={"gate_id": gate_ids[0], "status": "FAIL"},
        )
        evidence = {
            "schema_version": "1.0",
            "gate_id": gate_ids[0],
            "status": "FAIL",
            "subject_sha": subject_sha,
            "command_digest": sha256_text("qualification-one-product-test-failure"),
            "started_at": str(receipt["consumed_at"]),
            "finished_at": str(receipt["consumed_at"]),
            "exit_code": 1,
            "artifact_digest": sha256_text(str(receipt["receipt_digest"])),
            "summary": "One declared clean-canary product test failure was injected.",
            "mandatory": True,
        }
        evidence_path = self.delegate.artifacts.write(
            "gate-evidence.schema.json",
            evidence,
            filename=f"gate-{task_id}-{attempt_id}-{gate_ids[0]}-fault.json",
        )
        return QualityGateRun(
            (
                {
                    "gate_id": gate_ids[0],
                    "status": "FAIL",
                    "evidence_ref": str(evidence_path),
                },
            ),
            (evidence_path,),
            False,
        )
