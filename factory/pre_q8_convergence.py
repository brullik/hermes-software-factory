"""Isolated all-ten PRE-Q8 convergence matrices and namespaces."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .common import sha256_text, stable_json, utc_now
from .functional_readiness import PRE_Q8_SCENARIOS


class PreQ8ConvergenceError(RuntimeError):
    """A convergence sweep is incomplete, ambiguous, or not isolated."""


_RUN_ID: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
_SHA256: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
_PLANES: Final[frozenset[str]] = frozenset({"convergence", "pre-q8", "q8"})


@dataclass(frozen=True)
class ConvergenceScenarioResult:
    scenario_id: str
    status: str
    evidence_digest: str
    config_digest: str
    failure_class: str | None = None
    support_bundle_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "status": self.status,
            "evidence_digest": self.evidence_digest,
            "config_digest": self.config_digest,
            "failure_class": self.failure_class,
            "support_bundle_ref": self.support_bundle_ref,
        }

    def validate(self) -> None:
        if self.scenario_id not in PRE_Q8_SCENARIOS:
            raise PreQ8ConvergenceError("convergence scenario is outside the closed catalog")
        if self.status not in {"PASS", "FAIL"}:
            raise PreQ8ConvergenceError("convergence scenario status is invalid")
        if not _SHA256.fullmatch(self.evidence_digest) or not _SHA256.fullmatch(
            self.config_digest
        ):
            raise PreQ8ConvergenceError("convergence scenario digest is invalid")
        if self.status == "PASS" and (self.failure_class or self.support_bundle_ref):
            raise PreQ8ConvergenceError("passing convergence scenario contains failure evidence")
        if self.status == "FAIL" and not self.failure_class:
            raise PreQ8ConvergenceError("failed convergence scenario lacks a typed failure")


class ConvergenceStore:
    """Separate durable store for diagnostic sweeps; never writes official PRE-Q8."""

    def __init__(self, database: Path) -> None:
        if not database.is_absolute() or database.is_symlink():
            raise PreQ8ConvergenceError("convergence database path is unsafe")
        database.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS convergence_runs (
                run_id TEXT PRIMARY KEY,
                candidate_digest TEXT NOT NULL,
                git_tree TEXT NOT NULL,
                release_tree_digest TEXT NOT NULL,
                toolchain_digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                  'CONVERGENCE_RUNNING','CONVERGENCE_SWEEP_FAILED','CONVERGENCE_10_OF_10',
                  'CONVERGENCE_SEALED','CONVERGENCE_INVALIDATED'
                )),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS convergence_results (
                run_id TEXT NOT NULL REFERENCES convergence_runs(run_id),
                scenario_id TEXT NOT NULL,
                scenario_index INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PASS','FAIL')),
                evidence_digest TEXT NOT NULL,
                config_digest TEXT NOT NULL,
                failure_class TEXT,
                support_bundle_ref TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY(run_id,scenario_id),
                UNIQUE(run_id,scenario_index)
            );
            """
        )

    def close(self) -> None:
        self.connection.close()

    def start(
        self,
        *,
        run_id: str,
        candidate_digest: str,
        git_tree: str,
        release_tree_digest: str,
        toolchain_digest: str,
    ) -> bool:
        run = validate_run_id(run_id)
        if re.fullmatch(r"[a-f0-9]{40}", git_tree) is None or any(
            _SHA256.fullmatch(value) is None
            for value in (candidate_digest, release_tree_digest, toolchain_digest)
        ):
            raise PreQ8ConvergenceError("convergence run identity is invalid")
        identity = (candidate_digest, git_tree, release_tree_digest, toolchain_digest)
        existing = self.connection.execute(
            "SELECT candidate_digest,git_tree,release_tree_digest,toolchain_digest "
            "FROM convergence_runs WHERE run_id=?",
            (run,),
        ).fetchone()
        if existing is not None:
            if tuple(str(value) for value in existing) != identity:
                raise PreQ8ConvergenceError("immutable convergence run conflicts")
            return False
        now = utc_now()
        with self.connection:
            self.connection.execute(
                "INSERT INTO convergence_runs VALUES (?,?,?,?,?,'CONVERGENCE_RUNNING',?,?)",
                (run, *identity, now, now),
            )
        return True

    def record(self, run_id: str, result: ConvergenceScenarioResult) -> bool:
        run = validate_run_id(run_id)
        result.validate()
        status = self.connection.execute(
            "SELECT status FROM convergence_runs WHERE run_id=?", (run,)
        ).fetchone()
        if status is None or str(status[0]) != "CONVERGENCE_RUNNING":
            raise PreQ8ConvergenceError("convergence result requires a running sweep")
        identity = (
            result.status,
            result.evidence_digest,
            result.config_digest,
            result.failure_class,
            result.support_bundle_ref,
        )
        existing = self.connection.execute(
            "SELECT status,evidence_digest,config_digest,failure_class,support_bundle_ref "
            "FROM convergence_results WHERE run_id=? AND scenario_id=?",
            (run, result.scenario_id),
        ).fetchone()
        if existing is not None:
            if tuple(existing) != identity:
                raise PreQ8ConvergenceError("immutable convergence result conflicts")
            return False
        with self.connection:
            self.connection.execute(
                "INSERT INTO convergence_results VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run,
                    result.scenario_id,
                    PRE_Q8_SCENARIOS.index(result.scenario_id),
                    *identity,
                    utc_now(),
                ),
            )
        return True

    def results(self, run_id: str) -> tuple[ConvergenceScenarioResult, ...]:
        rows = self.connection.execute(
            "SELECT scenario_id,status,evidence_digest,config_digest,failure_class,"
            "support_bundle_ref FROM convergence_results WHERE run_id=? "
            "ORDER BY scenario_index",
            (validate_run_id(run_id),),
        ).fetchall()
        return tuple(
            ConvergenceScenarioResult(
                scenario_id=str(row[0]),
                status=str(row[1]),
                evidence_digest=str(row[2]),
                config_digest=str(row[3]),
                failure_class=str(row[4]) if row[4] is not None else None,
                support_bundle_ref=str(row[5]) if row[5] is not None else None,
            )
            for row in rows
        )

    def finalize(self, run_id: str) -> str:
        run = validate_run_id(run_id)
        results = self.results(run)
        if tuple(result.scenario_id for result in results) != PRE_Q8_SCENARIOS:
            raise PreQ8ConvergenceError("convergence sweep is incomplete")
        status = (
            "CONVERGENCE_10_OF_10"
            if all(result.status == "PASS" for result in results)
            else "CONVERGENCE_SWEEP_FAILED"
        )
        with self.connection:
            self.connection.execute(
                "UPDATE convergence_runs SET status=?,updated_at=? WHERE run_id=?",
                (status, utc_now(), run),
            )
        return status

    def mark_sealed(self, run_id: str) -> None:
        run = validate_run_id(run_id)
        current = self.connection.execute(
            "SELECT status FROM convergence_runs WHERE run_id=?", (run,)
        ).fetchone()
        if current is not None and str(current[0]) == "CONVERGENCE_SEALED":
            return
        with self.connection:
            changed = self.connection.execute(
                "UPDATE convergence_runs SET status='CONVERGENCE_SEALED',updated_at=? "
                "WHERE run_id=? AND status='CONVERGENCE_10_OF_10'",
                (utc_now(), run),
            ).rowcount
        if changed != 1:
            raise PreQ8ConvergenceError("only a 10/10 convergence run can be sealed")


def validate_run_id(run_id: str) -> str:
    normalized = run_id.strip().lower()
    if _RUN_ID.fullmatch(normalized) is None:
        raise PreQ8ConvergenceError("convergence run id is invalid")
    return normalized


def resource_namespace(
    *, plane: str, run_id: str, candidate_digest: str, scenario_id: str
) -> str:
    normalized_plane = plane.strip().lower()
    if normalized_plane not in _PLANES:
        raise PreQ8ConvergenceError("qualification plane is invalid")
    run = validate_run_id(run_id)
    if not _SHA256.fullmatch(candidate_digest) or scenario_id not in PRE_Q8_SCENARIOS:
        raise PreQ8ConvergenceError("qualification resource identity is invalid")
    scenario = scenario_id.replace("-", "")[:18]
    identity = sha256_text(
        stable_json(
            ["pre-q8-resource-v2", normalized_plane, run, candidate_digest, scenario_id]
        )
    )[:20]
    return f"hermes-canary-{normalized_plane.replace('-', '')}-{scenario}-{identity}"


def resource_idempotency_key(
    *, plane: str, run_id: str, candidate_digest: str, scenario_id: str
) -> str:
    normalized_plane = plane.strip().lower()
    resource_namespace(
        plane=normalized_plane,
        run_id=run_id,
        candidate_digest=candidate_digest,
        scenario_id=scenario_id,
    )
    return sha256_text(
        stable_json(
            [
                "pre-q8-resource-v2",
                normalized_plane,
                validate_run_id(run_id),
                candidate_digest,
                scenario_id,
            ]
        )
    )


def run_sweep(
    run_id: str,
    executor: Callable[[str], ConvergenceScenarioResult],
) -> tuple[ConvergenceScenarioResult, ...]:
    """Execute every closed scenario even when one or more scenarios fail."""

    validate_run_id(run_id)
    results: list[ConvergenceScenarioResult] = []
    for scenario_id in PRE_Q8_SCENARIOS:
        try:
            result = executor(scenario_id)
        # A sweep is diagnostic by contract: one broken scenario must not hide
        # any of the remaining nine.  The exception is converted to typed
        # failure evidence and execution continues.
        except Exception as error:  # noqa: BLE001
            result = ConvergenceScenarioResult(
                scenario_id=scenario_id,
                status="FAIL",
                evidence_digest=sha256_text(
                    stable_json(
                        {
                            "schema_version": "1.0",
                            "run_id": run_id,
                            "scenario_id": scenario_id,
                            "failure_class": type(error).__name__,
                        }
                    )
                ),
                config_digest=sha256_text(
                    stable_json([run_id, scenario_id, "executor-exception"])
                ),
                failure_class=type(error).__name__,
            )
        result.validate()
        if result.scenario_id != scenario_id:
            raise PreQ8ConvergenceError("convergence executor returned a different scenario")
        results.append(result)
    return tuple(results)


def matrix_body(
    *,
    run_id: str,
    git_tree: str,
    release_tree_digest: str,
    toolchain_digest: str,
    results: tuple[ConvergenceScenarioResult, ...],
) -> dict[str, Any]:
    run = validate_run_id(run_id)
    if not re.fullmatch(r"[a-f0-9]{40}", git_tree):
        raise PreQ8ConvergenceError("convergence Git tree is invalid")
    if any(
        _SHA256.fullmatch(value) is None
        for value in (release_tree_digest, toolchain_digest)
    ):
        raise PreQ8ConvergenceError("convergence release identity is invalid")
    if tuple(result.scenario_id for result in results) != PRE_Q8_SCENARIOS:
        raise PreQ8ConvergenceError("convergence matrix order differs from the closed catalog")
    for result in results:
        result.validate()
    pass_count = sum(result.status == "PASS" for result in results)
    return {
        "schema_version": "1.0",
        "matrix_type": "PREQ8_CONVERGENCE_MATRIX",
        "run_id": run,
        "git_tree": git_tree,
        "release_tree_digest": release_tree_digest,
        "toolchain_digest": toolchain_digest,
        "scenario_count": len(results),
        "pass_count": pass_count,
        "status": "10/10 PASS" if pass_count == len(PRE_Q8_SCENARIOS) else "SWEEP_FAILED",
        "scenarios": [result.as_dict() for result in results],
    }


def write_matrix(path: Path, body: Mapping[str, Any]) -> tuple[str, Path]:
    identity = {str(key): value for key, value in body.items()}
    digest = sha256_text(stable_json(identity))
    envelope = {**identity, "matrix_digest": digest, "observed_at": utc_now()}
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink():
            raise PreQ8ConvergenceError("convergence matrix path is a symlink")
        existing = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(existing, Mapping):
            raise PreQ8ConvergenceError("convergence matrix is not an object")
        existing_body = {
            str(key): value
            for key, value in existing.items()
            if key not in {"matrix_digest", "observed_at"}
        }
        if existing.get("matrix_digest") != digest or existing_body != identity:
            raise PreQ8ConvergenceError("immutable convergence matrix conflicts")
        return digest, path
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return digest, path
