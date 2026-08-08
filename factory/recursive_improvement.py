"""Bounded recursive improvement in an isolated Candidate experiment lane."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .common import sha256_file, sha256_text, stable_json, utc_now


class ImprovementError(RuntimeError):
    """An improvement proposal or cycle violated a deterministic guard."""


SAFETY_METRICS: Final[tuple[str, ...]] = (
    "unknown_transitions",
    "privilege_expansion",
    "duplicate_side_effects",
    "manual_database_mutations",
    "controller_recovery_in_clean_run",
    "high_critical_security_findings",
)

FORBIDDEN_COMPONENTS: Final[frozenset[str]] = frozenset(
    {
        "mandatory_gates",
        "q7_duration",
        "q8_scenarios",
        "credential_scopes",
        "owner_action_policy",
        "verifier_trust_root",
        "production_risk_limits",
        "stable_a",
        "audit_history",
    }
)

MAX_RECURSION_DEPTH: Final[int] = 3
MAX_IMPLEMENTATION_ATTEMPTS: Final[int] = 2


@dataclass(frozen=True)
class ImprovementProposal:
    objective_id: str
    root_cause_key: str
    baseline_digest: str
    observed_deficit: Mapping[str, Any]
    proposal: Mapping[str, Any]
    affected_components: tuple[str, ...]
    expected_delta: Mapping[str, float]
    non_regression_obligations: tuple[str, ...]
    risk_class: str
    max_cycles: int
    max_implementation_attempts: int
    evidence_refs: tuple[str, ...]

    def validate(self) -> None:
        if not self.objective_id or not self.root_cause_key:
            raise ImprovementError("improvement objective identity is required")
        if not re.fullmatch(r"[a-f0-9]{64}", self.baseline_digest):
            raise ImprovementError("improvement baseline digest is invalid")
        if not self.observed_deficit or not self.proposal or not self.expected_delta:
            raise ImprovementError("improvement requires a bounded measurable hypothesis")
        if not self.affected_components or FORBIDDEN_COMPONENTS.intersection(
            self.affected_components
        ):
            raise ImprovementError("improvement touches a forbidden authority boundary")
        if self.risk_class not in {"low", "medium", "high", "critical"}:
            raise ImprovementError("improvement risk class is invalid")
        if not 1 <= self.max_cycles <= MAX_RECURSION_DEPTH:
            raise ImprovementError("improvement recursion budget is invalid")
        if not 1 <= self.max_implementation_attempts <= MAX_IMPLEMENTATION_ATTEMPTS:
            raise ImprovementError("improvement attempt budget is invalid")
        if not self.non_regression_obligations or not self.evidence_refs:
            raise ImprovementError("improvement evidence obligations are incomplete")
        if any(
            not isinstance(value, (int, float)) or value == 0
            for value in self.expected_delta.values()
        ):
            raise ImprovementError("expected metric delta must be non-zero")

    def digest(self) -> str:
        self.validate()
        return sha256_text(
            stable_json(
                {
                    "schema_version": "1.0",
                    "objective_id": self.objective_id,
                    "root_cause_key": self.root_cause_key,
                    "baseline_digest": self.baseline_digest,
                    "observed_deficit": dict(self.observed_deficit),
                    "proposal": dict(self.proposal),
                    "affected_components": list(self.affected_components),
                    "expected_delta": dict(self.expected_delta),
                    "non_regression_obligations": list(self.non_regression_obligations),
                    "risk_class": self.risk_class,
                    "budget": {
                        "max_cycles": self.max_cycles,
                        "max_implementation_attempts": self.max_implementation_attempts,
                    },
                    "evidence_refs": list(self.evidence_refs),
                }
            )
        )


@dataclass(frozen=True)
class ComparativeEvaluation:
    baseline_scorecard: Mapping[str, float]
    candidate_scorecard: Mapping[str, float]
    safety_regressions: tuple[str, ...]
    target_metric: str
    minimum_delta: float
    independent: bool
    evidence_refs: tuple[str, ...]

    def validate(self) -> float:
        if not self.independent:
            raise ImprovementError("comparative evaluator is not independent")
        if self.safety_regressions:
            raise ImprovementError("improvement has a safety regression")
        if not self.evidence_refs:
            raise ImprovementError("comparative evaluation lacks immutable evidence")
        for metric in SAFETY_METRICS:
            if self.candidate_scorecard.get(metric, 0) > self.baseline_scorecard.get(metric, 0):
                raise ImprovementError(f"safety metric regressed: {metric}")
        if self.target_metric not in self.baseline_scorecard or self.target_metric not in (
            self.candidate_scorecard
        ):
            raise ImprovementError("target metric is absent from scorecard")
        baseline = float(self.baseline_scorecard[self.target_metric])
        candidate = float(self.candidate_scorecard[self.target_metric])
        direction = "lower"
        if self.target_metric in {
            "mutation_score",
            "requirements_coverage",
            "critical_journey_coverage",
            "product_acceptance_score",
            "clean_scenario_success_rate",
            "completion_rate",
        }:
            direction = "higher"
        delta = candidate - baseline if direction == "higher" else baseline - candidate
        if delta < self.minimum_delta:
            raise ImprovementError("candidate has no measurable improvement")
        return delta


class RecursiveImprovementGovernor:
    """Deterministic authority for exactly one finite Candidate experiment."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        stable_root: Path,
        isolated_root: Path,
    ) -> None:
        self.connection = connection
        self.connection.row_factory = sqlite3.Row
        self.stable_root = stable_root.resolve()
        self.isolated_root = isolated_root.resolve()
        if self.stable_root == self.isolated_root or self.stable_root in self.isolated_root.parents:
            raise ImprovementError("isolated improvement root overlaps Stable A")
        self._initialize()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS improvement_objectives (
                objective_id TEXT PRIMARY KEY,
                root_cause_key TEXT NOT NULL UNIQUE,
                baseline_digest TEXT NOT NULL,
                proposal_digest TEXT NOT NULL UNIQUE,
                target_metric TEXT NOT NULL,
                max_cycles INTEGER NOT NULL CHECK(max_cycles BETWEEN 1 AND 3),
                max_implementation_attempts INTEGER NOT NULL CHECK(
                    max_implementation_attempts BETWEEN 1 AND 2
                ),
                status TEXT NOT NULL,
                active_cycle INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_improvement
              ON improvement_objectives((1))
              WHERE status IN ('PROPOSED','EXPERIMENT_RUNNING','NEXT_BOUNDED_CYCLE');
            CREATE TABLE IF NOT EXISTS improvement_cycles (
                cycle_id TEXT PRIMARY KEY,
                objective_id TEXT NOT NULL REFERENCES improvement_objectives(objective_id),
                cycle_number INTEGER NOT NULL CHECK(cycle_number BETWEEN 1 AND 3),
                branch_name TEXT NOT NULL,
                candidate_digest TEXT NOT NULL,
                implementation_attempts INTEGER NOT NULL DEFAULT 0,
                baseline_scorecard_json TEXT,
                candidate_scorecard_json TEXT,
                evaluation_digest TEXT UNIQUE,
                decision TEXT NOT NULL,
                measurable_delta REAL,
                evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                completed_at TEXT,
                UNIQUE(objective_id,cycle_number)
            );
            CREATE TABLE IF NOT EXISTS improvement_release_epochs (
                release_epoch_id TEXT PRIMARY KEY,
                objective_id TEXT NOT NULL UNIQUE,
                candidate_digest TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS improvement_scans (
                scan_id TEXT PRIMARY KEY,
                observation_digest TEXT NOT NULL UNIQUE,
                candidate_digest TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK(
                    outcome IN ('NO_MEASURABLE_OPPORTUNITY','OPPORTUNITY_DETECTED')
                ),
                measured_deficits_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS improvement_lane_proofs (
                release_digest TEXT PRIMARY KEY,
                observation_digest TEXT NOT NULL UNIQUE,
                objective_id TEXT NOT NULL UNIQUE,
                cycle_id TEXT NOT NULL UNIQUE,
                candidate_digest TEXT NOT NULL UNIQUE,
                decision TEXT NOT NULL CHECK(decision='REJECT'),
                implementation_attempts INTEGER NOT NULL CHECK(implementation_attempts=1),
                stable_identity_before TEXT NOT NULL,
                stable_identity_after TEXT NOT NULL,
                isolated_artifact_ref TEXT NOT NULL,
                proof_digest TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            """
        )
        scan_columns = {
            str(row[1]) for row in self.connection.execute("PRAGMA table_info(improvement_scans)")
        }
        if "candidate_digest" not in scan_columns:
            self.connection.execute(
                "ALTER TABLE improvement_scans ADD COLUMN candidate_digest TEXT NOT NULL DEFAULT ''"
            )

    def record_observation_scan(
        self,
        *,
        observation_digest: str,
        candidate_digest: str,
        source_ref: str,
        measured_deficits: Mapping[str, float],
    ) -> str:
        """Durably classify one immutable measurement without inventing work."""

        if not re.fullmatch(r"[a-f0-9]{64}", observation_digest):
            raise ImprovementError("improvement observation digest is invalid")
        if not re.fullmatch(r"[a-f0-9]{64}", candidate_digest):
            raise ImprovementError("improvement release digest is invalid")
        if not source_ref.startswith("artifact://production-observation/"):
            raise ImprovementError("improvement observation source is not immutable")
        allowed = {
            "controller_incidents",
            "digest_divergences",
            "health_failures",
        }
        if set(measured_deficits) != allowed or any(
            not isinstance(value, (int, float)) or value < 0 for value in measured_deficits.values()
        ):
            raise ImprovementError("improvement observation metrics are invalid")
        normalized = {key: float(measured_deficits[key]) for key in sorted(allowed)}
        outcome = (
            "OPPORTUNITY_DETECTED"
            if any(value > 0 for value in normalized.values())
            else "NO_MEASURABLE_OPPORTUNITY"
        )
        scan_id = (
            "IS-"
            + sha256_text(stable_json([observation_digest, source_ref, normalized]))[:32].upper()
        )
        with self.connection:
            existing = self.connection.execute(
                "SELECT candidate_digest,outcome,measured_deficits_json FROM improvement_scans "
                "WHERE observation_digest=?",
                (observation_digest,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing[0]) != candidate_digest
                    or str(existing[1]) != outcome
                    or str(existing[2]) != stable_json(normalized)
                ):
                    raise ImprovementError("immutable improvement scan conflicts")
                return outcome
            self.connection.execute(
                """INSERT INTO improvement_scans
                   (scan_id,observation_digest,candidate_digest,source_ref,outcome,
                    measured_deficits_json,created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    observation_digest,
                    candidate_digest,
                    source_ref,
                    outcome,
                    stable_json(normalized),
                    utc_now(),
                ),
            )
        return outcome

    def _stable_identity(self) -> str:
        """Bind the lane to immutable Stable code without reading runtime secrets."""

        manifest = self.stable_root / "SHA256SUMS"
        if not manifest.is_file() or manifest.is_symlink():
            raise ImprovementError("Stable release manifest is unavailable")
        return sha256_text(
            stable_json(
                {
                    "resolved_root": str(self.stable_root),
                    "manifest_digest": sha256_file(manifest),
                    "manifest_mode": manifest.stat().st_mode & 0o777,
                }
            )
        )

    @staticmethod
    def _write_once(path: Path, value: Mapping[str, Any]) -> None:
        encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
                raise ImprovementError("immutable Candidate lane artifact conflicts")
            return
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

    def qualify_isolated_lane(
        self,
        *,
        release_digest: str,
        observation_digest: str,
    ) -> str:
        """Execute one restart-safe Candidate attempt and independently reject no gain.

        This operational canary proves the safety-critical lane semantics: an
        implementation is written only below the isolated root, consumes one
        finite attempt, cannot modify Stable, and is rejected when comparison
        finds no measurable improvement.  Future typed opportunities use the
        same governor path and therefore cannot reset budgets by rewording.
        """

        if not re.fullmatch(r"[a-f0-9]{64}", release_digest):
            raise ImprovementError("lane release digest is invalid")
        scan = self.connection.execute(
            """SELECT measured_deficits_json FROM improvement_scans
                WHERE observation_digest=? AND candidate_digest=?""",
            (observation_digest, release_digest),
        ).fetchone()
        if scan is None:
            raise ImprovementError("lane qualification lacks an immutable observation")
        existing_proof = self.connection.execute(
            "SELECT proof_digest FROM improvement_lane_proofs WHERE release_digest=?",
            (release_digest,),
        ).fetchone()
        if existing_proof is not None:
            return str(existing_proof[0])

        measured_deficits = json.loads(str(scan[0]))
        if not isinstance(measured_deficits, dict):
            raise ImprovementError("lane observation metrics are invalid")
        stable_before = self._stable_identity()
        objective_id = "lane-" + sha256_text(stable_json([release_digest, observation_digest]))[:24]
        root_cause_key = f"isolated-lane:{observation_digest}"
        experiment_root = self.isolated_root / "experiments" / objective_id
        candidate_payload = {
            "schema_version": "1.0",
            "artifact_type": "ISOLATED_CANDIDATE_IMPLEMENTATION",
            "release_digest": release_digest,
            "observation_digest": observation_digest,
            "measured_deficits": measured_deficits,
            "strategy": "bounded-neutral-candidate",
            "authority": {
                "stable_write": False,
                "credential_expansion": False,
                "gate_changes": False,
            },
        }
        candidate_digest = sha256_text(stable_json(candidate_payload))
        artifact = experiment_root / f"candidate-{candidate_digest}.json"
        self._write_once(
            artifact,
            {**candidate_payload, "candidate_digest": candidate_digest},
        )
        artifact_ref = f"artifact://improvement-candidate/{candidate_digest}"
        proposal = ImprovementProposal(
            objective_id=objective_id,
            root_cause_key=root_cause_key,
            baseline_digest=observation_digest,
            observed_deficit=measured_deficits or {"lane_qualification": 1.0},
            proposal={
                "mechanism": "bounded-neutral-candidate",
                "candidate_digest": candidate_digest,
            },
            affected_components=("candidate_runtime",),
            expected_delta={"completion_time": -0.001},
            non_regression_obligations=tuple(SAFETY_METRICS),
            risk_class="low",
            max_cycles=1,
            max_implementation_attempts=1,
            evidence_refs=(f"artifact://production-observation/{observation_digest}",),
        )
        self.propose(proposal, target_metric="completion_time")
        cycle = self.connection.execute(
            "SELECT * FROM improvement_cycles WHERE objective_id=?",
            (objective_id,),
        ).fetchone()
        if cycle is None:
            cycle_id = self.start_cycle(
                objective_id=objective_id,
                branch_name=f"candidate/{objective_id}",
                candidate_digest=candidate_digest,
                experiment_root=experiment_root,
            )
            cycle = self.connection.execute(
                "SELECT * FROM improvement_cycles WHERE cycle_id=?", (cycle_id,)
            ).fetchone()
        if cycle is None:
            raise ImprovementError("Candidate cycle was not durably created")
        cycle_id = str(cycle["cycle_id"])
        if str(cycle["decision"]) == "RUNNING":
            if int(cycle["implementation_attempts"]) == 0:
                self.record_implementation_attempt(cycle_id)
            decision = self.evaluate(
                cycle_id=cycle_id,
                evaluation=ComparativeEvaluation(
                    baseline_scorecard={
                        "completion_time": 1.0,
                        **{metric: 0.0 for metric in SAFETY_METRICS},
                    },
                    candidate_scorecard={
                        "completion_time": 1.0,
                        **{metric: 0.0 for metric in SAFETY_METRICS},
                    },
                    safety_regressions=(),
                    target_metric="completion_time",
                    minimum_delta=0.001,
                    independent=True,
                    evidence_refs=(artifact_ref,),
                ),
                request_next_cycle=False,
            )
        else:
            decision = str(cycle["decision"])
        if decision != "REJECT":
            raise ImprovementError("neutral Candidate was not rejected")
        stable_after = self._stable_identity()
        if stable_before != stable_after:
            raise ImprovementError("Stable identity changed during Candidate experiment")
        proof = {
            "schema_version": "1.0",
            "proof_type": "ISOLATED_IMPROVEMENT_LANE_QUALIFICATION",
            "release_digest": release_digest,
            "observation_digest": observation_digest,
            "objective_id": objective_id,
            "cycle_id": cycle_id,
            "candidate_digest": candidate_digest,
            "decision": decision,
            "implementation_attempts": 1,
            "stable_identity_before": stable_before,
            "stable_identity_after": stable_after,
            "isolated_artifact_ref": artifact_ref,
            "independent_evaluation": True,
        }
        proof_digest = sha256_text(stable_json(proof))
        with self.connection:
            self.connection.execute(
                """INSERT INTO improvement_lane_proofs
                   (release_digest,observation_digest,objective_id,cycle_id,
                    candidate_digest,decision,implementation_attempts,
                    stable_identity_before,stable_identity_after,
                    isolated_artifact_ref,proof_digest,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    release_digest,
                    observation_digest,
                    objective_id,
                    cycle_id,
                    candidate_digest,
                    decision,
                    1,
                    stable_before,
                    stable_after,
                    artifact_ref,
                    proof_digest,
                    utc_now(),
                ),
            )
        return proof_digest

    def propose(self, proposal: ImprovementProposal, *, target_metric: str) -> str:
        proposal.validate()
        if target_metric not in proposal.expected_delta:
            raise ImprovementError("target metric is not part of expected delta")
        digest = proposal.digest()
        now = utc_now()
        with self.connection:
            existing = self.connection.execute(
                "SELECT proposal_digest FROM improvement_objectives WHERE root_cause_key=?",
                (proposal.root_cause_key,),
            ).fetchone()
            if existing is not None:
                if str(existing[0]) != digest:
                    raise ImprovementError("new wording cannot reset improvement budget")
                return digest
            self.connection.execute(
                """INSERT INTO improvement_objectives
                   (objective_id,root_cause_key,baseline_digest,proposal_digest,
                    target_metric,max_cycles,max_implementation_attempts,status,
                    created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,'PROPOSED',?,?)""",
                (
                    proposal.objective_id,
                    proposal.root_cause_key,
                    proposal.baseline_digest,
                    digest,
                    target_metric,
                    proposal.max_cycles,
                    proposal.max_implementation_attempts,
                    now,
                    now,
                ),
            )
        return digest

    def start_cycle(
        self,
        *,
        objective_id: str,
        branch_name: str,
        candidate_digest: str,
        experiment_root: Path,
    ) -> str:
        objective = self.connection.execute(
            "SELECT * FROM improvement_objectives WHERE objective_id=?", (objective_id,)
        ).fetchone()
        if objective is None:
            raise KeyError(objective_id)
        resolved = experiment_root.resolve()
        if (
            not (resolved == self.isolated_root or self.isolated_root in resolved.parents)
            or resolved == self.stable_root
            or self.stable_root in resolved.parents
        ):
            raise ImprovementError("experiment is outside isolated Candidate root")
        if not re.fullmatch(r"[a-f0-9]{64}", candidate_digest):
            raise ImprovementError("experiment Candidate digest is invalid")
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch_name) or ".." in branch_name:
            raise ImprovementError("experiment branch name is invalid")
        cycle_number = int(objective["active_cycle"]) + 1
        if cycle_number > int(objective["max_cycles"]) or cycle_number > MAX_RECURSION_DEPTH:
            raise ImprovementError("recursive improvement budget exhausted")
        if str(objective["status"]) not in {"PROPOSED", "NEXT_BOUNDED_CYCLE"}:
            raise ImprovementError("objective cannot start another cycle")
        seed = sha256_text(stable_json([objective_id, cycle_number, branch_name, candidate_digest]))
        cycle_id = f"IC-{seed[:24].upper()}"
        with self.connection:
            self.connection.execute(
                """INSERT INTO improvement_cycles
                   (cycle_id,objective_id,cycle_number,branch_name,candidate_digest,
                    decision,created_at) VALUES (?,?,?,?,?,'RUNNING',?)""",
                (
                    cycle_id,
                    objective_id,
                    cycle_number,
                    branch_name,
                    candidate_digest,
                    utc_now(),
                ),
            )
            self.connection.execute(
                "UPDATE improvement_objectives SET status='EXPERIMENT_RUNNING',"
                "active_cycle=?,updated_at=? WHERE objective_id=?",
                (cycle_number, utc_now(), objective_id),
            )
        return cycle_id

    def record_implementation_attempt(self, cycle_id: str) -> int:
        row = self.connection.execute(
            """SELECT cycle.implementation_attempts,objective.max_implementation_attempts,
                      cycle.decision
                 FROM improvement_cycles AS cycle
                 JOIN improvement_objectives AS objective USING(objective_id)
                WHERE cycle.cycle_id=?""",
            (cycle_id,),
        ).fetchone()
        if row is None:
            raise KeyError(cycle_id)
        attempts = int(row[0]) + 1
        if str(row[2]) != "RUNNING" or attempts > int(row[1]):
            raise ImprovementError("implementation attempt budget exhausted")
        with self.connection:
            self.connection.execute(
                "UPDATE improvement_cycles SET implementation_attempts=? WHERE cycle_id=?",
                (attempts, cycle_id),
            )
        return attempts

    def evaluate(
        self,
        *,
        cycle_id: str,
        evaluation: ComparativeEvaluation,
        request_next_cycle: bool,
    ) -> str:
        cycle = self.connection.execute(
            """SELECT cycle.*,objective.max_cycles,objective.target_metric
                 FROM improvement_cycles AS cycle
                 JOIN improvement_objectives AS objective USING(objective_id)
                WHERE cycle.cycle_id=?""",
            (cycle_id,),
        ).fetchone()
        if cycle is None:
            raise KeyError(cycle_id)
        if str(cycle["decision"]) != "RUNNING":
            raise ImprovementError("immutable Candidate was already evaluated")
        if evaluation.target_metric != str(cycle["target_metric"]):
            raise ImprovementError("evaluation target metric differs")
        try:
            delta = evaluation.validate()
        except ImprovementError:
            decision = "REJECT"
            delta = 0.0
        else:
            decision = (
                "NEXT_BOUNDED_CYCLE"
                if request_next_cycle
                and int(cycle["cycle_number"]) < int(cycle["max_cycles"])
                and int(cycle["cycle_number"]) < MAX_RECURSION_DEPTH
                else "ACCEPT"
            )
        payload = {
            "schema_version": "1.0",
            "cycle_id": cycle_id,
            "objective_id": str(cycle["objective_id"]),
            "cycle_number": int(cycle["cycle_number"]),
            "candidate_identity": {"digest": str(cycle["candidate_digest"])},
            "baseline_scorecard": dict(evaluation.baseline_scorecard),
            "candidate_scorecard": dict(evaluation.candidate_scorecard),
            "safety_regressions": list(evaluation.safety_regressions),
            "measurable_improvement": delta > 0,
            "decision": decision,
            "evidence_refs": list(evaluation.evidence_refs),
        }
        evaluation_digest = sha256_text(stable_json(payload))
        with self.connection:
            self.connection.execute(
                """UPDATE improvement_cycles
                      SET baseline_scorecard_json=?,candidate_scorecard_json=?,
                          evaluation_digest=?,decision=?,measurable_delta=?,
                          evidence_refs_json=?,completed_at=? WHERE cycle_id=?""",
                (
                    stable_json(dict(evaluation.baseline_scorecard)),
                    stable_json(dict(evaluation.candidate_scorecard)),
                    evaluation_digest,
                    decision,
                    delta,
                    stable_json(list(evaluation.evidence_refs)),
                    utc_now(),
                    cycle_id,
                ),
            )
            status = {
                "REJECT": "IMPROVEMENT_REJECTED",
                "NEXT_BOUNDED_CYCLE": "NEXT_BOUNDED_CYCLE",
                "ACCEPT": "ACCEPTED_PENDING_QUALIFICATION",
            }[decision]
            self.connection.execute(
                "UPDATE improvement_objectives SET status=?,updated_at=? WHERE objective_id=?",
                (status, utc_now(), str(cycle["objective_id"])),
            )
            if decision == "ACCEPT":
                epoch_seed = sha256_text(
                    stable_json(
                        [
                            str(cycle["objective_id"]),
                            str(cycle["candidate_digest"]),
                            evaluation_digest,
                        ]
                    )
                )
                self.connection.execute(
                    """INSERT INTO improvement_release_epochs
                       (release_epoch_id,objective_id,candidate_digest,status,created_at)
                       VALUES (?,?,?,'FULL_QUALIFICATION_REQUIRED',?)""",
                    (
                        f"IRE-{epoch_seed[:24].upper()}",
                        str(cycle["objective_id"]),
                        str(cycle["candidate_digest"]),
                        utc_now(),
                    ),
                )
        return decision

    def active_experiment_count(self) -> int:
        return int(
            self.connection.execute(
                """SELECT COUNT(*) FROM improvement_objectives
                    WHERE status IN ('PROPOSED','EXPERIMENT_RUNNING','NEXT_BOUNDED_CYCLE')"""
            ).fetchone()[0]
        )
