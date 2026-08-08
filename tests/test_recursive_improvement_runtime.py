from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from factory.common import sha256_text, stable_json
from factory.recursive_improvement import ImprovementError, RecursiveImprovementGovernor
from scripts.recursive_improvement_control import _scan_observations


def _governor(tmp_path: Path) -> RecursiveImprovementGovernor:
    stable = tmp_path / "stable"
    isolated = tmp_path / "isolated"
    stable.mkdir()
    isolated.mkdir()
    return RecursiveImprovementGovernor(
        sqlite3.connect(":memory:"),
        stable_root=stable,
        isolated_root=isolated,
    )


def _observation(path: Path, **metrics: int) -> str:
    value = {
        "schema_version": "1.0",
        "proof_type": "PRODUCTION_OBSERVATION",
        "status": "PASS",
        "candidate_digest": "b" * 64,
        "controller_incidents": metrics.get("controller_incidents", 0),
        "digest_divergences": metrics.get("digest_divergences", 0),
        "health_failures": metrics.get("health_failures", 0),
    }
    digest = sha256_text(stable_json(value))
    path.write_text(
        json.dumps({**value, "proof_digest": digest}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return digest


def test_periodic_detection_records_immutable_no_opportunity(tmp_path: Path) -> None:
    governor = _governor(tmp_path)
    observations = tmp_path / "observations"
    observations.mkdir()
    digest = _observation(observations / "release.json")
    assert _scan_observations(governor, observations) == (
        1,
        "NO_MEASURABLE_OPPORTUNITY",
    )
    assert _scan_observations(governor, observations) == (
        1,
        "NO_MEASURABLE_OPPORTUNITY",
    )
    row = governor.connection.execute(
        "SELECT observation_digest,outcome FROM improvement_scans"
    ).fetchone()
    assert tuple(row) == (digest, "NO_MEASURABLE_OPPORTUNITY")


def test_isolated_lane_consumes_one_attempt_rejects_no_gain_and_preserves_stable(
    tmp_path: Path,
) -> None:
    governor = _governor(tmp_path)
    (governor.stable_root / "SHA256SUMS").write_text(
        "a" * 64 + "  factory/example.py\n", encoding="utf-8"
    )
    observations = tmp_path / "observations"
    observations.mkdir()
    digest = _observation(observations / "release.json")
    _scan_observations(governor, observations)
    before = (governor.stable_root / "SHA256SUMS").read_bytes()
    proof_digest = governor.qualify_isolated_lane(
        release_digest="b" * 64,
        observation_digest=digest,
    )
    assert (
        governor.qualify_isolated_lane(
            release_digest="b" * 64,
            observation_digest=digest,
        )
        == proof_digest
    )
    proof = governor.connection.execute(
        "SELECT decision,implementation_attempts,stable_identity_before,stable_identity_after "
        "FROM improvement_lane_proofs"
    ).fetchone()
    assert tuple(proof[:2]) == ("REJECT", 1)
    assert proof[2] == proof[3]
    assert governor.active_experiment_count() == 0
    assert (governor.stable_root / "SHA256SUMS").read_bytes() == before
    assert not any(governor.stable_root.glob("**/candidate-*.json"))


def test_measured_deficit_is_typed_without_starting_unbounded_work(tmp_path: Path) -> None:
    governor = _governor(tmp_path)
    observations = tmp_path / "observations"
    observations.mkdir()
    _observation(observations / "release.json", health_failures=1)
    assert _scan_observations(governor, observations) == (1, "OPPORTUNITY_DETECTED")
    assert governor.active_experiment_count() == 0
    with pytest.raises(ImprovementError, match="metrics"):
        governor.record_observation_scan(
            observation_digest="a" * 64,
            candidate_digest="b" * 64,
            source_ref="artifact://production-observation/" + "a" * 64,
            measured_deficits={"invented_metric": 1.0},
        )
