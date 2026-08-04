"""Tests for the post-promotion observation proof."""

from __future__ import annotations

import json
from pathlib import Path

from factory.production_observation import observe_once
from factory.release_executor import _release_digest
from factory.state import StateStore


def test_observation_graduates_only_healthy_exact_candidate(tmp_path: Path) -> None:
    current = tmp_path / "current"
    current.mkdir()
    (current / "VERSION").write_text("2.4.0\n", encoding="utf-8")
    candidate_digest = _release_digest(current).removeprefix("sha256:")
    database = tmp_path / "controller.db"
    state = StateStore(database)
    state.close()
    output = tmp_path / "observation.json"

    result = observe_once(
        candidate_digest=candidate_digest,
        promoted_at="2026-08-01T00:00:00+00:00",
        output_path=output,
        minimum_hours=0,
        minimum_entries=1,
        current_root=current,
        database=database,
        health_probe=lambda: True,
        services_probe=lambda: (True, ["controller", "gateway", "worker"]),
        observed_at="2026-08-01T00:00:01+00:00",
    )

    assert result["status"] == "LTS_READY"
    proof = json.loads(output.read_text(encoding="utf-8"))
    assert proof["candidate_digest"] == candidate_digest
    assert proof["controller_incidents"] == 0
    assert output.with_suffix(".journal.jsonl").read_text(encoding="utf-8").count("\n") == 1


def test_observation_requires_immediate_rollback_on_health_failure(tmp_path: Path) -> None:
    current = tmp_path / "current"
    current.mkdir()
    (current / "VERSION").write_text("2.4.0\n", encoding="utf-8")
    database = tmp_path / "controller.db"
    state = StateStore(database)
    state.close()

    result = observe_once(
        candidate_digest=_release_digest(current).removeprefix("sha256:"),
        promoted_at="2026-08-01T00:00:00+00:00",
        output_path=tmp_path / "observation.json",
        minimum_hours=0,
        minimum_entries=1,
        current_root=current,
        database=database,
        health_probe=lambda: False,
        services_probe=lambda: (True, []),
        observed_at="2026-08-01T00:00:01+00:00",
    )

    assert result["status"] == "ROLLBACK_REQUIRED"
