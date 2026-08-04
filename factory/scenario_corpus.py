"""Strict versioned scenario DSL and deterministic historical replay."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .common import redact_text, sha256_text, stable_json
from .failure_catalog import FailureAction, failure_disposition


class ScenarioError(RuntimeError):
    """A historical fixture is malformed or replays differently."""


_TOP_LEVEL = {
    "schema_version",
    "scenario_id",
    "source_release",
    "source_incident_count",
    "initial_state",
    "events",
    "injected_faults",
    "expected_decisions",
    "forbidden_decisions",
    "expected_terminal",
}
_INITIAL_STATE = {
    "schema_version",
    "product_status",
    "task_count",
    "accepted_result_count",
    "sanitized",
}
_EVENT = {"event_id", "type", "reason_code"}
_DECISION = {"event_id", "owner", "action", "registered"}
_TERMINALS = {"ACTIVE", "REPAIRING", "BLOCKED_OWNER", "FAILED_SAFE"}


@dataclass(frozen=True)
class HistoricalScenario:
    path: Path
    scenario_id: str
    source_release: str
    source_incident_count: int
    initial_state: Mapping[str, Any]
    events: tuple[Mapping[str, Any], ...]
    injected_faults: tuple[str, ...]
    expected_decisions: tuple[Mapping[str, Any], ...]
    forbidden_decisions: tuple[Mapping[str, Any], ...]
    expected_terminal: str
    fixture_digest: str


@dataclass(frozen=True)
class HistoricalReplayReport:
    fixture_count: int
    represented_incident_count: int
    passed_count: int
    failed_count: int
    replay_percent: int
    corpus_digest: str
    decision_count: int
    unknown_transition_count: int
    unregistered_reason_count: int


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ScenarioError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    keys = set(value)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        raise ScenarioError(f"{label} keys differ: missing={missing}, extra={extra}")


def _sequence(value: Any, label: str) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ScenarioError(f"{label} must be a list")
    return list(value)


def load_scenario(path: Path) -> HistoricalScenario:
    """Load a fail-closed, secret-free historical scenario fixture."""

    try:
        raw_text = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(raw_text)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ScenarioError(f"scenario cannot be read: {path.name}") from error
    payload = _mapping(raw, "scenario")
    _exact_keys(payload, _TOP_LEVEL, "scenario")
    if payload["schema_version"] != "1.0":
        raise ScenarioError("unsupported scenario schema version")
    scenario_id = str(payload["scenario_id"])
    if not scenario_id or path.stem != scenario_id:
        raise ScenarioError("scenario_id must equal the fixture filename")
    redacted, findings = redact_text(stable_json(payload))
    if findings or redacted != stable_json(payload):
        raise ScenarioError("historical fixture contains secret-like material")

    initial_state = _mapping(payload["initial_state"], "initial_state")
    _exact_keys(initial_state, _INITIAL_STATE, "initial_state")
    if initial_state["schema_version"] not in range(1, 19):
        raise ScenarioError("historical schema version is outside the supported matrix")
    if initial_state["product_status"] in {"COMPLETED", "CANCELLED"}:
        raise ScenarioError("historical incident fixture must begin active or failed-safe")
    for key in ("task_count", "accepted_result_count"):
        value = initial_state[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ScenarioError(f"initial_state.{key} must be a nonnegative integer")
    if initial_state["sanitized"] is not True:
        raise ScenarioError("historical fixture must attest sanitization")

    events = tuple(_mapping(value, "event") for value in _sequence(payload["events"], "events"))
    decisions = tuple(
        _mapping(value, "expected_decision")
        for value in _sequence(payload["expected_decisions"], "expected_decisions")
    )
    forbidden = tuple(
        _mapping(value, "forbidden_decision")
        for value in _sequence(payload["forbidden_decisions"], "forbidden_decisions")
    )
    if not events or len(events) != len(decisions):
        raise ScenarioError("each historical event requires one expected decision")
    event_ids: set[str] = set()
    for event in events:
        _exact_keys(event, _EVENT, "event")
        event_id = str(event["event_id"])
        if not event_id or event_id in event_ids or event["type"] != "failure_received":
            raise ScenarioError("events require unique IDs and failure_received type")
        if not str(event["reason_code"]):
            raise ScenarioError("event reason_code is empty")
        event_ids.add(event_id)
    for decision in (*decisions, *forbidden):
        _exact_keys(decision, _DECISION, "decision")
        if str(decision["event_id"]) not in event_ids:
            raise ScenarioError("decision references an unknown event")
        if decision["owner"] not in {"controller", "product", "external"}:
            raise ScenarioError("decision owner is unknown")
        try:
            FailureAction(str(decision["action"]))
        except ValueError as error:
            raise ScenarioError("decision action is unknown") from error
        if not isinstance(decision["registered"], bool):
            raise ScenarioError("decision registered flag must be boolean")
    expected_terminal = str(payload["expected_terminal"])
    if expected_terminal not in _TERMINALS:
        raise ScenarioError("expected_terminal is unknown")
    source_incident_count = payload["source_incident_count"]
    if (
        isinstance(source_incident_count, bool)
        or not isinstance(source_incident_count, int)
        or source_incident_count < 1
    ):
        raise ScenarioError("source_incident_count must be positive")
    faults = tuple(str(value) for value in _sequence(payload["injected_faults"], "injected_faults"))
    if any(not value for value in faults):
        raise ScenarioError("injected fault name is empty")
    return HistoricalScenario(
        path=path,
        scenario_id=scenario_id,
        source_release=str(payload["source_release"]),
        source_incident_count=source_incident_count,
        initial_state=initial_state,
        events=events,
        injected_faults=faults,
        expected_decisions=decisions,
        forbidden_decisions=forbidden,
        expected_terminal=expected_terminal,
        fixture_digest=sha256_text(stable_json(payload)),
    )


def _terminal_for_action(action: FailureAction) -> str:
    if action is FailureAction.CONTROLLER_QUARANTINE:
        return "FAILED_SAFE"
    if action in {
        FailureAction.REPAIR_NODE_VERSION,
        FailureAction.RECOMPILE_AFFECTED_SUBGRAPH,
    }:
        return "REPAIRING"
    if action is FailureAction.WAIT_EXTERNAL:
        return "BLOCKED_OWNER"
    return "ACTIVE"


def replay_scenario(scenario: HistoricalScenario) -> tuple[dict[str, Any], ...]:
    """Replay only catalog decisions; no provider or side effect is available."""

    expected = {
        str(decision["event_id"]): decision for decision in scenario.expected_decisions
    }
    forbidden = {
        stable_json(decision) for decision in scenario.forbidden_decisions
    }
    observed: list[dict[str, Any]] = []
    terminal = "ACTIVE"
    for event in scenario.events:
        event_id = str(event["event_id"])
        disposition = failure_disposition(str(event["reason_code"]))
        decision = {
            "event_id": event_id,
            "owner": disposition.owner,
            "action": disposition.action.value,
            "registered": disposition.registered,
        }
        if decision != dict(expected[event_id]):
            raise ScenarioError(
                f"historical decision changed: {scenario.scenario_id}/{event_id}"
            )
        if stable_json(decision) in forbidden:
            raise ScenarioError(
                f"forbidden historical decision occurred: {scenario.scenario_id}/{event_id}"
            )
        observed.append(decision)
        terminal = _terminal_for_action(disposition.action)
    if terminal != scenario.expected_terminal:
        raise ScenarioError(
            f"historical terminal changed: {scenario.scenario_id} expected "
            f"{scenario.expected_terminal}, got {terminal}"
        )
    return tuple(observed)


def replay_corpus(root: Path) -> HistoricalReplayReport:
    """Replay every fixture and bind the report to exact fixture digests."""

    paths = tuple(sorted(root.glob("*.yaml")))
    if not paths:
        raise ScenarioError("historical scenario corpus is empty")
    scenarios = tuple(load_scenario(path) for path in paths)
    identifiers = [item.scenario_id for item in scenarios]
    if len(identifiers) != len(set(identifiers)):
        raise ScenarioError("historical scenario IDs are not unique")
    passed = 0
    decisions = 0
    unknown = 0
    for scenario in scenarios:
        observed = replay_scenario(scenario)
        passed += 1
        decisions += len(observed)
        unknown += sum(int(not bool(item["registered"])) for item in observed)
    return HistoricalReplayReport(
        fixture_count=len(scenarios),
        represented_incident_count=sum(
            item.source_incident_count for item in scenarios
        ),
        passed_count=passed,
        failed_count=len(scenarios) - passed,
        replay_percent=100 if passed == len(scenarios) else 0,
        corpus_digest=sha256_text(
            stable_json(
                [(item.scenario_id, item.fixture_digest) for item in scenarios]
            )
        ),
        decision_count=decisions,
        unknown_transition_count=0,
        unregistered_reason_count=unknown,
    )
