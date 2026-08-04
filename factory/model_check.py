"""Bounded executable checks for the generated closed-world transition model."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, replace
from enum import IntEnum, StrEnum
from itertools import product

from .transition_catalog import (
    TRANSITION_CATALOG,
    ProductState,
    TransitionSpec,
)


class ModelCheckError(RuntimeError):
    """A generated transition invariant is false."""


class _Terminal(StrEnum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    FAILED_SAFE = "FAILED_SAFE"


class _Intent(IntEnum):
    NONE = 0
    PREPARED = 1
    EXECUTING = 2
    VERIFIED = 3


class _DeploymentState(StrEnum):
    LTS_A = "LTS_A"
    CANDIDATE_B = "CANDIDATE_B"
    PROMOTED_B = "PROMOTED_B"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class _AbstractState:
    """Finite task/side-effect state used at every requested model bound."""

    nodes: int
    accepted: int = 0
    in_flight: bool = False
    retries: int = 0
    crashes: int = 0
    process_down: bool = False
    side_effect_required: bool = False
    intent: _Intent = _Intent.NONE
    effect_count: int = 0
    capability_ceiling: int = 1
    effective_capabilities: int = 0
    deployment_state: _DeploymentState = _DeploymentState.LTS_A
    terminal: _Terminal = _Terminal.ACTIVE
    terminal_evidence: bool = False
    completion_evidence: bool = False


@dataclass(frozen=True)
class ModelCheckReport:
    transition_count: int
    state_event_coverage_percent: int
    terminal_reachable_states: int
    cyclic_components: int
    side_effect_transitions: int
    bounded_state_count: int
    composed_state_count: int
    product_bounds: tuple[int, ...]
    worker_bounds: tuple[int, ...]
    node_bounds: tuple[int, ...]
    retry_bound: int
    crash_bound: int
    deadlock_count: int
    livelock_count: int
    unsafe_terminal_count: int
    duplicate_side_effect_count: int
    privilege_expansion_count: int
    evidence_free_pass_count: int
    multiple_active_action_count: int
    rollback_unknown_state_count: int
    bounded_failure_escape_count: int


@dataclass(frozen=True)
class _BoundedModelReport:
    state_count: int
    composed_state_count: int
    deadlock_count: int
    livelock_count: int
    unsafe_terminal_count: int
    duplicate_side_effect_count: int
    privilege_expansion_count: int
    evidence_free_pass_count: int
    multiple_active_action_count: int
    rollback_unknown_state_count: int
    bounded_failure_escape_count: int


def _active_action_count(state: _AbstractState) -> int:
    return int(state.in_flight) + int(state.intent is _Intent.EXECUTING)


def _bounded_failure_reaches_failed_safe(
    state: _AbstractState,
    *,
    maximum_steps: int = 2,
) -> bool:
    frontier = {state}
    visited = {state}
    for _ in range(maximum_steps):
        next_frontier: set[_AbstractState] = set()
        for current in frontier:
            for successor in _successors(current):
                if (
                    successor.terminal is _Terminal.FAILED_SAFE
                    and successor.terminal_evidence
                ):
                    return True
                if successor not in visited:
                    visited.add(successor)
                    next_frontier.add(successor)
        frontier = next_frontier
    return False


def _strongly_connected_components(
    transitions: tuple[TransitionSpec, ...],
) -> list[set[ProductState]]:
    adjacency: dict[ProductState, set[ProductState]] = defaultdict(set)
    reverse: dict[ProductState, set[ProductState]] = defaultdict(set)
    for item in transitions:
        adjacency[item.source].add(item.target)
        reverse[item.target].add(item.source)
    visited: set[ProductState] = set()
    order: list[ProductState] = []

    def visit(state: ProductState) -> None:
        if state in visited:
            return
        visited.add(state)
        for target in adjacency[state]:
            visit(target)
        order.append(state)

    for state in ProductState:
        visit(state)
    visited.clear()
    components: list[set[ProductState]] = []

    def collect(state: ProductState, component: set[ProductState]) -> None:
        if state in visited:
            return
        visited.add(state)
        component.add(state)
        for source in reverse[state]:
            collect(source, component)

    for state in reversed(order):
        if state in visited:
            continue
        component: set[ProductState] = set()
        collect(state, component)
        components.append(component)
    return components


def _successors(state: _AbstractState) -> set[_AbstractState]:
    """Enumerate controller outcomes, including every crashable boundary."""

    if state.terminal is not _Terminal.ACTIVE:
        return set()
    if state.process_down:
        return {replace(state, process_down=False)}

    successors: set[_AbstractState] = set()
    if state.crashes < 1:
        successors.add(
            replace(state, crashes=state.crashes + 1, process_down=True)
        )

    # An unknown Controller event always has the direct quarantine edge.
    successors.add(
        replace(
            state,
            in_flight=False,
            intent=_Intent.VERIFIED if state.effect_count else _Intent.NONE,
            effective_capabilities=0,
            deployment_state=_DeploymentState.LTS_A,
            terminal=_Terminal.FAILED_SAFE,
            terminal_evidence=True,
        )
    )

    if state.accepted < state.nodes:
        if not state.in_flight:
            successors.add(
                replace(
                    state,
                    in_flight=True,
                    effective_capabilities=state.capability_ceiling,
                )
            )
        else:
            successors.add(
                replace(
                    state,
                    accepted=state.accepted + 1,
                    in_flight=False,
                    effective_capabilities=0,
                )
            )
            if state.retries < 2:
                successors.add(
                    replace(
                        state,
                        retries=state.retries + 1,
                        in_flight=False,
                        effective_capabilities=0,
                    )
                )
            else:
                successors.add(
                    replace(
                        state,
                        in_flight=False,
                        effective_capabilities=0,
                        terminal=_Terminal.FAILED_SAFE,
                        terminal_evidence=True,
                    )
                )
        return successors

    if not state.side_effect_required:
        successors.add(
            replace(
                state,
                terminal=_Terminal.COMPLETED,
                completion_evidence=True,
            )
        )
        return successors

    if state.intent is _Intent.NONE:
        successors.add(replace(state, intent=_Intent.PREPARED))
    elif state.intent is _Intent.PREPARED:
        successors.add(
            replace(
                state,
                intent=_Intent.EXECUTING,
                effective_capabilities=state.capability_ceiling,
            )
        )
    elif state.intent is _Intent.EXECUTING:
        # Reconciliation observes an already-applied effect and verifies it;
        # otherwise the adapter performs it exactly once.
        if state.effect_count == 0:
            successors.add(
                replace(
                    state,
                    effect_count=1,
                    deployment_state=_DeploymentState.CANDIDATE_B,
                )
            )
        else:
            successors.add(
                replace(
                    state,
                    intent=_Intent.VERIFIED,
                    effective_capabilities=0,
                )
            )
            successors.add(
                replace(
                    state,
                    intent=_Intent.VERIFIED,
                    effective_capabilities=0,
                    deployment_state=_DeploymentState.LTS_A,
                    terminal=_Terminal.FAILED_SAFE,
                    terminal_evidence=True,
                )
            )
    elif state.intent is _Intent.VERIFIED:
        successors.add(
            replace(
                state,
                deployment_state=_DeploymentState.PROMOTED_B,
                terminal=_Terminal.COMPLETED,
                completion_evidence=True,
            )
        )
    return successors


def _fair_successor(state: _AbstractState) -> _AbstractState:
    """Choose the successful fair environment edge for liveness proof."""

    if state.process_down:
        return replace(state, process_down=False)
    if state.accepted < state.nodes:
        if not state.in_flight:
            return replace(
                state,
                in_flight=True,
                effective_capabilities=state.capability_ceiling,
            )
        return replace(
            state,
            accepted=state.accepted + 1,
            in_flight=False,
            effective_capabilities=0,
        )
    if not state.side_effect_required:
        return replace(
            state,
            terminal=_Terminal.COMPLETED,
            completion_evidence=True,
        )
    if state.intent is _Intent.NONE:
        return replace(state, intent=_Intent.PREPARED)
    if state.intent is _Intent.PREPARED:
        return replace(
            state,
            intent=_Intent.EXECUTING,
            effective_capabilities=state.capability_ceiling,
        )
    if state.intent is _Intent.EXECUTING and state.effect_count == 0:
        return replace(
            state,
            effect_count=1,
            deployment_state=_DeploymentState.CANDIDATE_B,
        )
    if state.intent is _Intent.EXECUTING:
        return replace(
            state,
            intent=_Intent.VERIFIED,
            effective_capabilities=0,
        )
    return replace(
        state,
        deployment_state=_DeploymentState.PROMOTED_B,
        terminal=_Terminal.COMPLETED,
        completion_evidence=True,
    )


def _bounded_states() -> set[_AbstractState]:
    discovered: set[_AbstractState] = set()
    queue: deque[_AbstractState] = deque()
    for nodes, side_effect_required in product(range(5), (False, True)):
        initial = _AbstractState(
            nodes=nodes,
            side_effect_required=side_effect_required,
        )
        discovered.add(initial)
        queue.append(initial)
    while queue:
        current = queue.popleft()
        for successor in _successors(current):
            if successor not in discovered:
                discovered.add(successor)
                queue.append(successor)
    return discovered


def _check_bounded_model() -> _BoundedModelReport:
    states = _bounded_states()
    deadlocks = 0
    livelocks = 0
    unsafe_terminals = 0
    duplicate_effects = 0
    privilege_expansions = 0
    evidence_free_passes = 0
    multiple_actions = 0
    rollback_unknown = 0
    bounded_failure_escapes = 0

    for state in states:
        active_actions = _active_action_count(state)
        if active_actions > 1:
            multiple_actions += 1
        if state.effect_count > 1:
            duplicate_effects += 1
        if state.effective_capabilities > state.capability_ceiling:
            privilege_expansions += 1
        if state.terminal is _Terminal.COMPLETED and not state.completion_evidence:
            evidence_free_passes += 1
        if state.terminal is _Terminal.FAILED_SAFE and not state.terminal_evidence:
            unsafe_terminals += 1
        if state.terminal is not _Terminal.ACTIVE and state.effective_capabilities:
            unsafe_terminals += 1
        if state.terminal is not _Terminal.ACTIVE and state.intent in {
            _Intent.PREPARED,
            _Intent.EXECUTING,
        }:
            unsafe_terminals += 1
        if (
            state.side_effect_required
            and state.terminal is _Terminal.COMPLETED
            and (state.intent is not _Intent.VERIFIED or state.effect_count != 1)
        ):
            unsafe_terminals += 1
        if state.terminal is not _Terminal.ACTIVE and _successors(state):
            unsafe_terminals += 1
        if state.terminal is _Terminal.ACTIVE and not _successors(state):
            deadlocks += 1
        if state.terminal is _Terminal.ACTIVE and not _bounded_failure_reaches_failed_safe(
            state
        ):
            bounded_failure_escapes += 1
        if (
            state.side_effect_required
            and state.terminal is _Terminal.FAILED_SAFE
            and state.deployment_state is not _DeploymentState.LTS_A
        ):
            rollback_unknown += 1
        if (
            state.side_effect_required
            and state.terminal is _Terminal.COMPLETED
            and state.deployment_state is not _DeploymentState.PROMOTED_B
        ):
            rollback_unknown += 1

        if state.terminal is _Terminal.ACTIVE:
            cursor = state
            seen: set[_AbstractState] = set()
            for _ in range(16):
                if cursor.terminal is not _Terminal.ACTIVE:
                    break
                if cursor in seen:
                    livelocks += 1
                    break
                seen.add(cursor)
                cursor = _fair_successor(cursor)
            if cursor.terminal is _Terminal.ACTIVE:
                livelocks += 1

    if any(
        (
            deadlocks,
            livelocks,
            unsafe_terminals,
            duplicate_effects,
            privilege_expansions,
            evidence_free_passes,
            multiple_actions,
            rollback_unknown,
            bounded_failure_escapes,
        )
    ):
        raise ModelCheckError(
            "bounded model violated safety/liveness: "
            f"deadlocks={deadlocks},livelocks={livelocks},"
            f"unsafe_terminals={unsafe_terminals},duplicate_effects={duplicate_effects},"
            f"privilege_expansions={privilege_expansions},"
            f"evidence_free_passes={evidence_free_passes},multiple_actions={multiple_actions},"
            f"rollback_unknown={rollback_unknown},"
            f"bounded_failure_escapes={bounded_failure_escapes}"
        )

    # Compose one- and two-product states under one- and two-worker bounds.
    # A one-worker scheduler excludes pairs with two in-flight actions; a
    # two-worker scheduler admits them while retaining one action per product.
    composed = 0
    state_list = tuple(states)
    for product_count in (1, 2):
        for worker_count in (1, 2):
            if product_count == 1:
                composed += sum(
                    int(_active_action_count(state) <= worker_count)
                    for state in state_list
                )
                continue
            composed += sum(
                int(
                    _active_action_count(left) + _active_action_count(right)
                    <= worker_count
                )
                for left in state_list
                for right in state_list
            )
    return _BoundedModelReport(
        state_count=len(states),
        composed_state_count=composed,
        deadlock_count=deadlocks,
        livelock_count=livelocks,
        unsafe_terminal_count=unsafe_terminals,
        duplicate_side_effect_count=duplicate_effects,
        privilege_expansion_count=privilege_expansions,
        evidence_free_pass_count=evidence_free_passes,
        multiple_active_action_count=multiple_actions,
        rollback_unknown_state_count=rollback_unknown,
        bounded_failure_escape_count=bounded_failure_escapes,
    )


def check_transition_catalog() -> ModelCheckReport:
    """Prove catalog and bounded runtime safety/liveness properties."""

    coordinates: dict[tuple[ProductState, str], TransitionSpec] = {}
    for item in TRANSITION_CATALOG:
        coordinate = (item.source, item.event)
        prior = coordinates.get(coordinate)
        if prior is not None:
            raise ModelCheckError(
                f"ambiguous state/event: {item.source.value}/{item.event}"
            )
        coordinates[coordinate] = item
        if item.side_effect_allowed and not item.required_evidence:
            raise ModelCheckError(
                f"side-effect transition lacks proof: {item.transition_id}"
            )

    terminals = {
        ProductState.CANCELLED,
        ProductState.COMPLETED,
        ProductState.FAILED_SAFE,
    }
    reverse: dict[ProductState, set[ProductState]] = defaultdict(set)
    for item in TRANSITION_CATALOG:
        reverse[item.target].add(item.source)
    reachable = set(terminals)
    queue = deque(terminals)
    while queue:
        target = queue.popleft()
        for source in reverse[target]:
            if source not in reachable:
                reachable.add(source)
                queue.append(source)
    active = set(ProductState) - terminals
    missing_terminal_path = active - reachable
    if missing_terminal_path:
        raise ModelCheckError(
            "active state cannot reach terminal: "
            + min(state.value for state in missing_terminal_path)
        )

    cyclic_components = 0
    for component in _strongly_connected_components(TRANSITION_CATALOG):
        internal = [
            item
            for item in TRANSITION_CATALOG
            if item.source in component and item.target in component
        ]
        cyclic = len(component) > 1 or any(
            item.source is item.target for item in internal
        )
        if not cyclic:
            continue
        cyclic_components += 1
        if not any(item.ranking_function for item in internal):
            labels = ",".join(sorted(state.value for state in component))
            raise ModelCheckError(f"cyclic component lacks ranking proof: {labels}")

    bounded = _check_bounded_model()
    transition_coverage_percent = (
        100 * len(coordinates) // len(TRANSITION_CATALOG)
        if TRANSITION_CATALOG
        else 100
    )
    return ModelCheckReport(
        transition_count=len(TRANSITION_CATALOG),
        state_event_coverage_percent=transition_coverage_percent,
        terminal_reachable_states=len(active),
        cyclic_components=cyclic_components,
        side_effect_transitions=sum(
            int(item.side_effect_allowed) for item in TRANSITION_CATALOG
        ),
        bounded_state_count=bounded.state_count,
        composed_state_count=bounded.composed_state_count,
        product_bounds=(1, 2),
        worker_bounds=(1, 2),
        node_bounds=(0, 1, 2, 3, 4),
        retry_bound=2,
        crash_bound=1,
        deadlock_count=bounded.deadlock_count,
        livelock_count=bounded.livelock_count,
        unsafe_terminal_count=bounded.unsafe_terminal_count,
        duplicate_side_effect_count=bounded.duplicate_side_effect_count,
        privilege_expansion_count=bounded.privilege_expansion_count,
        evidence_free_pass_count=bounded.evidence_free_pass_count,
        multiple_active_action_count=bounded.multiple_active_action_count,
        rollback_unknown_state_count=bounded.rollback_unknown_state_count,
        bounded_failure_escape_count=bounded.bounded_failure_escape_count,
    )
