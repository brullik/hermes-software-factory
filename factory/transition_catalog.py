"""Single closed-world transition catalog used by runtime and qualification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .failure_catalog import FailureAction


class ProductState(StrEnum):
    IDEA_RECEIVED = "IDEA_RECEIVED"
    CONTRACT_DRAFTED = "CONTRACT_DRAFTED"
    CONTRACT_VALIDATED = "CONTRACT_VALIDATED"
    RISK_CLASSIFIED = "RISK_CLASSIFIED"
    ARCHITECTED = "ARCHITECTED"
    BACKLOG_READY = "BACKLOG_READY"
    IMPLEMENTING = "IMPLEMENTING"
    INTEGRATING = "INTEGRATING"
    STAGING_DEPLOYED = "STAGING_DEPLOYED"
    PRODUCT_ACCEPTANCE = "PRODUCT_ACCEPTANCE"
    RELEASE_READY = "RELEASE_READY"
    PRODUCTION_DEPLOYED = "PRODUCTION_DEPLOYED"
    OBSERVATION = "OBSERVATION"
    REPAIRING = "REPAIRING"
    DELAYED_QUOTA = "DELAYED_QUOTA"
    BLOCKED_OWNER = "BLOCKED_OWNER"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    PAUSED = "PAUSED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED_SAFE = "FAILED_SAFE"


class ProductEvent(StrEnum):
    ADVANCE = "ADVANCE"
    PRODUCT_REPAIR_REQUIRED = "PRODUCT_REPAIR_REQUIRED"
    TRANSIENT_DELAY = "TRANSIENT_DELAY"
    EXTERNAL_BLOCK = "EXTERNAL_BLOCK"
    PAUSE = "PAUSE"
    RESUME = "RESUME"
    CANCEL = "CANCEL"
    FAIL_SAFE = "FAIL_SAFE"
    CONTROLLER_QUARANTINE = "CONTROLLER_QUARANTINE"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    ROLLBACK_COMPLETE = "ROLLBACK_COMPLETE"
    RECOVERY_APPLY = "RECOVERY_APPLY"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True)
class TransitionSpec:
    transition_id: str
    source: ProductState
    event: str
    target: ProductState
    action: FailureAction
    required_evidence: tuple[str, ...] = ()
    ranking_function: str | None = None
    model_allowed: bool = False
    side_effect_allowed: bool = False


def _spec(
    transition_id: str,
    source: ProductState,
    event: ProductEvent | str,
    target: ProductState,
    action: FailureAction = FailureAction.CONTINUE,
    *,
    evidence: tuple[str, ...] = (),
    ranking: str | None = None,
    model_allowed: bool = False,
    side_effect_allowed: bool = False,
) -> TransitionSpec:
    return TransitionSpec(
        transition_id,
        source,
        event.value if isinstance(event, ProductEvent) else event,
        target,
        action,
        evidence,
        ranking,
        model_allowed,
        side_effect_allowed,
    )


_HAPPY_PATH: Final[tuple[tuple[ProductState, ProductState], ...]] = (
    (ProductState.IDEA_RECEIVED, ProductState.CONTRACT_DRAFTED),
    (ProductState.CONTRACT_DRAFTED, ProductState.CONTRACT_VALIDATED),
    (ProductState.CONTRACT_VALIDATED, ProductState.RISK_CLASSIFIED),
    (ProductState.RISK_CLASSIFIED, ProductState.ARCHITECTED),
    (ProductState.ARCHITECTED, ProductState.BACKLOG_READY),
    (ProductState.BACKLOG_READY, ProductState.IMPLEMENTING),
    (ProductState.IMPLEMENTING, ProductState.INTEGRATING),
    (ProductState.INTEGRATING, ProductState.STAGING_DEPLOYED),
    (ProductState.STAGING_DEPLOYED, ProductState.PRODUCT_ACCEPTANCE),
    (ProductState.PRODUCT_ACCEPTANCE, ProductState.RELEASE_READY),
    (ProductState.RELEASE_READY, ProductState.PRODUCTION_DEPLOYED),
    (ProductState.PRODUCTION_DEPLOYED, ProductState.OBSERVATION),
    (ProductState.OBSERVATION, ProductState.COMPLETED),
)

_ACTIVE: Final = tuple(
    state
    for state in ProductState
    if state
    not in {
        ProductState.CANCELLED,
        ProductState.COMPLETED,
        ProductState.FAILED_SAFE,
    }
)

_TRANSITIONS: list[TransitionSpec] = [
    _spec(
        f"advance_{source.value.lower()}_to_{target.value.lower()}",
        source,
        ProductEvent.COMPLETE if target is ProductState.COMPLETED else ProductEvent.ADVANCE,
        target,
        FailureAction.COMPLETE if target is ProductState.COMPLETED else FailureAction.CONTINUE,
        evidence=(
            ("completion_manifest",)
            if target is ProductState.COMPLETED
            else ("side_effect_receipt",)
            if target in {ProductState.STAGING_DEPLOYED, ProductState.PRODUCTION_DEPLOYED}
            else ()
        ),
        side_effect_allowed=target
        in {ProductState.STAGING_DEPLOYED, ProductState.PRODUCTION_DEPLOYED},
    )
    for source, target in _HAPPY_PATH
]

# The runtime's intake and evidence reducers intentionally coalesce several
# descriptive milestones into one atomic controller commit.  These are exact
# coordinates, not inferred shortcuts.
_TRANSITIONS.extend(
    (
        _spec(
            "intake_contract_and_risk_proven",
            ProductState.IDEA_RECEIVED,
            "CONTRACT_AND_RISK_PROVEN",
            ProductState.RISK_CLASSIFIED,
            evidence=("product_contract", "risk_assessment"),
        ),
        _spec(
            "architecture_and_backlog_proven",
            ProductState.ARCHITECTED,
            "BACKLOG_COMPILED",
            ProductState.IMPLEMENTING,
            evidence=("compiled_plan",),
        ),
        _spec(
            "product_acceptance_proven",
            ProductState.STAGING_DEPLOYED,
            "ACCEPTANCE_COMPLETE",
            ProductState.RELEASE_READY,
            evidence=("product_acceptance",),
        ),
        _spec(
            "production_and_observation_scheduled",
            ProductState.RELEASE_READY,
            "PRODUCTION_OBSERVATION_SCHEDULED",
            ProductState.OBSERVATION,
            evidence=("production_receipt", "observation_schedule"),
            side_effect_allowed=True,
        ),
    )
)

for _state in _ACTIVE:
    if _state is not ProductState.OBSERVATION:
        _TRANSITIONS.append(
            _spec(
                f"complete_{_state.value.lower()}_profile",
                _state,
                ProductEvent.COMPLETE,
                ProductState.COMPLETED,
                FailureAction.COMPLETE,
                evidence=("completion_manifest", "delivery_profile_proof"),
            )
        )

for _state in _ACTIVE:
    if _state not in {ProductState.PAUSED, ProductState.ROLLING_BACK}:
        _TRANSITIONS.append(
            _spec(
                f"pause_{_state.value.lower()}",
                _state,
                ProductEvent.PAUSE,
                ProductState.PAUSED,
                ranking="single_use_pause_receipt",
            )
        )
    _TRANSITIONS.append(
        _spec(
            f"cancel_{_state.value.lower()}",
            _state,
            ProductEvent.CANCEL,
            ProductState.CANCELLED,
            FailureAction.FAIL_SAFE,
            evidence=("cancellation_receipt",),
        )
    )
    _TRANSITIONS.append(
        _spec(
            f"fail_safe_{_state.value.lower()}",
            _state,
            ProductEvent.FAIL_SAFE,
            ProductState.FAILED_SAFE,
            FailureAction.FAIL_SAFE,
            evidence=("failure_envelope", "terminal_evidence"),
        )
    )
    _TRANSITIONS.append(
        _spec(
            f"quarantine_{_state.value.lower()}",
            _state,
            ProductEvent.CONTROLLER_QUARANTINE,
            ProductState.FAILED_SAFE,
            FailureAction.CONTROLLER_QUARANTINE,
            evidence=("controller_incident", "terminal_evidence"),
        )
    )

for _state in _ACTIVE:
    if _state not in {ProductState.BLOCKED_OWNER, ProductState.PAUSED}:
        _TRANSITIONS.append(
            _spec(
                f"external_block_{_state.value.lower()}",
                _state,
                ProductEvent.EXTERNAL_BLOCK,
                ProductState.BLOCKED_OWNER,
                FailureAction.WAIT_EXTERNAL,
                evidence=("owner_action_contract",),
                ranking="external_deadline_or_owner_action",
            )
        )

for _target in _ACTIVE:
    if _target is not ProductState.PAUSED:
        _TRANSITIONS.append(
            _spec(
                f"resume_paused_to_{_target.value.lower()}",
                ProductState.PAUSED,
                f"RESUME_TO_{_target.value}",
                _target,
                evidence=("resume_receipt",),
                ranking="single_use_resume_receipt",
            )
        )

for _target in _ACTIVE:
    if _target not in {ProductState.BLOCKED_OWNER, ProductState.PAUSED}:
        _TRANSITIONS.append(
            _spec(
                f"resume_blocked_owner_to_{_target.value.lower()}",
                ProductState.BLOCKED_OWNER,
                f"OWNER_RESUME_TO_{_target.value}",
                _target,
                evidence=("owner_action_contract", "capability_proof"),
                ranking="single_use_owner_action_contract",
            )
        )

for _target in _ACTIVE:
    if _target not in {ProductState.BLOCKED_OWNER, ProductState.PAUSED}:
        _TRANSITIONS.append(
            _spec(
                f"recover_failed_safe_to_{_target.value.lower()}",
                ProductState.FAILED_SAFE,
                f"RECOVERY_APPLY_TO_{_target.value}",
                _target,
                evidence=("recovery_certificate", "new_occurrence_epoch"),
                ranking="new_release_epoch",
            )
        )

for _state in (
    ProductState.BACKLOG_READY,
    ProductState.IMPLEMENTING,
    ProductState.INTEGRATING,
    ProductState.STAGING_DEPLOYED,
    ProductState.PRODUCT_ACCEPTANCE,
    ProductState.RELEASE_READY,
    ProductState.OBSERVATION,
):
    _TRANSITIONS.append(
        _spec(
            f"repair_{_state.value.lower()}",
            _state,
            ProductEvent.PRODUCT_REPAIR_REQUIRED,
            ProductState.REPAIRING,
            FailureAction.REPAIR_NODE_VERSION,
            evidence=("failure_envelope", "candidate_snapshot"),
            ranking="remaining_evidence_executions",
            model_allowed=True,
        )
    )

_TRANSITIONS.extend(
    (
        _spec(
            "repair_resume_implementation",
            ProductState.REPAIRING,
            ProductEvent.ADVANCE,
            ProductState.IMPLEMENTING,
            evidence=("revised_node_contract",),
            ranking="unresolved_affected_obligations",
        ),
        _spec(
            "repair_resume_integration",
            ProductState.REPAIRING,
            ProductEvent.RESUME,
            ProductState.INTEGRATING,
            evidence=("accepted_repair_binding",),
        ),
        _spec(
            "transient_delay",
            ProductState.IMPLEMENTING,
            ProductEvent.TRANSIENT_DELAY,
            ProductState.DELAYED_QUOTA,
            FailureAction.RETRY_TRANSIENT,
            evidence=("retry_deadline",),
            ranking="remaining_retries_plus_deadline",
        ),
        _spec(
            "transient_resume",
            ProductState.DELAYED_QUOTA,
            ProductEvent.RESUME,
            ProductState.IMPLEMENTING,
            evidence=("retry_deadline_elapsed",),
        ),
        _spec(
            "rollback_from_staging",
            ProductState.STAGING_DEPLOYED,
            ProductEvent.ROLLBACK_REQUIRED,
            ProductState.ROLLING_BACK,
            FailureAction.ROLLBACK,
            evidence=("rollback_intent",),
            ranking="rollback_step_index",
            side_effect_allowed=True,
        ),
        _spec(
            "rollback_from_production",
            ProductState.PRODUCTION_DEPLOYED,
            ProductEvent.ROLLBACK_REQUIRED,
            ProductState.ROLLING_BACK,
            FailureAction.ROLLBACK,
            evidence=("rollback_intent",),
            ranking="rollback_step_index",
            side_effect_allowed=True,
        ),
        _spec(
            "rollback_from_observation",
            ProductState.OBSERVATION,
            ProductEvent.ROLLBACK_REQUIRED,
            ProductState.ROLLING_BACK,
            FailureAction.ROLLBACK,
            evidence=("rollback_intent",),
            ranking="rollback_step_index",
            side_effect_allowed=True,
        ),
        _spec(
            "rollback_complete",
            ProductState.ROLLING_BACK,
            ProductEvent.ROLLBACK_COMPLETE,
            ProductState.ROLLED_BACK,
            FailureAction.ROLLBACK,
            evidence=("rollback_receipt", "health_evidence"),
            ranking="rollback_step_index",
        ),
        _spec(
            "rollback_repair",
            ProductState.ROLLED_BACK,
            ProductEvent.PRODUCT_REPAIR_REQUIRED,
            ProductState.IMPLEMENTING,
            FailureAction.REPAIR_NODE_VERSION,
            evidence=("new_occurrence_epoch", "recovery_certificate"),
        ),
        _spec(
            "rollback_redeploy_staging",
            ProductState.ROLLED_BACK,
            ProductEvent.RESUME,
            ProductState.STAGING_DEPLOYED,
            evidence=("recovery_certificate", "staging_receipt"),
            side_effect_allowed=True,
        ),
        _spec(
            "release_ready_redeploy_staging",
            ProductState.RELEASE_READY,
            ProductEvent.RESUME,
            ProductState.STAGING_DEPLOYED,
            evidence=("staging_receipt",),
            side_effect_allowed=True,
        ),
    )
)


def build_transition_index(
    transitions: tuple[TransitionSpec, ...],
) -> dict[tuple[ProductState, str, ProductState], TransitionSpec]:
    """Build an exact cardinality-independent index and reject duplicates."""

    index: dict[tuple[ProductState, str, ProductState], TransitionSpec] = {}
    dispatch_coordinates: set[tuple[ProductState, str]] = set()
    for item in transitions:
        coordinate = (item.source, item.event, item.target)
        dispatch_coordinate = (item.source, item.event)
        if coordinate in index or dispatch_coordinate in dispatch_coordinates:
            raise RuntimeError("duplicate closed-world transition coordinate")
        index[coordinate] = item
        dispatch_coordinates.add(dispatch_coordinate)
    return index


TRANSITION_CATALOG: Final[tuple[TransitionSpec, ...]] = tuple(_TRANSITIONS)
TRANSITION_INDEX: Final = build_transition_index(TRANSITION_CATALOG)


def transition_spec(
    source: str,
    event: str,
    target: str,
) -> TransitionSpec:
    """Resolve one exact transition; unknown coordinates are never inferred."""

    try:
        coordinate = (ProductState(source), str(event), ProductState(target))
    except ValueError as error:
        raise KeyError(f"unknown transition coordinate: {source}/{event}/{target}") from error
    try:
        return TRANSITION_INDEX[coordinate]
    except KeyError as error:
        raise KeyError(f"unknown transition coordinate: {source}/{event}/{target}") from error


def catalog_document() -> list[dict[str, object]]:
    """Generate the machine/docs/model-check transition matrix."""

    return [
        {
            "id": item.transition_id,
            "source": item.source.value,
            "event": item.event,
            "target": item.target.value,
            "action": item.action.value,
            "required_evidence": list(item.required_evidence),
            "ranking_function": item.ranking_function,
            "model_allowed": item.model_allowed,
            "side_effect_allowed": item.side_effect_allowed,
        }
        for item in TRANSITION_CATALOG
    ]
