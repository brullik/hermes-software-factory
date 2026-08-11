"""Deterministic trajectory ownership and immutable accepted-result lookup.

The Path Governor is controller code.  It does not ask a product agent to
interpret graph state and it never treats ``supersedes_task_id`` as the
runtime result pointer.  Legacy supersession chains are read only while a
direct binding is materialised during migration.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import sha256_text, stable_json, utc_now
from .failure_catalog import FailureAction, failure_disposition

_SHA256 = re.compile(r"[a-f0-9]{64}")
_TERMINAL_ACCEPTED = {"ACCEPTED", "SUPERSEDED"}
_MAX_LEGACY_LINEAGE = 10_000
_CANDIDATE_CONSUMER_STAGES = {
    "test",
    "security-review",
    "release-readiness-review",
}


class ResultLineageError(RuntimeError):
    """Base class for controller-owned accepted-result lookup failures."""


class ResultLineageCycleError(ResultLineageError):
    """A literal repeated task id was found in a legacy lineage."""


class ResultLineageDepthExceededError(ResultLineageError):
    """A corrupted legacy lineage exceeded the defensive traversal ceiling."""


class ResultLineageIdentityError(ResultLineageError):
    """A legacy reuse edge changed the semantic identity of accepted work."""


class ActiveResultBindingConflictError(ResultLineageIdentityError):
    """More than one result claims the active slot for one semantic node."""


class PathDecisionError(RuntimeError):
    """A proposed trajectory violates the controller progress contract."""


def failure_owner(*, failure_class: str, reason_code: str) -> str:
    """Classify ownership before any repair role or plan is selected."""

    # ``failure_class`` is retained for API compatibility and evidence, but it
    # cannot grant ownership. Only the exact closed-world reason catalog can.
    _ = failure_class
    return failure_disposition(reason_code).owner


class PathArbiterSandbox:
    """One-shot, read-only Sol advice boundary; returned proposals never mutate state."""

    _FORBIDDEN_KEYS = frozenset(
        {
            "credential",
            "credentials",
            "token",
            "secret",
            "sql",
            "task_id",
            "attempt_id",
            "github_token",
        }
    )

    def __init__(
        self,
        runner: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> None:
        self.runner = runner
        self._called_signatures: set[str] = set()

    def propose(
        self,
        *,
        root_problem_signature: str,
        path_snapshot: Mapping[str, Any],
    ) -> dict[str, Any]:
        if root_problem_signature in self._called_signatures:
            raise PathDecisionError("Path Arbiter budget is exhausted for this signature")
        if not _SHA256.fullmatch(root_problem_signature):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        serialized = stable_json(path_snapshot).lower()
        if any(f'"{key}":' in serialized for key in self._FORBIDDEN_KEYS):
            raise PathDecisionError("Path Arbiter snapshot exposes a forbidden coordinate")
        self._called_signatures.add(root_problem_signature)
        raw = self.runner(dict(path_snapshot))
        proposal = dict(raw)
        allowed = {
            "schema_version",
            "status",
            "root_problem_signature",
            "root_cause_class",
            "recommended_action",
            "affected_semantic_node_keys",
            "evidence_refs",
            "expected_progress_delta",
            "assumptions",
            "summary",
        }
        if set(proposal) - allowed:
            raise PathDecisionError("Path Arbiter proposal contains an executable mutation")
        if proposal.get("root_problem_signature") != root_problem_signature:
            raise PathDecisionError("Path Arbiter proposal signature conflicts")
        if proposal.get("recommended_action") not in {
            FailureAction.REPAIR_NODE_VERSION.value,
            FailureAction.RECOMPILE_AFFECTED_SUBGRAPH.value,
            FailureAction.CONTROLLER_QUARANTINE.value,
            FailureAction.FAIL_SAFE.value,
        }:
            raise PathDecisionError("Path Arbiter proposal action is invalid")
        return proposal


@dataclass(frozen=True)
class LegacyResultSource:
    task: dict[str, Any]
    depth: int


@dataclass(frozen=True)
class ResultBinding:
    binding_id: str
    product_id: str
    semantic_node_id: str
    source_task_id: str
    source_attempt_id: str
    result_ref: str
    result_digest: str
    output_schema: str
    contract_digest: str
    policy_digest: str
    candidate_digest: str | None
    accepted_at: str
    status: str

    @classmethod
    def from_row(cls, row: sqlite3.Row | Mapping[str, Any]) -> ResultBinding:
        return cls(
            binding_id=str(row["binding_id"]),
            product_id=str(row["product_id"]),
            semantic_node_id=str(row["semantic_node_id"]),
            source_task_id=str(row["source_task_id"]),
            source_attempt_id=str(row["source_attempt_id"]),
            result_ref=str(row["result_ref"]),
            result_digest=str(row["result_digest"]),
            output_schema=str(row["output_schema"]),
            contract_digest=str(row["contract_digest"]),
            policy_digest=str(row["policy_digest"]),
            candidate_digest=(
                str(row["candidate_digest"])
                if row["candidate_digest"] is not None
                else None
            ),
            accepted_at=str(row["accepted_at"]),
            status=str(row["status"]),
        )


@dataclass(frozen=True, order=True)
class ProgressVector:
    unmet_mandatory_obligations: int
    unresolved_root_problem_signatures: int
    unaccepted_changed_semantic_nodes: int
    open_controller_incidents: int
    missing_candidate_evidence: int
    lineage_indirection_depth: int
    no_progress_decisions: int

    def as_dict(self) -> dict[str, int]:
        return {
            "unmet_mandatory_obligations": self.unmet_mandatory_obligations,
            "unresolved_root_problem_signatures": (
                self.unresolved_root_problem_signatures
            ),
            "unaccepted_changed_semantic_nodes": (
                self.unaccepted_changed_semantic_nodes
            ),
            "open_controller_incidents": self.open_controller_incidents,
            "missing_candidate_evidence": self.missing_candidate_evidence,
            "lineage_indirection_depth": self.lineage_indirection_depth,
            "no_progress_decisions": self.no_progress_decisions,
        }

    def strictly_improves(self, previous: ProgressVector) -> bool:
        # Retry/no-progress counters are monotonic trajectory telemetry, not a
        # ranking function. Including them here made real progress impossible
        # to order once a counter increased.
        progress_keys = (
            "unmet_mandatory_obligations",
            "unresolved_root_problem_signatures",
            "unaccepted_changed_semantic_nodes",
            "open_controller_incidents",
            "missing_candidate_evidence",
            "lineage_indirection_depth",
        )
        before_values = previous.as_dict()
        after_values = self.as_dict()
        before = tuple(before_values[key] for key in progress_keys)
        after = tuple(after_values[key] for key in progress_keys)
        return all(new <= old for old, new in zip(before, after, strict=True)) and any(
            new < old for old, new in zip(before, after, strict=True)
        )


def root_cause_key(values: Mapping[str, Any]) -> str:
    """Hash semantic coordinates while excluding volatile attempt prose/ids."""

    failed_gate_ids = sorted(
        {str(value) for value in values.get("failed_gate_ids", ())}
    )
    owner = str(values.get("problem_owner") or "") or failure_owner(
        failure_class=str(values.get("failure_class") or ""),
        reason_code=str(values.get("reason_code") or ""),
    )
    semantic_node_key = re.sub(
        r"@(candidate|plan):[^:@]+$",
        "",
        str(values.get("semantic_node_key") or ""),
    )
    reason_coordinate = (
        str(values.get("controller_invariant_id") or values.get("reason_code") or "")
        if owner in {"controller", "external"} or not failed_gate_ids
        else "mandatory-gate"
    )
    coordinates = {
        "product_id": str(values.get("product_id") or ""),
        "problem_owner": owner,
        "reason_coordinate": reason_coordinate,
        "semantic_node_key": semantic_node_key,
        "lifecycle_stage": str(values.get("lifecycle_stage") or ""),
        "failed_gate_ids": failed_gate_ids,
        "required_paths": sorted(
            {str(value) for value in values.get("required_paths", ())}
        ),
    }
    return sha256_text(stable_json(coordinates))


def stable_root_problem_signature(values: Mapping[str, Any]) -> str:
    """Compatibility alias for the Hermes 2.4 ``root_cause_key``."""

    return root_cause_key(values)


def occurrence_epoch_key(values: Mapping[str, Any]) -> str:
    """Bind one root cause to an exact controller/candidate/toolchain epoch."""

    required = (
        "root_cause_key",
        "controller_release_digest",
        "candidate_snapshot_digest",
        "policy_digest",
        "contract_digest",
        "toolchain_manifest_digest",
    )
    coordinates: dict[str, str] = {}
    for name in required:
        value = str(values.get(name) or "")
        if not _SHA256.fullmatch(value):
            raise ValueError(f"{name} must be a lowercase SHA-256")
        coordinates[name] = value
    return sha256_text(stable_json(coordinates))


def task_contract_digest(task: Mapping[str, Any]) -> str:
    """Return a stable semantic contract digest, excluding execution identity."""

    contract = {
        "product_id": str(task.get("product_id") or ""),
        "semantic_node_key": str(
            task.get("semantic_node_key")
            or task.get("plan_node_id")
            or task.get("stage_key")
            or task.get("task_id")
        ),
        "role": str(task.get("role") or ""),
        "output_schema": str(task.get("output_schema") or ""),
        "lifecycle_stage": str(task.get("lifecycle_stage") or ""),
        "review_kind": str(task.get("review_kind") or ""),
        "evidence_profile": str(task.get("evidence_profile") or ""),
        "goal_ids": _json_array(
            task.get("goal_ids_json")
            if task.get("goal_ids_json") is not None
            else task.get("goal_ids")
        ),
        "completion_obligation_ids": _json_array(
            task.get("completion_obligation_ids_json")
            if task.get("completion_obligation_ids_json") is not None
            else task.get("completion_obligation_ids")
        ),
    }
    return sha256_text(stable_json(contract))


def semantic_node_id(task: Mapping[str, Any], contract_digest: str) -> str:
    key = str(
        task.get("semantic_node_key")
        or task.get("plan_node_id")
        or task.get("stage_key")
        or task.get("task_id")
    )
    digest = sha256_text(
        stable_json([str(task.get("product_id") or ""), key, contract_digest])
    )
    return f"SN-{digest[:20].upper()}"


def _json_array(value: object) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _identity(task: Mapping[str, Any]) -> tuple[str, ...]:
    fixed = tuple(
        str(task.get(field) or "")
        for field in (
            "product_id",
            "role",
            "output_schema",
            "lifecycle_stage",
            "review_kind",
            "evidence_profile",
        )
    )
    semantic_identity = str(
        task.get("semantic_node_key") or task.get("semantic_node_id") or ""
    )
    return (*fixed, semantic_identity)


def supersession_is_compatible(
    source: Mapping[str, Any],
    replacement: Mapping[str, Any],
) -> bool:
    """Return whether two tasks describe one exact replaceable contract identity."""

    source_identity = _identity(source)
    replacement_identity = _identity(replacement)
    if source_identity[:-1] != replacement_identity[:-1]:
        return False
    source_key = str(source.get("semantic_node_key") or "")
    replacement_key = str(replacement.get("semantic_node_key") or "")
    if source_key and replacement_key:
        return source_key == replacement_key
    source_node = str(source.get("semantic_node_id") or "")
    replacement_node = str(replacement.get("semantic_node_id") or "")
    if source_node and replacement_node:
        return source_node == replacement_node
    return source_identity[-1] == replacement_identity[-1]


def execution_slot_cost(task: Mapping[str, Any]) -> int:
    """Return the closed-world repository execution cost for one task."""

    role = str(task.get("role") or "").replace("_", "-")
    capability_profile = str(task.get("capability_profile") or "")
    stage = str(task.get("lifecycle_stage") or task.get("stage_key") or "")
    repository_writer = role == "builder" and capability_profile == "builder_workspace"
    evidence_execution = stage in {"implementation-slice", "repair"}
    return int(repository_writer and evidence_execution)


class PathGovernor:
    """Sole deterministic owner of accepted-result and trajectory mutations."""

    def __init__(self, connection: sqlite3.Connection, *, policy_digest: str) -> None:
        if not _SHA256.fullmatch(policy_digest):
            raise ValueError("Path Governor policy digest must be a lowercase SHA-256")
        self.connection = connection
        self.policy_digest = policy_digest

    def direct_binding(self, task_id: str) -> ResultBinding | None:
        row = self.connection.execute(
            """SELECT binding.*
                 FROM tasks AS task
                 JOIN result_bindings AS binding
                   ON binding.binding_id=task.result_binding_id
                WHERE task.task_id=? AND binding.status='ACTIVE'
                  AND binding.product_id=task.product_id""",
            (task_id,),
        ).fetchone()
        if row is None:
            return None
        binding = ResultBinding.from_row(row)
        task = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task is None:
            raise KeyError(task_id)
        expected_contract = str(task["contract_digest"] or task_contract_digest(task))
        expected_node = str(task["semantic_node_id"] or semantic_node_id(task, expected_contract))
        if (
            binding.product_id != str(task["product_id"])
            or binding.semantic_node_id != expected_node
            or binding.contract_digest != expected_contract
            or binding.output_schema != str(task["output_schema"] or "")
            or not _SHA256.fullmatch(binding.result_digest)
        ):
            raise ResultLineageIdentityError(
                f"direct accepted-result binding conflicts for {task_id}"
            )
        return binding

    def resolve_legacy_source(self, task_id: str) -> LegacyResultSource:
        requested = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if requested is None:
            raise KeyError(task_id)
        requested_mapping = dict(requested)
        if (
            str(requested_mapping.get("status") or "") != "DONE"
            or str(requested_mapping.get("graph_status") or "")
            not in _TERMINAL_ACCEPTED
        ):
            raise ResultLineageIdentityError(f"accepted task is missing for {task_id}")

        current = requested_mapping
        visited: set[str] = set()
        depth = 0
        while True:
            current_id = str(current["task_id"])
            if current_id in visited:
                raise ResultLineageCycleError(
                    f"accepted task reuse lineage is cyclic for {task_id} at {current_id}"
                )
            if depth >= _MAX_LEGACY_LINEAGE:
                raise ResultLineageDepthExceededError(
                    f"accepted task reuse lineage exceeded {_MAX_LEGACY_LINEAGE} for {task_id}"
                )
            visited.add(current_id)

            attempts = self.connection.execute(
                """SELECT attempt_id FROM attempts
                    WHERE task_id=? AND status IN ('completed','repair_required')
                    ORDER BY created_at, attempt_id""",
                (current_id,),
            ).fetchall()
            if attempts:
                return LegacyResultSource(current, depth)

            if str(current.get("graph_status") or "") == "SUPERSEDED":
                replacements = self.connection.execute(
                    """SELECT * FROM tasks
                         WHERE product_id=? AND supersedes_task_id=?
                           AND status='DONE'
                           AND graph_status IN ('ACCEPTED','SUPERSEDED')
                         ORDER BY created_at, task_id""",
                    (str(current["product_id"]), current_id),
                ).fetchall()
                if len(replacements) > 1:
                    raise ResultLineageIdentityError(
                        f"accepted task replacement lineage is ambiguous for {task_id}"
                    )
                if replacements:
                    replacement = dict(replacements[0])
                    if not supersession_is_compatible(current, replacement):
                        raise ResultLineageIdentityError(
                            f"accepted task replacement identity conflicts for {task_id}"
                        )
                    current = replacement
                    depth += 1
                    continue
                raise ResultLineageIdentityError(
                    f"accepted task replacement is missing for {task_id}"
                )

            predecessor_id = str(current.get("supersedes_task_id") or "")
            predecessor_row = (
                self.connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (predecessor_id,)
                ).fetchone()
                if predecessor_id
                else None
            )
            if predecessor_row is None:
                raise ResultLineageIdentityError(
                    f"accepted task result is missing for {task_id}"
                )
            predecessor = dict(predecessor_row)
            if (
                str(current.get("graph_status") or "") != "ACCEPTED"
                or str(predecessor.get("graph_status") or "") != "ACCEPTED"
                or str(predecessor.get("status") or "") != "DONE"
                or not supersession_is_compatible(predecessor, current)
                or not str(current.get("result_ref") or "")
                or str(current.get("result_ref") or "")
                != str(predecessor.get("result_ref") or "")
                or not str(current.get("result_digest") or "")
                or str(current.get("result_digest") or "")
                != str(predecessor.get("result_digest") or "")
            ):
                raise ResultLineageIdentityError(
                    f"accepted task reuse lineage is invalid for {task_id}"
                )
            current = predecessor
            depth += 1

    def bind_result(
        self,
        *,
        task_id: str,
        source_task_id: str,
        source_attempt_id: str,
        result_ref: str,
        result_digest: str,
        output_schema: str,
        candidate_digest: str | None = None,
        accepted_at: str | None = None,
    ) -> ResultBinding:
        """Create or reuse the one active immutable binding for a semantic node.

        The caller owns the surrounding transaction.  This lets outcome commit,
        migration, task state, event, and outbox mutations share one commit.
        """

        if not source_attempt_id or not result_ref:
            raise ValueError("accepted result provenance is required")
        if not _SHA256.fullmatch(result_digest):
            raise ValueError("accepted result digest must be a lowercase SHA-256")
        task_row = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        source_row = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (source_task_id,)
        ).fetchone()
        if task_row is None or source_row is None:
            raise KeyError(task_id if task_row is None else source_task_id)
        task = dict(task_row)
        source = dict(source_row)
        if (
            str(task.get("product_id") or "") != str(source.get("product_id") or "")
            or not supersession_is_compatible(source, task)
            or str(task.get("graph_status") or "") not in _TERMINAL_ACCEPTED
            or str(source.get("status") or "") != "DONE"
            or str(source.get("graph_status") or "") not in _TERMINAL_ACCEPTED
            or output_schema != str(task.get("output_schema") or "")
        ):
            raise ResultLineageIdentityError(
                f"accepted result provenance conflicts for {task_id}"
            )
        attempt = self.connection.execute(
            """SELECT attempt_id FROM attempts
                 WHERE attempt_id=? AND task_id=?
                   AND status IN ('completed','repair_required')""",
            (source_attempt_id, source_task_id),
        ).fetchone()
        if attempt is None:
            raise ResultLineageIdentityError(
                f"accepted source attempt is missing for {task_id}"
            )

        contract = str(task.get("contract_digest") or task_contract_digest(task))
        node_id = str(task.get("semantic_node_id") or semantic_node_id(task, contract))
        node_key = str(
            task.get("semantic_node_key")
            or task.get("plan_node_id")
            or task.get("stage_key")
            or task_id
        )
        now = accepted_at or utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO semantic_nodes
               (semantic_node_id, product_id, semantic_node_key, role,
                lifecycle_stage, contract_digest, contract_ref, status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)""",
            (
                node_id,
                str(task["product_id"]),
                node_key,
                str(task.get("role") or ""),
                str(task.get("lifecycle_stage") or task.get("stage_key") or "legacy"),
                contract,
                str(task.get("contract_ref") or f"state://task/{task_id}"),
                now,
                now,
            ),
        )
        binding_seed = stable_json(
            [str(task["product_id"]), node_id, result_digest, contract]
        )
        binding_id = f"RB-{sha256_text(binding_seed)[:20].upper()}"
        self.connection.execute(
            """INSERT OR IGNORE INTO result_bindings
               (binding_id, product_id, semantic_node_id, source_task_id,
                source_attempt_id, result_ref, result_digest, output_schema,
                contract_digest, policy_digest, candidate_digest, accepted_at,
                status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')""",
            (
                binding_id,
                str(task["product_id"]),
                node_id,
                source_task_id,
                source_attempt_id,
                result_ref,
                result_digest,
                output_schema,
                contract,
                self.policy_digest,
                candidate_digest,
                now,
            ),
        )
        exact = self.connection.execute(
            "SELECT * FROM result_bindings WHERE binding_id=?",
            (binding_id,),
        ).fetchone()
        if exact is None:
            competing = self.connection.execute(
                """SELECT binding_id FROM result_bindings
                     WHERE product_id=? AND semantic_node_id=? AND status='ACTIVE'
                     ORDER BY binding_id""",
                (str(task["product_id"]), node_id),
            ).fetchall()
            if competing:
                raise ActiveResultBindingConflictError(
                    f"active result binding conflicts for {task_id}"
                )
            raise RuntimeError("exact result binding was not persisted")
        binding = ResultBinding.from_row(exact)
        if (
            binding.product_id != str(task["product_id"])
            or binding.semantic_node_id != node_id
            or binding.result_ref != result_ref
            or binding.result_digest != result_digest
            or binding.source_task_id != source_task_id
            or binding.source_attempt_id != source_attempt_id
            or binding.output_schema != output_schema
            or binding.contract_digest != contract
            or binding.policy_digest != self.policy_digest
            or binding.candidate_digest != candidate_digest
            or binding.status not in {"ACTIVE", "SUPERSEDED"}
        ):
            raise ResultLineageIdentityError(
                f"immutable accepted-result binding conflicts for {task_id}"
            )
        if binding.status == "SUPERSEDED":
            return binding
        competing = self.connection.execute(
            """SELECT binding_id FROM result_bindings
                 WHERE product_id=? AND semantic_node_id=? AND status='ACTIVE'
                   AND binding_id!=?
                 ORDER BY binding_id""",
            (str(task["product_id"]), node_id, binding_id),
        ).fetchall()
        if competing:
            raise ActiveResultBindingConflictError(
                f"active result binding conflicts for {task_id}"
            )
        self.connection.execute(
            """UPDATE tasks
                  SET semantic_node_id=?, contract_digest=?, result_binding_id=?,
                      updated_at=?
                WHERE task_id=?""",
            (node_id, contract, binding_id, now, task_id),
        )
        plan_id = str(task.get("plan_id") or "")
        if plan_id:
            self.connection.execute(
                """INSERT OR REPLACE INTO plan_memberships
                   (plan_id, semantic_node_id, binding_id, execution_task_id,
                    membership_state, mandatory, created_at)
                   VALUES (?, ?, ?, NULL, 'BOUND', ?, ?)""",
                (plan_id, node_id, binding_id, int(task.get("mandatory") or 0), now),
            )
        return binding

    def retire_active_binding_for_replacement(
        self,
        *,
        product_id: str,
        semantic_node_id: str,
    ) -> str | None:
        """Retire the one active binding before executing a changed semantic node."""

        if not product_id or not semantic_node_id:
            raise ValueError("binding replacement identity is required")
        rows = self.connection.execute(
            """SELECT binding_id FROM result_bindings
                 WHERE product_id=? AND semantic_node_id=? AND status='ACTIVE'
                 ORDER BY binding_id""",
            (product_id, semantic_node_id),
        ).fetchall()
        if len(rows) > 1:
            raise ActiveResultBindingConflictError(
                "multiple active result bindings exist for one semantic node"
            )
        if not rows:
            return None
        binding_id = str(rows[0]["binding_id"])
        updated = self.connection.execute(
            """UPDATE result_bindings SET status='SUPERSEDED'
                 WHERE binding_id=? AND product_id=?
                   AND semantic_node_id=? AND status='ACTIVE'""",
            (binding_id, product_id, semantic_node_id),
        ).rowcount
        if updated != 1:
            raise ActiveResultBindingConflictError(
                "active result binding changed during replacement"
            )
        return binding_id

    def retire_reviewed_architecture_binding_for_correction(
        self,
        task_id: str,
    ) -> str | None:
        """Retire one reviewed architecture binding for its exact correction.

        The caller must own the surrounding ``BEGIN IMMEDIATE`` transaction.
        A correction is allowed to replace an accepted architecture result only
        through the reviewer that consumed the old result and requested the new
        one.  Historical bindings and frozen snapshot items are never changed.
        """

        task_row = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task_row is None:
            raise KeyError(task_id)
        task = dict(task_row)
        role = str(task.get("role") or "").replace("_", "-")
        if role != "solution-architect" or str(task.get("stage_key") or "") != "repair":
            return None
        if (
            str(task.get("capability_profile") or "") != "planning_readonly"
            or str(task.get("output_schema") or "")
            != "architecture-package.schema.json"
            or "architecture_package"
            not in {
                str(value)
                for value in _json_array(task.get("produces_evidence_types_json"))
            }
        ):
            raise ResultLineageIdentityError(
                f"architecture correction contract is not eligible for {task_id}"
            )

        contract_ref = str(task.get("contract_ref") or "")
        if contract_ref != f"evidence/task-{task_id}.json":
            raise ResultLineageIdentityError(
                f"architecture correction contract reference is not exact for {task_id}"
            )
        database_row = self.connection.execute("PRAGMA database_list").fetchone()
        database_path = Path(str(database_row[2] or "")) if database_row else Path()
        evidence_root = database_path.parent / "evidence"
        unresolved = evidence_root / Path(contract_ref).name
        try:
            contract_path = unresolved.resolve(strict=True)
            resolved_evidence_root = evidence_root.resolve(strict=True)
        except OSError as error:
            raise ResultLineageIdentityError(
                f"architecture correction contract is missing for {task_id}"
            ) from error
        if (
            contract_path.parent != resolved_evidence_root
            or unresolved.is_symlink()
            or not contract_path.is_file()
        ):
            raise ResultLineageIdentityError(
                f"architecture correction contract path is invalid for {task_id}"
            )
        try:
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ResultLineageIdentityError(
                f"architecture correction contract is unreadable for {task_id}"
            ) from error
        if not isinstance(contract, dict):
            raise ResultLineageIdentityError(
                f"architecture correction contract is not an object for {task_id}"
            )
        contract_digest = task_contract_digest(contract)
        correction_node_id = semantic_node_id(contract, contract_digest)
        if (
            str(contract.get("task_id") or "") != task_id
            or str(contract.get("product_id") or "")
            != str(task.get("product_id") or "")
            or str(contract.get("role") or "").replace("_", "-")
            != "solution-architect"
            or str(contract.get("lifecycle_stage") or "")
            != "architecture-review"
            or str(contract.get("capability_profile") or "") != "planning_readonly"
            or str(contract.get("output_schema") or "")
            != "architecture-package.schema.json"
            or "architecture_package"
            not in {
                str(value) for value in contract.get("produces_evidence_types", [])
            }
            or str(task.get("contract_digest") or "") != contract_digest
            or str(task.get("semantic_node_id") or "") != correction_node_id
        ):
            raise ResultLineageIdentityError(
                f"architecture correction immutable identity conflicts for {task_id}"
            )

        plan_id = str(task.get("plan_id") or "")
        product_id = str(task.get("product_id") or "")
        reviewer_edges = self.connection.execute(
            """SELECT edge.to_task_id, reviewer.*
                 FROM task_edges AS edge
                 JOIN tasks AS reviewer ON reviewer.task_id=edge.to_task_id
                WHERE edge.plan_id=? AND edge.from_task_id=?
                  AND edge.edge_type='revalidates' AND edge.required=1
                ORDER BY edge.to_task_id""",
            (plan_id, task_id),
        ).fetchall()
        if len(reviewer_edges) != 1:
            raise ResultLineageIdentityError(
                f"architecture correction requires one reviewer edge for {task_id}"
            )
        reviewer = dict(reviewer_edges[0])
        reviewer_id = str(reviewer["to_task_id"])
        try:
            reviewer_dependencies = _json_array(reviewer.get("dependencies_json"))
        except (TypeError, json.JSONDecodeError) as error:
            raise ResultLineageIdentityError(
                f"architecture reviewer dependencies are invalid for {task_id}"
            ) from error
        if (
            str(reviewer.get("product_id") or "") != product_id
            or str(reviewer.get("plan_id") or "") != plan_id
            or str(reviewer.get("role") or "").replace("_", "-")
            != "independent-reviewer"
            or str(reviewer.get("lifecycle_stage") or "")
            != "architecture-review"
            or reviewer_dependencies.count(task_id) != 1
        ):
            raise ResultLineageIdentityError(
                f"architecture reviewer lineage conflicts for {task_id}"
            )
        prior_edges = self.connection.execute(
            """SELECT edge.from_task_id, source.*
                 FROM task_edges AS edge
                 JOIN tasks AS source ON source.task_id=edge.from_task_id
                WHERE edge.plan_id=? AND edge.to_task_id=?
                  AND edge.edge_type='evidence_from' AND edge.required=1
                ORDER BY edge.from_task_id""",
            (plan_id, reviewer_id),
        ).fetchall()
        if len(prior_edges) != 1:
            raise ResultLineageIdentityError(
                f"architecture reviewer requires one prior evidence edge for {task_id}"
            )
        prior = dict(prior_edges[0])
        prior_task_id = str(prior["from_task_id"])

        active_rows = self.connection.execute(
            """SELECT * FROM result_bindings
                 WHERE product_id=? AND semantic_node_id=? AND status='ACTIVE'
                 ORDER BY binding_id""",
            (product_id, correction_node_id),
        ).fetchall()
        if len(active_rows) > 1:
            raise ActiveResultBindingConflictError(
                "multiple active architecture bindings exist for one semantic node"
            )
        if not active_rows:
            return None
        active = ResultBinding.from_row(active_rows[0])
        if active.source_task_id == task_id:
            if (
                active.contract_digest != contract_digest
                or active.output_schema != str(task.get("output_schema") or "")
            ):
                raise ResultLineageIdentityError(
                    f"architecture correction replay conflicts for {task_id}"
                )
            return None
        if (
            active.source_task_id != prior_task_id
            or str(prior.get("status") or "") != "DONE"
            or str(prior.get("graph_status") or "") != "ACCEPTED"
            or str(prior.get("semantic_node_id") or "") != correction_node_id
            or str(prior.get("contract_digest") or "") != contract_digest
            or str(prior.get("output_schema") or "")
            != str(task.get("output_schema") or "")
            or int(prior.get("task_revision") or 0)
            >= int(task.get("task_revision") or 0)
            or str(prior.get("result_binding_id") or "") != active.binding_id
            or active.contract_digest != contract_digest
            or active.output_schema != str(task.get("output_schema") or "")
        ):
            raise ResultLineageIdentityError(
                f"prior reviewed architecture binding conflicts for {task_id}"
            )
        updated = self.connection.execute(
            """UPDATE result_bindings SET status='SUPERSEDED'
                 WHERE binding_id=? AND product_id=? AND semantic_node_id=?
                   AND source_task_id=? AND status='ACTIVE'""",
            (
                active.binding_id,
                product_id,
                correction_node_id,
                prior_task_id,
            ),
        ).rowcount
        if updated != 1:
            raise ActiveResultBindingConflictError(
                "reviewed architecture binding changed during correction"
            )
        remaining = self.connection.execute(
            """SELECT COUNT(*) FROM result_bindings
                 WHERE product_id=? AND semantic_node_id=? AND status='ACTIVE'""",
            (product_id, correction_node_id),
        ).fetchone()
        if remaining is None or int(remaining[0]) != 0:
            raise ActiveResultBindingConflictError(
                "reviewed architecture binding retirement is not exclusive"
            )
        return active.binding_id

    def advance_reviewed_architecture_evidence_for_correction(
        self,
        task_id: str,
        retired_binding_id: str,
    ) -> None:
        """Point the same reviewer at the newly accepted architecture source."""

        task_row = self.connection.execute(
            "SELECT product_id,plan_id FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        retired = self.connection.execute(
            """SELECT product_id,source_task_id,status FROM result_bindings
                 WHERE binding_id=?""",
            (retired_binding_id,),
        ).fetchone()
        if (
            task_row is None
            or retired is None
            or str(retired["product_id"]) != str(task_row["product_id"])
            or str(retired["status"]) != "SUPERSEDED"
        ):
            raise ResultLineageIdentityError(
                f"retired architecture evidence conflicts for {task_id}"
            )
        active = self.connection.execute(
            """SELECT source_task_id FROM result_bindings
                 WHERE product_id=? AND status='ACTIVE'
                   AND semantic_node_id=(
                       SELECT semantic_node_id FROM tasks WHERE task_id=?
                   )
                 ORDER BY binding_id""",
            (str(task_row["product_id"]), task_id),
        ).fetchall()
        if len(active) != 1 or str(active[0]["source_task_id"]) != task_id:
            raise ResultLineageIdentityError(
                f"new architecture binding is not exact for {task_id}"
            )
        reviewer_rows = self.connection.execute(
            """SELECT to_task_id FROM task_edges
                 WHERE plan_id=? AND from_task_id=?
                   AND edge_type='revalidates' AND required=1
                 ORDER BY to_task_id""",
            (str(task_row["plan_id"]), task_id),
        ).fetchall()
        if len(reviewer_rows) != 1:
            raise ResultLineageIdentityError(
                f"architecture correction reviewer changed for {task_id}"
            )
        reviewer_id = str(reviewer_rows[0]["to_task_id"])
        old_source_id = str(retired["source_task_id"])
        updated = self.connection.execute(
            """UPDATE task_edges SET from_task_id=?, created_at=?
                 WHERE plan_id=? AND from_task_id=? AND to_task_id=?
                   AND edge_type='evidence_from' AND required=1""",
            (
                task_id,
                utc_now(),
                str(task_row["plan_id"]),
                old_source_id,
                reviewer_id,
            ),
        ).rowcount
        if updated != 1:
            raise ResultLineageIdentityError(
                f"architecture reviewer evidence edge changed for {task_id}"
            )
        current = self.connection.execute(
            """SELECT COUNT(*) FROM task_edges
                 WHERE plan_id=? AND from_task_id=? AND to_task_id=?
                   AND edge_type='evidence_from' AND required=1""",
            (str(task_row["plan_id"]), task_id, reviewer_id),
        ).fetchone()
        if current is None or int(current[0]) != 1:
            raise ResultLineageIdentityError(
                f"architecture reviewer evidence did not advance for {task_id}"
            )

    def register_execution_membership(self, task_id: str) -> str:
        task_row = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task_row is None:
            raise KeyError(task_id)
        task = dict(task_row)
        plan_id = str(task.get("plan_id") or "")
        identity_rescoped = False
        if (
            str(task.get("role") or "") == "path-governor"
            and str(task.get("lifecycle_stage") or "") == "candidate-snapshot"
        ):
            if not plan_id:
                raise ResultLineageIdentityError(
                    f"candidate snapshot task is missing a plan identity for {task_id}"
                )
            base_key = str(
                task.get("semantic_node_key")
                or task.get("plan_node_id")
                or task.get("stage_key")
                or task_id
            )
            scope_suffix = f"@plan:{plan_id}"
            if not base_key.endswith(scope_suffix):
                task["semantic_node_key"] = f"{base_key}{scope_suffix}"
                identity_rescoped = True
        elif str(task.get("role") or "") == "replanner":
            if not plan_id:
                raise ResultLineageIdentityError(
                    f"replanner task is missing a plan identity for {task_id}"
                )
            base_key = str(
                task.get("semantic_node_key")
                or task.get("plan_node_id")
                or task.get("stage_key")
                or task_id
            )
            scope_marker = "@plan:"
            scope_suffix = f"{scope_marker}{plan_id}"
            if scope_marker in base_key and not base_key.endswith(scope_suffix):
                raise ResultLineageIdentityError(
                    f"replanner identity conflicts with its plan for {task_id}"
                )
            if not base_key.endswith(scope_suffix):
                task["semantic_node_key"] = f"{base_key}{scope_suffix}"
                identity_rescoped = True
        elif (
            str(task.get("lifecycle_stage") or "") in _CANDIDATE_CONSUMER_STAGES
            and str(task.get("candidate_snapshot_id") or "")
        ):
            snapshot_id = str(task["candidate_snapshot_id"])
            snapshot = self.connection.execute(
                """SELECT product_id, plan_id, status
                     FROM candidate_snapshots WHERE snapshot_id=?""",
                (snapshot_id,),
            ).fetchone()
            if snapshot is None or (
                str(snapshot["product_id"]) != str(task.get("product_id") or "")
                or str(snapshot["plan_id"]) != plan_id
                or str(snapshot["status"]) != "FROZEN"
            ):
                raise ResultLineageIdentityError(
                    f"candidate consumer snapshot identity conflicts for {task_id}"
                )
            base_key = str(
                task.get("semantic_node_key")
                or task.get("plan_node_id")
                or task.get("stage_key")
                or task_id
            )
            scope_marker = "@candidate:"
            scope_suffix = f"{scope_marker}{snapshot_id}"
            if scope_marker in base_key and not base_key.endswith(scope_suffix):
                raise ResultLineageIdentityError(
                    f"candidate consumer identity cannot change for {task_id}"
                )
            if not base_key.endswith(scope_suffix):
                task["semantic_node_key"] = f"{base_key}{scope_suffix}"
                identity_rescoped = True
        # Candidate scoping changes execution identity, never the immutable
        # task-contract digest.  Re-digesting after appending ``@candidate``
        # would make the durable row disagree with its signed contract file.
        contract = str(task.get("contract_digest") or task_contract_digest(task))
        node_id = str(
            semantic_node_id(task, contract)
            if identity_rescoped
            else task.get("semantic_node_id") or semantic_node_id(task, contract)
        )
        now = utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO semantic_nodes
               (semantic_node_id, product_id, semantic_node_key, role,
                lifecycle_stage, contract_digest, contract_ref, status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)""",
            (
                node_id,
                str(task["product_id"]),
                str(task.get("semantic_node_key") or task.get("plan_node_id") or task_id),
                str(task.get("role") or ""),
                str(task.get("lifecycle_stage") or task.get("stage_key") or "legacy"),
                contract,
                str(task.get("contract_ref") or f"state://task/{task_id}"),
                now,
                now,
            ),
        )
        self.connection.execute(
            """UPDATE tasks SET semantic_node_key=?, semantic_node_id=?,
                      contract_digest=?, updated_at=? WHERE task_id=?""",
            (
                task.get("semantic_node_key"),
                node_id,
                contract,
                now,
                task_id,
            ),
        )
        self.connection.execute(
            """DELETE FROM plan_memberships
                WHERE plan_id=? AND execution_task_id=?
                  AND membership_state='EXECUTION'""",
            (plan_id, task_id),
        )
        self.connection.execute(
            """INSERT OR REPLACE INTO plan_memberships
               (plan_id, semantic_node_id, binding_id, execution_task_id,
                membership_state, mandatory, created_at)
               VALUES (?, ?, NULL, ?, 'EXECUTION', ?, ?)""",
            (
                plan_id,
                node_id,
                task_id,
                int(task.get("mandatory") or 0),
                now,
            ),
        )
        return node_id

    def apply_plan_delta(
        self,
        *,
        plan_id: str,
        preserve_binding_ids: Sequence[str],
        execution_task_ids: Sequence[str],
    ) -> None:
        """Persist a bounded delta and reject a no-op before any mutation."""

        if not execution_task_ids:
            raise PathDecisionError("no-op plan delta has no changed or new semantic node")
        for binding_id in preserve_binding_ids:
            row = self.connection.execute(
                """SELECT semantic_node_id FROM result_bindings
                    WHERE binding_id=? AND status='ACTIVE'""",
                (binding_id,),
            ).fetchone()
            if row is None:
                raise PathDecisionError(f"preserved binding is unavailable: {binding_id}")
            self.connection.execute(
                """INSERT OR REPLACE INTO plan_memberships
                   (plan_id, semantic_node_id, binding_id, execution_task_id,
                    membership_state, mandatory, created_at)
                   VALUES (?, ?, ?, NULL, 'BOUND', 1, ?)""",
                (plan_id, str(row[0]), binding_id, utc_now()),
            )
        for task_id in execution_task_ids:
            node_id = self.register_execution_membership(task_id)
            task = self.connection.execute(
                "SELECT mandatory FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if task is None:
                raise KeyError(task_id)
            self.connection.execute(
                """INSERT OR REPLACE INTO plan_memberships
                   (plan_id, semantic_node_id, binding_id, execution_task_id,
                    membership_state, mandatory, created_at)
                   VALUES (?, ?, NULL, ?, 'EXECUTION', ?, ?)""",
                (plan_id, node_id, task_id, int(task[0] or 0), utc_now()),
            )

    def create_candidate_snapshot(
        self,
        *,
        product_id: str,
        plan_id: str,
        repository_commit: str,
        tree_digest: str,
        architecture_binding_id: str,
        result_binding_ids: Sequence[str],
        created_at: str | None = None,
    ) -> str:
        """Freeze one review candidate over architecture and implementation bindings."""

        if not re.fullmatch(r"[a-f0-9]{40}", repository_commit):
            raise ValueError("candidate repository commit must be a 40-character git SHA")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", tree_digest):
            raise ValueError("candidate tree digest must be sha256-prefixed")
        ordered = tuple(sorted(set(result_binding_ids)))
        if not ordered or architecture_binding_id not in ordered:
            raise ValueError("candidate snapshot requires its architecture binding")
        placeholders = ",".join("?" for _ in ordered)
        rows = self.connection.execute(
            f"""SELECT binding.binding_id, binding.semantic_node_id,
                       binding.product_id, binding.result_ref,
                       binding.result_digest, binding.contract_digest,
                       binding.policy_digest, binding.source_task_id,
                       binding.source_attempt_id, binding.status,
                       source.product_id AS source_product_id,
                       attempt.task_id AS attempt_task_id,
                       attempt.status AS attempt_status
                   FROM result_bindings
                   AS binding
                   JOIN tasks AS source
                     ON source.task_id=binding.source_task_id
                   JOIN attempts AS attempt
                     ON attempt.attempt_id=binding.source_attempt_id
                  WHERE binding.binding_id IN ({placeholders})
                    AND binding.status IN ('ACTIVE','SUPERSEDED')
                  ORDER BY binding.binding_id""",
            ordered,
        ).fetchall()
        if len(rows) != len(ordered) or any(
            str(row["product_id"]) != product_id
            or str(row["source_product_id"]) != product_id
            or str(row["attempt_task_id"]) != str(row["source_task_id"])
            or str(row["attempt_status"]) not in {"completed", "repair_required"}
            or not str(row["result_ref"] or "")
            or not _SHA256.fullmatch(str(row["result_digest"] or ""))
            or not _SHA256.fullmatch(str(row["contract_digest"] or ""))
            or not _SHA256.fullmatch(str(row["policy_digest"] or ""))
            for row in rows
        ):
            raise ResultLineageIdentityError(
                "candidate snapshot contains a missing or cross-product binding"
            )
        digest = sha256_text(
            stable_json(
                {
                    "product_id": product_id,
                    "plan_id": plan_id,
                    "repository_commit": repository_commit,
                    "tree_digest": tree_digest,
                    "architecture_binding_id": architecture_binding_id,
                    "result_binding_ids": ordered,
                }
            )
        )
        snapshot_id = f"CS-{digest[:20].upper()}"
        now = created_at or utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO candidate_snapshots
               (snapshot_id, product_id, plan_id, repository_commit, tree_digest,
                architecture_binding_id, snapshot_digest, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'FROZEN', ?)""",
            (
                snapshot_id,
                product_id,
                plan_id,
                repository_commit,
                tree_digest,
                architecture_binding_id,
                digest,
                now,
            ),
        )
        for row in rows:
            self.connection.execute(
                """INSERT OR IGNORE INTO candidate_snapshot_items
                   (snapshot_id, semantic_node_id, binding_id)
                   VALUES (?, ?, ?)""",
                (snapshot_id, str(row["semantic_node_id"]), str(row["binding_id"])),
            )
        return snapshot_id

    def candidate_membership_bindings(
        self,
        *,
        product_id: str,
        plan_id: str,
    ) -> tuple[str, tuple[str, ...]]:
        """Return the authoritative architecture and implementation bindings.

        Plan Delta intentionally does not clone accepted tasks into each revision.
        Candidate construction must therefore read active ``BOUND`` memberships,
        never historical task rows or supersession edges.
        """

        rows = self.connection.execute(
            """SELECT node.lifecycle_stage, membership.binding_id
                 FROM plan_memberships AS membership
                 JOIN semantic_nodes AS node
                   ON node.semantic_node_id=membership.semantic_node_id
                 JOIN result_bindings AS binding
                   ON binding.binding_id=membership.binding_id
                WHERE membership.plan_id=?
                  AND membership.membership_state='BOUND'
                  AND membership.binding_id IS NOT NULL
                  AND membership.execution_task_id IS NULL
                  AND node.product_id=? AND node.status='ACTIVE'
                  AND binding.product_id=? AND binding.status='ACTIVE'
                  AND node.lifecycle_stage IN
                      ('architecture-review','implementation-slice')
                ORDER BY node.lifecycle_stage, node.semantic_node_key,
                         membership.binding_id""",
            (plan_id, product_id, product_id),
        ).fetchall()
        architecture = tuple(
            str(row["binding_id"])
            for row in rows
            if str(row["lifecycle_stage"]) == "architecture-review"
        )
        implementations = tuple(
            str(row["binding_id"])
            for row in rows
            if str(row["lifecycle_stage"]) == "implementation-slice"
        )
        if len(architecture) != 1 or not implementations:
            raise RuntimeError(
                "candidate snapshot memberships require exactly one active "
                "architecture binding and at least one implementation binding"
            )
        bindings = tuple(sorted({*architecture, *implementations}))
        return architecture[0], bindings

    def candidate_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        snapshot = self.connection.execute(
            "SELECT * FROM candidate_snapshots WHERE snapshot_id=? AND status='FROZEN'",
            (snapshot_id,),
        ).fetchone()
        if snapshot is None:
            raise KeyError(snapshot_id)
        rows = self.connection.execute(
            """SELECT item.semantic_node_id, item.binding_id,
                      binding.result_ref, binding.result_digest,
                      binding.output_schema, binding.contract_digest,
                      binding.policy_digest, binding.source_task_id,
                      binding.source_attempt_id, binding.product_id,
                      binding.status AS binding_status,
                      source.product_id AS source_product_id,
                      attempt.task_id AS attempt_task_id,
                      attempt.status AS attempt_status
                 FROM candidate_snapshot_items AS item
                 JOIN result_bindings AS binding
                   ON binding.binding_id=item.binding_id
                 JOIN tasks AS source
                   ON source.task_id=binding.source_task_id
                 JOIN attempts AS attempt
                   ON attempt.attempt_id=binding.source_attempt_id
                WHERE item.snapshot_id=?
                  AND binding.status IN ('ACTIVE','SUPERSEDED')
                ORDER BY item.semantic_node_id""",
            (snapshot_id,),
        ).fetchall()
        expected_items = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM candidate_snapshot_items WHERE snapshot_id=?",
                (snapshot_id,),
            ).fetchone()[0]
        )
        product_id = str(snapshot["product_id"])
        if len(rows) != expected_items or any(
            str(row["product_id"]) != product_id
            or str(row["source_product_id"]) != product_id
            or str(row["attempt_task_id"]) != str(row["source_task_id"])
            or str(row["attempt_status"]) not in {"completed", "repair_required"}
            or not str(row["result_ref"] or "")
            or not _SHA256.fullmatch(str(row["result_digest"] or ""))
            or not _SHA256.fullmatch(str(row["contract_digest"] or ""))
            or not _SHA256.fullmatch(str(row["policy_digest"] or ""))
            for row in rows
        ):
            raise ResultLineageIdentityError(
                "frozen candidate snapshot binding provenance conflicts"
            )
        binding_ids = tuple(sorted(str(row["binding_id"]) for row in rows))
        expected_digest = sha256_text(
            stable_json(
                {
                    "product_id": product_id,
                    "plan_id": str(snapshot["plan_id"]),
                    "repository_commit": str(snapshot["repository_commit"]),
                    "tree_digest": str(snapshot["tree_digest"]),
                    "architecture_binding_id": str(snapshot["architecture_binding_id"]),
                    "result_binding_ids": binding_ids,
                }
            )
        )
        if expected_digest != str(snapshot["snapshot_digest"]):
            raise ResultLineageIdentityError(
                "frozen candidate snapshot digest conflicts"
            )
        payload = dict(snapshot)
        payload["result_bindings"] = [
            {
                key: row[key]
                for key in (
                    "semantic_node_id",
                    "binding_id",
                    "result_ref",
                    "result_digest",
                    "output_schema",
                )
            }
            for row in rows
        ]
        payload["schema_version"] = "1.0"
        return payload

    def consume_budget(
        self,
        *,
        product_id: str,
        root_problem_signature: str,
        action_kind: str,
        progress: ProgressVector,
        evidence_digest: str | None = None,
    ) -> str:
        """Consume the exact bounded trajectory budget or terminate fail-safe."""

        if not _SHA256.fullmatch(root_problem_signature):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        if evidence_digest is not None and not _SHA256.fullmatch(evidence_digest):
            raise ValueError("evidence digest must be a lowercase SHA-256")
        now = utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO problem_budgets
               (product_id, root_problem_signature, deterministic_actions_used,
                arbiter_calls_used, execution_attempts_used,
                last_progress_vector_json, last_evidence_digest, status,
                created_at, updated_at)
               VALUES (?, ?, 0, 0, 0, ?, NULL, 'ACTIVE', ?, ?)""",
            (product_id, root_problem_signature, stable_json(progress.as_dict()), now, now),
        )
        row = self.connection.execute(
            """SELECT * FROM problem_budgets
                WHERE product_id=? AND root_problem_signature=?""",
            (product_id, root_problem_signature),
        ).fetchone()
        if row is None:
            raise RuntimeError("problem budget was not persisted")
        columns = {
            "deterministic": ("deterministic_actions_used", 1),
            "arbiter": ("arbiter_calls_used", 1),
            "execution": ("execution_attempts_used", 2),
        }
        if action_kind not in columns:
            raise ValueError("unsupported Path Governor budget action")
        column, maximum = columns[action_kind]
        used = int(row[column])
        previous_raw = json.loads(str(row["last_progress_vector_json"] or "{}"))
        previous = ProgressVector(
            *[int(previous_raw.get(key, 0)) for key in progress.as_dict()]
        )
        fresh_evidence = bool(evidence_digest and evidence_digest != row["last_evidence_digest"])
        if used >= maximum or (used > 0 and not progress.strictly_improves(previous) and not fresh_evidence):
            self.connection.execute(
                """UPDATE problem_budgets SET status='EXHAUSTED', updated_at=?
                    WHERE product_id=? AND root_problem_signature=?""",
                (now, product_id, root_problem_signature),
            )
            return "FAIL_SAFE"
        self.connection.execute(
            f"""UPDATE problem_budgets SET {column}={column}+1,
                       last_progress_vector_json=?, last_evidence_digest=?,
                       updated_at=?
                 WHERE product_id=? AND root_problem_signature=?""",
            (
                stable_json(progress.as_dict()),
                evidence_digest,
                now,
                product_id,
                root_problem_signature,
            ),
        )
        return "CONTINUE"

    def apply_controller_correction(
        self,
        *,
        product_id: str,
        root_problem_signature: str,
        progress: ProgressVector,
        evidence_digest: str,
    ) -> str:
        """Reopen one failed-safe path through its unused deterministic slot.

        This is deliberately narrower than ``consume_budget``.  It applies only
        to an existing exhausted row, requires fresh immutable controller
        evidence, and preserves every already-consumed arbiter/execution slot.
        The caller owns the transaction and must create only controller-governed
        recovery work carrying the same root signature.
        """

        if not _SHA256.fullmatch(root_problem_signature):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        if not _SHA256.fullmatch(evidence_digest):
            raise ValueError("controller correction evidence must be a lowercase SHA-256")
        row = self.connection.execute(
            """SELECT deterministic_actions_used, arbiter_calls_used,
                      execution_attempts_used, last_evidence_digest, status
                 FROM problem_budgets
                WHERE product_id=? AND root_problem_signature=?""",
            (product_id, root_problem_signature),
        ).fetchone()
        if row is None:
            raise KeyError(root_problem_signature)
        now = utc_now()
        if (
            str(row["status"]) != "EXHAUSTED"
            or int(row["deterministic_actions_used"]) >= 1
            or int(row["execution_attempts_used"]) >= 2
            or str(row["last_evidence_digest"] or "") == evidence_digest
        ):
            return "FAIL_SAFE"
        self.connection.execute(
            """UPDATE problem_budgets
                  SET deterministic_actions_used=deterministic_actions_used+1,
                      last_progress_vector_json=?, last_evidence_digest=?,
                      status='ACTIVE', updated_at=?
                WHERE product_id=? AND root_problem_signature=?""",
            (
                stable_json(progress.as_dict()),
                evidence_digest,
                now,
                product_id,
                root_problem_signature,
            ),
        )
        return "CONTINUE"

    def progress_vector(self, product_id: str) -> ProgressVector:
        """Build the durable, payload-free trajectory vector for one product."""

        product = self.connection.execute(
            "SELECT active_plan_id FROM products WHERE product_id=?",
            (product_id,),
        ).fetchone()
        if product is None:
            raise KeyError(product_id)
        plan_id = str(product[0] or "")
        unmet = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM plan_memberships
                    WHERE plan_id=? AND mandatory=1 AND membership_state!='BOUND'""",
                (plan_id,),
            ).fetchone()[0]
        )
        unaccepted = int(
            self.connection.execute(
                """SELECT COUNT(*)
                     FROM plan_memberships AS membership
                     JOIN tasks AS task
                       ON task.task_id=membership.execution_task_id
                    WHERE membership.plan_id=?
                      AND membership.membership_state='EXECUTION'
                      AND task.graph_status!='ACCEPTED'""",
                (plan_id,),
            ).fetchone()[0]
        )
        open_signatures = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM problem_budgets
                    WHERE product_id=? AND status='ACTIVE'""",
                (product_id,),
            ).fetchone()[0]
        )
        open_incidents = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM controller_incidents
                    WHERE product_id=? AND status='OPEN'""",
                (product_id,),
            ).fetchone()[0]
        )
        candidate_stage = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM tasks
                    WHERE product_id=? AND plan_id=?
                      AND lifecycle_stage='candidate-snapshot'""",
                (product_id, plan_id),
            ).fetchone()[0]
        )
        frozen_candidates = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM candidate_snapshots
                    WHERE product_id=? AND plan_id=? AND status='FROZEN'""",
                (product_id, plan_id),
            ).fetchone()[0]
        )
        missing_candidate = int(candidate_stage > 0 and frozen_candidates == 0)
        legacy_indirection = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM tasks
                    WHERE product_id=? AND plan_id=? AND graph_status='ACCEPTED'
                      AND result_binding_id IS NULL""",
                (product_id, plan_id),
            ).fetchone()[0]
        )
        no_progress = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM path_decisions
                    WHERE product_id=? AND status IN ('REJECTED','FAILED_SAFE')""",
                (product_id,),
            ).fetchone()[0]
        )
        return ProgressVector(
            unmet,
            open_signatures,
            unaccepted,
            open_incidents,
            missing_candidate,
            legacy_indirection,
            no_progress,
        )

    def path_snapshot_digest(
        self,
        *,
        product_id: str,
        root_problem_signature: str,
        progress: ProgressVector,
        evidence_digest: str | None = None,
    ) -> str:
        """Digest the typed state coordinates used for one trajectory decision."""

        product = self.connection.execute(
            """SELECT active_plan_id, active_plan_revision, status
                 FROM products WHERE product_id=?""",
            (product_id,),
        ).fetchone()
        if product is None:
            raise KeyError(product_id)
        return sha256_text(
            stable_json(
                {
                    "product_id": product_id,
                    "active_plan_id": str(product[0] or ""),
                    "active_plan_revision": int(product[1] or 0),
                    "product_status": str(product[2] or ""),
                    "root_problem_signature": root_problem_signature,
                    "progress_vector": progress.as_dict(),
                    "evidence_digest": evidence_digest,
                }
            )
        )

    def reserve_execution_slots(
        self,
        *,
        product_id: str,
        root_problem_signature: str,
        count: int,
        progress: ProgressVector,
    ) -> str:
        """Reserve at most two evidence-producing executions for a signature."""

        if count < 1:
            raise ValueError("execution reservation count must be positive")
        if not _SHA256.fullmatch(root_problem_signature):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        now = utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO problem_budgets
               (product_id, root_problem_signature, deterministic_actions_used,
                arbiter_calls_used, execution_attempts_used,
                last_progress_vector_json, last_evidence_digest, status,
                created_at, updated_at)
               VALUES (?, ?, 0, 0, 0, ?, NULL, 'ACTIVE', ?, ?)""",
            (product_id, root_problem_signature, stable_json(progress.as_dict()), now, now),
        )
        row = self.connection.execute(
            """SELECT execution_attempts_used, status FROM problem_budgets
                WHERE product_id=? AND root_problem_signature=?""",
            (product_id, root_problem_signature),
        ).fetchone()
        if row is None:
            raise RuntimeError("problem budget was not persisted")
        if str(row["status"]) != "ACTIVE" or 2 < int(
            row["execution_attempts_used"]
        ) + count:
            self.connection.execute(
                """UPDATE problem_budgets SET status='EXHAUSTED', updated_at=?
                    WHERE product_id=? AND root_problem_signature=?""",
                (now, product_id, root_problem_signature),
            )
            return "FAIL_SAFE"
        self.connection.execute(
            """UPDATE problem_budgets
                  SET execution_attempts_used=execution_attempts_used+?,
                      last_progress_vector_json=?, updated_at=?
                WHERE product_id=? AND root_problem_signature=?""",
            (
                count,
                stable_json(progress.as_dict()),
                now,
                product_id,
                root_problem_signature,
            ),
        )
        return "CONTINUE"

    def reserve_task_execution_once(
        self,
        *,
        task_id: str,
        root_problem_signature: str,
        progress: ProgressVector,
    ) -> str:
        """Reserve one real Builder execution, keyed by its plan membership."""

        if not _SHA256.fullmatch(root_problem_signature):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        task_row = self.connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task_row is None:
            raise KeyError(task_id)
        task = dict(task_row)
        if execution_slot_cost(task) == 0:
            return "CONTINUE"
        if str(task.get("root_problem_signature") or "") != root_problem_signature:
            raise PathDecisionError("execution reservation signature conflicts")
        plan_id = str(task.get("plan_id") or "")
        if not plan_id:
            raise PathDecisionError("execution reservation lacks a plan identity")
        existing = self.connection.execute(
            """SELECT semantic_node_id, membership_state
                 FROM plan_memberships
                WHERE plan_id=? AND execution_task_id=?""",
            (plan_id, task_id),
        ).fetchall()
        if existing:
            if len(existing) != 1 or str(existing[0]["membership_state"]) != "EXECUTION":
                raise PathDecisionError("execution reservation membership conflicts")
            return "CONTINUE"

        savepoint = "path_governor_task_execution_reservation"
        self.connection.execute(f"SAVEPOINT {savepoint}")
        try:
            now = utc_now()
            self.connection.execute(
                """INSERT OR IGNORE INTO problem_budgets
                   (product_id, root_problem_signature, deterministic_actions_used,
                    arbiter_calls_used, execution_attempts_used,
                    last_progress_vector_json, last_evidence_digest, status,
                    created_at, updated_at)
                   VALUES (?, ?, 0, 0, 0, ?, NULL, 'ACTIVE', ?, ?)""",
                (
                    str(task["product_id"]),
                    root_problem_signature,
                    stable_json(progress.as_dict()),
                    now,
                    now,
                ),
            )
            budget = self.connection.execute(
                """SELECT execution_attempts_used, status FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (str(task["product_id"]), root_problem_signature),
            ).fetchone()
            if budget is None:
                raise RuntimeError("problem budget was not persisted")
            if (
                str(budget["status"]) != "ACTIVE"
                or int(budget["execution_attempts_used"]) >= 2
            ):
                self.connection.execute(
                    """UPDATE problem_budgets SET status='EXHAUSTED', updated_at=?
                        WHERE product_id=? AND root_problem_signature=?""",
                    (now, str(task["product_id"]), root_problem_signature),
                )
                self.connection.execute(f"RELEASE {savepoint}")
                return "FAIL_SAFE"
            self.register_execution_membership(task_id)
            updated = self.connection.execute(
                """UPDATE problem_budgets
                      SET execution_attempts_used=execution_attempts_used+1,
                          last_progress_vector_json=?, updated_at=?
                    WHERE product_id=? AND root_problem_signature=?
                      AND status='ACTIVE' AND execution_attempts_used<2""",
                (
                    stable_json(progress.as_dict()),
                    now,
                    str(task["product_id"]),
                    root_problem_signature,
                ),
            ).rowcount
            if updated != 1:
                raise PathDecisionError("execution reservation changed concurrently")
            self.connection.execute(f"RELEASE {savepoint}")
            return "CONTINUE"
        except Exception:
            self.connection.execute(f"ROLLBACK TO {savepoint}")
            self.connection.execute(f"RELEASE {savepoint}")
            raise

    def reclaim_unused_execution_reservations(
        self,
        *,
        product_id: str,
        root_problem_signature: str,
    ) -> int:
        """Reclaim superseded implementation slots that never ran.

        The plan membership is the durable reservation identity.  Marking it
        reclaimed makes this operation idempotent without weakening the
        per-problem two-execution cap.  Attempted, accepted, active, or
        differently signed work is never eligible.
        """

        if not product_id:
            raise ValueError("reservation product identity is required")
        if not _SHA256.fullmatch(root_problem_signature):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        savepoint = "path_governor_unused_reservation_reclaim"
        self.connection.execute(f"SAVEPOINT {savepoint}")
        try:
            rows = self.connection.execute(
                """SELECT membership.plan_id AS membership_plan_id,
                          membership.semantic_node_id AS membership_node_id,
                          membership.execution_task_id AS task_id,
                          task.plan_id AS task_plan_id,
                          task.semantic_node_id AS task_node_id,
                          task.status AS task_status,
                          task.result_ref,
                          task.result_digest,
                          task.result_binding_id,
                          plan.status AS plan_status,
                          (SELECT COUNT(*) FROM attempts AS attempt
                            WHERE attempt.task_id=task.task_id) AS attempt_count
                     FROM plan_memberships AS membership
                     JOIN tasks AS task
                       ON task.task_id=membership.execution_task_id
                LEFT JOIN plans AS plan ON plan.plan_id=membership.plan_id
                    WHERE membership.membership_state='EXECUTION'
                      AND task.product_id=?
                      AND task.root_problem_signature=?
                      AND task.lifecycle_stage='implementation-slice'
                      AND task.graph_status='SUPERSEDED'
                    ORDER BY membership.plan_id, membership.semantic_node_id,
                             task.task_id""",
                (product_id, root_problem_signature),
            ).fetchall()
            reclaimable: list[tuple[str, str, str]] = []
            seen_tasks: set[str] = set()
            for row in rows:
                task_id = str(row["task_id"] or "")
                membership_plan_id = str(row["membership_plan_id"] or "")
                membership_node_id = str(row["membership_node_id"] or "")
                if (
                    not task_id
                    or task_id in seen_tasks
                    or membership_plan_id != str(row["task_plan_id"] or "")
                    or membership_node_id != str(row["task_node_id"] or "")
                    or not row["plan_status"]
                ):
                    raise PathDecisionError(
                        "unused execution reservation identity is ambiguous"
                    )
                seen_tasks.add(task_id)
                if (
                    str(row["plan_status"]) != "SUPERSEDED"
                    or str(row["task_status"] or "") != "DONE"
                    or row["result_ref"] is not None
                    or row["result_digest"] is not None
                    or row["result_binding_id"] is not None
                    or int(row["attempt_count"] or 0) != 0
                ):
                    continue
                reclaimable.append(
                    (membership_plan_id, membership_node_id, task_id)
                )
            if not reclaimable:
                self.connection.execute(f"RELEASE {savepoint}")
                return 0

            budget = self.connection.execute(
                """SELECT execution_attempts_used, status
                     FROM problem_budgets
                    WHERE product_id=? AND root_problem_signature=?""",
                (product_id, root_problem_signature),
            ).fetchone()
            count = len(reclaimable)
            if (
                budget is None
                or str(budget["status"]) != "ACTIVE"
                or int(budget["execution_attempts_used"]) < count
            ):
                raise PathDecisionError(
                    "unused execution reservation accounting is inconsistent"
                )
            for plan_id, node_id, task_id in reclaimable:
                updated = self.connection.execute(
                    """UPDATE plan_memberships
                          SET membership_state='RECLAIMED_UNUSED'
                        WHERE plan_id=? AND semantic_node_id=?
                          AND execution_task_id=?
                          AND membership_state='EXECUTION'""",
                    (plan_id, node_id, task_id),
                ).rowcount
                if updated != 1:
                    raise PathDecisionError(
                        "unused execution reservation changed during reclaim"
                    )
            updated_budget = self.connection.execute(
                """UPDATE problem_budgets
                      SET execution_attempts_used=execution_attempts_used-?,
                          updated_at=?
                    WHERE product_id=? AND root_problem_signature=?
                      AND status='ACTIVE' AND execution_attempts_used>=?""",
                (
                    count,
                    utc_now(),
                    product_id,
                    root_problem_signature,
                    count,
                ),
            ).rowcount
            if updated_budget != 1:
                raise PathDecisionError(
                    "unused execution reservation budget changed during reclaim"
                )
            self.connection.execute(f"RELEASE {savepoint}")
            return count
        except Exception:
            self.connection.execute(f"ROLLBACK TO {savepoint}")
            self.connection.execute(f"RELEASE {savepoint}")
            raise

    def record_decision(
        self,
        *,
        product_id: str,
        root_problem_signature: str | None,
        action: str,
        path_snapshot_digest: str,
        progress_before: ProgressVector,
        expected_progress_after: ProgressVector,
        evidence_digest: str | None = None,
        status: str = "APPLIED",
        max_history: int = 256,
    ) -> str:
        """Persist one idempotent append-only decision."""

        if max_history < 16:
            raise ValueError("Path Governor decision history bound is too small")
        if not _SHA256.fullmatch(path_snapshot_digest):
            raise ValueError("path snapshot digest must be a lowercase SHA-256")
        if root_problem_signature is not None and not _SHA256.fullmatch(
            root_problem_signature
        ):
            raise ValueError("root problem signature must be a lowercase SHA-256")
        if status not in {"PROPOSED", "APPLYING", "APPLIED", "REJECTED", "FAILED_SAFE"}:
            raise ValueError("Path Governor decision status is invalid")
        try:
            FailureAction(action)
        except ValueError as error:
            raise ValueError("Path Governor action is outside the closed catalog") from error
        if status == "APPLIED" and not expected_progress_after.strictly_improves(
            progress_before
        ) and evidence_digest is None:
            raise PathDecisionError(
                "applied decision must strictly improve progress or add fresh evidence"
            )
        payload = {
            "action": action,
            "root_problem_signature": root_problem_signature,
        }
        decision_seed = stable_json(
            [product_id, root_problem_signature, action, path_snapshot_digest]
        )
        decision_id = f"PD-{sha256_text(decision_seed)[:20].upper()}"
        now = utc_now()
        self.connection.execute(
            """INSERT OR IGNORE INTO path_decisions
               (decision_id, product_id, root_problem_signature, action, owner,
                path_snapshot_digest, decision_payload_json,
                progress_before_json, expected_progress_after_json,
                evidence_digest, status, created_at, applied_at)
               VALUES (?, ?, ?, ?, 'path-governor', ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                decision_id,
                product_id,
                root_problem_signature,
                action,
                path_snapshot_digest,
                stable_json(payload),
                stable_json(progress_before.as_dict()),
                stable_json(expected_progress_after.as_dict()),
                evidence_digest,
                status,
                now,
                now if status == "APPLIED" else None,
            ),
        )
        # Hot-state compaction is a separate explicit operation and requires a
        # WORM archive receipt enforced by the database trigger. Merely crossing
        # a row-count threshold can never erase forensic history.
        _ = max_history
        return decision_id
