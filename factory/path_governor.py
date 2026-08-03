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
from typing import Any

from .common import sha256_text, stable_json, utc_now

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


class PathDecisionError(RuntimeError):
    """A proposed trajectory violates the controller progress contract."""


def failure_owner(*, failure_class: str, reason_code: str) -> str:
    """Classify ownership before any repair role or plan is selected."""

    if failure_class in {"controller", "transient"} or reason_code.startswith(
        ("controller_", "migration_", "artifact_", "repair_requeue_")
    ):
        return "controller"
    if reason_code in {
        "missing_credential",
        "oauth_device_code",
        "two_factor_authentication",
        "captcha",
        "external_account_creation",
        "paid_resource_purchase",
        "dns_action_without_access",
        "legal_decision",
        "unapproved_irreversible_production_action",
    }:
        return "external"
    return "product"


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
            "REPAIR_NODE",
            "REPLAN_DELTA",
            "CONTROLLER_RECOVERY",
            "COMPACT_LINEAGE",
            "FAIL_SAFE",
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
        before = tuple(previous.as_dict().values())
        after = tuple(self.as_dict().values())
        return all(new <= old for old, new in zip(before, after, strict=True)) and any(
            new < old for old, new in zip(before, after, strict=True)
        )


def stable_root_problem_signature(values: Mapping[str, Any]) -> str:
    """Hash semantic coordinates while excluding volatile attempt prose/ids."""

    coordinates = {
        "product_id": str(values.get("product_id") or ""),
        "failure_class": str(values.get("failure_class") or ""),
        "reason_code": str(values.get("reason_code") or ""),
        "semantic_node_key": str(values.get("semantic_node_key") or ""),
        "lifecycle_stage": str(values.get("lifecycle_stage") or ""),
        "failed_gate_ids": sorted(
            {str(value) for value in values.get("failed_gate_ids", ())}
        ),
        "required_paths": sorted(
            {str(value) for value in values.get("required_paths", ())}
        ),
    }
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
    return tuple(
        str(task.get(field) or "")
        for field in (
            "product_id",
            "role",
            "output_schema",
            "lifecycle_stage",
            "review_kind",
            "evidence_profile",
            "semantic_node_key",
        )
    )


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
                    if _identity(replacement) != _identity(current):
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
                or _identity(current) != _identity(predecessor)
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
            or _identity(task) != _identity(source)
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
        existing = self.connection.execute(
            """SELECT * FROM result_bindings
                 WHERE product_id=? AND semantic_node_id=? AND status='ACTIVE'""",
            (str(task["product_id"]), node_id),
        ).fetchone()
        if existing is None:
            raise RuntimeError("active result binding was not persisted")
        binding = ResultBinding.from_row(existing)
        if (
            binding.binding_id != binding_id
            or binding.result_ref != result_ref
            or binding.result_digest != result_digest
            or binding.source_task_id != source_task_id
            or binding.source_attempt_id != source_attempt_id
        ):
            raise ResultLineageIdentityError(
                f"immutable accepted-result binding conflicts for {task_id}"
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
        contract = str(
            task_contract_digest(task)
            if identity_rescoped
            else task.get("contract_digest") or task_contract_digest(task)
        )
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
            f"""SELECT binding_id, semantic_node_id, product_id
                  FROM result_bindings
                 WHERE binding_id IN ({placeholders}) AND status='ACTIVE'
                 ORDER BY binding_id""",
            ordered,
        ).fetchall()
        if len(rows) != len(ordered) or any(
            str(row["product_id"]) != product_id for row in rows
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
                      binding.output_schema
                 FROM candidate_snapshot_items AS item
                 JOIN result_bindings AS binding
                   ON binding.binding_id=item.binding_id
                WHERE item.snapshot_id=? AND binding.status='ACTIVE'
                ORDER BY item.semantic_node_id""",
            (snapshot_id,),
        ).fetchall()
        payload = dict(snapshot)
        payload["result_bindings"] = [dict(row) for row in rows]
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
        """Persist an idempotent decision and compact old terminal history."""

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
        self.connection.execute(
            """DELETE FROM path_decisions
                WHERE decision_id IN (
                    SELECT decision_id FROM path_decisions
                     WHERE product_id=?
                       AND status IN ('APPLIED','REJECTED','FAILED_SAFE')
                     ORDER BY created_at DESC, decision_id DESC
                     LIMIT -1 OFFSET ?
                )""",
            (product_id, max_history),
        )
        return decision_id
