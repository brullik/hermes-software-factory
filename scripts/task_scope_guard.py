#!/usr/bin/env python3
"""Fail-closed merge-base guard for immutable Hermes Task Scope Contracts."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, overload

CONTRACT_PATH = ".hermes/task-scope-contract.json"
SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
BRANCH = re.compile(r"^(?:codex|agent)/[A-Za-z0-9][A-Za-z0-9._/-]{1,118}$")
REQUIRED_FIELDS = {
    "schema_version", "contract_id", "original_goal_digest", "product_id",
    "task_id", "branch", "trusted_base_sha", "allowed_paths",
    "forbidden_paths", "max_changed_files", "max_additions",
    "max_deletions", "rationale", "approved_by",
    "approval_evidence_ref", "approval_evidence_digest", "created_at",
    "expires_at", "parent_contract_digest", "contract_digest",
}


class ScopeViolation(RuntimeError):
    """The branch differs from its frozen, attested scope."""


@overload
def _git(repo: Path, *args: str, binary: Literal[False] = False) -> str: ...


@overload
def _git(repo: Path, *args: str, binary: Literal[True]) -> bytes: ...


def _git(repo: Path, *args: str, binary: bool = False) -> str | bytes:
    command = ["git", "-C", str(repo), *args]
    if binary:
        binary_result = subprocess.run(command, check=False, capture_output=True)
        if binary_result.returncode != 0:
            stderr = binary_result.stderr.decode("utf-8", errors="replace")
            raise ScopeViolation(f"git probe failed: {args[0]}: {stderr.strip()[:300]}")
        return binary_result.stdout
    text_result = subprocess.run(
        command, check=False, capture_output=True, text=True, encoding="utf-8"
    )
    if text_result.returncode != 0:
        raise ScopeViolation(
            f"git probe failed: {args[0]}: {text_result.stderr.strip()[:300]}"
        )
    return text_result.stdout


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "contract_digest"}
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ScopeViolation(f"{field} must be a date-time string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ScopeViolation(f"{field} is not a valid date-time") from error
    if parsed.tzinfo is None:
        raise ScopeViolation(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        return path == prefix or path.startswith(prefix + "/")
    if any(marker in pattern for marker in "*?["):
        return fnmatch.fnmatchcase(path, pattern)
    return path == pattern


def _validate_contract(
    contract: Any,
    *,
    merge_base: str,
    branch: str,
    original_goal_digest: str,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(contract, dict) or set(contract) != REQUIRED_FIELDS:
        raise ScopeViolation("contract fields differ from schema")
    if contract["schema_version"] != "1.0":
        raise ScopeViolation("unsupported contract schema")
    for key in ("contract_id", "product_id", "task_id", "rationale"):
        if not isinstance(contract[key], str) or not contract[key]:
            raise ScopeViolation(f"{key} is empty")
    if len(contract["rationale"]) < 20:
        raise ScopeViolation("rationale is too short")
    if not isinstance(contract["branch"], str) or BRANCH.fullmatch(contract["branch"]) is None:
        raise ScopeViolation("contract branch is invalid")
    if branch != contract["branch"]:
        raise ScopeViolation("runtime branch differs from frozen contract")
    if not isinstance(contract["trusted_base_sha"], str) or SHA40.fullmatch(
        contract["trusted_base_sha"]
    ) is None:
        raise ScopeViolation("trusted base SHA is invalid")
    if merge_base != contract["trusted_base_sha"]:
        raise ScopeViolation("real merge-base differs from frozen trusted base")
    if (
        contract["original_goal_digest"] != original_goal_digest
        or SHA256.fullmatch(str(contract["original_goal_digest"])) is None
    ):
        raise ScopeViolation("original goal lineage differs")
    for key in ("allowed_paths", "forbidden_paths"):
        paths = contract[key]
        if not isinstance(paths, list) or (key == "allowed_paths" and not paths):
            raise ScopeViolation(f"{key} is invalid")
        if len(paths) != len(set(paths)) or not all(
            isinstance(path, str) and 0 < len(path) <= 240 for path in paths
        ):
            raise ScopeViolation(f"{key} contains invalid or duplicate paths")
    for key, maximum in (
        ("max_changed_files", 100),
        ("max_additions", 20000),
        ("max_deletions", 20000),
    ):
        value = contract[key]
        minimum = 1 if key == "max_changed_files" else 0
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ScopeViolation(f"{key} is invalid")
    if contract["approved_by"] not in {"desktop-bootstrap", "hermes-path-arbiter"}:
        raise ScopeViolation("approver is not trusted")
    evidence_digest = contract["approval_evidence_digest"]
    if not isinstance(evidence_digest, str) or SHA256.fullmatch(evidence_digest) is None:
        raise ScopeViolation("approval evidence digest is invalid")
    evidence_ref = contract["approval_evidence_ref"]
    if not isinstance(evidence_ref, str) or not evidence_ref.endswith("/" + evidence_digest):
        raise ScopeViolation("approval evidence reference is not digest-bound")
    parent = contract["parent_contract_digest"]
    if parent is not None and (not isinstance(parent, str) or SHA256.fullmatch(parent) is None):
        raise ScopeViolation("parent contract digest is invalid")
    digest = contract["contract_digest"]
    if not isinstance(digest, str) or digest != _canonical_digest(contract):
        raise ScopeViolation("contract digest differs")
    created = _timestamp(contract["created_at"], "created_at")
    expires = _timestamp(contract["expires_at"], "expires_at")
    if expires <= created or now > expires:
        raise ScopeViolation("contract is expired or has an invalid validity window")
    return contract


def evaluate(
    repo: Path,
    *,
    base_ref: str,
    head_ref: str,
    branch: str,
    original_goal_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    merge_base = str(_git(repo, "merge-base", base_ref, head_ref)).strip()
    if SHA40.fullmatch(merge_base) is None:
        raise ScopeViolation("merge-base is not a commit SHA")
    _git(repo, "merge-base", "--is-ancestor", merge_base, head_ref)
    commits = str(
        _git(repo, "rev-list", "--ancestry-path", "--reverse", f"{merge_base}..{head_ref}")
    ).splitlines()
    if not commits:
        raise ScopeViolation("branch has no commits after merge-base")
    first_commit = commits[0].strip()
    first_paths = [
        path
        for path in str(
            _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", first_commit)
        ).splitlines()
        if path
    ]
    if first_paths != [CONTRACT_PATH]:
        raise ScopeViolation("first branch commit must contain only the scope contract")
    first_bytes = _git(repo, "show", f"{first_commit}:{CONTRACT_PATH}", binary=True)
    head_bytes = _git(repo, "show", f"{head_ref}:{CONTRACT_PATH}", binary=True)
    if first_bytes != head_bytes:
        raise ScopeViolation("frozen scope contract was modified after the first commit")
    try:
        contract_value = json.loads(first_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScopeViolation("scope contract is not valid UTF-8 JSON") from error
    contract = _validate_contract(
        contract_value,
        merge_base=merge_base,
        branch=branch,
        original_goal_digest=original_goal_digest,
        now=now or datetime.now(UTC),
    )
    status_lines = str(
        _git(repo, "diff", "--name-status", "--find-renames", merge_base, head_ref)
    ).splitlines()
    changed_paths: list[str] = []
    for line in status_lines:
        parts = line.split("\t")
        if not parts:
            continue
        if parts[0].startswith(("R", "C")):
            raise ScopeViolation("renames and copies are outside bounded scope")
        if len(parts) != 2:
            raise ScopeViolation("unparseable changed path")
        changed_paths.append(parts[1])
    if len(changed_paths) != len(set(changed_paths)):
        raise ScopeViolation("changed path cardinality is ambiguous")
    if len(changed_paths) > contract["max_changed_files"]:
        raise ScopeViolation("changed file budget exceeded")
    for path in changed_paths:
        if any(_path_matches(path, pattern) for pattern in contract["forbidden_paths"]):
            raise ScopeViolation(f"forbidden path changed: {path}")
        if not any(_path_matches(path, pattern) for pattern in contract["allowed_paths"]):
            raise ScopeViolation(
                f"path outside frozen scope: {path}; expansion requires a separate attestation"
            )
    additions = 0
    deletions = 0
    for line in str(_git(repo, "diff", "--numstat", merge_base, head_ref)).splitlines():
        added, removed, _path = line.split("\t", 2)
        if added == "-" or removed == "-":
            raise ScopeViolation("binary changes are outside bounded line budgets")
        additions += int(added)
        deletions += int(removed)
    if additions > contract["max_additions"]:
        raise ScopeViolation("addition budget exceeded")
    if deletions > contract["max_deletions"]:
        raise ScopeViolation("deletion budget exceeded")
    _git(repo, "diff", "--check", merge_base, head_ref)
    return {
        "status": "PASS",
        "branch": branch,
        "merge_base": merge_base,
        "head": str(_git(repo, "rev-parse", head_ref)).strip(),
        "first_contract_commit": first_commit,
        "contract_digest": contract["contract_digest"],
        "changed_files": len(changed_paths),
        "additions": additions,
        "deletions": deletions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument("--branch", required=True)
    parser.add_argument("--original-goal-digest", required=True)
    args = parser.parse_args()
    try:
        report = evaluate(
            args.repository,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            branch=args.branch,
            original_goal_digest=args.original_goal_digest,
        )
    except ScopeViolation as error:
        print(json.dumps({"status": "FAIL", "reason": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
