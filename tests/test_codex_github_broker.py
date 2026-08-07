from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from factory.credential_broker import (
    BrokerPolicy,
    BrokerRequest,
    CredentialBrokerError,
    GitHubCredentialBroker,
)

HEAD = "a" * 40
MERGE = "b" * 40
POLICY_DIGEST = "c" * 64
REQUIRED_CHECKS = (
    "factory/package-integrity",
    "factory/scope-guard",
    "factory/quality",
)
CORE_OPERATIONS = frozenset(
    {
        "identity.read",
        "repository.read",
        "branch.push",
        "pull_request.create",
        "pull_request.read",
        "checks.read",
        "review_threads.read",
        "pull_request.merge_or_close",
    }
)


class StrictRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.pull_reads = 0
        self.head = HEAD
        self.base = "main"
        self.draft = False
        self.check_states = {name: "success" for name in REQUIRED_CHECKS}
        self.unresolved = 0

    def __call__(
        self,
        argv: list[str],
        environment: Mapping[str, str],
        cwd: Path | None,
    ) -> subprocess.CompletedProcess[str]:
        del environment, cwd
        self.calls.append(argv)
        if argv == ["gh", "api", "user"]:
            value: Any = {"login": "brullik", "id": 1}
        elif argv[-1].endswith("/pulls/17") and "PUT" not in argv:
            self.pull_reads += 1
            value = {
                "number": 17,
                "state": "open" if self.pull_reads == 1 else "closed",
                "draft": self.draft,
                "head": {"sha": self.head, "ref": "codex/canary-commissioning"},
                "base": {"ref": self.base},
                "merged": self.pull_reads > 1,
                "merge_commit_sha": MERGE if self.pull_reads > 1 else None,
            }
        elif argv[-1].endswith(f"/commits/{HEAD}/check-runs"):
            value = {
                "check_runs": [
                    {"name": name, "conclusion": state}
                    for name, state in self.check_states.items()
                ]
            }
        elif argv[-1].endswith(f"/commits/{HEAD}/status"):
            value = {"state": "success", "statuses": []}
        elif "graphql" in argv:
            value = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {"isResolved": False}
                                    for _ in range(self.unresolved)
                                ],
                                "pageInfo": {"hasNextPage": False},
                            }
                        }
                    }
                }
            }
        elif "PUT" in argv and argv[-5].endswith("/pulls/17/merge"):
            value = {"merged": True, "sha": MERGE, "message": "merged"}
        elif argv[-1].endswith(f"/commits/{MERGE}"):
            value = {"sha": MERGE, "parents": [{"sha": "d" * 40}]}
        elif (
            "DELETE" in argv and "/git/refs/heads/" in argv[-1]
        ) or (argv and argv[0] == "git"):
            value = {}
        else:  # pragma: no cover - makes a new untyped command immediately visible
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")


def _broker(tmp_path: Path, runner: StrictRunner) -> GitHubCredentialBroker:
    credential = tmp_path / "github-token"
    credential.write_text("fixture-token-not-a-real-secret", encoding="utf-8")
    credential.chmod(0o600)
    return GitHubCredentialBroker(
        policy=BrokerPolicy(
            owner="brullik",
            repository_prefixes=(),
            repository_names=("hermes-software-factory",),
            workspace_roots=(tmp_path / "worktrees",),
            allow_delete=False,
            allow_archive=False,
            allowed_operations=CORE_OPERATIONS,
            strict_merge_contract=True,
            required_checks=REQUIRED_CHECKS,
            policy_digest=POLICY_DIGEST,
        ),
        credential_path=credential,
        receipt_root=tmp_path / "receipts",
        credential_epoch_id="CE-CODEX-1",
        command_runner=runner,
    )


def _merge_payload(tmp_path: Path) -> dict[str, object]:
    workspace = tmp_path / "worktrees" / "commissioning"
    workspace.mkdir(parents=True)
    manifest = workspace / "evidence-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "repository": "brullik/hermes-software-factory",
                "base": "main",
                "branch": "codex/canary-commissioning",
                "head_sha": HEAD,
                "policy_digest": POLICY_DIGEST,
                "secret_scan": {
                    "status": "PASS",
                    "findings": 0,
                    "head_sha": HEAD,
                },
                "tests": {"status": "PASS"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "number": 17,
        "action": "merge",
        "expected_head_sha": HEAD,
        "merge_method": "squash",
        "workspace": str(workspace),
        "evidence_manifest": manifest.name,
        "evidence_manifest_digest": sha256(manifest.read_bytes()).hexdigest(),
        "policy_digest": POLICY_DIGEST,
    }


def _merge_request(tmp_path: Path, request_id: str = "CODEX-MERGE-0001") -> BrokerRequest:
    return BrokerRequest(
        request_id=request_id,
        operation="pull_request.merge_or_close",
        owner="brullik",
        repository="hermes-software-factory",
        payload=_merge_payload(tmp_path),
    )


def test_strict_merge_binds_sha_squash_checks_threads_manifest_and_postconditions(
    tmp_path: Path,
) -> None:
    runner = StrictRunner()
    broker = _broker(tmp_path, runner)
    request = _merge_request(tmp_path)

    receipt = broker.execute(request)

    assert receipt.result == "PASS"
    assert f"head_sha:{HEAD}" in receipt.object_ids
    assert f"merge_sha:{MERGE}" in receipt.object_ids
    assert "merge_method:squash" in receipt.object_ids
    assert "parents:1" in receipt.object_ids
    merge_call = next(argv for argv in runner.calls if "PUT" in argv)
    assert f"sha={HEAD}" in merge_call
    assert "merge_method=squash" in merge_call
    first_call_count = len(runner.calls)
    assert broker.execute(request) == receipt
    assert len(runner.calls) == first_call_count

    changed = dict(request.payload)
    changed["expected_head_sha"] = "e" * 40
    with pytest.raises(CredentialBrokerError, match="replay request conflicts"):
        broker.execute(
            BrokerRequest(
                request_id=request.request_id,
                operation=request.operation,
                owner=request.owner,
                repository=request.repository,
                payload=changed,
            )
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("stale", "head differs"),
        ("wrong-base", "base differs"),
        ("draft", "is draft"),
        ("failed-check", "checks are not passing"),
        ("missing-check", "checks are not passing"),
        ("pending-check", "checks are not passing"),
        ("thread", "unresolved review threads"),
        ("method", "method must be squash"),
        ("policy", "policy digest differs"),
        ("manifest", "manifest digest differs"),
    ],
)
def test_strict_merge_rejects_negative_preconditions(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    runner = StrictRunner()
    broker = _broker(tmp_path, runner)
    request = _merge_request(tmp_path, f"CODEX-NEGATIVE-{mutation}")
    payload = dict(request.payload)
    if mutation == "stale":
        runner.head = "f" * 40
    elif mutation == "wrong-base":
        runner.base = "develop"
    elif mutation == "draft":
        runner.draft = True
    elif mutation == "failed-check":
        runner.check_states[REQUIRED_CHECKS[0]] = "failure"
    elif mutation == "missing-check":
        del runner.check_states[REQUIRED_CHECKS[0]]
    elif mutation == "pending-check":
        runner.check_states[REQUIRED_CHECKS[0]] = "in_progress"
    elif mutation == "thread":
        runner.unresolved = 1
    elif mutation == "method":
        payload["merge_method"] = "rebase"
    elif mutation == "policy":
        payload["policy_digest"] = "0" * 64
    elif mutation == "manifest":
        payload["evidence_manifest_digest"] = "0" * 64
    with pytest.raises(CredentialBrokerError, match=message):
        broker.execute(
            BrokerRequest(
                request_id=request.request_id,
                operation=request.operation,
                owner=request.owner,
                repository=request.repository,
                payload=payload,
            )
        )


def test_strict_merge_rejects_unreadable_manifest_without_mutation(
    tmp_path: Path,
) -> None:
    runner = StrictRunner()
    broker = _broker(tmp_path, runner)
    request = _merge_request(tmp_path, "CODEX-NEGATIVE-UNREADABLE-MANIFEST")
    workspace = Path(str(request.payload["workspace"]))
    manifest = workspace / str(request.payload["evidence_manifest"])
    manifest.chmod(0)

    with pytest.raises(CredentialBrokerError, match="manifest is unreadable"):
        broker.execute(request)

    assert not any("PUT" in argv for argv in runner.calls)


def test_core_policy_rejects_main_push_wrong_pr_and_unrelated_repository(
    tmp_path: Path,
) -> None:
    runner = StrictRunner()
    broker = _broker(tmp_path, runner)
    workspace = tmp_path / "worktrees" / "task"
    workspace.mkdir(parents=True)
    with pytest.raises(CredentialBrokerError, match="task branch"):
        broker.execute(
            BrokerRequest(
                request_id="CODEX-PUSH-MAIN-1",
                operation="branch.push",
                owner="brullik",
                repository="hermes-software-factory",
                payload={"workspace": str(workspace), "branch": "main"},
            )
        )
    with pytest.raises(CredentialBrokerError, match="base is outside policy"):
        broker.execute(
            BrokerRequest(
                request_id="CODEX-PR-BASE-1",
                operation="pull_request.create",
                owner="brullik",
                repository="hermes-software-factory",
                payload={"head": "codex/task", "base": "develop", "title": "x"},
            )
        )
    with pytest.raises(CredentialBrokerError, match="outside allowlist"):
        broker.execute(
            BrokerRequest(
                request_id="CODEX-REPO-DENY-1",
                operation="repository.read",
                owner="brullik",
                repository="unrelated-repository",
                payload={},
            )
        )
    with pytest.raises(CredentialBrokerError, match="operation is not allowlisted"):
        broker.execute(
            BrokerRequest(
                request_id="CODEX-DELETE-DENY-1",
                operation="repository.archive_or_delete",
                owner="brullik",
                repository="hermes-software-factory",
                payload={"action": "delete"},
            )
        )


def test_core_branch_push_and_delete_have_closed_arguments(tmp_path: Path) -> None:
    runner = StrictRunner()
    broker = _broker(tmp_path, runner)
    workspace = tmp_path / "worktrees" / "task"
    workspace.mkdir(parents=True)
    for ordinal, action in enumerate(("push", "delete"), start=1):
        broker.execute(
            BrokerRequest(
                request_id=f"CODEX-BRANCH-{ordinal}",
                operation="branch.push",
                owner="brullik",
                repository="hermes-software-factory",
                payload={
                    "workspace": str(workspace),
                    "branch": "codex/task",
                    "action": action,
                },
            )
        )
    git_calls = [argv for argv in runner.calls if argv and argv[0] == "git"]
    assert "HEAD:refs/heads/codex/task" in git_calls[0]
    assert "--set-upstream" not in git_calls[0]
    assert f"safe.directory={workspace}" in git_calls[0]
    assert git_calls[1][-2:] == ["--delete", "codex/task"]
    assert f"safe.directory={workspace}" in git_calls[1]


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        (
            "fatal: detected dubious ownership in repository",
            "broker_workspace_ownership_denied",
        ),
        (
            "error: unable to open loose object: Permission denied",
            "broker_workspace_permission_denied",
        ),
        ("fatal: bad object HEAD", "broker_workspace_object_unreadable"),
    ],
)
def test_broker_types_workspace_failures_without_returning_git_output(
    tmp_path: Path,
    stderr: str,
    reason: str,
) -> None:
    runner = StrictRunner()
    broker = _broker(tmp_path, runner)
    broker.command_runner = lambda argv, environment, cwd: subprocess.CompletedProcess(
        argv, 1, "", stderr
    )
    with pytest.raises(CredentialBrokerError, match=f"^{reason}$"):
        broker._run(["git", "push"], environment={})
