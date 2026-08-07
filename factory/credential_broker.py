"""Operation-scoped GitHub credential broker for the isolated Candidate plane."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Final

from .common import redact_text, sha256_text, stable_json, utc_now


class CredentialBrokerError(RuntimeError):
    """A broker policy, credential, or adapter invariant failed."""


GITHUB_BROKER_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "identity.read",
        "repository.create_private",
        "repository.read",
        "branch.push",
        "pull_request.create",
        "pull_request.read",
        "checks.read",
        "review_threads.read",
        "pull_request.merge_or_close",
        "repository.archive_or_delete",
    }
)

CORE_TASK_BRANCH_PATTERN: Final[str] = (
    r"(?:codex|canary|chore|docs|feat|feature|fix|refactor|test)/"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,118}"
)


@dataclass(frozen=True)
class BrokerPolicy:
    owner: str
    repository_prefixes: tuple[str, ...] = ("hermes-canary-",)
    repository_names: tuple[str, ...] = ()
    workspace_roots: tuple[Path, ...] = ()
    allow_delete: bool = True
    allow_archive: bool = True
    allow_merge: bool = True
    allowed_operations: frozenset[str] = GITHUB_BROKER_OPERATIONS
    strict_merge_contract: bool = False
    base_branch: str = "main"
    task_branch_pattern: str = CORE_TASK_BRANCH_PATTERN
    required_checks: tuple[str, ...] = ()
    policy_digest: str | None = None

    def validate(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.owner):
            raise CredentialBrokerError("broker owner is invalid")
        if not self.repository_prefixes and not self.repository_names:
            raise CredentialBrokerError("broker repository allowlist is empty")
        if any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
            for value in self.repository_prefixes
        ):
            raise CredentialBrokerError("broker repository prefixes are invalid")
        if any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
            for value in self.repository_names
        ):
            raise CredentialBrokerError("broker repository names are invalid")
        if any(not root.is_absolute() for root in self.workspace_roots):
            raise CredentialBrokerError("broker workspace roots must be absolute")
        if not self.allowed_operations or not self.allowed_operations.issubset(
            GITHUB_BROKER_OPERATIONS
        ):
            raise CredentialBrokerError("broker operation allowlist is invalid")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", self.base_branch):
            raise CredentialBrokerError("broker base branch is invalid")
        try:
            re.compile(self.task_branch_pattern)
        except re.error as error:
            raise CredentialBrokerError("broker task branch policy is invalid") from error
        if any(
            not value or len(value) > 160 or "\n" in value
            for value in self.required_checks
        ):
            raise CredentialBrokerError("broker required checks are invalid")
        if self.strict_merge_contract:
            if not self.required_checks:
                raise CredentialBrokerError("strict broker requires status checks")
            if self.policy_digest is None or not re.fullmatch(
                r"[a-f0-9]{64}", self.policy_digest
            ):
                raise CredentialBrokerError("strict broker policy digest is invalid")


@dataclass(frozen=True)
class BrokerRequest:
    request_id: str
    operation: str
    owner: str
    repository: str
    payload: Mapping[str, Any]

    def digest(self) -> str:
        return sha256_text(
            stable_json(
                {
                    "request_id": self.request_id,
                    "operation": self.operation,
                    "owner": self.owner,
                    "repository": self.repository,
                    "payload": dict(self.payload),
                }
            )
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> BrokerRequest:
        if set(value) != {"request_id", "operation", "owner", "repository", "payload"}:
            raise CredentialBrokerError("broker request schema is invalid")
        payload = value["payload"]
        if not isinstance(payload, dict):
            raise CredentialBrokerError("broker request payload must be an object")
        return cls(
            request_id=str(value["request_id"]),
            operation=str(value["operation"]),
            owner=str(value["owner"]),
            repository=str(value["repository"]),
            payload=dict(payload),
        )


@dataclass(frozen=True)
class BrokerReceipt:
    request_id: str
    operation: str
    target_slug: str
    subject_identity: str
    result: str
    object_ids: tuple[str, ...]
    credential_epoch_id: str
    timestamp: str
    request_digest: str
    receipt_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "operation": self.operation,
            "target_slug": self.target_slug,
            "subject_identity": self.subject_identity,
            "result": self.result,
            "object_ids": list(self.object_ids),
            "credential_epoch_id": self.credential_epoch_id,
            "timestamp": self.timestamp,
            "request_digest": self.request_digest,
            "receipt_digest": self.receipt_digest,
        }


CommandRunner = Callable[[list[str], Mapping[str, str], Path | None], subprocess.CompletedProcess[str]]


def _default_runner(
    argv: list[str], environment: Mapping[str, str], cwd: Path | None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )


def _is_private_systemd_credential_view(path: Path, metadata: os.stat_result) -> bool:
    """Accept systemd's root-owned, ACL-scoped read-only credential projection."""

    raw_directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not raw_directory:
        return False
    directory = Path(raw_directory)
    try:
        if (
            not directory.is_absolute()
            or directory.is_symlink()
            or path.parent.resolve() != directory.resolve()
        ):
            return False
        directory_metadata = directory.stat()
    except OSError:
        return False
    return (
        stat.S_IMODE(metadata.st_mode) == 0o440
        and stat.S_IMODE(directory_metadata.st_mode) == 0o550
        and metadata.st_uid == directory_metadata.st_uid == 0
        and metadata.st_gid == directory_metadata.st_gid == 0
    )


class GitHubCredentialBroker:
    """Execute a closed set of GitHub operations without returning a token."""

    def __init__(
        self,
        *,
        policy: BrokerPolicy,
        credential_path: Path,
        receipt_root: Path,
        credential_epoch_id: str,
        command_runner: CommandRunner | None = None,
        askpass_path: Path = Path("/usr/libexec/hermes-github-askpass"),
    ) -> None:
        policy.validate()
        self.policy = policy
        self.credential_path = credential_path
        self.receipt_root = receipt_root
        self.credential_epoch_id = credential_epoch_id
        self.command_runner = command_runner or _default_runner
        self.askpass_path = askpass_path

    def _credential(self) -> str:
        path = self.credential_path
        if not path.is_file() or path.is_symlink():
            raise CredentialBrokerError("missing_candidate_github_credential")
        metadata = path.stat()
        if (
            os.name != "nt"
            and metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
            and not _is_private_systemd_credential_view(path, metadata)
        ):
            raise CredentialBrokerError("candidate_github_credential_permissions")
        value = path.read_text(encoding="utf-8").strip()
        if not value or "\n" in value or "\x00" in value:
            raise CredentialBrokerError("candidate_github_credential_invalid")
        return value

    def _validate_request(self, request: BrokerRequest) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,160}", request.request_id):
            raise CredentialBrokerError("broker request id is invalid")
        if request.operation not in self.policy.allowed_operations:
            raise CredentialBrokerError("broker operation is not allowlisted")
        if request.owner != self.policy.owner:
            raise CredentialBrokerError("broker owner is outside allowlist")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", request.repository):
            raise CredentialBrokerError("broker repository is invalid")
        if request.repository not in self.policy.repository_names and not any(
            request.repository.startswith(prefix) for prefix in self.policy.repository_prefixes
        ):
            raise CredentialBrokerError("broker repository is outside allowlist")
        visibility = str(request.payload.get("visibility") or "private")
        if request.operation == "repository.create_private" and visibility != "private":
            raise CredentialBrokerError("broker cannot create a public repository")
        action = str(request.payload.get("action") or "")
        if request.operation == "repository.archive_or_delete":
            if action == "delete" and not self.policy.allow_delete:
                raise CredentialBrokerError("repository deletion is denied by policy")
            if action == "archive" and not self.policy.allow_archive:
                raise CredentialBrokerError("repository archive is denied by policy")
            if action not in {"delete", "archive"}:
                raise CredentialBrokerError("repository cleanup action is invalid")
        if request.operation == "pull_request.merge_or_close":
            if action == "merge" and not self.policy.allow_merge:
                raise CredentialBrokerError("pull request merge is denied by policy")
            if action not in {"merge", "close"}:
                raise CredentialBrokerError("pull request terminal action is invalid")

    def _task_branch(self, value: object) -> str:
        branch = str(value or "")
        if (
            branch == self.policy.base_branch
            or ".." in branch
            or branch.startswith("/")
            or branch.endswith("/")
            or re.fullmatch(self.policy.task_branch_pattern, branch) is None
        ):
            raise CredentialBrokerError("broker task branch is outside policy")
        return branch

    def _workspace(self, request: BrokerRequest) -> Path:
        raw = str(request.payload.get("workspace") or "")
        if not raw:
            raise CredentialBrokerError("broker workspace is required")
        path = Path(raw).resolve()
        if not self.policy.workspace_roots or not any(
            path == root.resolve() or root.resolve() in path.parents
            for root in self.policy.workspace_roots
        ):
            raise CredentialBrokerError("broker workspace is outside allowlist")
        return path

    def _environment(self, credential: str) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/var/lib/hermes-factory-github-broker"),
            "LANG": "C.UTF-8",
            "GH_TOKEN": credential,
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "GIT_ASKPASS": str(self.askpass_path),
            "GIT_USERNAME": "x-access-token",
        }

    def _run(
        self,
        argv: list[str],
        *,
        environment: Mapping[str, str],
        cwd: Path | None = None,
    ) -> Any:
        try:
            result = self.command_runner(argv, environment, cwd)
        except (OSError, subprocess.SubprocessError) as error:
            raise CredentialBrokerError(
                f"broker adapter unavailable:{type(error).__name__}"
            ) from error
        if result.returncode != 0:
            safe, _ = redact_text((result.stdout + "\n" + result.stderr).strip())
            lowered = safe.lower()
            if "bad credentials" in lowered or "http 401" in lowered:
                raise CredentialBrokerError("candidate_github_credential_expired")
            workflow_write_denied = (
                "refusing to allow a personal access token to create or update workflow"
                in lowered
                and "workflow" in lowered
                and "scope" in lowered
            ) or (
                "not permitted to create or update workflow" in lowered
                and "workflows permission" in lowered
            )
            if workflow_write_denied:
                raise CredentialBrokerError(
                    "candidate_github_workflow_permission_denied"
                )
            if "http 403" in lowered or "resource not accessible" in lowered:
                raise CredentialBrokerError("candidate_github_operation_denied")
            raise CredentialBrokerError(
                f"broker adapter failed:{result.returncode}:{safe[:300]}"
            )
        output = result.stdout.strip()
        if not output:
            return {}
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {"text_digest": sha256_text(output)}

    @staticmethod
    def _object_ids(value: Any) -> tuple[str, ...]:
        if not isinstance(value, dict):
            return ()
        identifiers: list[str] = []
        for key in (
            "id",
            "node_id",
            "sha",
            "number",
            "full_name",
            "login",
            "state",
            "head_sha",
            "merge_sha",
            "merged",
        ):
            raw = value.get(key)
            if isinstance(raw, (str, int, bool)) and str(raw):
                identifiers.append(f"{key}:{raw}")
        extra = value.get("object_ids")
        if isinstance(extra, list):
            identifiers.extend(
                str(item)
                for item in extra
                if isinstance(item, str)
                and re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,240}", item)
            )
        return tuple(identifiers)

    def _pull_request(
        self,
        endpoint: str,
        number: int,
        environment: Mapping[str, str],
    ) -> dict[str, Any]:
        value = self._run(
            ["gh", "api", f"{endpoint}/pulls/{number}"],
            environment=environment,
        )
        if not isinstance(value, dict):
            raise CredentialBrokerError("pull request response is invalid")
        return value

    def _checks(
        self,
        endpoint: str,
        commit_sha: str,
        environment: Mapping[str, str],
    ) -> dict[str, Any]:
        checks = self._run(
            ["gh", "api", f"{endpoint}/commits/{commit_sha}/check-runs"],
            environment=environment,
        )
        combined = self._run(
            ["gh", "api", f"{endpoint}/commits/{commit_sha}/status"],
            environment=environment,
        )
        check_object_ids: list[str] = []
        if isinstance(checks, dict) and isinstance(checks.get("check_runs"), list):
            for item in checks["check_runs"]:
                if not isinstance(item, dict):
                    continue
                name = re.sub(
                    r"[^A-Za-z0-9_. /-]", "", str(item.get("name") or "")
                )[:120]
                state = str(
                    item.get("conclusion") or item.get("status") or "PENDING"
                ).upper()
                if name:
                    check_object_ids.append(f"check:{name}:{state}")
        if isinstance(combined, dict) and isinstance(combined.get("statuses"), list):
            for item in combined["statuses"]:
                if not isinstance(item, dict):
                    continue
                name = re.sub(
                    r"[^A-Za-z0-9_. /-]", "", str(item.get("context") or "")
                )[:120]
                state = str(item.get("state") or "PENDING").upper()
                if name:
                    check_object_ids.append(f"check:{name}:{state}")
        return {
            "sha": commit_sha,
            "check_runs_digest": sha256_text(stable_json(checks)),
            "combined_status": (
                str(combined.get("state") or "")
                if isinstance(combined, dict)
                else ""
            ),
            "object_ids": sorted(set(check_object_ids)),
        }

    def _review_threads(
        self,
        request: BrokerRequest,
        number: int,
        environment: Mapping[str, str],
    ) -> dict[str, Any]:
        query = (
            "query($owner:String!,$name:String!,$number:Int!){"
            "repository(owner:$owner,name:$name){pullRequest(number:$number){"
            "reviewThreads(first:100){nodes{isResolved}pageInfo{hasNextPage}}}}}"
        )
        value = self._run(
            [
                "gh",
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-F",
                f"owner={request.owner}",
                "-F",
                f"name={request.repository}",
                "-F",
                f"number={number}",
            ],
            environment=environment,
        )
        try:
            threads = value["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes = threads["nodes"]
            has_next_page = threads["pageInfo"]["hasNextPage"]
        except (KeyError, TypeError) as error:
            raise CredentialBrokerError("review thread response is invalid") from error
        if has_next_page is not False or not isinstance(nodes, list):
            raise CredentialBrokerError("review thread result is incomplete")
        if not all(isinstance(item, dict) for item in nodes):
            raise CredentialBrokerError("review thread response is invalid")
        unresolved = sum(item.get("isResolved") is not True for item in nodes)
        return {
            "number": number,
            "state": "threads_verified",
            "object_ids": [
                f"review_threads:{len(nodes)}",
                f"unresolved_threads:{unresolved}",
            ],
        }

    def _evidence_manifest(
        self,
        request: BrokerRequest,
        *,
        expected_head_sha: str,
        branch: str,
    ) -> str:
        workspace = self._workspace(request)
        raw_relative = str(request.payload.get("evidence_manifest") or "")
        relative = Path(raw_relative)
        if (
            not raw_relative
            or relative.is_absolute()
            or ".." in relative.parts
            or "\\" in raw_relative
        ):
            raise CredentialBrokerError("evidence manifest path is invalid")
        path = (workspace / relative).resolve()
        if workspace.resolve() not in path.parents or path.is_symlink() or not path.is_file():
            raise CredentialBrokerError("evidence manifest is outside workspace")
        encoded = path.read_bytes()
        if not encoded or len(encoded) > 1_048_576:
            raise CredentialBrokerError("evidence manifest size is invalid")
        actual_digest = sha256(encoded).hexdigest()
        supplied_digest = str(request.payload.get("evidence_manifest_digest") or "")
        if supplied_digest != actual_digest:
            raise CredentialBrokerError("evidence manifest digest differs")
        try:
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CredentialBrokerError("evidence manifest is invalid") from error
        if not isinstance(value, dict):
            raise CredentialBrokerError("evidence manifest is invalid")
        secret_scan = value.get("secret_scan")
        tests = value.get("tests")
        expected = {
            "repository": f"{request.owner}/{request.repository}",
            "base": self.policy.base_branch,
            "branch": branch,
            "head_sha": expected_head_sha,
            "policy_digest": self.policy.policy_digest,
        }
        if any(value.get(key) != expected_value for key, expected_value in expected.items()):
            raise CredentialBrokerError("evidence manifest target differs")
        if not isinstance(secret_scan, dict) or (
            secret_scan.get("status") != "PASS"
            or secret_scan.get("findings") != 0
            or secret_scan.get("head_sha") != expected_head_sha
        ):
            raise CredentialBrokerError("evidence manifest secret scan is not passing")
        if not isinstance(tests, dict) or tests.get("status") != "PASS":
            raise CredentialBrokerError("evidence manifest tests are not passing")
        return actual_digest

    def _delete_branch_after_merge(
        self,
        endpoint: str,
        branch: str,
        environment: Mapping[str, str],
    ) -> str:
        argv = ["gh", "api", "-X", "DELETE", f"{endpoint}/git/refs/heads/{branch}"]
        try:
            result = self.command_runner(argv, environment, None)
        except (OSError, subprocess.SubprocessError) as error:
            raise CredentialBrokerError("broker branch cleanup unavailable") from error
        if result.returncode == 0:
            return "deleted"
        safe, _ = redact_text((result.stdout + "\n" + result.stderr).strip())
        lowered = safe.lower()
        if "http 404" in lowered or (
            "http 422" in lowered and "reference does not exist" in lowered
        ):
            return "already_absent"
        raise CredentialBrokerError("broker post-merge branch cleanup failed")

    def _strict_merge(
        self,
        request: BrokerRequest,
        endpoint: str,
        number: int,
        environment: Mapping[str, str],
    ) -> dict[str, Any]:
        expected_head_sha = str(request.payload.get("expected_head_sha") or "")
        if not re.fullmatch(r"[a-f0-9]{40}", expected_head_sha):
            raise CredentialBrokerError("merge expected head SHA is invalid")
        if request.payload.get("merge_method") != "squash":
            raise CredentialBrokerError("merge method must be squash")
        if request.payload.get("policy_digest") != self.policy.policy_digest:
            raise CredentialBrokerError("merge policy digest differs")

        pull = self._pull_request(endpoint, number, environment)
        head = pull.get("head")
        base = pull.get("base")
        branch = self._task_branch(head.get("ref") if isinstance(head, dict) else "")
        if pull.get("state") != "open":
            raise CredentialBrokerError("merge pull request is not open")
        if pull.get("draft") is not False:
            raise CredentialBrokerError("merge pull request is draft")
        if not isinstance(base, dict) or base.get("ref") != self.policy.base_branch:
            raise CredentialBrokerError("merge pull request base differs")
        if not isinstance(head, dict) or head.get("sha") != expected_head_sha:
            raise CredentialBrokerError("merge pull request head differs")

        checks = self._checks(endpoint, expected_head_sha, environment)
        states: dict[str, str] = {}
        for item in checks["object_ids"]:
            if not item.startswith("check:"):
                continue
            name, separator, state = item.removeprefix("check:").rpartition(":")
            if separator:
                states[name] = state.upper()
        if any(states.get(name) != "SUCCESS" for name in self.policy.required_checks):
            raise CredentialBrokerError("merge required checks are not passing")

        threads = self._review_threads(request, number, environment)
        if "unresolved_threads:0" not in threads["object_ids"]:
            raise CredentialBrokerError("merge has unresolved review threads")
        manifest_digest = self._evidence_manifest(
            request,
            expected_head_sha=expected_head_sha,
            branch=branch,
        )

        result = self._run(
            [
                "gh",
                "api",
                "-X",
                "PUT",
                f"{endpoint}/pulls/{number}/merge",
                "-f",
                f"sha={expected_head_sha}",
                "-f",
                "merge_method=squash",
            ],
            environment=environment,
        )
        merge_sha = str(result.get("sha") or "") if isinstance(result, dict) else ""
        if (
            not isinstance(result, dict)
            or result.get("merged") is not True
            or not re.fullmatch(r"[a-f0-9]{40}", merge_sha)
        ):
            raise CredentialBrokerError("merge API did not confirm merge")

        live = self._pull_request(endpoint, number, environment)
        if (
            live.get("state") != "closed"
            or live.get("merged") is not True
            or live.get("merge_commit_sha") != merge_sha
        ):
            raise CredentialBrokerError("merge postcondition differs from live PR")
        commit = self._run(
            ["gh", "api", f"{endpoint}/commits/{merge_sha}"],
            environment=environment,
        )
        parents = commit.get("parents") if isinstance(commit, dict) else None
        if not isinstance(parents, list) or len(parents) != 1:
            raise CredentialBrokerError("squash commit is not single-parent")
        branch_state = self._delete_branch_after_merge(endpoint, branch, environment)
        return {
            "number": number,
            "state": "squash_merge_verified",
            "head_sha": expected_head_sha,
            "merge_sha": merge_sha,
            "merged": True,
            "object_ids": [
                f"branch:{branch}",
                f"branch_cleanup:{branch_state}",
                f"policy_digest:{self.policy.policy_digest}",
                f"evidence_manifest_digest:{manifest_digest}",
                "merge_method:squash",
                "parents:1",
                "unresolved_threads:0",
            ],
        }

    def _execute(self, request: BrokerRequest, environment: Mapping[str, str]) -> Any:
        slug = f"{request.owner}/{request.repository}"
        endpoint = f"repos/{slug}"
        operation = request.operation
        payload = request.payload
        if operation == "identity.read":
            return self._run(["gh", "api", "user"], environment=environment)
        if operation == "repository.create_private":
            return self._run(
                [
                    "gh",
                    "api",
                    "-X",
                    "POST",
                    "user/repos",
                    "-f",
                    f"name={request.repository}",
                    "-F",
                    "private=true",
                    "-f",
                    "auto_init=false",
                    "-F",
                    "has_issues=true",
                    "-F",
                    "has_projects=false",
                    "-F",
                    "has_wiki=false",
                    "-F",
                    "allow_merge_commit=true",
                    "-F",
                    "allow_squash_merge=true",
                    "-F",
                    "allow_rebase_merge=true",
                    "-F",
                    "delete_branch_on_merge=true",
                ],
                environment=environment,
            )
        if operation == "repository.read":
            query = str(payload.get("query") or "")
            if query == "configuration":
                repository = self._run(
                    ["gh", "api", endpoint],
                    environment=environment,
                )
                if not isinstance(repository, dict):
                    raise CredentialBrokerError(
                        "repository configuration response is invalid"
                    )
                expected = {
                    "private": True,
                    "has_issues": True,
                    "has_projects": False,
                    "has_wiki": False,
                    "delete_branch_on_merge": True,
                }
                if any(repository.get(key) is not value for key, value in expected.items()):
                    raise CredentialBrokerError(
                        "candidate_github_repository_configuration_unverified"
                    )
                if not any(
                    repository.get(key) is True
                    for key in (
                        "allow_merge_commit",
                        "allow_squash_merge",
                        "allow_rebase_merge",
                    )
                ):
                    raise CredentialBrokerError(
                        "candidate_github_repository_merge_method_unavailable"
                    )
                return {
                    "full_name": repository.get("full_name"),
                    "state": "configuration_verified",
                    "object_ids": [
                        "private:true",
                        "issues:true",
                        "projects:false",
                        "wiki:false",
                        "delete_branch_on_merge:true",
                        "merge_method:available",
                    ],
                }
            if query == "pull_request_for_head_sha":
                expected_sha = str(payload.get("sha") or "")
                if not re.fullmatch(r"[a-f0-9]{40}", expected_sha):
                    raise CredentialBrokerError("pull request head SHA is invalid")
                pulls = self._run(
                    ["gh", "api", f"{endpoint}/pulls?state=open&per_page=100"],
                    environment=environment,
                )
                if not isinstance(pulls, list):
                    raise CredentialBrokerError("pull request list is invalid")
                matches = [
                    item
                    for item in pulls
                    if isinstance(item, dict)
                    and isinstance(item.get("head"), dict)
                    and str(item["head"].get("sha") or "") == expected_sha
                ]
                if len(matches) != 1:
                    raise CredentialBrokerError("pull request head is not unique")
                return {
                    "number": matches[0].get("number"),
                    "head_sha": expected_sha,
                    "state": matches[0].get("state"),
                }
            if query == "pull_request":
                number = int(payload.get("number") or 0)
                if number < 1:
                    raise CredentialBrokerError("pull request number is invalid")
                pull = self._pull_request(endpoint, number, environment)
                head = pull.get("head")
                return {
                    "number": number,
                    "state": pull.get("state"),
                    "head_sha": head.get("sha") if isinstance(head, dict) else None,
                    "merge_sha": pull.get("merge_commit_sha"),
                    "merged": pull.get("merged"),
                }
            if query:
                raise CredentialBrokerError("repository read query is not allowlisted")
            workspace_raw = str(payload.get("workspace") or "")
            if not workspace_raw:
                return self._run(["gh", "api", endpoint], environment=environment)
            workspace = self._workspace(request)
            if workspace.exists() and any(workspace.iterdir()):
                raise CredentialBrokerError("broker clone destination is not empty")
            workspace.parent.mkdir(parents=True, exist_ok=True)
            return self._run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "clone",
                    "--no-tags",
                    f"https://github.com/{slug}.git",
                    str(workspace),
                ],
                environment=environment,
                cwd=workspace.parent,
            )
        if operation == "branch.push":
            workspace = self._workspace(request)
            branch = str(payload.get("branch") or "")
            if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or ".." in branch:
                raise CredentialBrokerError("broker branch is invalid")
            action = str(payload.get("action") or "push")
            if self.policy.strict_merge_contract:
                branch = self._task_branch(branch)
                if action not in {"push", "delete"}:
                    raise CredentialBrokerError("broker branch action is invalid")
                if action == "delete":
                    return self._run(
                        [
                            "git",
                            "-C",
                            str(workspace),
                            "-c",
                            "core.hooksPath=/dev/null",
                            "-c",
                            "protocol.file.allow=never",
                            "push",
                            "origin",
                            "--delete",
                            branch,
                        ],
                        environment=environment,
                    )
                return self._run(
                    [
                        "git",
                        "-C",
                        str(workspace),
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "protocol.file.allow=never",
                        "push",
                        "origin",
                        f"HEAD:refs/heads/{branch}",
                    ],
                    environment=environment,
                )
            return self._run(
                [
                    "git",
                    "-C",
                    str(workspace),
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "protocol.file.allow=never",
                    "push",
                    "--set-upstream",
                    "origin",
                    f"HEAD:refs/heads/{branch}",
                ],
                environment=environment,
            )
        if operation == "pull_request.create":
            head = str(payload.get("head") or "")
            base = str(payload.get("base") or self.policy.base_branch)
            if self.policy.strict_merge_contract:
                head = self._task_branch(head)
                if base != self.policy.base_branch:
                    raise CredentialBrokerError("pull request base is outside policy")
            return self._run(
                [
                    "gh",
                    "api",
                    "-X",
                    "POST",
                    f"{endpoint}/pulls",
                    "-f",
                    f"title={str(payload.get('title') or 'Hermes Candidate probe')[:120]}",
                    "-f",
                    f"head={head}",
                    "-f",
                    f"base={base}",
                    "-f",
                    "body=Operation-specific Hermes Q6.5 canary",
                ],
                environment=environment,
            )
        if operation == "pull_request.read":
            number = int(payload.get("number") or 0)
            if number < 1:
                raise CredentialBrokerError("pull request number is invalid")
            pull = self._pull_request(endpoint, number, environment)
            pull_head = pull.get("head")
            pull_base = pull.get("base")
            return {
                "number": number,
                "state": pull.get("state"),
                "head_sha": (
                    pull_head.get("sha") if isinstance(pull_head, dict) else None
                ),
                "merged": pull.get("merged"),
                "object_ids": [
                    f"base:{pull_base.get('ref') if isinstance(pull_base, dict) else ''}",
                    f"head_ref:{pull_head.get('ref') if isinstance(pull_head, dict) else ''}",
                    f"draft:{pull.get('draft')}",
                ],
            }
        if operation == "checks.read":
            sha = str(payload.get("sha") or "")
            if not re.fullmatch(r"[a-f0-9]{40}", sha):
                raise CredentialBrokerError("checks commit SHA is invalid")
            return self._checks(endpoint, sha, environment)
        if operation == "review_threads.read":
            number = int(payload.get("number") or 0)
            if number < 1:
                raise CredentialBrokerError("pull request number is invalid")
            return self._review_threads(request, number, environment)
        if operation == "pull_request.merge_or_close":
            number = int(payload.get("number") or 0)
            if number < 1:
                raise CredentialBrokerError("pull request number is invalid")
            action = str(payload["action"])
            if action == "merge":
                if self.policy.strict_merge_contract:
                    return self._strict_merge(request, endpoint, number, environment)
                return self._run(
                    ["gh", "api", "-X", "PUT", f"{endpoint}/pulls/{number}/merge"],
                    environment=environment,
                )
            return self._run(
                [
                    "gh",
                    "api",
                    "-X",
                    "PATCH",
                    f"{endpoint}/pulls/{number}",
                    "-f",
                    "state=closed",
                ],
                environment=environment,
            )
        if operation == "repository.archive_or_delete":
            if str(payload["action"]) == "delete":
                return self._run(
                    ["gh", "api", "-X", "DELETE", endpoint],
                    environment=environment,
                )
            return self._run(
                ["gh", "api", "-X", "PATCH", endpoint, "-F", "archived=true"],
                environment=environment,
            )
        raise CredentialBrokerError("broker operation implementation is missing")

    def execute(self, request: BrokerRequest) -> BrokerReceipt:
        self._validate_request(request)
        receipt_path = self.receipt_root / f"{request.request_id}.json"
        if receipt_path.is_file() and not receipt_path.is_symlink():
            value = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt = BrokerReceipt(
                request_id=str(value["request_id"]),
                operation=str(value["operation"]),
                target_slug=str(value["target_slug"]),
                subject_identity=str(value["subject_identity"]),
                result=str(value["result"]),
                object_ids=tuple(str(item) for item in value["object_ids"]),
                credential_epoch_id=str(value["credential_epoch_id"]),
                timestamp=str(value["timestamp"]),
                request_digest=str(value["request_digest"]),
                receipt_digest=str(value["receipt_digest"]),
            )
            if receipt.request_digest != request.digest():
                raise CredentialBrokerError("broker replay request conflicts")
            unsigned = receipt.as_dict()
            unsigned.pop("receipt_digest")
            if receipt.receipt_digest != sha256_text(stable_json(unsigned)):
                raise CredentialBrokerError("broker replay receipt digest differs")
            return receipt
        credential = self._credential()
        environment = self._environment(credential)
        identity = self._run(["gh", "api", "user"], environment=environment)
        login = str(identity.get("login") or "") if isinstance(identity, dict) else ""
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", login):
            raise CredentialBrokerError("broker GitHub identity is invalid")
        result = self._execute(request, environment)
        timestamp = utc_now()
        payload = {
            "request_id": request.request_id,
            "operation": request.operation,
            "target_slug": f"{request.owner}/{request.repository}",
            "subject_identity": login,
            "result": "PASS",
            "object_ids": list(self._object_ids(result)),
            "credential_epoch_id": self.credential_epoch_id,
            "timestamp": timestamp,
            "request_digest": request.digest(),
        }
        receipt = BrokerReceipt(
            request_id=request.request_id,
            operation=request.operation,
            target_slug=str(payload["target_slug"]),
            subject_identity=login,
            result="PASS",
            object_ids=tuple(str(value) for value in payload["object_ids"]),
            credential_epoch_id=self.credential_epoch_id,
            timestamp=timestamp,
            request_digest=request.digest(),
            receipt_digest=sha256_text(stable_json(payload)),
        )
        encoded = json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        if credential in encoded:
            raise CredentialBrokerError("credential exposure detected in receipt")
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        return receipt


class BrokerClient:
    def __init__(self, socket_path: Path, *, timeout_seconds: float = 30.0) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def execute(self, request: BrokerRequest) -> BrokerReceipt:
        encoded = stable_json(
            {
                "request_id": request.request_id,
                "operation": request.operation,
                "owner": request.owner,
                "repository": request.repository,
                "payload": dict(request.payload),
            }
        ).encode("utf-8") + b"\n"
        if len(encoded) > 65_536:
            raise CredentialBrokerError("broker request exceeds size limit")
        unix_family = getattr(socket, "AF_UNIX", None)
        if unix_family is None:
            raise CredentialBrokerError("Unix broker sockets are unavailable")
        with socket.socket(unix_family, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout_seconds)
            try:
                connection.connect(str(self.socket_path))
            except OSError as error:
                raise CredentialBrokerError("github_credential_broker_unavailable") from error
            connection.sendall(encoded)
            response = bytearray()
            while b"\n" not in response:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > 65_536:
                    raise CredentialBrokerError("broker response exceeds size limit")
        try:
            value = json.loads(bytes(response).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CredentialBrokerError("broker response is invalid") from error
        if not isinstance(value, dict) or value.get("status") != "PASS":
            reason = str(value.get("reason_code") or "broker_operation_failed")
            raise CredentialBrokerError(reason)
        receipt = value.get("receipt")
        if not isinstance(receipt, dict):
            raise CredentialBrokerError("broker receipt is missing")
        result = BrokerReceipt(
            request_id=str(receipt["request_id"]),
            operation=str(receipt["operation"]),
            target_slug=str(receipt["target_slug"]),
            subject_identity=str(receipt["subject_identity"]),
            result=str(receipt["result"]),
            object_ids=tuple(str(item) for item in receipt["object_ids"]),
            credential_epoch_id=str(receipt["credential_epoch_id"]),
            timestamp=str(receipt["timestamp"]),
            request_digest=str(receipt["request_digest"]),
            receipt_digest=str(receipt["receipt_digest"]),
        )
        if (
            result.request_id != request.request_id
            or result.operation != request.operation
            or result.target_slug != f"{request.owner}/{request.repository}"
            or result.request_digest != request.digest()
        ):
            raise CredentialBrokerError("broker receipt is not bound to request")
        unsigned = result.as_dict()
        unsigned.pop("receipt_digest")
        if result.receipt_digest != sha256_text(stable_json(unsigned)):
            raise CredentialBrokerError("broker receipt digest differs")
        return result


class BrokerServer:
    """Sequential Unix-socket server; systemd limits the caller group."""

    def __init__(
        self,
        *,
        socket_path: Path,
        broker: GitHubCredentialBroker,
        socket_mode: int = 0o660,
    ) -> None:
        self.socket_path = socket_path
        self.broker = broker
        self.socket_mode = socket_mode

    @staticmethod
    def _failure(reason_code: str) -> bytes:
        return stable_json({"status": "FAIL", "reason_code": reason_code}).encode(
            "utf-8"
        ) + b"\n"

    def _handle(self, payload: bytes) -> bytes:
        try:
            value = json.loads(payload.decode("utf-8"))
            if not isinstance(value, dict):
                raise CredentialBrokerError("broker request must be an object")
            request = BrokerRequest.from_dict(value)
            receipt = self.broker.execute(request)
        except (
            CredentialBrokerError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as error:
            reason = str(error).split(":", 1)[0]
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", reason):
                reason = "broker_operation_failed"
            return self._failure(reason)
        return stable_json({"status": "PASS", "receipt": receipt.as_dict()}).encode(
            "utf-8"
        ) + b"\n"

    def serve_forever(self) -> None:
        unix_family = getattr(socket, "AF_UNIX", None)
        if unix_family is None:
            raise CredentialBrokerError("Unix broker sockets are unavailable")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if not self.socket_path.is_socket():
                raise CredentialBrokerError("broker socket path conflicts")
            self.socket_path.unlink()
        with socket.socket(unix_family, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, self.socket_mode)
            listener.listen(16)
            while True:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(30)
                    request = bytearray()
                    while b"\n" not in request:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)
                        if len(request) > 65_536:
                            connection.sendall(self._failure("broker_request_too_large"))
                            break
                    else:
                        connection.sendall(self._handle(bytes(request).split(b"\n", 1)[0]))
