"""Typed, replay-safe boundary for deploying one governed Candidate commit."""

from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from factory.common import redact_text, sha256_text, stable_json, utc_now

CANONICAL_REPOSITORY = "brullik/hermes-software-factory"
CANONICAL_REMOTE = "https://github.com/brullik/hermes-software-factory.git"
DEPLOY_OPERATION = "candidate.deploy"
PREPARE_SCRIPT = "scripts/bootstrap/prepare-candidate-plane.sh"

_SHA = re.compile(r"[a-f0-9]{40}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,179}\Z")
_REQUEST_FIELDS = {
    "schema_version",
    "request_id",
    "operation",
    "repository",
    "commit_sha",
    "tree_sha",
    "merge_receipt_id",
    "merge_receipt_digest",
}
_MERGE_RECEIPT_FIELDS = {
    "credential_epoch_id",
    "object_ids",
    "operation",
    "receipt_digest",
    "request_digest",
    "request_id",
    "result",
    "subject_identity",
    "target_slug",
    "timestamp",
}
_MERGE_OBJECT_KEYS = {
    "number",
    "state",
    "head_sha",
    "merge_sha",
    "merged",
    "branch",
    "branch_cleanup",
    "policy_digest",
    "evidence_manifest_digest",
    "merge_method",
    "parents",
    "unresolved_threads",
}
_RESULT_FIELDS = {
    "schema_version",
    "request_id",
    "request_digest",
    "operation",
    "repository",
    "commit_sha",
    "tree_sha",
    "merge_receipt_id",
    "merge_receipt_digest",
    "result",
    "exit_code",
    "started_at",
    "completed_at",
    "stdout_digest",
    "stderr_digest",
    "stdout_tail",
    "stderr_tail",
    "redactions",
    "receipt_digest",
}


class CandidateDeploymentError(RuntimeError):
    """A fail-closed, secret-free typed rejection."""

    def __init__(self, reason_code: str) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_]{2,95}", reason_code) is None:
            reason_code = "candidate_deployment_rejected"
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class CandidateDeploymentRequest:
    schema_version: str
    request_id: str
    operation: str
    repository: str
    commit_sha: str
    tree_sha: str
    merge_receipt_id: str
    merge_receipt_digest: str

    @classmethod
    def from_mapping(cls, value: object) -> CandidateDeploymentRequest:
        if not isinstance(value, dict) or set(value) != _REQUEST_FIELDS:
            raise CandidateDeploymentError("deployment_request_fields_differ")
        if not all(isinstance(value[field], str) for field in _REQUEST_FIELDS):
            raise CandidateDeploymentError("deployment_request_types_invalid")
        request = cls(
            schema_version=value["schema_version"],
            request_id=value["request_id"],
            operation=value["operation"],
            repository=value["repository"],
            commit_sha=value["commit_sha"],
            tree_sha=value["tree_sha"],
            merge_receipt_id=value["merge_receipt_id"],
            merge_receipt_digest=value["merge_receipt_digest"],
        )
        if request.schema_version != "1.0":
            raise CandidateDeploymentError("deployment_request_schema_invalid")
        if _REQUEST_ID.fullmatch(request.request_id) is None:
            raise CandidateDeploymentError("deployment_request_id_invalid")
        if request.operation != DEPLOY_OPERATION:
            raise CandidateDeploymentError("deployment_operation_not_allowed")
        if request.repository != CANONICAL_REPOSITORY:
            raise CandidateDeploymentError("deployment_repository_not_allowed")
        if _SHA.fullmatch(request.commit_sha) is None:
            raise CandidateDeploymentError("deployment_commit_invalid")
        if _SHA.fullmatch(request.tree_sha) is None:
            raise CandidateDeploymentError("deployment_tree_invalid")
        if _REQUEST_ID.fullmatch(request.merge_receipt_id) is None:
            raise CandidateDeploymentError("merge_receipt_id_invalid")
        if _SHA256.fullmatch(request.merge_receipt_digest) is None:
            raise CandidateDeploymentError("merge_receipt_digest_invalid")
        return request

    def digest(self) -> str:
        return cast(str, sha256_text(stable_json(asdict(self))))


GitRunner = Callable[[list[str], Mapping[str, str], Path], subprocess.CompletedProcess[str]]
PrepareRunner = Callable[
    [list[str], Mapping[str, str], Path, float], subprocess.CompletedProcess[str]
]


def _default_git_runner(
    argv: list[str], environment: Mapping[str, str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300.0,
    )


def _default_prepare_runner(
    argv: list[str],
    environment: Mapping[str, str],
    cwd: Path,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=dict(environment),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    """Return Linux PID/UID/GID peer credentials for one connected Unix socket."""

    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise CandidateDeploymentError("peer_credentials_unavailable")
    encoded = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
    return struct.unpack("3i", encoded)


def require_exact_peer(
    connection: socket.socket, *, allowed_uid: int, allowed_gid: int
) -> tuple[int, int, int]:
    """Accept only the one commissioned requester identity."""

    identity = peer_credentials(connection)
    _pid, uid, gid = identity
    if uid != allowed_uid or gid != allowed_gid:
        raise CandidateDeploymentError("deployment_peer_not_allowed")
    return identity


class CandidateDeploymentBroker:
    """Validate one exact main merge and invoke only the Candidate bootstrap."""

    def __init__(
        self,
        *,
        source_root: Path,
        state_root: Path,
        merge_receipt_root: Path,
        expected_source_uid: int = 0,
        expected_merge_receipt_uid: int,
        expected_remote_url: str = CANONICAL_REMOTE,
        git_runner: GitRunner = _default_git_runner,
        prepare_runner: PrepareRunner = _default_prepare_runner,
        prepare_timeout_seconds: float = 21_600.0,
    ) -> None:
        self.state_root = state_root.resolve()
        self.source_root = source_root.resolve()
        self.merge_receipt_root = merge_receipt_root.resolve()
        if self.source_root != self.state_root / "source":
            raise CandidateDeploymentError("deployment_source_root_not_fixed")
        self.expected_source_uid = expected_source_uid
        self.expected_merge_receipt_uid = expected_merge_receipt_uid
        self.expected_remote_url = expected_remote_url
        self.git_runner = git_runner
        self.prepare_runner = prepare_runner
        self.prepare_timeout_seconds = prepare_timeout_seconds
        self.result_root = self.state_root / "receipts"
        self.intent_root = self.state_root / "intents"
        self.commit_guard_root = self.state_root / "commit-guards"
        self.lock_path = self.state_root / "deployment.lock"

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "GIT_ASKPASS": "/bin/false",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/root",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    @staticmethod
    def _ensure_directory(path: Path, uid: int, mode: int = 0o700) -> None:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_uid != uid
            or metadata.st_mode & 0o022
        ):
            raise CandidateDeploymentError("deployment_private_directory_invalid")
        os.chmod(path, mode)

    @staticmethod
    def _write_immutable(path: Path, value: Mapping[str, object]) -> None:
        encoded = (stable_json(value) + "\n").encode("utf-8")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _read_immutable_json(path: Path, *, expected_uid: int) -> dict[str, Any]:
        try:
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
        except OSError as error:
            raise CandidateDeploymentError("immutable_receipt_unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_mode & 0o222
                or metadata.st_nlink != 1
                or not 1 <= metadata.st_size <= 1_048_576
            ):
                raise CandidateDeploymentError("immutable_receipt_metadata_invalid")
            chunks: list[bytes] = []
            remaining = metadata.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            encoded = b"".join(chunks)
            if len(encoded) != metadata.st_size:
                raise CandidateDeploymentError("immutable_receipt_read_incomplete")
        finally:
            os.close(descriptor)
        try:
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CandidateDeploymentError("immutable_receipt_json_invalid") from error
        if not isinstance(value, dict):
            raise CandidateDeploymentError("immutable_receipt_json_invalid")
        return value

    def _prepare_state(self) -> None:
        self._ensure_directory(self.state_root, self.expected_source_uid)
        for path in (self.result_root, self.intent_root, self.commit_guard_root):
            self._ensure_directory(path, self.expected_source_uid)

    def _git(self, *arguments: str, allow_not_found: bool = False) -> str:
        prefix = [
            "git",
            "-c",
            f"safe.directory={self.source_root}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.file.allow=never",
            "-C",
            str(self.source_root),
        ]
        try:
            result = self.git_runner(
                [*prefix, *arguments], self._environment(), self.source_root
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CandidateDeploymentError("deployment_git_probe_failed") from error
        if result.returncode != 0:
            if allow_not_found and result.returncode == 1:
                return ""
            raise CandidateDeploymentError("deployment_git_probe_failed")
        return result.stdout.strip()

    def _validate_source_checkout(self) -> None:
        for path in (self.source_root, self.source_root / ".git"):
            try:
                metadata = path.lstat()
            except OSError as error:
                raise CandidateDeploymentError("source_checkout_unavailable") from error
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or path.is_symlink()
                or metadata.st_uid != self.expected_source_uid
                or metadata.st_mode & 0o022
            ):
                raise CandidateDeploymentError("source_checkout_ownership_invalid")
        if self._git("rev-parse", "--is-inside-work-tree") != "true":
            raise CandidateDeploymentError("source_checkout_not_git")
        if Path(self._git("rev-parse", "--show-toplevel")).resolve() != self.source_root:
            raise CandidateDeploymentError("source_checkout_root_differs")
        if self._git("remote").splitlines() != ["origin"]:
            raise CandidateDeploymentError("source_checkout_remotes_differ")
        if self._git("remote", "get-url", "origin") != self.expected_remote_url:
            raise CandidateDeploymentError("source_checkout_origin_differs")
        if self._git(
            "config", "--local", "--get-all", "remote.origin.pushurl", allow_not_found=True
        ):
            raise CandidateDeploymentError("source_checkout_pushurl_forbidden")
        unsafe_config = self._git(
            "config",
            "--local",
            "--name-only",
            "--get-regexp",
            r"^(credential|http|url|include|includeIf)\.",
            allow_not_found=True,
        )
        if unsafe_config:
            raise CandidateDeploymentError("source_checkout_git_config_forbidden")
        if self._git("status", "--porcelain=v1", "--untracked-files=all"):
            raise CandidateDeploymentError("source_checkout_not_clean")

    @staticmethod
    def _merge_object_map(values: object) -> dict[str, str]:
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise CandidateDeploymentError("merge_receipt_objects_invalid")
        result: dict[str, str] = {}
        for item in values:
            key, separator, value = item.partition(":")
            if not separator or key in result:
                raise CandidateDeploymentError("merge_receipt_objects_invalid")
            result[key] = value
        if set(result) != _MERGE_OBJECT_KEYS:
            raise CandidateDeploymentError("merge_receipt_objects_differ")
        return result

    def _validate_merge_receipt(self, request: CandidateDeploymentRequest) -> None:
        try:
            root_metadata = self.merge_receipt_root.lstat()
        except OSError as error:
            raise CandidateDeploymentError("merge_receipt_root_unavailable") from error
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or self.merge_receipt_root.is_symlink()
            or root_metadata.st_uid != self.expected_merge_receipt_uid
            or root_metadata.st_mode & 0o022
        ):
            raise CandidateDeploymentError("merge_receipt_root_invalid")
        path = self.merge_receipt_root / f"{request.merge_receipt_id}.json"
        receipt = self._read_immutable_json(
            path, expected_uid=self.expected_merge_receipt_uid
        )
        if set(receipt) != _MERGE_RECEIPT_FIELDS:
            raise CandidateDeploymentError("merge_receipt_fields_differ")
        supplied_digest = str(receipt.get("receipt_digest") or "")
        unsigned = dict(receipt)
        unsigned.pop("receipt_digest", None)
        if (
            supplied_digest != request.merge_receipt_digest
            or supplied_digest != sha256_text(stable_json(unsigned))
        ):
            raise CandidateDeploymentError("merge_receipt_digest_differs")
        if (
            receipt.get("request_id") != request.merge_receipt_id
            or receipt.get("operation") != "pull_request.merge_or_close"
            or receipt.get("target_slug") != CANONICAL_REPOSITORY
            or receipt.get("subject_identity") != "brullik"
            or receipt.get("result") != "PASS"
            or not isinstance(receipt.get("credential_epoch_id"), str)
            or not receipt.get("credential_epoch_id")
            or not isinstance(receipt.get("timestamp"), str)
            or not receipt.get("timestamp")
            or _SHA256.fullmatch(str(receipt.get("request_digest") or "")) is None
        ):
            raise CandidateDeploymentError("merge_receipt_identity_differs")
        objects = self._merge_object_map(receipt.get("object_ids"))
        if (
            objects["state"] != "squash_merge_verified"
            or objects["merge_sha"] != request.commit_sha
            or objects["merged"] != "True"
            or objects["merge_method"] != "squash"
            or objects["parents"] != "1"
            or objects["unresolved_threads"] != "0"
            or not objects["branch"].startswith("codex/")
            or objects["branch_cleanup"] not in {"deleted", "already_absent"}
            or _SHA.fullmatch(objects["head_sha"]) is None
            or _SHA256.fullmatch(objects["policy_digest"]) is None
            or _SHA256.fullmatch(objects["evidence_manifest_digest"]) is None
            or not objects["number"].isdigit()
        ):
            raise CandidateDeploymentError("merge_receipt_not_pass_squash")

    def _synchronize_exact_main(self, request: CandidateDeploymentRequest) -> Path:
        self._git(
            "fetch",
            "--no-tags",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
        )
        origin_main = self._git("rev-parse", "refs/remotes/origin/main^{commit}")
        if origin_main != request.commit_sha:
            raise CandidateDeploymentError("origin_main_commit_differs")
        if self._git("rev-parse", f"{origin_main}^{{tree}}") != request.tree_sha:
            raise CandidateDeploymentError("origin_main_tree_differs")
        parents = self._git("rev-list", "--parents", "-n", "1", origin_main).split()
        if len(parents) != 2 or parents[0] != origin_main:
            raise CandidateDeploymentError("origin_main_not_squash_commit")
        if self._git("rev-parse", "HEAD^{commit}") != origin_main:
            self._git("switch", "--detach", origin_main)
        if self._git("status", "--porcelain=v1", "--untracked-files=all"):
            raise CandidateDeploymentError("source_checkout_not_clean")
        remote = self._git("ls-remote", "--heads", "origin", "refs/heads/main").split()
        if remote != [origin_main, "refs/heads/main"]:
            raise CandidateDeploymentError("origin_main_changed_during_validation")
        if self._git("rev-parse", "HEAD^{tree}") != request.tree_sha:
            raise CandidateDeploymentError("source_checkout_tree_differs")
        script = self.source_root / PREPARE_SCRIPT
        if self._git("ls-files", "--error-unmatch", PREPARE_SCRIPT) != PREPARE_SCRIPT:
            raise CandidateDeploymentError("candidate_prepare_script_untracked")
        expected_blob = self._git("rev-parse", f"{origin_main}:{PREPARE_SCRIPT}")
        if self._git("hash-object", PREPARE_SCRIPT) != expected_blob:
            raise CandidateDeploymentError("candidate_prepare_script_differs")
        metadata = script.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or script.is_symlink()
            or metadata.st_uid != self.expected_source_uid
            or not metadata.st_mode & stat.S_IXUSR
        ):
            raise CandidateDeploymentError("candidate_prepare_script_invalid")
        return script

    def _replay(self, request: CandidateDeploymentRequest) -> dict[str, Any] | None:
        path = self.result_root / f"{request.request_id}.json"
        if not path.exists():
            return None
        receipt = self._read_immutable_json(path, expected_uid=self.expected_source_uid)
        if set(receipt) != _RESULT_FIELDS:
            raise CandidateDeploymentError("deployment_result_fields_differ")
        unsigned = dict(receipt)
        digest = str(unsigned.pop("receipt_digest", ""))
        if digest != sha256_text(stable_json(unsigned)):
            raise CandidateDeploymentError("deployment_result_digest_differs")
        if receipt.get("request_digest") != request.digest():
            raise CandidateDeploymentError("deployment_replay_conflict")
        return receipt

    def _reserve(self, request: CandidateDeploymentRequest) -> None:
        intent = {
            "schema_version": "1.0",
            "request_id": request.request_id,
            "request_digest": request.digest(),
            "commit_sha": request.commit_sha,
            "tree_sha": request.tree_sha,
            "merge_receipt_digest": request.merge_receipt_digest,
            "reserved_at": utc_now(),
        }
        request_intent = self.intent_root / f"{request.request_id}.json"
        commit_guard = self.commit_guard_root / f"{request.commit_sha}.json"
        if request_intent.exists():
            raise CandidateDeploymentError("deployment_outcome_uncertain")
        if commit_guard.exists():
            raise CandidateDeploymentError("deployment_commit_already_attempted")
        self._write_immutable(request_intent, intent)
        try:
            self._write_immutable(commit_guard, intent)
        except FileExistsError as error:
            raise CandidateDeploymentError("deployment_commit_already_attempted") from error

    def _result_receipt(
        self,
        request: CandidateDeploymentRequest,
        result: subprocess.CompletedProcess[str],
        *,
        started_at: str,
    ) -> dict[str, Any]:
        stdout, stdout_redactions = redact_text(result.stdout[-16_384:])
        stderr, stderr_redactions = redact_text(result.stderr[-16_384:])
        core: dict[str, Any] = {
            "schema_version": "1.0",
            "request_id": request.request_id,
            "request_digest": request.digest(),
            "operation": request.operation,
            "repository": request.repository,
            "commit_sha": request.commit_sha,
            "tree_sha": request.tree_sha,
            "merge_receipt_id": request.merge_receipt_id,
            "merge_receipt_digest": request.merge_receipt_digest,
            "result": "PASS" if result.returncode == 0 else "FAILED",
            "exit_code": result.returncode,
            "started_at": started_at,
            "completed_at": utc_now(),
            "stdout_digest": sha256_text(stdout),
            "stderr_digest": sha256_text(stderr),
            # Child output is never returned across the requester boundary.
            # Digests and typed redaction counts are sufficient for correlation.
            "stdout_tail": "",
            "stderr_tail": "",
            "redactions": [*stdout_redactions, *stderr_redactions],
        }
        return {**core, "receipt_digest": sha256_text(stable_json(core))}

    def execute(self, raw_request: object) -> dict[str, Any]:
        request = CandidateDeploymentRequest.from_mapping(raw_request)
        self._prepare_state()
        replayed = self._replay(request)
        if replayed is not None:
            return replayed
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise CandidateDeploymentError("deployment_in_progress") from error
            replayed = self._replay(request)
            if replayed is not None:
                return replayed
            self._validate_source_checkout()
            self._validate_merge_receipt(request)
            script = self._synchronize_exact_main(request)
            self._reserve(request)
            started_at = utc_now()
            try:
                result = self.prepare_runner(
                    [str(script)],
                    self._environment(),
                    self.source_root,
                    self.prepare_timeout_seconds,
                )
            except (OSError, subprocess.SubprocessError) as error:
                result = subprocess.CompletedProcess(
                    [str(script)], 70, "", f"{type(error).__name__}: prepare unavailable"
                )
            receipt = self._result_receipt(request, result, started_at=started_at)
            self._write_immutable(
                self.result_root / f"{request.request_id}.json", receipt
            )
            return receipt
        finally:
            os.close(descriptor)


class CandidateDeploymentClient:
    """Secret-free client for the single typed deployment operation."""

    def __init__(self, socket_path: Path, *, timeout_seconds: float = 21_600.0) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def execute(self, request: CandidateDeploymentRequest) -> dict[str, Any]:
        encoded = (stable_json(asdict(request)) + "\n").encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout_seconds)
            try:
                connection.connect(str(self.socket_path))
                connection.sendall(encoded)
                response = bytearray()
                while b"\n" not in response:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > 1_048_576:
                        raise CandidateDeploymentError("deployment_response_too_large")
            except OSError as error:
                raise CandidateDeploymentError("candidate_deployment_broker_unavailable") from error
        try:
            value = json.loads(bytes(response).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CandidateDeploymentError("deployment_response_invalid") from error
        if not isinstance(value, dict) or value.get("status") not in {"PASS", "FAILED"}:
            raise CandidateDeploymentError("deployment_response_invalid")
        receipt = value.get("receipt")
        if value["status"] == "PASS" and not isinstance(receipt, dict):
            raise CandidateDeploymentError("deployment_response_receipt_missing")
        if isinstance(receipt, dict):
            if set(receipt) != _RESULT_FIELDS:
                raise CandidateDeploymentError("deployment_response_receipt_invalid")
            unsigned = dict(receipt)
            receipt_digest = str(unsigned.pop("receipt_digest", ""))
            if (
                receipt_digest != sha256_text(stable_json(unsigned))
                or receipt.get("request_digest") != request.digest()
                or receipt.get("result") != value["status"]
            ):
                raise CandidateDeploymentError("deployment_response_receipt_invalid")
        return value


def serve_candidate_deployment_broker(
    *,
    socket_path: Path,
    broker: CandidateDeploymentBroker,
    allowed_uid: int,
    allowed_gid: int,
    socket_uid: int = 0,
) -> None:
    """Serve sequential typed requests after exact SO_PEERCRED validation."""

    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        metadata = socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != socket_uid:
            raise CandidateDeploymentError("deployment_socket_path_conflicts")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chown(socket_path, socket_uid, allowed_gid)
        os.chmod(socket_path, 0o660)
        listener.listen(8)
        while True:
            connection, _address = listener.accept()
            with connection:
                try:
                    require_exact_peer(
                        connection, allowed_uid=allowed_uid, allowed_gid=allowed_gid
                    )
                    encoded = bytearray()
                    while b"\n" not in encoded:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        encoded.extend(chunk)
                        if len(encoded) > 65_536:
                            raise CandidateDeploymentError("deployment_request_too_large")
                    request = json.loads(bytes(encoded).decode("utf-8"))
                    receipt = broker.execute(request)
                    response = {
                        "status": receipt["result"],
                        "receipt": receipt,
                    }
                    if receipt["result"] != "PASS":
                        response["reason_code"] = "candidate_deployment_failed"
                except CandidateDeploymentError as error:
                    response = {"status": "FAILED", "reason_code": error.reason_code}
                except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                    response = {
                        "status": "FAILED",
                        "reason_code": "deployment_request_invalid",
                    }
                except OSError:
                    response = {
                        "status": "FAILED",
                        "reason_code": "candidate_deployment_internal_failure",
                    }
                try:
                    connection.sendall((stable_json(response) + "\n").encode("utf-8"))
                except OSError:
                    continue


def resolve_user(name: str) -> tuple[int, int]:
    """Resolve one exact local service identity at broker startup."""

    try:
        identity = pwd.getpwnam(name)
    except KeyError as error:
        raise CandidateDeploymentError("deployment_local_identity_missing") from error
    return identity.pw_uid, identity.pw_gid
