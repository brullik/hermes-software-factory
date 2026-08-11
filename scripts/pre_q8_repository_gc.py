#!/usr/bin/env python3
"""Attest, freeze and DELETE exact qualification repositories with receipts."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from factory.common import sha256_text, stable_json, utc_now
from factory.credential_broker import BrokerClient, BrokerRequest
from factory.qualification_repository_gc import (
    QualificationRepositoryGCError,
    attest_repository_identity,
    finalize_repository_cleanup,
    load_repository_ledger,
    mark_scenario_evidence_frozen,
    qualification_repository_cleanup_plan,
    record_provisioned_repository,
    update_repository_cleanup_state,
    verify_repository_cleanup_eligibility,
)


def _default_token_file() -> Path:
    credential_directory = str(os.environ.get("CREDENTIALS_DIRECTORY") or "").strip()
    if credential_directory:
        return Path(credential_directory) / "github-token"
    return Path("/etc/hermes-factory/candidate-credentials.d/github-token")


def _token(path: Path) -> str:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise QualificationRepositoryGCError("GitHub credential path is unsafe")
    metadata = path.stat()
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o037:
        raise QualificationRepositoryGCError(
            "GitHub credential permissions are unsafe"
        )
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(character.isspace() for character in value):
        raise QualificationRepositoryGCError("GitHub credential is invalid")
    return value


class GitHubMetadata:
    """Bounded read-only GitHub metadata client for root-owned GC."""

    def __init__(self, token: str) -> None:
        self.token = token

    def _request(
        self,
        path: str,
        *,
        allow_404: bool = False,
    ) -> dict[str, Any] | None:
        request = urllib.request.Request(
            "https://api.github.com" + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "hermes-qualification-repository-gc/2",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if allow_404 and error.code == 404:
                return None
            raise QualificationRepositoryGCError(
                f"GitHub repository metadata failed with HTTP {error.code}"
            ) from error
        except urllib.error.URLError as error:
            raise QualificationRepositoryGCError(
                "GitHub repository metadata is unavailable"
            ) from error
        if len(raw) > 2 * 1024 * 1024:
            raise QualificationRepositoryGCError(
                "GitHub repository metadata is too large"
            )
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, Mapping):
            raise QualificationRepositoryGCError(
                "GitHub repository metadata is invalid"
            )
        return {str(key): item for key, item in value.items()}

    def repository(self, owner: str, name: str) -> dict[str, Any] | None:
        return self._request(
            "/repos/"
            + urllib.parse.quote(owner, safe="")
            + "/"
            + urllib.parse.quote(name, safe=""),
            allow_404=True,
        )

    def branch_head(
        self,
        owner: str,
        name: str,
        branch: str,
    ) -> str | None:
        value = self._request(
            "/repos/"
            + urllib.parse.quote(owner, safe="")
            + "/"
            + urllib.parse.quote(name, safe="")
            + "/git/ref/heads/"
            + urllib.parse.quote(branch, safe=""),
            allow_404=True,
        )
        if value is None:
            return None
        target = value.get("object")
        sha = (
            str(target.get("sha") or "")
            if isinstance(target, Mapping)
            else ""
        )
        if len(sha) != 40:
            raise QualificationRepositoryGCError(
                "GitHub branch head is invalid"
            )
        return sha


def _write_receipt(path: Path, body: Mapping[str, Any]) -> dict[str, Any]:
    identity = {str(key): value for key, value in body.items()}
    envelope = {
        **identity,
        "receipt_digest": sha256_text(stable_json(identity)),
    }
    encoded = json.dumps(
        envelope,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise QualificationRepositoryGCError("cleanup receipt conflicts")
        return envelope
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o440,
    )
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return envelope


def _fixture_receipt(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise QualificationRepositoryGCError("fixture receipt is invalid")
    body = {str(key): item for key, item in value.items()}
    observed_at = body.pop("observed_at", None)
    digest = str(body.pop("receipt_digest", ""))
    if not observed_at or digest != sha256_text(stable_json(body)):
        raise QualificationRepositoryGCError("fixture receipt digest differs")
    return {**body, "receipt_digest": digest}


def _quick_check_database(database: Path) -> None:
    if not database.is_file() or database.is_symlink():
        raise QualificationRepositoryGCError("scenario database is unavailable")
    connection = sqlite3.connect(
        f"file:{database}?mode=ro",
        uri=True,
        timeout=30,
    )
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()
    finally:
        connection.close()
    if quick_check is None or str(quick_check[0]) != "ok":
        raise QualificationRepositoryGCError(
            "scenario database quick_check failed"
        )


def _database_identity(database: Path) -> dict[str, str]:
    _quick_check_database(database)
    connection = sqlite3.connect(
        f"file:{database}?mode=ro",
        uri=True,
        timeout=30,
    )
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """SELECT product_id, repository_name, repository_url,
                      default_branch, bootstrap_sha
                 FROM products"""
        ).fetchall()
    finally:
        connection.close()
    if len(rows) != 1:
        raise QualificationRepositoryGCError(
            "scenario repository identity is ambiguous"
        )
    value = dict(rows[0])
    required = {
        "product_id",
        "repository_name",
        "repository_url",
        "default_branch",
        "bootstrap_sha",
    }
    if any(not str(value.get(key) or "") for key in required):
        raise QualificationRepositoryGCError(
            "scenario repository identity is incomplete"
        )
    return {key: str(value[key]) for key in required}


def _attest_scenario_entries(
    args: argparse.Namespace,
    client: GitHubMetadata,
) -> int:
    ledger = load_repository_ledger(args.ledger)
    changed = 0
    for raw in ledger["repositories"]:
        entry = dict(raw)
        if (
            entry.get("scenario_id") != args.scenario_id
            or entry.get("state") != "PROVISIONED"
        ):
            continue
        owner = str(entry["repository_owner"])
        name = str(entry["repository_name"])
        live = client.repository(owner, name)
        branch = str(entry.get("expected_default_branch") or "main")
        if live is None:
            expected_head_sha = (
                str(entry.get("expected_head_sha"))
                if entry.get("expected_head_sha")
                else None
            )
            live_head_sha = None
        elif entry.get("product_id") is None:
            expected_head_sha = str(entry.get("expected_head_sha") or "")
            live_head_sha = client.branch_head(owner, name, branch)
        else:
            database = Path(str(entry.get("database_path") or ""))
            identity = _database_identity(database)
            if (
                identity["product_id"] != str(entry["product_id"])
                or identity["repository_name"] != name
                or identity["repository_url"].removesuffix(".git")
                != f"https://github.com/{owner}/{name}"
                or identity["default_branch"] != branch
            ):
                raise QualificationRepositoryGCError(
                    "scenario database repository identity differs"
                )
            expected_head_sha = identity["bootstrap_sha"]
            live_head_sha = client.branch_head(owner, name, branch)
        attest_repository_identity(
            args.ledger,
            str(entry["entry_id"]),
            live_repository=live,
            live_head_sha=live_head_sha,
            expected_head_sha=expected_head_sha,
        )
        changed += 1
    return changed


def _freeze(args: argparse.Namespace) -> dict[str, Any]:
    if not args.evidence_root.is_dir() or args.evidence_root.is_symlink():
        raise QualificationRepositoryGCError("scenario evidence is not frozen")
    if not any(
        path.is_file() and not path.is_symlink()
        for path in args.evidence_root.rglob("*")
    ):
        raise QualificationRepositoryGCError("scenario evidence is empty")
    client = GitHubMetadata(_token(args.token_file))
    attested = _attest_scenario_entries(args, client)
    ledger = load_repository_ledger(args.ledger)
    for entry in ledger["repositories"]:
        if entry.get("scenario_id") != args.scenario_id:
            continue
        raw_database = str(entry.get("database_path") or "")
        if raw_database:
            _quick_check_database(Path(raw_database))
    frozen = mark_scenario_evidence_frozen(args.ledger, args.scenario_id)
    return {
        "scenario_id": args.scenario_id,
        "attested_count": attested,
        "frozen_count": frozen,
    }


def _cleanup(args: argparse.Namespace) -> dict[str, Any]:
    if not args.run_inactive:
        raise QualificationRepositoryGCError(
            "repository cleanup requires inactive run"
        )
    client = GitHubMetadata(_token(args.token_file))
    broker = BrokerClient(args.broker_socket)
    plan = qualification_repository_cleanup_plan(
        args.ledger,
        run_active=False,
    )
    failed = 0
    for entry in plan["entries"]:
        entry_id = str(entry["entry_id"])
        owner = str(entry["repository_owner"])
        name = str(entry["repository_name"])
        try:
            live = client.repository(owner, name)
            branch = str(entry.get("expected_default_branch") or "main")
            live_head_sha = (
                client.branch_head(owner, name, branch)
                if live is not None
                else None
            )
            eligible, reason = verify_repository_cleanup_eligibility(
                entry,
                live,
                run_active=False,
                permanent_allowlist=tuple(args.permanent_repository),
                live_head_sha=live_head_sha,
            )
            if not eligible:
                raise QualificationRepositoryGCError(reason)
            if live is None:
                status = "ALREADY_ABSENT"
                broker_receipt_digest = None
                repository_id = entry.get("repository_id")
                repository_node_id = entry.get("repository_node_id")
            else:
                repository_id = live.get("id")
                repository_node_id = live.get("node_id")
                update_repository_cleanup_state(
                    args.ledger,
                    entry_id,
                    state="DELETE_REQUESTED",
                )
                request = BrokerRequest(
                    request_id="QGC-"
                    + sha256_text(
                        stable_json(
                            [
                                entry_id,
                                owner,
                                name,
                                "delete-v2",
                                repository_id,
                                live_head_sha,
                            ]
                        )
                    )[:40],
                    operation="repository.archive_or_delete",
                    owner=owner,
                    repository=name,
                    payload={"action": "delete"},
                )
                broker_receipt = broker.execute(request)
                broker_receipt_digest = broker_receipt.receipt_digest
                if client.repository(owner, name) is not None:
                    raise QualificationRepositoryGCError(
                        "repository still exists after DELETE"
                    )
                status = "DELETED"
            attestation = entry.get("identity_attestation")
            receipt = _write_receipt(
                args.ledger.parent
                / "repository-cleanup-receipts"
                / f"{entry_id}.json",
                {
                    "schema_version": "2.0",
                    "entry_id": entry_id,
                    "repository_owner": owner,
                    "repository_name": name,
                    "repository_id": repository_id,
                    "repository_node_id": repository_node_id,
                    "verified_head_sha": live_head_sha,
                    "identity_attestation_digest": (
                        attestation.get("attestation_digest")
                        if isinstance(attestation, Mapping)
                        else None
                    ),
                    "operation": "repository.archive_or_delete",
                    "action": "delete",
                    "status": status,
                    "broker_receipt_digest": broker_receipt_digest,
                    "verified_get_status": 404,
                },
            )
            update_repository_cleanup_state(
                args.ledger,
                entry_id,
                state=status,
                cleanup_receipt=receipt,
            )
        except Exception as error:  # noqa: BLE001 - durable state is mandatory
            failed += 1
            update_repository_cleanup_state(
                args.ledger,
                entry_id,
                state="CLEANUP_FAILED",
                cleanup_receipt={
                    "schema_version": "2.0",
                    "status": "CLEANUP_FAILED",
                    "error_type": type(error).__name__,
                    "observed_at": utc_now(),
                },
            )
    try:
        summary = finalize_repository_cleanup(
            args.ledger,
            output=args.output,
        )
    except QualificationRepositoryGCError:
        if failed:
            raise
        raise
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    fixture = commands.add_parser("record-fixture")
    fixture.add_argument("--ledger", type=Path, required=True)
    fixture.add_argument("--receipt", type=Path, required=True)
    fixture.add_argument("--epoch-id", required=True)
    fixture.add_argument("--owner", required=True)
    fixture.add_argument("--database-path")

    freeze = commands.add_parser("freeze-scenario")
    freeze.add_argument("--ledger", type=Path, required=True)
    freeze.add_argument("--scenario-id", required=True)
    freeze.add_argument("--evidence-root", type=Path, required=True)
    freeze.add_argument(
        "--token-file",
        type=Path,
        default=_default_token_file(),
    )

    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--ledger", type=Path, required=True)
    cleanup.add_argument("--token-file", type=Path, required=True)
    cleanup.add_argument(
        "--broker-socket",
        type=Path,
        default=Path("/run/hermes-factory-github-broker/broker.sock"),
    )
    cleanup.add_argument("--output", type=Path, required=True)
    cleanup.add_argument("--permanent-repository", action="append", default=[])
    cleanup.add_argument("--run-inactive", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "record-fixture":
            receipt = _fixture_receipt(args.receipt)
            entry = record_provisioned_repository(
                args.ledger,
                qualification_plane=str(receipt["qualification_plane"]),
                epoch_id=args.epoch_id,
                run_id=str(receipt["run_id"]),
                scenario_id=str(receipt["scenario_id"]),
                candidate_digest=str(receipt["candidate_digest"]),
                product_id=None,
                repository_owner=args.owner,
                repository_name=str(receipt["repository_name"]),
                repository_id=int(receipt["repository_id"]),
                repository_node_id=None,
                expected_head_sha=str(receipt["seed_commit"]),
                expected_default_branch="main",
                identity_proof_mode="PENDING_FIXTURE_LIVE_ATTESTATION",
                expected_description=(
                    "Hermes content-addressed PRE-Q8 repair fixture"
                ),
                provision_receipt_digest=str(receipt["receipt_digest"]),
                database_path=args.database_path,
            )
            result = {"entry_id": entry["entry_id"]}
        elif args.command == "freeze-scenario":
            result = _freeze(args)
        else:
            result = _cleanup(args)
    except (
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(
            stable_json(
                {"status": "FAIL", "error_type": type(error).__name__}
            ),
            file=sys.stderr,
        )
        return 1
    print(stable_json({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
