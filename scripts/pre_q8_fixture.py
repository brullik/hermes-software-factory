#!/usr/bin/env python3
"""Provision and retire one content-addressed private GitHub qualification fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from factory.common import sha256_text, stable_json, utc_now
from factory.pre_q8_convergence import resource_namespace
from factory.pre_q8_fixture import fixture_files, fixture_manifest


class FixtureControlError(RuntimeError):
    """The private fixture cannot be proven or safely retired."""


class GitHubAPIError(FixtureControlError):
    """A typed GitHub API failure used for safe create-or-resume decisions."""

    def __init__(self, status: int) -> None:
        super().__init__(f"GitHub fixture API failed with HTTP {status}")
        self.status = status


class GitHubClient:
    def __init__(self, token: str) -> None:
        if not token or any(character.isspace() for character in token):
            raise FixtureControlError("GitHub fixture credential is invalid")
        self.token = token

    def request(
        self, method: str, path: str, payload: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        data = (
            json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
        request = urllib.request.Request(
            f"https://api.github.com{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "hermes-preq8-fixture/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            raise GitHubAPIError(error.code) from error
        except urllib.error.URLError as error:
            raise FixtureControlError("GitHub fixture API is unavailable") from error
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise FixtureControlError("GitHub fixture response is invalid")
        return {str(key): item for key, item in value.items()}


def _token(path: Path) -> str:
    metadata = path.stat()
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise FixtureControlError("GitHub fixture credential path is unsafe")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise FixtureControlError("GitHub fixture credential permissions are unsafe")
    return path.read_text(encoding="utf-8").strip()


def _optional_request(
    client: GitHubClient,
    method: str,
    path: str,
    *,
    absent_statuses: tuple[int, ...] = (404,),
) -> dict[str, Any] | None:
    try:
        return client.request(method, path)
    except GitHubAPIError as error:
        if error.status in absent_statuses:
            return None
        raise


def _write_receipt(path: Path, body: Mapping[str, Any]) -> dict[str, Any]:
    digest = sha256_text(stable_json(dict(body)))
    envelope = {**dict(body), "receipt_digest": digest, "observed_at": utc_now()}
    encoded = json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            raise FixtureControlError("fixture receipt is invalid")
        existing.pop("observed_at", None)
        expected = {**dict(body), "receipt_digest": digest}
        if existing != expected:
            raise FixtureControlError("immutable fixture receipt conflicts")
        return {**expected, "observed_at": "existing"}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return envelope


def _read_receipt(path: Path, receipt_type: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise FixtureControlError("fixture receipt is unavailable or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FixtureControlError("fixture receipt is invalid")
    body = {str(key): item for key, item in value.items()}
    observed_at = body.pop("observed_at", None)
    receipt_digest = str(body.pop("receipt_digest", ""))
    if (
        value.get("receipt_type") != receipt_type
        or not observed_at
        or sha256_text(stable_json(body)) != receipt_digest
    ):
        raise FixtureControlError("fixture receipt integrity failed")
    return {**body, "receipt_digest": receipt_digest, "observed_at": observed_at}


def _verify_repository(
    *,
    client: GitHubClient,
    owner: str,
    repository_name: str,
    expected_commit: str,
    expected_id: object | None = None,
    archived: bool = False,
) -> dict[str, Any]:
    manifest = fixture_manifest()
    files = fixture_files()
    repository = client.request("GET", f"/repos/{owner}/{repository_name}")
    branch = client.request(
        "GET", f"/repos/{owner}/{repository_name}/git/ref/heads/main"
    )
    commit = client.request(
        "GET", f"/repos/{owner}/{repository_name}/git/commits/{expected_commit}"
    )
    tree_sha = str(commit.get("tree", {}).get("sha") or "")
    tree = client.request(
        "GET", f"/repos/{owner}/{repository_name}/git/trees/{tree_sha}?recursive=1"
    )
    observed_tree = {
        str(item.get("path")): (
            str(item.get("mode")),
            str(item.get("type")),
            str(item.get("sha")),
        )
        for item in tree.get("tree", [])
        if isinstance(item, Mapping) and item.get("type") == "blob"
    }
    expected_tree = {
        path: (
            "100644",
            "blob",
            hashlib.sha1(
                f"blob {len(content)}\0".encode("ascii") + content,
                usedforsecurity=False,
            ).hexdigest(),
        )
        for path, content in files.items()
    }
    if (
        repository.get("name") != repository_name
        or repository.get("private") is not True
        or repository.get("visibility") not in {None, "private"}
        or repository.get("archived") is not archived
        or repository.get("default_branch") != "main"
        or branch.get("object", {}).get("sha") != expected_commit
        or commit.get("sha") != expected_commit
        or commit.get("message")
        != f"Hermes fixture {manifest['fixture_seed_digest']}"
        or observed_tree != expected_tree
        or (expected_id is not None and repository.get("id") != expected_id)
    ):
        raise FixtureControlError("fixture repository identity differs")
    return repository


def provision(
    *,
    client: GitHubClient,
    owner: str,
    plane: str,
    run_id: str,
    candidate_digest: str,
    receipt_path: Path,
) -> dict[str, Any]:
    manifest = fixture_manifest()
    repository_name = resource_namespace(
        plane=plane,
        run_id=run_id,
        candidate_digest=candidate_digest,
        scenario_id="existing-repository-repair",
    )
    user = client.request("GET", "/user")
    login = str(user.get("login") or "")
    endpoint = "/user/repos" if login.casefold() == owner.casefold() else f"/orgs/{owner}/repos"
    if receipt_path.exists():
        receipt = _read_receipt(
            receipt_path, "PREQ8_EXISTING_REPOSITORY_FIXTURE"
        )
        if (
            receipt.get("fixture_seed_digest") != manifest["fixture_seed_digest"]
            or receipt.get("repository_name") != repository_name
            or receipt.get("qualification_plane") != plane.upper().replace("-", "_")
            or receipt.get("run_id") != run_id
            or receipt.get("candidate_digest") != candidate_digest
        ):
            raise FixtureControlError("existing fixture repository identity differs")
        _verify_repository(
            client=client,
            owner=owner,
            repository_name=repository_name,
            expected_commit=str(receipt["seed_commit"]),
            expected_id=receipt["repository_id"],
        )
        return receipt
    repository = _optional_request(client, "GET", f"/repos/{owner}/{repository_name}")
    if repository is None:
        repository = client.request(
            "POST",
            endpoint,
            {
                "name": repository_name,
                "private": True,
                "auto_init": False,
                "has_issues": False,
                "has_projects": False,
                "has_wiki": False,
                "description": "Hermes content-addressed PRE-Q8 repair fixture",
            },
        )
    if (
        str(repository.get("name") or "") != repository_name
        or repository.get("private") is not True
        or repository.get("archived") is True
    ):
        raise FixtureControlError("created fixture repository identity differs")
    branch_get_path = f"/repos/{owner}/{repository_name}/git/ref/heads/main"
    branch_update_path = f"/repos/{owner}/{repository_name}/git/refs/heads/main"
    branch = _optional_request(
        client,
        "GET",
        branch_get_path,
        absent_statuses=(404, 409),
    )
    if branch is not None:
        branch_commit = str(branch.get("object", {}).get("sha") or "")
        try:
            verified = _verify_repository(
                client=client,
                owner=owner,
                repository_name=repository_name,
                expected_commit=branch_commit,
                expected_id=repository["id"],
            )
        except GitHubAPIError:
            raise
        except FixtureControlError:
            pass
        else:
            body = {
                "schema_version": "1.0",
                "receipt_type": "PREQ8_EXISTING_REPOSITORY_FIXTURE",
                "qualification_plane": plane.upper().replace("-", "_"),
                "run_id": run_id,
                "candidate_digest": candidate_digest,
                "scenario_id": "existing-repository-repair",
                "fixture_seed_digest": manifest["fixture_seed_digest"],
                "repository_name": repository_name,
                "repository_url": f"https://github.com/{owner}/{repository_name}",
                "repository_id": verified["id"],
                "visibility": "private",
                "default_branch": "main",
                "seed_commit": branch_commit,
            }
            return _write_receipt(receipt_path, body)
    if branch is None:
        bootstrap = client.request(
            "PUT",
            f"/repos/{owner}/{repository_name}/contents/.hermes-bootstrap",
            {
                "message": f"Hermes fixture bootstrap {manifest['fixture_seed_digest']}",
                "content": b64encode(
                    f"{manifest['fixture_seed_digest']}\n".encode("ascii")
                ).decode("ascii"),
                "branch": "main",
                "committer": {
                    "name": "Hermes Qualification",
                    "email": "qualification@invalid.local",
                },
                "author": {
                    "name": "Hermes Qualification",
                    "email": "qualification@invalid.local",
                },
            },
        )
        parent_commit = str(bootstrap.get("commit", {}).get("sha") or "")
    else:
        parent_commit = str(branch.get("object", {}).get("sha") or "")
    if len(parent_commit) != 40:
        raise FixtureControlError("fixture bootstrap commit is invalid")
    blobs: list[dict[str, str]] = []
    files = fixture_files()
    for entry in manifest["files"]:
        relative = str(entry["path"])
        content = files[relative]
        blob = client.request(
            "POST",
            f"/repos/{owner}/{repository_name}/git/blobs",
            {"content": b64encode(content).decode("ascii"), "encoding": "base64"},
        )
        blobs.append(
            {"path": relative, "mode": "100644", "type": "blob", "sha": str(blob["sha"])}
        )
    tree = client.request(
        "POST", f"/repos/{owner}/{repository_name}/git/trees", {"tree": blobs}
    )
    commit = client.request(
        "POST",
        f"/repos/{owner}/{repository_name}/git/commits",
        {
            "message": f"Hermes fixture {manifest['fixture_seed_digest']}",
            "tree": tree["sha"],
            "parents": [parent_commit],
            "author": {
                "name": "Hermes Qualification",
                "email": "qualification@invalid.local",
                "date": "2026-08-10T00:00:00Z",
            },
            "committer": {
                "name": "Hermes Qualification",
                "email": "qualification@invalid.local",
                "date": "2026-08-10T00:00:00Z",
            },
        },
    )
    client.request(
        "PATCH",
        branch_update_path,
        {"sha": commit["sha"], "force": True},
    )
    client.request(
        "PATCH", f"/repos/{owner}/{repository_name}", {"default_branch": "main"}
    )
    verified = _verify_repository(
        client=client,
        owner=owner,
        repository_name=repository_name,
        expected_commit=str(commit["sha"]),
        expected_id=repository["id"],
    )
    body = {
        "schema_version": "1.0",
        "receipt_type": "PREQ8_EXISTING_REPOSITORY_FIXTURE",
        "qualification_plane": plane.upper().replace("-", "_"),
        "run_id": run_id,
        "candidate_digest": candidate_digest,
        "scenario_id": "existing-repository-repair",
        "fixture_seed_digest": manifest["fixture_seed_digest"],
        "repository_name": repository_name,
        "repository_url": f"https://github.com/{owner}/{repository_name}",
        "repository_id": verified["id"],
        "visibility": "private",
        "default_branch": "main",
        "seed_commit": commit["sha"],
    }
    return _write_receipt(receipt_path, body)


def archive(
    *, client: GitHubClient, owner: str, receipt_path: Path, output: Path
) -> dict[str, Any]:
    receipt = _read_receipt(
        receipt_path, "PREQ8_EXISTING_REPOSITORY_FIXTURE"
    )
    name = str(receipt.get("repository_name") or "")
    body = {
        "schema_version": "1.0",
        "receipt_type": "PREQ8_EXISTING_REPOSITORY_FIXTURE_ARCHIVE",
        "provision_receipt_digest": receipt["receipt_digest"],
        "repository_name": name,
        "repository_id": receipt["repository_id"],
        "archived": True,
    }
    if output.exists():
        existing = _read_receipt(
            output, "PREQ8_EXISTING_REPOSITORY_FIXTURE_ARCHIVE"
        )
        if {
            key: existing[key]
            for key in body
        } != body:
            raise FixtureControlError("fixture archive receipt conflicts")
        _verify_repository(
            client=client,
            owner=owner,
            repository_name=name,
            expected_commit=str(receipt["seed_commit"]),
            expected_id=receipt["repository_id"],
            archived=True,
        )
        return existing
    repository = client.request("GET", f"/repos/{owner}/{name}")
    if repository.get("archived") is not True:
        client.request("PATCH", f"/repos/{owner}/{name}", {"archived": True})
    _verify_repository(
        client=client,
        owner=owner,
        repository_name=name,
        expected_commit=str(receipt["seed_commit"]),
        expected_id=receipt["repository_id"],
        archived=True,
    )
    return _write_receipt(output, body)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--owner", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("provision")
    create.add_argument("--plane", choices=("convergence", "pre-q8", "q8"), required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--candidate-digest", required=True)
    create.add_argument("--receipt", type=Path, required=True)
    retire = commands.add_parser("archive")
    retire.add_argument("--receipt", type=Path, required=True)
    retire.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        client = GitHubClient(_token(args.token_file))
        if args.command == "provision":
            result = provision(
                client=client,
                owner=args.owner,
                plane=args.plane,
                run_id=args.run_id,
                candidate_digest=args.candidate_digest,
                receipt_path=args.receipt,
            )
        else:
            result = archive(
                client=client,
                owner=args.owner,
                receipt_path=args.receipt,
                output=args.output,
            )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
        print(stable_json({"status": "FAIL", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    print(stable_json({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
