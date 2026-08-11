#!/usr/bin/env python3
"""Two-phase GC for exact audit-proven historical qualification repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

SHA40: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{40}$")
NAME: Final[re.Pattern[str]] = re.compile(
    r"^hermes-canary-(?:convergence|preq8|q8)-[a-z0-9]+-[a-f0-9]{20}$"
)


class HistoricalGCError(RuntimeError):
    """A historical repository cannot be safely identified or deleted."""


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def digest(value: Mapping[str, Any], excluded: str) -> str:
    payload = {
        str(key): item
        for key, item in value.items()
        if key != excluded
    }
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def resource_namespace(
    plane: str,
    run_id: str,
    candidate_digest: str,
    scenario_id: str,
) -> str:
    normalized_plane = plane.strip().lower().replace("_", "-")
    scenario = scenario_id.replace("-", "")[:18]
    identity = hashlib.sha256(
        stable_json(
            [
                "pre-q8-resource-v2",
                normalized_plane,
                run_id,
                candidate_digest,
                scenario_id,
            ]
        ).encode("utf-8")
    ).hexdigest()[:20]
    return (
        f"hermes-canary-{normalized_plane.replace('-', '')}-"
        f"{scenario}-{identity}"
    )


def read_token(path: Path) -> str:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise HistoricalGCError("token path is unsafe")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o037:
        raise HistoricalGCError("token permissions are too broad")
    value = path.read_text(encoding="utf-8").strip()
    if not value or any(character.isspace() for character in value):
        raise HistoricalGCError("token is invalid")
    return value


def validate_inventory(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HistoricalGCError("inventory is not an object")
    inventory = {str(key): item for key, item in value.items()}
    entries = inventory.get("repositories")
    if (
        inventory.get("schema_version") != "2.0"
        or inventory.get("repository_count") != 40
        or not isinstance(entries, list)
        or len(entries) != 40
        or inventory.get("inventory_digest")
        != digest(inventory, "inventory_digest")
    ):
        raise HistoricalGCError(
            "historical inventory digest or cardinality differs"
        )
    names: set[str] = set()
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise HistoricalGCError("historical inventory entry is invalid")
        entry = {str(key): item for key, item in raw.items()}
        if entry.get("entry_digest") != digest(entry, "entry_digest"):
            raise HistoricalGCError(
                "historical inventory entry digest differs"
            )
        name = str(entry.get("repository_name") or "")
        expected = resource_namespace(
            str(entry.get("qualification_plane") or ""),
            str(entry.get("run_id") or ""),
            str(entry.get("candidate_digest") or ""),
            str(entry.get("scenario_id") or ""),
        )
        if (
            NAME.fullmatch(name) is None
            or name != expected
            or name in names
            or entry.get("repository_owner") != inventory.get("owner")
            or entry.get("repository_visibility") != "private"
            or SHA40.fullmatch(str(entry.get("expected_head_sha") or ""))
            is None
            or SHA40.fullmatch(str(entry.get("expected_bootstrap_sha") or ""))
            is None
        ):
            raise HistoricalGCError(
                "historical inventory static identity differs"
            )
        names.add(name)
    return inventory


class GitHub:
    """Bounded GitHub client used only by the root-owned historical GC."""

    def __init__(self, token: str) -> None:
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        allow_404: bool = False,
    ) -> dict[str, Any] | list[Any] | None:
        request = urllib.request.Request(
            "https://api.github.com" + path,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "hermes-historical-qualification-gc/2",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if allow_404 and error.code == 404:
                return None
            raise HistoricalGCError(
                f"GitHub API failed with HTTP {error.code}"
            ) from error
        except urllib.error.URLError as error:
            raise HistoricalGCError("GitHub API is unavailable") from error
        if len(raw) > 4 * 1024 * 1024:
            raise HistoricalGCError("GitHub API response is too large")
        if not raw:
            return {}
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, (dict, list)):
            raise HistoricalGCError("GitHub API response type is invalid")
        return value

    @staticmethod
    def _repo_path(owner: str, name: str) -> str:
        return (
            "/repos/"
            + urllib.parse.quote(owner, safe="")
            + "/"
            + urllib.parse.quote(name, safe="")
        )

    def repository(self, owner: str, name: str) -> dict[str, Any] | None:
        value = self.request(
            "GET",
            self._repo_path(owner, name),
            allow_404=True,
        )
        if value is None:
            return None
        if not isinstance(value, dict):
            raise HistoricalGCError("repository response is invalid")
        return value

    def branch_ref(
        self,
        owner: str,
        name: str,
        branch: str,
    ) -> dict[str, Any] | None:
        value = self.request(
            "GET",
            self._repo_path(owner, name)
            + "/git/ref/heads/"
            + urllib.parse.quote(branch, safe=""),
            allow_404=True,
        )
        if value is None:
            return None
        if not isinstance(value, dict):
            raise HistoricalGCError("branch ref response is invalid")
        return value

    def commit(
        self,
        owner: str,
        name: str,
        sha: str,
    ) -> dict[str, Any] | None:
        value = self.request(
            "GET",
            self._repo_path(owner, name) + "/git/commits/" + sha,
            allow_404=True,
        )
        if value is None:
            return None
        if not isinstance(value, dict):
            raise HistoricalGCError("commit response is invalid")
        return value

    def delete(self, owner: str, name: str) -> None:
        self.request("DELETE", self._repo_path(owner, name))

    def owned_prefixed_names(self, owner: str) -> set[str]:
        names: set[str] = set()
        page = 1
        while True:
            value = self.request(
                "GET",
                "/user/repos?"
                + urllib.parse.urlencode(
                    {
                        "affiliation": "owner",
                        "visibility": "all",
                        "per_page": 100,
                        "page": page,
                    }
                ),
            )
            if not isinstance(value, list):
                raise HistoricalGCError(
                    "owned repository inventory is invalid"
                )
            for raw in value:
                if not isinstance(raw, Mapping):
                    continue
                raw_owner = raw.get("owner")
                raw_name = raw.get("name")
                if (
                    isinstance(raw_name, str)
                    and raw_name.startswith("hermes-canary-")
                    and isinstance(raw_owner, Mapping)
                    and raw_owner.get("login") == owner
                ):
                    names.add(raw_name)
            if len(value) < 100:
                return names
            page += 1


def write_immutable(path: Path, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(
        dict(value),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_text(encoding="utf-8") != encoded:
            raise HistoricalGCError(f"immutable file conflicts: {path.name}")
        return
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


def _head_from_ref(value: Mapping[str, Any]) -> str:
    target = value.get("object")
    sha = str(target.get("sha") or "") if isinstance(target, Mapping) else ""
    if SHA40.fullmatch(sha) is None:
        raise HistoricalGCError("live repository head SHA is invalid")
    return sha


def _identity_projection(repository: Mapping[str, Any]) -> dict[str, Any]:
    owner = repository.get("owner")
    return {
        "id": repository.get("id"),
        "node_id": repository.get("node_id"),
        "name": repository.get("name"),
        "full_name": repository.get("full_name"),
        "private": repository.get("private"),
        "fork": repository.get("fork"),
        "owner_login": owner.get("login") if isinstance(owner, Mapping) else None,
        "default_branch": repository.get("default_branch"),
        "description": repository.get("description"),
        "archived": repository.get("archived"),
    }


def _ref_projection(reference: Mapping[str, Any]) -> dict[str, Any]:
    target = reference.get("object")
    return {
        "ref": reference.get("ref"),
        "node_id": reference.get("node_id"),
        "object_type": target.get("type") if isinstance(target, Mapping) else None,
        "object_sha": target.get("sha") if isinstance(target, Mapping) else None,
    }


def _commit_projection(commit: Mapping[str, Any]) -> dict[str, Any]:
    tree = commit.get("tree")
    return {
        "sha": commit.get("sha"),
        "message": commit.get("message"),
        "tree_sha": tree.get("sha") if isinstance(tree, Mapping) else None,
        "parent_shas": [
            str(parent.get("sha") or "")
            for parent in commit.get("parents", [])
            if isinstance(parent, Mapping)
        ],
    }


def verify_live_identity(
    entry: Mapping[str, Any],
    live_repository: Mapping[str, Any] | None,
    live_ref: Mapping[str, Any] | None,
    bootstrap_commit: Mapping[str, Any] | None,
) -> dict[str, Any]:
    owner = str(entry["repository_owner"])
    name = str(entry["repository_name"])
    if live_repository is None:
        body: dict[str, Any] = {
            "schema_version": "2.0",
            "repository_owner": owner,
            "repository_name": name,
            "status": "ALREADY_ABSENT",
            "repository_id": None,
            "repository_node_id": None,
            "head_sha": None,
            "metadata_digest": None,
            "ref_digest": None,
            "commit_digest": None,
        }
        return {
            **body,
            "attestation_entry_digest": digest(
                body,
                "attestation_entry_digest",
            ),
        }
    live_owner = live_repository.get("owner")
    repository_id = live_repository.get("id")
    node_id = live_repository.get("node_id")
    if (
        live_repository.get("name") != name
        or live_repository.get("full_name") != f"{owner}/{name}"
        or live_repository.get("private") is not True
        or live_repository.get("fork") is True
        or not isinstance(live_owner, Mapping)
        or live_owner.get("login") != owner
        or not isinstance(repository_id, int)
        or repository_id < 1
        or not isinstance(node_id, str)
        or not node_id
        or live_repository.get("default_branch")
        != entry.get("expected_default_branch")
        or live_ref is None
        or bootstrap_commit is None
    ):
        raise HistoricalGCError(
            "live historical repository identity differs"
        )
    head_sha = _head_from_ref(live_ref)
    if (
        head_sha != entry.get("expected_head_sha")
        or bootstrap_commit.get("sha") != entry.get("expected_bootstrap_sha")
        or bootstrap_commit.get("message") != entry.get("expected_commit_message")
    ):
        raise HistoricalGCError("live historical Git identity differs")
    known_id = entry.get("repository_id")
    if known_id is not None and repository_id != known_id:
        raise HistoricalGCError("live historical repository ID differs")
    description = live_repository.get("description")
    if entry.get("identity_proof_mode") == "FIXTURE_RECEIPT_ID_HEAD_V1":
        if description != entry.get("expected_description"):
            raise HistoricalGCError("fixture description differs")
        description_status = "EXACT"
    else:
        if description is not None and description != entry.get("expected_description"):
            raise HistoricalGCError("legacy product description differs")
        if (
            description is None
            and entry.get("legacy_description_exception")
            != "CREDENTIAL_BROKER_OMITTED_DESCRIPTION_V1"
        ):
            raise HistoricalGCError(
                "legacy null description is not authorized"
            )
        description_status = (
            "NULL_BROKER_OMISSION" if description is None else "EXACT"
        )
    body = {
        "schema_version": "2.0",
        "repository_owner": owner,
        "repository_name": name,
        "status": "ATTESTED",
        "repository_id": repository_id,
        "repository_node_id": node_id,
        "head_sha": head_sha,
        "description_status": description_status,
        "metadata_digest": hashlib.sha256(
            stable_json(_identity_projection(live_repository)).encode("utf-8")
        ).hexdigest(),
        "ref_digest": hashlib.sha256(
            stable_json(_ref_projection(live_ref)).encode("utf-8")
        ).hexdigest(),
        "commit_digest": hashlib.sha256(
            stable_json(_commit_projection(bootstrap_commit)).encode("utf-8")
        ).hexdigest(),
    }
    return {
        **body,
        "attestation_entry_digest": digest(
            body,
            "attestation_entry_digest",
        ),
    }


def validate_attestation(
    value: object,
    inventory: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HistoricalGCError("historical attestation is not an object")
    attestation = {str(key): item for key, item in value.items()}
    entries = attestation.get("repositories")
    if (
        attestation.get("schema_version") != "2.0"
        or attestation.get("inventory_digest")
        != inventory.get("inventory_digest")
        or attestation.get("repository_count") != 40
        or not isinstance(entries, list)
        or len(entries) != 40
        or attestation.get("attestation_digest")
        != digest(attestation, "attestation_digest")
    ):
        raise HistoricalGCError(
            "historical attestation digest or cardinality differs"
        )
    names: set[str] = set()
    for raw in entries:
        if (
            not isinstance(raw, Mapping)
            or raw.get("attestation_entry_digest")
            != digest(raw, "attestation_entry_digest")
        ):
            raise HistoricalGCError(
                "historical attestation entry differs"
            )
        name = str(raw.get("repository_name") or "")
        if not name or name in names:
            raise HistoricalGCError(
                "historical attestation repository identity is ambiguous"
            )
        names.add(name)
    return attestation


def unknown_repository_names(
    inventory: Mapping[str, Any],
    live_names: set[str],
) -> list[str]:
    known = {
        str(entry["repository_name"])
        for entry in inventory["repositories"]
    }
    return sorted(live_names - known)


def _live_evidence(
    client: GitHub,
    entry: Mapping[str, Any],
) -> tuple[
    dict[str, Any] | None,
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    owner = str(entry["repository_owner"])
    name = str(entry["repository_name"])
    live = client.repository(owner, name)
    if live is None:
        return None, None, None
    reference = client.branch_ref(
        owner,
        name,
        str(entry["expected_default_branch"]),
    )
    commit = client.commit(
        owner,
        name,
        str(entry["expected_bootstrap_sha"]),
    )
    return live, reference, commit


def attest(
    *,
    inventory: Mapping[str, Any],
    client: GitHub,
    owner: str,
    attestation_path: Path,
    receipt_root: Path,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    counts = {
        "attested": 0,
        "already_absent": 0,
        "refused": 0,
        "failed": 0,
    }
    for raw in inventory["repositories"]:
        entry = dict(raw)
        name = str(entry["repository_name"])
        try:
            live, reference, commit = _live_evidence(client, entry)
            result = verify_live_identity(entry, live, reference, commit)
            if result["status"] == "ATTESTED":
                counts["attested"] += 1
            else:
                counts["already_absent"] += 1
            receipt = {
                **result,
                "audit_label": entry["audit_label"],
                "scenario_id": entry["scenario_id"],
                "inventory_entry_digest": entry["entry_digest"],
            }
            receipt["attestation_entry_digest"] = digest(
                receipt,
                "attestation_entry_digest",
            )
            write_immutable(
                receipt_root
                / f"{entry['audit_label']}-{entry['scenario_id']}.json",
                receipt,
            )
            results.append(receipt)
        except HistoricalGCError as error:
            counts["refused"] += 1
            results.append(
                {
                    "repository_name": name,
                    "status": "REFUSED",
                    "reason": str(error),
                }
            )
        except Exception as error:  # noqa: BLE001 - report every entry
            counts["failed"] += 1
            results.append(
                {
                    "repository_name": name,
                    "status": "FAILED",
                    "reason": type(error).__name__,
                }
            )
    unknown = unknown_repository_names(
        inventory,
        client.owned_prefixed_names(owner),
    )
    body: dict[str, Any] = {
        "schema_version": "2.0",
        "inventory_digest": inventory["inventory_digest"],
        "repository_count": 40,
        "counts": counts,
        "unknown_qualification_repositories": unknown,
        "repositories": results,
        "status": (
            "PASS"
            if counts["attested"] + counts["already_absent"] == 40
            and counts["refused"] == 0
            and counts["failed"] == 0
            else "FAIL"
        ),
    }
    envelope = {
        **body,
        "attestation_digest": digest(body, "attestation_digest"),
    }
    write_immutable(attestation_path, envelope)
    return envelope


def _preflight_apply(
    *,
    inventory: Mapping[str, Any],
    attestation: Mapping[str, Any],
    client: GitHub,
) -> list[dict[str, Any]]:
    inventory_by_name = {
        str(entry["repository_name"]): dict(entry)
        for entry in inventory["repositories"]
    }
    attestation_by_name = {
        str(entry["repository_name"]): dict(entry)
        for entry in attestation["repositories"]
        if isinstance(entry, Mapping)
    }
    if set(inventory_by_name) != set(attestation_by_name):
        raise HistoricalGCError(
            "historical attestation does not cover exact inventory"
        )
    actions: list[dict[str, Any]] = []
    for name in sorted(inventory_by_name):
        entry = inventory_by_name[name]
        attested = attestation_by_name[name]
        live, reference, commit = _live_evidence(client, entry)
        current = verify_live_identity(entry, live, reference, commit)
        if live is None:
            actions.append(
                {
                    "action": "ALREADY_ABSENT",
                    "entry": entry,
                    "attested": attested,
                    "current": current,
                }
            )
            continue
        if (
            attested.get("status") != "ATTESTED"
            or current.get("repository_id") != attested.get("repository_id")
            or current.get("repository_node_id")
            != attested.get("repository_node_id")
            or current.get("head_sha") != attested.get("head_sha")
        ):
            raise HistoricalGCError(
                f"live identity changed after attestation: {name}"
            )
        actions.append(
            {
                "action": "DELETE",
                "entry": entry,
                "attested": attested,
                "current": current,
            }
        )
    if len(actions) != 40:
        raise HistoricalGCError("historical apply preflight cardinality differs")
    return actions


def apply(
    *,
    inventory: Mapping[str, Any],
    attestation: Mapping[str, Any],
    client: GitHub,
    owner: str,
    receipt_root: Path,
) -> dict[str, Any]:
    actions = _preflight_apply(
        inventory=inventory,
        attestation=attestation,
        client=client,
    )
    counts = {
        "deleted": 0,
        "already_absent": 0,
        "refused": 0,
        "failed": 0,
    }
    results: list[dict[str, Any]] = []
    for action in actions:
        entry = dict(action["entry"])
        attested = dict(action["attested"])
        name = str(entry["repository_name"])
        try:
            live, reference, commit = _live_evidence(client, entry)
            current = verify_live_identity(entry, live, reference, commit)
            if live is None:
                status = "ALREADY_ABSENT"
                counts["already_absent"] += 1
            else:
                if (
                    action["action"] != "DELETE"
                    or attested.get("status") != "ATTESTED"
                    or current.get("repository_id")
                    != attested.get("repository_id")
                    or current.get("repository_node_id")
                    != attested.get("repository_node_id")
                    or current.get("head_sha") != attested.get("head_sha")
                ):
                    raise HistoricalGCError(
                        "live identity changed during delete phase"
                    )
                client.delete(owner, name)
                if client.repository(owner, name) is not None:
                    raise HistoricalGCError(
                        "repository still exists after DELETE"
                    )
                status = "DELETED"
                counts["deleted"] += 1
            body: dict[str, Any] = {
                "schema_version": "2.0",
                "repository_owner": owner,
                "repository_name": name,
                "inventory_entry_digest": entry["entry_digest"],
                "attestation_entry_digest": attested[
                    "attestation_entry_digest"
                ],
                "status": status,
                "verified_get_status": 404,
            }
            receipt = {
                **body,
                "receipt_digest": digest(body, "receipt_digest"),
            }
            write_immutable(
                receipt_root
                / f"{entry['audit_label']}-{entry['scenario_id']}.json",
                receipt,
            )
            results.append(receipt)
        except HistoricalGCError as error:
            counts["refused"] += 1
            results.append(
                {
                    "repository_name": name,
                    "status": "REFUSED",
                    "reason": str(error),
                }
            )
        except Exception as error:  # noqa: BLE001 - report and resume idempotently
            counts["failed"] += 1
            results.append(
                {
                    "repository_name": name,
                    "status": "FAILED",
                    "reason": type(error).__name__,
                }
            )
    return {
        "schema_version": "2.0",
        "repository_count": 40,
        "preflight_count": len(actions),
        "counts": counts,
        "repositories": results,
        "status": (
            "PASS"
            if counts["deleted"] + counts["already_absent"] == 40
            and counts["refused"] == 0
            and counts["failed"] == 0
            else "FAIL"
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    attest_parser = commands.add_parser("attest")
    attest_parser.add_argument("--inventory", type=Path, required=True)
    attest_parser.add_argument("--owner", required=True)
    attest_parser.add_argument("--token-file", type=Path, required=True)
    attest_parser.add_argument("--attestation", type=Path, required=True)
    attest_parser.add_argument("--receipt-root", type=Path, required=True)
    apply_parser = commands.add_parser("apply")
    apply_parser.add_argument("--inventory", type=Path, required=True)
    apply_parser.add_argument("--attestation", type=Path, required=True)
    apply_parser.add_argument("--owner", required=True)
    apply_parser.add_argument("--token-file", type=Path, required=True)
    apply_parser.add_argument("--receipt-root", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        inventory = validate_inventory(
            json.loads(args.inventory.read_text(encoding="utf-8"))
        )
        if args.owner != inventory.get("owner"):
            raise HistoricalGCError("runtime owner differs from inventory")
        client = GitHub(read_token(args.token_file))
        if args.command == "attest":
            report = attest(
                inventory=inventory,
                client=client,
                owner=args.owner,
                attestation_path=args.attestation,
                receipt_root=args.receipt_root,
            )
        else:
            attestation = validate_attestation(
                json.loads(args.attestation.read_text(encoding="utf-8")),
                inventory,
            )
            if attestation.get("status") != "PASS":
                raise HistoricalGCError(
                    "historical attestation is not PASS"
                )
            report = apply(
                inventory=inventory,
                attestation=attestation,
                client=client,
                owner=args.owner,
                receipt_root=args.receipt_root,
            )
    except (
        HistoricalGCError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(
            json.dumps(
                {
                    "schema_version": "2.0",
                    "status": "FAIL",
                    "error_type": type(error).__name__,
                    "reason": str(error)[:500],
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
