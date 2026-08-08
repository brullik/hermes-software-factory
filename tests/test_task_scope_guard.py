from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from scripts.task_scope_guard import CONTRACT_PATH, ScopeViolation, evaluate

GOAL_DIGEST = "031b0f3414532cb26781bb6637ae0f456c94a5270aeaca7c852e13b29bce6497"
EVIDENCE_DIGEST = "1" * 64
NOW = datetime(2026, 8, 8, 16, 0, tzinfo=UTC)


class TaskScopeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Scope Guard Test")
        self.git("config", "user.email", "scope-guard@example.invalid")
        (self.repo / "README.md").write_text("base\n", encoding="utf-8")
        self.git("add", "README.md")
        self.git("commit", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.branch = "codex/test-scope-guard"
        self.git("switch", "-c", self.branch)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()

    def freeze(self, *, max_additions: int = 200) -> None:
        contract = {
            "schema_version": "1.0",
            "contract_id": "test.scope-guard.contract",
            "original_goal_digest": GOAL_DIGEST,
            "product_id": "hermes-software-factory",
            "task_id": "test-scope-guard",
            "branch": self.branch,
            "trusted_base_sha": self.base,
            "allowed_paths": [CONTRACT_PATH, "docs/canary.md"],
            "forbidden_paths": [".git/**", "config/systemd/hermes-factory-gateway.service"],
            "max_changed_files": 2,
            "max_additions": max_additions,
            "max_deletions": 0,
            "rationale": "Exercise the immutable merge-base scope guard with a bounded fixture.",
            "approved_by": "desktop-bootstrap",
            "approval_evidence_ref": f"artifact://desktop-bootstrap/{EVIDENCE_DIGEST}",
            "approval_evidence_digest": EVIDENCE_DIGEST,
            "created_at": "2026-08-08T00:00:00Z",
            "expires_at": "2030-08-08T00:00:00Z",
            "parent_contract_digest": None,
            "contract_digest": "",
        }
        canonical = json.dumps(
            {key: value for key, value in contract.items() if key != "contract_digest"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        contract["contract_digest"] = hashlib.sha256(canonical).hexdigest()
        path = self.repo / CONTRACT_PATH
        path.parent.mkdir()
        path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.git("add", CONTRACT_PATH)
        self.git("commit", "-m", "freeze contract")

    def assess(self) -> dict[str, object]:
        return evaluate(
            self.repo,
            base_ref=self.base,
            head_ref="HEAD",
            branch=self.branch,
            original_goal_digest=GOAL_DIGEST,
            now=NOW,
        )

    def test_allowed_path_passes(self) -> None:
        self.freeze()
        path = self.repo / "docs" / "canary.md"
        path.parent.mkdir()
        path.write_text("neutral canary\n", encoding="utf-8")
        self.git("add", "docs/canary.md")
        self.git("commit", "-m", "allowed")
        self.assertEqual(self.assess()["status"], "PASS")

    def test_path_outside_contract_fails(self) -> None:
        self.freeze()
        path = self.repo / "factory" / "outside.py"
        path.parent.mkdir()
        path.write_text("outside = True\n", encoding="utf-8")
        self.git("add", "factory/outside.py")
        self.git("commit", "-m", "outside")
        with self.assertRaisesRegex(ScopeViolation, "outside frozen scope"):
            self.assess()

    def test_contract_mutation_after_first_commit_fails(self) -> None:
        self.freeze()
        path = self.repo / CONTRACT_PATH
        value = json.loads(path.read_text(encoding="utf-8"))
        value["rationale"] += " Mutation."
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.git("add", CONTRACT_PATH)
        self.git("commit", "-m", "mutate contract")
        with self.assertRaisesRegex(ScopeViolation, "modified after the first commit"):
            self.assess()

    def test_line_budget_fails(self) -> None:
        self.freeze(max_additions=40)
        path = self.repo / "docs" / "canary.md"
        path.parent.mkdir()
        path.write_text("".join(f"line-{index}\n" for index in range(20)), encoding="utf-8")
        self.git("add", "docs/canary.md")
        self.git("commit", "-m", "exceed budget")
        with self.assertRaisesRegex(ScopeViolation, "addition budget exceeded"):
            self.assess()


if __name__ == "__main__":
    unittest.main()
