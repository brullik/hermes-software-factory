from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import yaml

from factory.config import FactoryConfig
from factory.providers import ExternalBlocker
from factory.release_executor import ConfiguredReleaseExecutor, _release_digest

ROOT = Path(__file__).resolve().parents[1]


class FakeGitHub:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def pull_request_for_head_sha(self, expected_sha: str) -> str:
        self.calls.append(("find", expected_sha))
        return "17"

    def verify_pull_request(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("verify", (args, kwargs)))
        return None

    def merge_pull_request_checked(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("merge", (args, kwargs)))
        return None

    def merged_commit(self, pull_request: str) -> str:
        self.calls.append(("merged", pull_request))
        return "b" * 40


def make_config(root: Path) -> FactoryConfig:
    raw = yaml.safe_load((ROOT / "config" / "factory-config.example.yaml").read_text(encoding="utf-8"))
    raw["paths"]["state"] = str(root / "state")
    raw["paths"]["policies"] = str(ROOT / "policies")
    raw["paths"]["schemas"] = str(ROOT / "schemas")
    raw["paths"]["prompts"] = str(ROOT / "prompts")
    raw["paths"]["worktrees"] = str(root / "worktrees")
    raw["paths"]["logs"] = str(root / "logs")
    raw["controller"]["database_url"] = f"sqlite:///{(root / 'controller.db').as_posix()}"
    raw["deployment"]["staging_root"] = str(root / "staging")
    raw["deployment"]["production_helper"] = ""
    raw["backup"]["offsite_configured"] = False
    return FactoryConfig(raw, ROOT / "config" / "factory-config.example.yaml")


def workspace(root: Path) -> Path:
    source = root / "workspace"
    (source / "factory").mkdir(parents=True)
    (source / "scripts").mkdir()
    (source / "VERSION").write_text("2.0.0\n", encoding="utf-8")
    (source / "factory" / "module.py").write_text("release\n", encoding="utf-8")
    (source / "scripts" / "verify_manifest.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    (source / "SHA256SUMS").write_text("fixture\n", encoding="utf-8")
    return source


def proposal() -> dict[str, object]:
    return {
        "repository": "brullik/hermes-software-factory",
        "candidate_sha": "a" * 40,
    }


def test_staging_executor_derives_digest_and_promotes_transactionally() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        executor = ConfiguredReleaseExecutor(config, github=github)
        source = workspace(root)

        result = executor.execute(
            stage="staging",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=None,
        )

        assert result["status"] == "completed"
        assert result["candidate_sha"] == "a" * 40
        assert result["release"]["image_digest"] == _release_digest(source)
        assert result["staging"] == "deployed"
        assert result["production"] == "not_started"
        assert (root / "staging" / "P-RELEASE-001" / "current" / "VERSION").is_file()
        audit = list(config.evidence_dir.glob("release-adapter-*.json"))
        assert len(audit) == 1
        assert json.loads(audit[0].read_text(encoding="utf-8"))["pull_request"] == "17"


def test_production_requires_offsite_backup_before_governance_or_merge() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        executor = ConfiguredReleaseExecutor(config, github=github)
        source = workspace(root)
        digest = _release_digest(source)

        try:
            executor.execute(
                stage="production",
                proposed=proposal(),
                product_id="P-RELEASE-001",
                task_contract={"risk_tier": "medium"},
                workspace=source,
                expected_staging_digest=digest,
            )
        except ExternalBlocker as error:
            assert "offsite" in str(error).lower()
        else:
            raise AssertionError("production should be blocked without offsite backup")

        assert [name for name, _ in github.calls] == ["find"]
