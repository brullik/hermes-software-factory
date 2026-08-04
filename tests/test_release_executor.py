from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from factory.config import FactoryConfig
from factory.github import GitHubCommandError, RequiredChecksStatus
from factory.providers import ExternalBlocker
from factory.release_executor import (
    CandidateChecksFailed,
    ConfiguredReleaseExecutor,
    _release_digest,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeGitHub:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.created = False
        self.candidate_sha = ""
        self.is_merged = False

    def create_pull_request(self, **kwargs: Any) -> None:
        self.calls.append(("create", kwargs))
        self.created = True

    def pull_request_for_head_sha(self, expected_sha: str) -> str:
        self.calls.append(("find", expected_sha))
        self.candidate_sha = expected_sha
        if not self.created:
            raise GitHubCommandError("no pull request")
        return "17"

    def verify_pull_request(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("verify", (args, kwargs)))

    def required_checks_status(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
    ) -> RequiredChecksStatus:
        self.calls.append(("checks", (pull_request, expected_sha, required_checks)))
        return RequiredChecksStatus(
            pull_request,
            expected_sha,
            tuple((name, "SUCCESS") for name in required_checks),
            required_checks,
            (),
            (),
        )

    def close_pull_request(self, pull_request: str) -> None:
        self.calls.append(("close", pull_request))

    def merge_pull_request_checked(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(("merge", (args, kwargs)))
        self.is_merged = True

    def merged_commit(self, pull_request: str) -> str:
        self.calls.append(("merged", pull_request))
        if not self.is_merged:
            raise GitHubCommandError("pull request is not merged")
        return "b" * 40


class AllowlistedRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[0] == "git" and "push" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0].endswith("sudo") or argv[0].endswith("sudo.exe"):
            release_id = argv[argv.index("--release-id") + 1]
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"status": "PROMOTED", "release_id": release_id}) + "\n",
                "",
            )
        return subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )


class FailingCheckGitHub(FakeGitHub):
    def required_checks_status(
        self,
        pull_request: str,
        *,
        expected_sha: str,
        required_checks: tuple[str, ...],
    ) -> RequiredChecksStatus:
        self.calls.append(("checks", (pull_request, expected_sha, required_checks)))
        return RequiredChecksStatus(
            pull_request,
            expected_sha,
            tuple((name, "FAILURE") for name in required_checks),
            (),
            (),
            required_checks,
        )


def run_git(source: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


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
    (source / "src" / "product").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "artifacts").mkdir()
    (source / "pyproject.toml").write_text(
        '[project]\nname = "product"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    (source / "README.md").write_text("baseline\n", encoding="utf-8")
    (source / "src" / "product" / "__init__.py").write_text("", encoding="utf-8")
    run_git(source, "init", "--initial-branch=main")
    run_git(source, "remote", "add", "origin", "https://github.com/brullik/bybit-grid-research.git")
    run_git(source, "add", ".")
    run_git(
        source,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "baseline",
    )
    run_git(source, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    (source / "README.md").write_text("candidate\n", encoding="utf-8")
    (source / "tests" / "test_product.py").write_text("def test_product():\n    assert True\n", encoding="utf-8")
    (source / "artifacts" / "runtime.json").write_text('{"generated": true}\n', encoding="utf-8")
    return source


def proposal(product_id: str = "P-RELEASE-001") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "artifact_id": "release-operation-fixture",
        "product_id": product_id,
        "created_at": "2026-07-28T00:00:00Z",
        "producer": {"role": "release-operator", "tier": "terra"},
        "policy_digest": "a" * 64,
        "repository": "attacker/ignored",
        "candidate_sha": "f" * 40,
    }


def make_executor(
    config: FactoryConfig,
    github: FakeGitHub,
    runner: AllowlistedRunner,
) -> ConfiguredReleaseExecutor:
    return ConfiguredReleaseExecutor(
        config,
        github_factory=lambda _owner, _repository: github,
        command_runner=runner,
        assurance_runner=lambda _workspace, candidate_sha: {
            gate_id: {"status": "PASS", "subject_sha": candidate_sha}
            for gate_id in (
                "target-secret-scan",
                "target-sast",
                "target-dependency-audit",
                "target-license-check",
            )
        },
    )


def test_staging_publishes_controller_owned_candidate_and_excludes_runtime_artifacts() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        runner = AllowlistedRunner()
        executor = make_executor(config, github, runner)
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
        assert result["repository"] == "brullik/bybit-grid-research"
        assert result["candidate_sha"] == run_git(source, "rev-parse", "HEAD")
        assert result["candidate_sha"] != proposal()["candidate_sha"]
        assert result["release"]["version"] == "1.2.3"
        assert result["staging"] == "deployed"
        assert result["production"] == "not_started"
        staged = root / "staging" / "P-RELEASE-001" / "current"
        assert (staged / "tests" / "test_product.py").is_file()
        assert not (staged / "artifacts").exists()
        assert not (staged / ".git").exists()
        assert run_git(source, "ls-tree", "-r", "--name-only", "HEAD").find("artifacts/") == -1
        assert any(name == "create" for name, _ in github.calls)
        assert any(call[0] == "git" and "push" in call for call in runner.calls)
        record = json.loads(
            (root / "staging" / "P-RELEASE-001" / "release.json").read_text(encoding="utf-8")
        )
        assert record["candidate_sha"] == result["candidate_sha"]
        assert record["image_digest"] == _release_digest(staged)
        audit = list(config.evidence_dir.glob("release-adapter-staging-*.json"))
        assert len(audit) == 1
        assert json.loads(audit[0].read_text(encoding="utf-8"))["pull_request"] == "17"


def test_failed_pm_acceptance_closes_candidate_and_restores_main_for_repair() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FailingCheckGitHub()
        runner = AllowlistedRunner()
        executor = make_executor(config, github, runner)
        source = workspace(root)

        try:
            executor.execute(
                stage="staging",
                proposed=proposal(),
                product_id="P-RELEASE-001",
                task_contract={"risk_tier": "medium"},
                workspace=source,
                expected_staging_digest=None,
            )
        except CandidateChecksFailed as error:
            assert error.reason_code == "pm_acceptance_failed"
            evidence = config.evidence_dir / Path(error.evidence_ref).name
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            assert payload["failed"] == ["pm-acceptance"]
            assert "pm-acceptance" in payload["summary"]
        else:
            raise AssertionError("failed pm-acceptance must schedule code repair")

        assert ("close", "17") in github.calls
        assert run_git(source, "branch", "--show-current") == "main"
        assert (source / "README.md").read_text(encoding="utf-8") == "baseline\n"
        assert not (source / "tests" / "test_product.py").exists()
        assert not (source / "artifacts").exists()


def test_candidate_publisher_rejects_workflow_changes() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        runner = AllowlistedRunner()
        executor = make_executor(config, github, runner)
        source = workspace(root)
        workflow = source / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: unsafe\n", encoding="utf-8")

        try:
            executor.execute(
                stage="staging",
                proposed=proposal(),
                product_id="P-RELEASE-001",
                task_contract={"risk_tier": "medium"},
                workspace=source,
                expected_staging_digest=None,
            )
        except ExternalBlocker as error:
            assert "protected path" in str(error)
        else:
            raise AssertionError("workflow mutation should be blocked")

        assert not any(call[0] == "git" and "push" in call for call in runner.calls)


def test_staging_fails_closed_when_same_candidate_assurance_fails() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        runner = AllowlistedRunner()
        executor = ConfiguredReleaseExecutor(
            config,
            github_factory=lambda _owner, _repository: github,
            command_runner=runner,
            assurance_runner=lambda _workspace, candidate_sha: {
                gate_id: {
                    "status": "FAIL" if gate_id == "target-sast" else "PASS",
                    "subject_sha": candidate_sha,
                }
                for gate_id in (
                    "target-secret-scan",
                    "target-sast",
                    "target-dependency-audit",
                    "target-license-check",
                )
            },
        )
        source = workspace(root)

        try:
            executor.execute(
                stage="staging",
                proposed=proposal(),
                product_id="P-RELEASE-001",
                task_contract={"risk_tier": "medium"},
                workspace=source,
                expected_staging_digest=None,
            )
        except ExternalBlocker as error:
            assert "target-sast" in str(error)
        else:
            raise AssertionError("failed same-candidate assurance should block staging")

        assert not (root / "staging" / "P-RELEASE-001" / "current").exists()


def test_production_requires_offsite_backup_before_governance_or_merge() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        runner = AllowlistedRunner()
        executor = make_executor(config, github, runner)
        source = workspace(root)
        staging = executor.execute(
            stage="staging",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=None,
        )
        github.calls.clear()

        try:
            executor.execute(
                stage="production",
                proposed=proposal(),
                product_id="P-RELEASE-001",
                task_contract={"risk_tier": "medium"},
                workspace=source,
                expected_staging_digest=str(staging["release"]["image_digest"]),
            )
        except ExternalBlocker as error:
            assert "offsite" in str(error).lower()
        else:
            raise AssertionError("production should be blocked without offsite backup")

        assert github.calls == []


def test_production_merges_staged_candidate_and_calls_product_helper() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.raw["backup"]["offsite_configured"] = True
        config.raw["deployment"]["production_helper"] = "/usr/local/sbin/hermes-factory-release-submit"
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        runner = AllowlistedRunner()
        executor = make_executor(config, github, runner)
        source = workspace(root)
        staging = executor.execute(
            stage="staging",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=None,
        )

        result = executor.execute(
            stage="production",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=str(staging["release"]["image_digest"]),
        )

        assert result["candidate_sha"] == "b" * 40
        assert result["merge"] == {"performed": True, "merge_sha": "b" * 40}
        assert result["production"] == "deployed"
        helper = next(call for call in runner.calls if call[0].endswith("sudo") or call[0].endswith("sudo.exe"))
        assert "--product-id" in helper
        assert helper[helper.index("--product-id") + 1] == "P-RELEASE-001"
        assert helper[helper.index("--repository") + 1] == "brullik/bybit-grid-research"


def test_production_reconcile_observes_merged_pr_without_second_merge() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = make_config(root)
        config.raw["backup"]["offsite_configured"] = True
        config.raw["deployment"]["production_helper"] = (
            "/usr/local/sbin/hermes-factory-release-submit"
        )
        config.state_dir.mkdir(parents=True)
        github = FakeGitHub()
        runner = AllowlistedRunner()
        executor = make_executor(config, github, runner)
        source = workspace(root)
        staging = executor.execute(
            stage="staging",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=None,
        )
        digest = str(staging["release"]["image_digest"])
        executor.execute(
            stage="production",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=digest,
        )

        reconciled = executor.reconcile(
            stage="production",
            proposed=proposal(),
            product_id="P-RELEASE-001",
            task_contract={"risk_tier": "medium"},
            workspace=source,
            expected_staging_digest=digest,
        )

        merge_calls = [call for call in github.calls if call[0] == "merge"]
        assert len(merge_calls) == 1
        assert reconciled["merge"] == {"performed": True, "merge_sha": "b" * 40}
        assert reconciled["production"] == "deployed"


def test_release_digest_ignores_git_metadata() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        (source / "file.txt").write_text("content\n", encoding="utf-8")
        expected = _release_digest(source)
        (source / ".git").mkdir()
        (source / ".git" / "index").write_text("mutable metadata\n", encoding="utf-8")
        cache = source / "package" / "__pycache__"
        cache.mkdir(parents=True)
        (cache / "module.cpython-312.pyc").write_bytes(b"runtime bytecode")
        assert _release_digest(source) == expected
