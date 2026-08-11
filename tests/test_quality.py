from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from test_worker import make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.config import FactoryConfig
from factory.quality import QualityGateEngine, UnknownQualityGatesError
from scripts.quality_gate import _BoundedProcessResult, _git_changed_paths, run_gate


def _single_python_gate_engine(
    root: Path,
    *,
    gate_id: str,
    command: str,
) -> QualityGateEngine:
    base_config = make_config(
        root,
        selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
    )
    catalog = root / "quality-gates-test.yaml"
    catalog.write_text(
        yaml.safe_dump(
            {
                "version": "1.0",
                "gates": [
                    {
                        "id": gate_id,
                        "command": command,
                        "allowlist_prefixes": ["python3 -m"],
                        "timeout_seconds": 10,
                        "mandatory": True,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config = FactoryConfig(base_config.raw, root / "factory.yaml")
    config.raw["paths"]["quality_gates"] = str(catalog)
    return QualityGateEngine(config, ArtifactStore(config))


def test_python_gates_use_candidate_interpreter(tmp_path: Path) -> None:
    workspace = tmp_path / "candidate"
    workspace.mkdir()
    candidate_python = tmp_path / "venv" / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python"
    )
    candidate_python.parent.mkdir(parents=True)
    candidate_python.write_text("candidate interpreter fixture\n", encoding="utf-8")
    engine = _single_python_gate_engine(
        tmp_path,
        gate_id="target-tests",
        command="python3 -m pytest -q",
    )
    calls: list[list[str]] = []

    def record(
        argv: list[str],
        **_kwargs: object,
    ) -> _BoundedProcessResult:
        calls.append(argv)
        return _BoundedProcessResult(0, "pass", "", False, (), False)

    with patch("scripts.quality_gate._run_bounded_python_gate", side_effect=record):
        result = engine.run(
            cwd=workspace,
            subject_sha="1" * 64,
            task_id="T-CANDIDATE-PYTHON",
            attempt_id="A-CANDIDATE-PYTHON",
            gate_ids=["target-tests"],
        )

    assert result.mandatory_passed
    assert calls[0][0] == str(candidate_python)
    assert calls[0][1:] == ["-m", "pytest", "-q"]


def test_controller_helper_is_outside_workspace_diff(tmp_path: Path) -> None:
    workspace = tmp_path / "candidate"
    workspace.mkdir()
    subprocess.run(
        ["git", "init", "-q"],
        cwd=workspace,
        check=True,
        capture_output=True,
    )
    tracked = workspace / "README.md"
    tracked.write_text("candidate\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "README.md"],
        cwd=workspace,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Hermes Test",
            "-c",
            "user.email=hermes@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        cwd=workspace,
        check=True,
        capture_output=True,
    )
    engine = _single_python_gate_engine(
        tmp_path,
        gate_id="target-compile",
        command="python3 -m compileall -q src tests",
    )
    observed_helper: list[Path] = []

    def record_helper(
        argv: list[str],
        **kwargs: object,
    ) -> _BoundedProcessResult:
        environment = kwargs.get("environment")
        assert isinstance(environment, dict)
        helper = Path(str(environment["PYTHONPYCACHEPREFIX"])) / "controller-helper.py"
        helper.write_text("controller owned\n", encoding="utf-8")
        observed_helper.append(helper)
        return _BoundedProcessResult(0, "pass", "", False, (), False)

    with patch(
        "scripts.quality_gate._run_bounded_python_gate",
        side_effect=record_helper,
    ):
        result = engine.run(
            cwd=workspace,
            subject_sha="2" * 64,
            task_id="T-HELPER-SCOPE",
            attempt_id="A-HELPER-SCOPE",
            gate_ids=["target-compile"],
        )

    assert result.mandatory_passed
    assert len(observed_helper) == 1
    observed_helper[0].relative_to(engine.config.state_dir)
    with pytest.raises(ValueError):
        observed_helper[0].relative_to(workspace)
    assert _git_changed_paths(workspace) == []


class QualityGateTests(unittest.TestCase):
    def test_changed_target_paths_trusts_only_the_exact_resolved_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "target"
            repository.mkdir()
            calls: list[list[str]] = []

            def run_git(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
                calls.append(argv)
                return subprocess.CompletedProcess(
                    argv,
                    1 if "symbolic-ref" in argv else 0,
                    stdout=b"",
                    stderr=b"",
                )

            with patch("scripts.quality_gate.subprocess.run", side_effect=run_git):
                self.assertEqual(_git_changed_paths(repository), [])

            exact_trust = f"safe.directory={repository.resolve().as_posix()}"
            self.assertEqual(len(calls), 3)
            for argv in calls:
                self.assertEqual(argv[:3], ["git", "-c", exact_trust])
                self.assertNotIn("--global", argv)
            for argv in (calls[1],):
                self.assertIn("--no-ext-diff", argv)
                self.assertIn("--no-textconv", argv)

    def test_compile_gate_redirects_bytecode_outside_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src" / "sample.py"
            test_file = root / "tests" / "test_sample.py"
            source.parent.mkdir()
            test_file.parent.mkdir()
            source.write_text("VALUE = 1\n", encoding="utf-8")
            test_file.write_text("from src.sample import VALUE\n", encoding="utf-8")
            gate = {
                "id": "target-compile",
                "command": "python3 -m compileall -q src tests",
                "allowlist_prefixes": ["python3 -m compileall"],
                "mandatory": True,
            }

            result = run_gate(
                gate,
                root,
                "a" * 64,
                python_executable=sys.executable,
            )

            self.assertEqual(result["status"], "PASS")
            self.assertEqual(list(root.rglob("*.pyc")), [])
            self.assertEqual(list(root.rglob("__pycache__")), [])

    def test_allowlisted_gates_persist_evidence_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_root = root / "state"
            workspace = root / "candidate"
            workspace.mkdir()
            base_config = make_config(
                state_root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            config_root = root / "config"
            config_root.mkdir()
            (config_root / "factory.yaml").write_text("version: '1.0'\n", encoding="utf-8")
            (config_root / "quality-gates.yaml").write_text(
                yaml.safe_dump(
                    {
                        "version": "1.0",
                        "gates": [
                            {
                                "id": "pass-gate",
                                "command": "python3 -c \"print(1)\"",
                                "allowlist_prefixes": ["python3 -c"],
                                "timeout_seconds": 10,
                                "mandatory": True,
                            },
                            {
                                "id": "optional-fail",
                                "command": "python3 -c \"raise SystemExit(3)\"",
                                "allowlist_prefixes": ["python3 -c"],
                                "timeout_seconds": 10,
                                "mandatory": False,
                            },
                            {
                                "id": "expected-nonzero",
                                "command": "python3 -c \"raise SystemExit(3)\"",
                                "allowlist_prefixes": ["python3 -c"],
                                "success_exit_codes": [3],
                                "timeout_seconds": 10,
                                "mandatory": True,
                            },
                        ],
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            config = FactoryConfig(base_config.raw, config_root / "factory.yaml")
            config.raw["paths"]["quality_gates"] = str(config_root / "quality-gates.yaml")
            engine = QualityGateEngine(config, ArtifactStore(config))

            run = engine.run(
                cwd=workspace,
                subject_sha="a" * 64,
                task_id="T-QUALITY-001",
                attempt_id="attempt-quality-001",
                gate_ids=["pass-gate", "optional-fail", "expected-nonzero"],
            )

            self.assertTrue(run.mandatory_passed)
            self.assertEqual(
                [result["status"] for result in run.results],
                ["PASS", "FAIL", "PASS"],
            )
            self.assertEqual(len(run.evidence_paths), 3)
            for path in run.evidence_paths:
                self.assertEqual(ArtifactStore(config).validate("gate-evidence.schema.json", yaml.safe_load(path.read_text(encoding="utf-8"))), [])
            with self.assertRaises(UnknownQualityGatesError) as caught:
                engine.run(
                    cwd=workspace,
                    subject_sha="a" * 64,
                    task_id="T-QUALITY-002",
                    attempt_id="attempt-quality-002",
                    gate_ids=["unknown-gate"],
                )
            self.assertEqual(caught.exception.gate_ids, ("unknown-gate",))

    def test_target_secret_scan_ignores_baseline_and_fails_on_changed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "target"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "factory-tests@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Factory Tests"],
                cwd=repository,
                check=True,
            )
            secret_marker = "sk-" + ("A" * 24)
            (repository / "baseline.py").write_text(
                f"FIXTURE = {secret_marker!r}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "baseline.py"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repository, check=True)

            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            engine = QualityGateEngine(config, ArtifactStore(config))
            baseline_run = engine.run(
                cwd=repository,
                subject_sha="b" * 64,
                task_id="T-QUALITY-BASELINE",
                attempt_id="attempt-quality-baseline",
                gate_ids=["target-secret-scan"],
            )
            self.assertTrue(baseline_run.mandatory_passed)

            (repository / "changed.py").write_text(
                f"NEW_VALUE = {secret_marker!r}\n",
                encoding="utf-8",
            )
            changed_run = engine.run(
                cwd=repository,
                subject_sha="c" * 64,
                task_id="T-QUALITY-CHANGED",
                attempt_id="attempt-quality-changed",
                gate_ids=["target-secret-scan"],
            )
            self.assertFalse(changed_run.mandatory_passed)
            evidence = json.loads(changed_run.evidence_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "FAIL")
            self.assertIn("changed.py", evidence["summary"])
            self.assertNotIn(secret_marker, evidence["summary"])

    def test_target_secret_scan_accepts_an_exact_broker_owned_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "target"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "factory-tests@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Factory Tests"],
                cwd=repository,
                check=True,
            )
            (repository / "baseline.py").write_text("BASELINE = True\n", encoding="utf-8")
            subprocess.run(["git", "add", "baseline.py"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repository, check=True)
            (repository / "changed.py").write_text("CHANGED = True\n", encoding="utf-8")

            different_owner_environment = os.environ.copy()
            different_owner_environment["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"
            probe = subprocess.run(
                ["git", "status", "--short"],
                cwd=repository,
                env=different_owner_environment,
                capture_output=True,
                check=False,
            )
            if probe.returncode == 0:
                self.skipTest("Git cannot simulate a broker-owned worktree on this platform")

            with patch.dict(
                os.environ,
                {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"},
            ):
                result = run_gate(
                    {
                        "id": "target-secret-scan",
                        "adapter": "target_changed_secret_scan",
                        "command": "controller:target-changed-secret-scan",
                        "allowlist_prefixes": ["controller:target-changed-secret-scan"],
                        "mandatory": True,
                    },
                    repository,
                    "d" * 64,
                )

            self.assertEqual(result["status"], "PASS", result)
            self.assertEqual(
                result["summary"],
                "no secret-like content detected in changed target files",
            )

    def test_target_sast_scans_only_changed_source_and_fails_on_bandit_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "target"
            source = repository / "src" / "sample.py"
            source.parent.mkdir(parents=True)
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "factory-tests@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Factory Tests"],
                cwd=repository,
                check=True,
            )
            source.write_text("def parse(value: str) -> str:\n    return value\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/sample.py"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repository, check=True)

            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            engine = QualityGateEngine(config, ArtifactStore(config))
            baseline_run = engine.run(
                cwd=repository,
                subject_sha="d" * 64,
                task_id="T-SAST-BASELINE",
                attempt_id="attempt-sast-baseline",
                gate_ids=["target-sast"],
            )
            self.assertTrue(baseline_run.mandatory_passed)

            source.write_text(
                "def parse(value: str) -> object:\n    return eval(value)\n",
                encoding="utf-8",
            )
            unsafe_run = engine.run(
                cwd=repository,
                subject_sha="e" * 64,
                task_id="T-SAST-UNSAFE",
                attempt_id="attempt-sast-unsafe",
                gate_ids=["target-sast"],
            )
            self.assertFalse(unsafe_run.mandatory_passed)
            evidence = json.loads(unsafe_run.evidence_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "FAIL")
            self.assertIn("S307", evidence["summary"])

    def test_target_sast_scans_committed_candidate_against_remote_default_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "target"
            source = repository / "src" / "sample.py"
            source.parent.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "factory-tests@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Factory Tests"],
                cwd=repository,
                check=True,
            )
            source.write_text("def parse(value: str) -> str:\n    return value\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/sample.py"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repository, check=True)
            subprocess.run(
                ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"],
                cwd=repository,
                check=True,
            )
            subprocess.run(["git", "switch", "-q", "-c", "candidate"], cwd=repository, check=True)
            source.write_text(
                "def parse(value: str) -> object:\n    return eval(value)\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "src/sample.py"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "candidate"], cwd=repository, check=True)

            config = make_config(
                root,
                selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"),
            )
            engine = QualityGateEngine(config, ArtifactStore(config))
            run = engine.run(
                cwd=repository,
                subject_sha=subprocess.check_output(
                    ["git", "rev-parse", "HEAD"],
                    cwd=repository,
                    text=True,
                ).strip(),
                task_id="T-SAST-COMMITTED",
                attempt_id="attempt-sast-committed",
                gate_ids=["target-sast"],
            )

            self.assertFalse(run.mandatory_passed)
            evidence = json.loads(run.evidence_paths[0].read_text(encoding="utf-8"))
            self.assertEqual(evidence["status"], "FAIL")
            self.assertIn("S307", evidence["summary"])

    @staticmethod
    def _offline_dependency_gate(root: Path, scanner: Path) -> dict[str, object]:
        return {
            "id": "target-dependency-audit",
            "adapter": "target_dependency_audit",
            "command": "controller:target-dependency-audit",
            "allowlist_prefixes": ["controller:target-dependency-audit"],
            "scanner_path": str(scanner),
            "scanner_sha256": hashlib.sha256(scanner.read_bytes()).hexdigest(),
            "database_cache_directory": str(root / "osv-cache"),
            "database_max_age_seconds": 3600,
            "mandatory": True,
        }

    def test_target_dependency_audit_is_offline_and_records_vulnerabilities(self) -> None:
        payload = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "example",
                                "version": "1.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [{"id": "PYSEC-TEST-1"}],
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "osv-scanner"
            scanner.write_bytes(b"verified-scanner")
            database = root / "osv-cache" / "osv-scanner" / "PyPI" / "all.zip"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"verified-database")
            gate = self._offline_dependency_gate(root, scanner)

            def offline_runner(
                args: list[str],
                **kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                self.assertIn("--offline", args)
                self.assertIn("--no-resolve", args)
                lockfile_argument = next(
                    argument for argument in args if argument.startswith("--lockfile=osv-scanner:")
                )
                inventory_path = Path(lockfile_argument.split(":", 1)[1])
                inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
                package = inventory["results"][0]["packages"][0]["package"]
                self.assertEqual(package, {"ecosystem": "PyPI", "name": "example", "version": "1.0"})
                environment = kwargs["env"]
                self.assertIsInstance(environment, dict)
                self.assertEqual(
                    environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"],  # type: ignore[index]
                    str(root / "osv-cache"),
                )
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=1,
                    stdout=json.dumps(payload),
                    stderr="",
                )

            with (
                patch("scripts.quality_gate._target_site_packages", return_value=root),
                patch(
                    "scripts.quality_gate._runtime_dependency_records",
                    return_value=(
                        [{"name": "example", "version": "1.0", "license": "MIT"}],
                        ["example"],
                    ),
                ),
                patch("scripts.quality_gate.subprocess.run", side_effect=offline_runner),
            ):
                result = run_gate(
                    gate,
                    root,
                    "f" * 64,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("example:PYSEC-TEST-1", result["summary"])
        self.assertIn("inventory_sha256=", result["summary"])
        self.assertIn("network_mode=offline", result["summary"])

    def test_target_dependency_audit_fails_closed_when_database_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "osv-scanner"
            scanner.write_bytes(b"verified-scanner")
            database = root / "osv-cache" / "osv-scanner" / "PyPI" / "all.zip"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"stale-database")
            os.utime(database, (1, 1))
            gate = self._offline_dependency_gate(root, scanner)
            gate["database_max_age_seconds"] = 10
            with (
                patch("scripts.quality_gate._target_site_packages", return_value=root),
                patch(
                    "scripts.quality_gate._runtime_dependency_records",
                    return_value=(
                        [{"name": "example", "version": "1.0", "license": "MIT"}],
                        ["example"],
                    ),
                ),
                patch("scripts.quality_gate.time.time", return_value=100),
                patch("scripts.quality_gate.subprocess.run") as scanner_runner,
            ):
                result = run_gate(
                    gate,
                    root,
                    "2" * 64,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "ERROR")
        self.assertIsNone(result["exit_code"])
        self.assertIn("database is stale", result["summary"])
        scanner_runner.assert_not_called()

    def test_CARD_P0_malformed_scanner_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "osv-scanner"
            scanner.write_bytes(b"verified-scanner")
            database = root / "osv-cache" / "osv-scanner" / "PyPI" / "all.zip"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"verified-database")
            gate = self._offline_dependency_gate(root, scanner)
            malformed = subprocess.CompletedProcess(
                args=[str(scanner)],
                returncode=0,
                stdout="{not-json",
                stderr="",
            )
            with (
                patch("scripts.quality_gate._target_site_packages", return_value=root),
                patch(
                    "scripts.quality_gate._runtime_dependency_records",
                    return_value=(
                        [{"name": "example", "version": "1.0", "license": "MIT"}],
                        ["example"],
                    ),
                ),
                patch("scripts.quality_gate.subprocess.run", return_value=malformed),
            ):
                result = run_gate(
                    gate,
                    root,
                    "5" * 64,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "ERROR")
        self.assertIsNone(result["exit_code"])
        self.assertIn("target dependency audit failed closed", result["summary"])

    def test_target_dependency_audit_attests_explicit_zero_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "osv-scanner"
            scanner.write_bytes(b"verified-scanner")
            gate = self._offline_dependency_gate(root, scanner)
            (root / "pyproject.toml").write_text(
                "[project]\nname='candidate'\nversion='1.0'\ndependencies=[]\n",
                encoding="utf-8",
            )
            source = root / "src" / "candidate" / "__init__.py"
            source.parent.mkdir(parents=True)
            source.write_text("import json\nfrom pathlib import Path\n", encoding="utf-8")
            with (
                patch("scripts.quality_gate._target_site_packages", return_value=root),
                patch("scripts.quality_gate.subprocess.run") as scanner_runner,
            ):
                result = run_gate(
                    gate,
                    root,
                    "3" * 64,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("audited_runtime_packages=0", result["summary"])
        self.assertIn("zero_dependency_attestation_sha256=", result["summary"])
        self.assertIn("scanner_mode=not_applicable", result["summary"])
        scanner_runner.assert_not_called()

    def test_zero_dependency_attestation_rejects_undeclared_runtime_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scanner = root / "osv-scanner"
            scanner.write_bytes(b"verified-scanner")
            gate = self._offline_dependency_gate(root, scanner)
            (root / "pyproject.toml").write_text(
                "[project]\nname='candidate'\nversion='1.0'\ndependencies=[]\n",
                encoding="utf-8",
            )
            source = root / "src" / "candidate" / "__init__.py"
            source.parent.mkdir(parents=True)
            source.write_text("import requests\n", encoding="utf-8")
            with (
                patch("scripts.quality_gate._target_site_packages", return_value=root),
                patch("scripts.quality_gate.subprocess.run") as scanner_runner,
            ):
                result = run_gate(
                    gate,
                    root,
                    "4" * 64,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "ERROR")
        self.assertIsNone(result["exit_code"])
        self.assertIn("undeclared third-party runtime imports: requests", result["summary"])
        scanner_runner.assert_not_called()

    def test_target_license_check_fails_closed_on_policy_denied_runtime_license(self) -> None:
        gate = {
            "id": "target-license-check",
            "adapter": "target_license_check",
            "command": "controller:target-license-check",
            "allowlist_prefixes": ["controller:target-license-check"],
            "mandatory": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                "[project]\nname='candidate'\nversion='1.0'\ndependencies=['Example>=1']\n",
                encoding="utf-8",
            )
            site_packages = root / "site-packages"
            metadata_dir = site_packages / "example-1.0.dist-info"
            metadata_dir.mkdir(parents=True)
            (metadata_dir / "METADATA").write_text(
                "Metadata-Version: 2.4\n"
                "Name: Example\n"
                "Version: 1.0\n"
                "License-Expression: GPL-3.0-only\n",
                encoding="utf-8",
            )
            with patch(
                "scripts.quality_gate._target_site_packages",
                return_value=site_packages,
            ):
                result = run_gate(
                    gate,
                    root,
                    "1" * 64,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("GPL-3.0-only", result["summary"])
        self.assertIn("policy_denied_licenses=", result["summary"])

    def test_target_container_image_scan_builds_and_scans_exact_digest(self) -> None:
        subject_sha = "6" * 64
        image_digest = "sha256:" + ("7" * 64)
        image_ref = f"localhost/hermes-quality-{subject_sha[:16]}:scan"
        immutable_ref = f"{image_ref}@{image_digest}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verifier = root / "scripts" / "image_security_verify.py"
            verifier.parent.mkdir(parents=True)
            verifier.write_text("# controller test fixture\n", encoding="utf-8")
            containerfile = root / "container" / "Containerfile"
            containerfile.parent.mkdir(parents=True)
            containerfile.write_text("FROM scratch\n", encoding="utf-8")
            scanner = root / "osv-scanner"
            scanner.write_bytes(b"verified-image-scanner")
            gate = {
                "id": "target-container-image-scan",
                "adapter": "target_container_image_scan",
                "command": "controller:target-container-image-scan",
                "allowlist_prefixes": ["controller:target-container-image-scan"],
                "scanner_path": str(scanner),
                "scanner_sha256": hashlib.sha256(scanner.read_bytes()).hexdigest(),
                "require_root_owned": False,
                "timeout_seconds": 60,
                "mandatory": True,
            }
            calls: list[list[str]] = []

            def image_runner(
                args: list[str],
                **kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                calls.append(args)
                if "build" in args:
                    output = Path(args[args.index("--output") + 1])
                    output.write_text(
                        json.dumps(
                            {
                                "status": "pass",
                                "subject_sha": subject_sha,
                                "image_ref": image_ref,
                                "image_digest": image_digest,
                                "immutable_image_ref": immutable_ref,
                            }
                        ),
                        encoding="utf-8",
                    )
                elif "scan" in args:
                    output = Path(args[args.index("--output") + 1])
                    output.write_text(
                        json.dumps(
                            {
                                "status": "pass",
                                "subject_sha": subject_sha,
                                "image_ref": immutable_ref,
                                "image_digest": image_digest,
                                "scanner": str(scanner.resolve()),
                                "evidence_valid": True,
                                "scanner_exit_code": 0,
                                "blocking_findings": 0,
                            }
                        ),
                        encoding="utf-8",
                    )
                return subprocess.CompletedProcess(
                    args=args,
                    returncode=0,
                    stdout="",
                    stderr="",
                )

            with patch(
                "scripts.quality_gate.subprocess.run",
                side_effect=image_runner,
            ):
                result = run_gate(
                    gate,
                    root,
                    subject_sha,
                    python_executable="target-python",
                )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn(f"image_digest={image_digest}", result["summary"])
        self.assertIn("scanner_evidence_sha256=", result["summary"])
        self.assertIn("image_cleanup=pass", result["summary"])
        self.assertEqual(len(calls), 3)
        self.assertIn("build", calls[0])
        self.assertIn("scan", calls[1])
        self.assertEqual(calls[2][:4], ["podman", "image", "rm", "--force"])

    def test_target_container_image_scan_is_not_applicable_without_container(self) -> None:
        gate = {
            "id": "target-container-image-scan",
            "adapter": "target_container_image_scan",
            "command": "controller:target-container-image-scan",
            "allowlist_prefixes": ["controller:target-container-image-scan"],
            "mandatory": True,
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("scripts.quality_gate.subprocess.run") as runner,
        ):
            result = run_gate(
                gate,
                Path(directory),
                "8" * 64,
                python_executable="target-python",
            )

        self.assertEqual(result["status"], "PASS")
        self.assertIn("container_image_scan=not_applicable", result["summary"])
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
