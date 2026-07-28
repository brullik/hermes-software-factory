from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from test_worker import make_config, selected_registry

from factory.artifacts import ArtifactStore
from factory.config import FactoryConfig
from factory.quality import QualityGateEngine


class QualityGateTests(unittest.TestCase):
    def test_allowlisted_gates_persist_evidence_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_config = make_config(root, selected_registry(root / "registry.yaml", selected="gpt-5.6-luna"))
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
                cwd=root,
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
            with self.assertRaises(ValueError):
                engine.run(
                    cwd=root,
                    subject_sha="a" * 64,
                    task_id="T-QUALITY-002",
                    attempt_id="attempt-quality-002",
                    gate_ids=["unknown-gate"],
                )

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


if __name__ == "__main__":
    unittest.main()
