from __future__ import annotations

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
                        ],
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            config = FactoryConfig(base_config.raw, config_root / "factory.yaml")
            engine = QualityGateEngine(config, ArtifactStore(config))

            run = engine.run(
                cwd=root,
                subject_sha="a" * 64,
                task_id="T-QUALITY-001",
                attempt_id="attempt-quality-001",
                gate_ids=["pass-gate", "optional-fail"],
            )

            self.assertTrue(run.mandatory_passed)
            self.assertEqual([result["status"] for result in run.results], ["PASS", "FAIL"])
            self.assertEqual(len(run.evidence_paths), 2)
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


if __name__ == "__main__":
    unittest.main()
