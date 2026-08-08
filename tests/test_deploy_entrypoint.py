from __future__ import annotations

import os
import runpy
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "scripts" / "deploy" / "promote-release.py"
RELEASE_SUBMIT = ROOT / "scripts" / "deploy" / "release-submit.py"


class DeployEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        loaded = runpy.run_path(str(ENTRYPOINT))
        cls.validate_health_url = loaded["validate_health_url"]
        cls.health_probe = loaded["health_probe"]
        cls.optional_services = loaded["OPTIONAL_SERVICES"]
        cls.install_runtime_units = loaded["install_runtime_units"]
        cls.runtime_switch = loaded["RuntimeSwitch"]
        submit = runpy.run_path(str(RELEASE_SUBMIT))
        cls.install_root = submit["_install_root"]
        cls.reconcile_root_receipt = submit["_reconcile_root_receipt"]
        cls.submit_error = submit["SubmitError"]

    def test_health_url_requires_loopback_http(self) -> None:
        self.assertEqual(
            type(self).validate_health_url("http://127.0.0.1:8787/healthz"),
            "http://127.0.0.1:8787/healthz",
        )
        self.assertEqual(
            type(self).validate_health_url("http://localhost:8787/readyz"),
            "http://localhost:8787/readyz",
        )

    def test_health_url_rejects_external_hosts_and_credentials(self) -> None:
        for value in (
            "https://127.0.0.1:8787/healthz",
            "http://example.com/healthz",
            "http://user:password@127.0.0.1:8787/healthz",
            "http://127.0.0.1:8787/healthz?token=secret",
        ):
            with self.assertRaises(ValueError):
                type(self).validate_health_url(value)

    def test_health_probe_rejects_invalid_retry_parameters(self) -> None:
        with self.assertRaises(ValueError):
            type(self).health_probe("http://127.0.0.1:8787/healthz", 0, 1.0)
        with self.assertRaises(ValueError):
            type(self).health_probe("http://127.0.0.1:8787/healthz", 1, -1.0)

    def test_external_product_install_root_is_controller_derived(self) -> None:
        config = {
            "github": {"owner": "brullik", "factory_repository": "hermes-software-factory"},
            "deployment": {"production_target": {"install_root": "/opt/hermes-factory"}},
        }
        external = type(self).install_root(
            config,
            "brullik/bybit-grid-research",
            "bybit-grid-research-1234",
        )
        self.assertEqual(external.name, "bybit-grid-research-1234")
        self.assertEqual(external.parent.name, "hermes-factory-products")

    def test_external_product_install_root_rejects_other_owner_and_unsafe_id(self) -> None:
        config = {
            "github": {"owner": "brullik", "factory_repository": "hermes-software-factory"},
            "deployment": {"production_target": {"install_root": "/opt/hermes-factory"}},
        }
        with self.assertRaises(type(self).submit_error):
            type(self).install_root(config, "attacker/bybit-grid-research", "safe-product")
        with self.assertRaises(type(self).submit_error):
            type(self).install_root(config, "brullik/bybit-grid-research", "../escape")

    def test_root_receipt_reconciles_exact_postcondition_without_effect(self) -> None:
        from factory.release_executor import _release_digest

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = root / "current"
            current.mkdir()
            (current / "artifact.txt").write_text("immutable\n", encoding="utf-8")
            receipt_path = root / "receipt.json"
            expected = {
                "schema_version": "1.0",
                "status": "PROMOTED",
                "repository": "brullik/product",
                "product_id": "product-1",
                "release_id": "a" * 40,
                "image_digest": _release_digest(current),
            }

            first = type(self).reconcile_root_receipt(
                receipt_path=receipt_path,
                install_root=root,
                expected=expected,
                require_factory_health=False,
            )
            second = type(self).reconcile_root_receipt(
                receipt_path=receipt_path,
                install_root=root,
                expected=expected,
                require_factory_health=False,
            )

            self.assertEqual(first, second)
            self.assertEqual(first["reconciliation"], "verified_postcondition")
            self.assertEqual(receipt_path.read_text(encoding="utf-8").count("PROMOTED"), 1)

    def test_second_worker_is_durable_and_restarted_when_installed(self) -> None:
        worker_one = (ROOT / "config" / "systemd" / "hermes-factory-worker.service").read_text(
            encoding="utf-8"
        )
        worker_two = (ROOT / "config" / "systemd" / "hermes-factory-worker-2.service").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "scripts" / "bootstrap" / "install.sh").read_text(encoding="utf-8")

        self.assertIn("--worker-id hermes-worker-1", worker_one)
        self.assertNotIn("--worker-id hermes-worker-2", worker_one)
        self.assertIn("--worker-id hermes-worker-2", worker_two)
        self.assertNotIn("--worker-id hermes-worker-1", worker_two)
        self.assertIn(
            "hermes-factory-worker-2.service",
            type(self).optional_services,
        )
        self.assertGreaterEqual(
            installer.count("hermes-factory-worker-2.service"),
            2,
        )

    def test_runtime_unit_install_is_exact_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            source = release / "config" / "systemd"
            target = root / "systemd"
            source.mkdir(parents=True)
            target.mkdir()
            for name in (
                "hermes-factory-controller.service",
                "hermes-factory-gateway.service",
                "hermes-factory-worker.service",
                "hermes-factory-worker-2.service",
                "hermes-factory-product-github-broker.service",
            ):
                (source / name).write_text(f"[Unit]\nDescription={name}\n", encoding="utf-8")
            (source / "untrusted.service").write_text("[Service]\n", encoding="utf-8")
            installed = type(self).install_runtime_units(
                release_root=release,
                systemd_root=target,
            )
            self.assertIn("hermes-factory-product-github-broker.service", installed)
            self.assertFalse((target / "untrusted.service").exists())
            self.assertFalse(any(path.name.endswith(".tmp") for path in target.iterdir()))

    def test_promoted_gateway_imports_the_promoted_factory_release(self) -> None:
        gateway = (ROOT / "config" / "systemd" / "hermes-factory-gateway.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("WorkingDirectory=/opt/hermes-factory/current", gateway)
        self.assertIn("Environment=PYTHONPATH=/opt/hermes-factory/current", gateway)
        self.assertIn("ReadOnlyPaths=/opt/hermes-factory/current", gateway)
        self.assertNotIn("/opt/hermes-codex-runtime", gateway)

    @unittest.skipIf(os.name == "nt", "Windows test process cannot create symlinks")
    def test_runtime_switch_binds_code_and_python_then_restores_lts(self) -> None:
        from factory.deployment import DeploymentError
        from factory.release_executor import _release_digest

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            install = root / "install"
            current = install / "current"
            current.mkdir(parents=True)
            (current / "VERSION").write_text("old\n", encoding="utf-8")
            old_digest = _release_digest(current).removeprefix("sha256:")
            old_runtime = install / "venv"
            (old_runtime / "bin").mkdir(parents=True)
            (old_runtime / "bin" / "python").write_text("old\n", encoding="utf-8")
            release_id = "a" * 40
            candidate_runtime_root = root / "candidate" / "venvs"
            candidate_runtime = candidate_runtime_root / release_id
            (candidate_runtime / "bin").mkdir(parents=True)
            (candidate_runtime / "bin" / "python").write_text("new\n", encoding="utf-8")
            runtime_link = root / "candidate" / "venv"
            runtime_link.symlink_to(candidate_runtime, target_is_directory=True)
            candidate_source = root / "candidate-source"
            candidate_source.mkdir()
            (candidate_source / "VERSION").write_text("new\n", encoding="utf-8")
            candidate_digest = _release_digest(candidate_source).removeprefix("sha256:")
            switch_arguments = {
                "install_root": install,
                "release_id": release_id,
                "old_release_digest": old_digest,
                "candidate_release_digest": candidate_digest,
                "candidate_runtime_link": runtime_link,
                "candidate_runtime_root": candidate_runtime_root,
            }
            untrusted_switch = type(self).runtime_switch(
                **switch_arguments,
                candidate_runtime_trust=lambda _path: False,
            )
            with self.assertRaises(DeploymentError):
                untrusted_switch.prepare()
            switch = type(self).runtime_switch(
                **switch_arguments,
                candidate_runtime_trust=lambda _path: True,
            )

            switch.prepare()
            self.assertTrue((install / "venv").is_symlink())
            self.assertEqual(
                (install / "venv").resolve().name, f"venv-lts-before-{release_id[:12]}"
            )
            (current / "VERSION").write_text("new\n", encoding="utf-8")
            switch.select_for(current)
            self.assertEqual((install / "venv").resolve(), candidate_runtime.resolve())
            (current / "VERSION").write_text("old\n", encoding="utf-8")
            switch.select_for(current)
            self.assertEqual(
                (install / "venv").resolve().name, f"venv-lts-before-{release_id[:12]}"
            )


if __name__ == "__main__":
    unittest.main()
