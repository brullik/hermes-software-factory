from __future__ import annotations

import runpy
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
        submit = runpy.run_path(str(RELEASE_SUBMIT))
        cls.install_root = submit["_install_root"]
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

    def test_second_worker_is_durable_and_restarted_when_installed(self) -> None:
        worker_one = (
            ROOT / "config" / "systemd" / "hermes-factory-worker.service"
        ).read_text(encoding="utf-8")
        worker_two = (
            ROOT / "config" / "systemd" / "hermes-factory-worker-2.service"
        ).read_text(encoding="utf-8")
        installer = (
            ROOT / "scripts" / "bootstrap" / "install.sh"
        ).read_text(encoding="utf-8")

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


if __name__ == "__main__":
    unittest.main()
