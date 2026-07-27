from __future__ import annotations

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "scripts" / "deploy" / "promote-release.py"


class DeployEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        loaded = runpy.run_path(str(ENTRYPOINT))
        cls.validate_health_url = loaded["validate_health_url"]
        cls.health_probe = loaded["health_probe"]

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


if __name__ == "__main__":
    unittest.main()
