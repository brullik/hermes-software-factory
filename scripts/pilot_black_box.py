#!/usr/bin/env python3
"""Run credential-free black-box checks against the neutral pilot surface."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from jsonschema import Draft202012Validator, FormatChecker

from factory.artifacts import artifact_metadata
from factory.common import new_id
from factory.config import load_config

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_NAME = "pilot-black-box.schema.json"


def _url(base_url: str, path: str) -> str:
    normalized = base_url.rstrip("/") + "/"
    return urljoin(normalized, path.lstrip("/"))


def _get(base_url: str, path: str) -> tuple[int, bytes]:
    request = urllib.request.Request(_url(base_url, path), headers={"Cache-Control": "no-store"})
    with urllib.request.urlopen(request, timeout=5) as response:
        return int(response.status), response.read()


def _json_get(base_url: str, path: str) -> tuple[int, dict[str, Any]]:
    status, body = _get(base_url, path)
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{path} did not return a JSON object")
    return status, payload


def _check(checks: list[dict[str, str]], identifier: str, status: str, result: str) -> None:
    checks.append({"id": identifier, "status": status, "result": result})


def run_checks(base_url: str, *, minimum_events: int | None = None) -> dict[str, Any]:
    """Return a machine-readable result without trusting any model-generated claim."""

    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base URL must be an absolute HTTP(S) URL")
    checks: list[dict[str, str]] = []
    try:
        status, body = _get(base_url, "/")
        if status == 200 and b"Hermes Factory Pilot" in body and b"/health/live" in body:
            _check(checks, "browser-surface", "PASS", "HTTP 200 static pilot surface contains the expected acceptance UI")
        else:
            _check(checks, "browser-surface", "FAIL", f"unexpected browser surface response HTTP {status}")

        status, live = _json_get(base_url, "/health/live")
        _check(
            checks,
            "live",
            "PASS" if status == 200 and live.get("status") == "PASS" else "FAIL",
            f"HTTP {status} /health/live status={live.get('status')}",
        )

        status, ready = _json_get(base_url, "/health/ready")
        ready_pass = status == 200 and ready.get("status") == "PASS" and ready.get("database") is True
        _check(checks, "ready", "PASS" if ready_pass else "FAIL", f"HTTP {status} /health/ready database={ready.get('database')}")

        status, api_status = _json_get(base_url, "/api/status")
        api_pass = (
            status == 200
            and api_status.get("status") == "PASS"
            and api_status.get("credentials_required") is False
            and api_status.get("risk") == "low"
        )
        _check(
            checks,
            "api-status",
            "PASS" if api_pass else "FAIL",
            f"HTTP {status} credentials_required={api_status.get('credentials_required')} risk={api_status.get('risk')}",
        )
        event_count = api_status.get("events")
        if minimum_events is not None:
            restart_pass = isinstance(event_count, int) and event_count >= minimum_events
            _check(checks, "restart-persistence", "PASS" if restart_pass else "FAIL", f"events={event_count} minimum={minimum_events}")
            restart_status = "PASS" if restart_pass else "FAIL"
        else:
            restart_status = "NOT_RUN"
            _check(checks, "restart-persistence", "PASS", f"events={event_count}; restart threshold not requested")

        status, metrics = _get(base_url, "/metrics")
        metrics_pass = status == 200 and b"hermes_factory_pilot_events_total" in metrics
        _check(checks, "metrics", "PASS" if metrics_pass else "FAIL", f"HTTP {status} Prometheus pilot metric present={metrics_pass}")
    except (OSError, urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as error:
        _check(checks, "transport", "FAIL", f"pilot black-box transport failed: {type(error).__name__}")
        restart_status = "FAIL"

    overall = "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL"
    return {
        "status": overall,
        "endpoint": base_url.rstrip("/"),
        "checks": checks,
        "restart_persistence": restart_status,
        "rollback": "NOT_TESTED_EXTERNAL",
        "summary": "All neutral pilot black-box checks passed." if overall == "PASS" else "One or more neutral pilot black-box checks failed.",
    }


def build_artifact(config_path: Path | None, base_url: str, minimum_events: int | None) -> dict[str, Any]:
    config = load_config(config_path)
    result = run_checks(base_url, minimum_events=minimum_events)
    return {
        **artifact_metadata(config, "product-tester", new_id("pilot-black-box"), "hermes-factory-pilot"),
        **result,
        "evidence_refs": ["pilot/README.md", "pilot/docs/ARCHITECTURE.md", base_url.rstrip("/")],
    }


def write_immutable(path: Path, artifact: dict[str, Any]) -> None:
    schema = json.loads((ROOT / "schemas" / SCHEMA_NAME).read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact))
    if errors:
        raise ValueError("Invalid pilot black-box artifact: " + "; ".join(error.message for error in errors))
    payload = json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") != payload:
        raise RuntimeError(f"Refusing to overwrite immutable evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Hermes Factory neutral pilot black-box checks")
    parser.add_argument("--base-url", default="http://127.0.0.1:8090")
    parser.add_argument("--minimum-events", type=int)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.minimum_events is not None and args.minimum_events < 1:
        raise SystemExit("--minimum-events must be positive")
    artifact = build_artifact(args.config, args.base_url, args.minimum_events)
    if args.evidence:
        write_immutable(args.evidence if args.evidence.is_absolute() else ROOT / args.evidence, artifact)
    print(json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if artifact["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
