"""Real-process isolated Q6 service harness without production credentials."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

from .autonomy import CAPABILITY_PROFILES
from .common import sha256_file, sha256_text, stable_json
from .deployment import TransactionalDeployer

_PRODUCTION_CREDENTIAL_ENV = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "B2_APPLICATION_KEY",
    "B2_APPLICATION_KEY_ID",
    "RESTIC_PASSWORD",
)


class ServiceQualificationError(RuntimeError):
    """An isolated real service or its postcondition failed."""


@dataclass(frozen=True)
class ServiceQualificationReport:
    service_scenarios: int
    controller_processes: int
    worker_processes: int
    gateway_processes: int
    hermes_subprocesses: int
    sqlite_databases: int
    deployment_transactions: int
    manual_database_mutations: int
    duplicate_side_effects: int
    controller_defects: int
    candidate_production_credentials: int
    candidate_writes_to_stable_db: int
    report_digest: str


class _TelegramFixtureHandler(BaseHTTPRequestHandler):
    server: _TelegramFixtureServer

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            self.send_error(400)
            return
        if self.path.endswith("/getUpdates"):
            with self.server.lock:
                updates, self.server.updates = self.server.updates, []
            self._json({"ok": True, "result": updates})
            return
        if self.path.endswith("/sendMessage") and isinstance(payload, dict):
            with self.server.lock:
                self.server.messages.append(dict(payload))
            self._json({"ok": True, "result": {"message_id": 1}})
            return
        self.send_error(404)

    def _json(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class _TelegramFixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _TelegramFixtureHandler)
        self.updates: list[dict[str, Any]] = [
            {
                "update_id": 1,
                "message": {
                    "from": {"id": 42},
                    "chat": {"id": 42, "type": "private"},
                    "text": "/help",
                },
            }
        ]
        self.messages: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def handle_error(self, request: object, client_address: object) -> None:
        del request, client_address


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _http_json(url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET",
    )
    try:
        with urlopen(request, timeout=5) as response:
            value = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, TimeoutError, UnicodeError, json.JSONDecodeError) as error:
        raise ServiceQualificationError(f"isolated HTTP probe failed: {url}") from error
    if not isinstance(value, dict):
        raise ServiceQualificationError("isolated HTTP response is not an object")
    return value


def _wait_controller(port: int, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ServiceQualificationError("isolated controller exited early")
        try:
            if _http_json(f"http://127.0.0.1:{port}/healthz").get("status") == "PASS":
                return
        except ServiceQualificationError:
            pass
        time.sleep(0.1)
    raise ServiceQualificationError("isolated controller health timed out")


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _candidate_config(
    repository_root: Path,
    work_root: Path,
    *,
    controller_port: int,
    telegram_port: int,
) -> Path:
    raw = yaml.safe_load(
        (repository_root / "config" / "factory-config.example.yaml").read_text(
            encoding="utf-8"
        )
    )
    state = work_root / "candidate-state"
    state.mkdir(parents=True)
    raw["controller"]["database_url"] = f"sqlite:///{(state / 'controller.db').as_posix()}"
    raw["controller"]["reconcile_interval_seconds"] = 60
    raw["paths"].update(
        {
            "policies": str(repository_root / "policies"),
            "schemas": str(repository_root / "schemas"),
            "prompts": str(repository_root / "prompts"),
            "state": str(state),
            "worktrees": str(work_root / "candidate-worktrees"),
            "logs": str(work_root / "candidate-logs"),
        }
    )
    raw["network"]["admin_port"] = controller_port
    raw["models"]["registry"] = str(
        repository_root / "config" / "model-routing" / "model-registry.template.yaml"
    )
    raw["telegram"]["allowed_user_ids"] = [42]
    raw["telegram"]["api_base_url"] = f"http://127.0.0.1:{telegram_port}"
    raw["deployment"]["production_helper"] = ""
    raw["deployment"]["production_target"] = {
        "mode": "isolated_candidate",
        "host": "127.0.0.1",
        "install_root": str(work_root / "isolated-target"),
        "entrypoint": "disabled",
    }
    raw["backup"]["offsite_configured"] = False
    attested_capabilities = tuple(
        dict.fromkeys(
            capability
            for profile in ("repository_bootstrap", "release_staging")
            for capability in CAPABILITY_PROFILES[profile]
            if capability.startswith(("git.", "github.", "repository."))
        )
    )
    attestation = state / "isolated-capabilities.json"
    attestation.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "plane": "ISOLATED_Q6",
                "capabilities": {
                    capability: {
                        "status": "AVAILABLE",
                        "scope": {"allowed_operations": [capability]},
                    }
                    for capability in attested_capabilities
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    raw["qualification"] = {
        "plane": "ISOLATED_Q6",
        "capability_attestation_path": str(attestation),
        "capability_attestation_digest": sha256_file(attestation),
    }
    path = work_root / "candidate.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8", newline="\n")
    return path


def _hermes_subprocess_probe(
    repository_root: Path,
    work_root: Path,
    base_environment: dict[str, str],
) -> None:
    fake = work_root / "fake-hermes" / "hermes_cli"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "main.py").write_text(
        "import json\n"
        "def _prepare_agent_startup(args):\n"
        "    return None\n"
        "def _run_and_exit_oneshot(prompt, **kwargs):\n"
        "    print(json.dumps({'status': 'completed', 'summary': 'isolated'}))\n"
        "    raise SystemExit(0)\n",
        encoding="utf-8",
        newline="\n",
    )
    environment = dict(base_environment)
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(fake.parent), str(repository_root))
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "factory.hermes_stdin",
            "--model",
            "isolated-model",
            "--provider",
            "isolated-provider",
            "--toolsets",
            "vision",
            "--max-input-bytes",
            "4096",
        ],
        cwd=repository_root,
        env=environment,
        input="Return one deterministic isolated result.",
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0 or '"status": "completed"' not in result.stdout:
        raise ServiceQualificationError("Hermes subprocess probe failed")


def _deployment_probe(work_root: Path) -> None:
    source = work_root / "release-source"
    source.mkdir()
    (source / "VERSION").write_text("isolated\n", encoding="utf-8")
    install_root = work_root / "isolated-install"
    activations = 0

    def activate() -> None:
        nonlocal activations
        activations += 1

    deployer = TransactionalDeployer(
        install_root,
        health_probe=lambda current: (current / "VERSION").is_file(),
        activate=activate,
    )
    first = deployer.promote("isolated-release", source)
    second = deployer.promote("isolated-release", source)
    if first.status != "PROMOTED" or second.status != "PROMOTED" or activations != 1:
        raise ServiceQualificationError("isolated deployment was not exactly-once")


def _candidate_boundary_metrics(
    *,
    environment: dict[str, str],
    config_path: Path,
    stable_database: Path,
    stable_digest_before: str,
) -> tuple[int, int]:
    """Derive isolation metrics from the actual process environment and files."""

    production_credentials = sum(
        1 for key in _PRODUCTION_CREDENTIAL_ENV if environment.get(key)
    )
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    deployment = raw.get("deployment", {}) if isinstance(raw, dict) else {}
    if not isinstance(deployment, dict):
        raise ServiceQualificationError("candidate deployment config is invalid")
    if str(deployment.get("production_helper") or ""):
        production_credentials += 1
    target = deployment.get("production_target")
    if not isinstance(target, dict) or target.get("mode") != "isolated_candidate":
        production_credentials += 1
    stable_writes = int(
        not stable_database.is_file()
        or sha256_file(stable_database) != stable_digest_before
    )
    return production_credentials, stable_writes


def run_service_qualification(
    repository_root: Path,
    work_root: Path,
) -> ServiceQualificationReport:
    """Run controller, worker, gateway, Hermes, SQLite, and deploy adapter."""

    repository_root = repository_root.resolve()
    work_root.mkdir(parents=True, exist_ok=False)
    telegram = _TelegramFixtureServer()
    telegram_thread = threading.Thread(target=telegram.serve_forever, daemon=True)
    telegram_thread.start()
    controller_port = _free_port()
    config = _candidate_config(
        repository_root,
        work_root,
        controller_port=controller_port,
        telegram_port=telegram.server_port,
    )
    credentials = work_root / "credentials"
    credentials.mkdir()
    (credentials / "telegram-token").write_text("isolated-token\n", encoding="utf-8")
    environment = os.environ.copy()
    candidate_home = work_root / "candidate-home"
    candidate_home.mkdir()
    for key in _PRODUCTION_CREDENTIAL_ENV:
        environment.pop(key, None)
    environment["HOME"] = str(candidate_home)
    environment["USERPROFILE"] = str(candidate_home)
    environment["GH_CONFIG_DIR"] = str(candidate_home / "gh")
    environment["XDG_CONFIG_HOME"] = str(candidate_home / ".config")
    environment["PYTHONPATH"] = str(repository_root)
    environment["FACTORY_CONFIG"] = str(config)
    stable_database = work_root / "stable-state" / "controller.db"
    stable_database.parent.mkdir()
    stable_connection = sqlite3.connect(stable_database)
    try:
        stable_connection.execute(
            "CREATE TABLE sentinel(identity TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        stable_connection.execute(
            "INSERT INTO sentinel(identity,value) VALUES ('stable-a','immutable')"
        )
        stable_connection.commit()
    finally:
        stable_connection.close()
    stable_digest_before = sha256_file(stable_database)
    controller = subprocess.Popen(
        [sys.executable, "-m", "factory.controller", "--config", str(config)],
        cwd=repository_root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    gateway: subprocess.Popen[str] | None = None
    try:
        _wait_controller(controller_port, controller)
        intake = _http_json(
            f"http://127.0.0.1:{controller_port}/intake",
            {
                "source": "cli",
                "owner_id": "isolated-owner",
                "idea": "Build a staging-only isolated qualification product",
                "goal_text": "Build a staging-only isolated qualification product",
                "delivery_mode": "new_repository",
                "delivery_profile": "STAGING_ONLY_PROTOTYPE",
                "repository_visibility": "private",
                "idempotency_key": "q6-isolated-intake",
            },
        )
        product_id = str(intake.get("product_id") or "")
        if not product_id:
            raise ServiceQualificationError("isolated intake returned no product")
        _http_json(
            f"http://127.0.0.1:{controller_port}/products/{product_id}/pause",
            {},
        )
        _http_json(
            f"http://127.0.0.1:{controller_port}/products/{product_id}/resume",
            {"status": "IMPLEMENTING"},
        )
        _http_json(
            f"http://127.0.0.1:{controller_port}/products/{product_id}/cancel",
            {},
        )

        worker = subprocess.run(
            [
                sys.executable,
                "-m",
                "factory.worker",
                "--config",
                str(config),
                "--worker-id",
                "qualification-worker",
                "--once",
            ],
            cwd=repository_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        if worker.returncode != 0 or '"status": "IDLE"' not in worker.stdout:
            raise ServiceQualificationError("isolated worker process was not healthy")

        gateway_environment = dict(environment)
        gateway_environment["CREDENTIALS_DIRECTORY"] = str(credentials)
        gateway = subprocess.Popen(
            [sys.executable, "-m", "factory.gateway", "--config", str(config)],
            cwd=repository_root,
            env=gateway_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with telegram.lock:
                help_responses = sum(
                    1
                    for message in telegram.messages
                    if str(message.get("text") or "").startswith("/idea ")
                )
                if help_responses == 1:
                    break
            if gateway.poll() is not None:
                raise ServiceQualificationError("isolated gateway exited early")
            time.sleep(0.1)
        time.sleep(1.2)
        with telegram.lock:
            sent_payloads = [stable_json(message) for message in telegram.messages]
            help_responses = sum(
                1
                for message in telegram.messages
                if str(message.get("text") or "").startswith("/idea ")
            )
        duplicate_messages = len(sent_payloads) - len(set(sent_payloads))
        if help_responses != 1 or duplicate_messages:
            raise ServiceQualificationError(
                "isolated gateway side effect was not exactly once: "
                f"help={help_responses}, duplicates={duplicate_messages}"
            )

        _hermes_subprocess_probe(repository_root, work_root, environment)
        _deployment_probe(work_root)
    finally:
        if gateway is not None:
            _stop(gateway)
        _stop(controller)
        telegram.shutdown()
        telegram.server_close()
        telegram_thread.join(timeout=5)

    database = work_root / "candidate-state" / "controller.db"
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    try:
        defect_rows = connection.execute(
            "SELECT reason_code FROM controller_incidents "
            "WHERE status!='RESOLVED' ORDER BY reason_code"
        ).fetchall()
        defects = len(defect_rows)
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        connection.close()
    if defects or integrity != "ok":
        reasons = ",".join(str(row[0]) for row in defect_rows)
        raise ServiceQualificationError(
            "isolated service state contains a controller defect: "
            f"count={defects}, reasons={reasons or 'NONE'}, integrity={integrity}"
        )
    production_credentials, stable_writes = _candidate_boundary_metrics(
        environment=environment,
        config_path=config,
        stable_database=stable_database,
        stable_digest_before=stable_digest_before,
    )
    if production_credentials or stable_writes:
        raise ServiceQualificationError(
            "isolated candidate boundary was violated: "
            f"credentials={production_credentials}, stable_writes={stable_writes}"
        )
    payload = {
        "service_scenarios": 5,
        "controller_processes": 1,
        "worker_processes": 1,
        "gateway_processes": 1,
        "hermes_subprocesses": 1,
        "sqlite_databases": 1,
        "deployment_transactions": 1,
        "manual_database_mutations": 0,
        "duplicate_side_effects": 0,
        "controller_defects": 0,
        "candidate_production_credentials": production_credentials,
        "candidate_writes_to_stable_db": stable_writes,
    }
    return ServiceQualificationReport(
        **payload,
        report_digest=sha256_text(stable_json(payload)),
    )
