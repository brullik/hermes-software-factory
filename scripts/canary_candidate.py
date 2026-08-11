#!/usr/bin/env python3
"""Run one isolated clean-canary product through the normal Candidate B runtime."""

# Every created qualification repository is ledgered here for terminal DELETE.

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, cast

from factory.artifacts import ArtifactStore
from factory.canary_faults import (
    CanaryFaultContract,
    CanaryFaultError,
    CanaryFaultJournal,
    FaultInjectingHermesRunner,
    FaultInjectingQualityGate,
)
from factory.canary_qualification import CanaryObservationError, load_canary_catalog
from factory.canary_release import IsolatedCanaryReleaseExecutor
from factory.capabilities import CapabilityBroker
from factory.common import sha256_text, stable_json
from factory.config import ConfigError, FactoryConfig, load_config
from factory.intake import IntakeRejected, IntakeService
from factory.pre_q8_convergence import (
    resource_idempotency_key,
    resource_namespace,
)
from factory.qualification_repository_gc import record_provisioned_repository
from factory.repository import build_repository_bootstrapper
from factory.state import StateStore, is_sqlite_busy
from factory.worker import AgentWorker


class CanaryCandidateError(RuntimeError):
    """The Candidate B canary command cannot preserve its qualification contract."""


def _runtime(config_path: Path) -> tuple[FactoryConfig, CanaryFaultContract]:
    config = load_config(config_path)
    contract = CanaryFaultContract.from_config(config)
    catalog_path = Path(str(config.raw["paths"]["canary_catalog"]))
    scenario = load_canary_catalog(catalog_path).get(contract.scenario_id)
    if scenario is None or scenario.scenario_digest != contract.scenario_digest:
        raise CanaryCandidateError("candidate scenario differs from root-owned catalog")
    return config, contract


def prepare(config: FactoryConfig, contract: CanaryFaultContract) -> dict[str, Any]:
    if config.database_path.exists():
        raise CanaryCandidateError("clean canary database already exists")
    config.state_dir.mkdir(parents=True, exist_ok=True)
    Path(str(config.raw["paths"]["logs"])).mkdir(parents=True, exist_ok=True)
    contract.receipt_root.mkdir(parents=True, exist_ok=True)
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        migration_version = int(
            state._connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        )
    finally:
        state.close()
    return {
        "scenario_id": contract.scenario_id,
        "database": str(config.database_path),
        "migration_version": migration_version,
    }


def submit(config: FactoryConfig, contract: CanaryFaultContract) -> dict[str, Any]:
    catalog = load_canary_catalog(Path(str(config.raw["paths"]["canary_catalog"])))
    scenario = catalog[contract.scenario_id]
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        existing_url = str(config.raw["qualification"].get("existing_repository_url") or "")
        if scenario.delivery_mode == "existing_repository" and not existing_url:
            raise CanaryCandidateError("existing-repository canary URL is not configured")
        repository_name = (
            None
            if scenario.delivery_mode == "existing_repository"
            else resource_namespace(
                plane=contract.qualification_plane,
                run_id=contract.run_id,
                candidate_digest=contract.candidate_digest,
                scenario_id=scenario.scenario_id,
            )
        )
        result = IntakeService(config, state, ArtifactStore(config)).submit(
            source="cli",
            owner_id="independent-clean-canary",
            goal_text=scenario.idea,
            delivery_mode=scenario.delivery_mode,
            repository_url=(
                existing_url if scenario.delivery_mode == "existing_repository" else None
            ),
            repository_name=(repository_name),
            repository_visibility="private",
            delivery_profile=scenario.delivery_profile,
            constraints={
                "qualification_scenario_id": scenario.scenario_id,
                "qualification_scenario_digest": scenario.scenario_digest,
                "qualification_plane": contract.qualification_plane,
                "qualification_run_id": contract.run_id,
                "qualification_epoch_id": contract.epoch_id,
                "fixture_seed_digest": contract.fixture_seed_digest,
                "expected_events": list(scenario.events),
                "declared_faults": list(scenario.injected_faults),
                "production_target": "isolated_candidate",
            },
            idempotency_key=resource_idempotency_key(
                plane=contract.qualification_plane,
                run_id=contract.run_id,
                candidate_digest=contract.candidate_digest,
                scenario_id=scenario.scenario_id,
            ),
        )
        if "KNOWN_PRODUCT_DEFECT" in contract.faults and not CanaryFaultJournal(contract).consumed(
            "KNOWN_PRODUCT_DEFECT"
        ):
            CanaryFaultJournal(contract).consume(
                "KNOWN_PRODUCT_DEFECT",
                point="existing_repository_fixture",
                product_id=result.product_id,
                observed={"repository_url": existing_url},
            )
        if repository_name is not None:
            owner = str(config.raw.get("github", {}).get("owner") or "")
            provision_identity = {
                "qualification_plane": contract.qualification_plane,
                "epoch_id": contract.epoch_id,
                "run_id": contract.run_id,
                "scenario_id": scenario.scenario_id,
                "candidate_digest": contract.candidate_digest,
                "product_id": result.product_id,
                "repository_owner": owner,
                "repository_name": repository_name,
                "description": f"Hermes product {result.product_id}",
            }
            record_provisioned_repository(
                contract.receipt_root.parent.parent / "repository-ledger.json",
                qualification_plane=contract.qualification_plane,
                epoch_id=contract.epoch_id,
                run_id=contract.run_id,
                scenario_id=scenario.scenario_id,
                candidate_digest=contract.candidate_digest,
                product_id=result.product_id,
                repository_owner=owner,
                repository_name=repository_name,
                repository_id=None,
                expected_description=f"Hermes product {result.product_id}",
                provision_receipt_digest=sha256_text(stable_json(provision_identity)),
                database_path=str(config.database_path),
            )
        return {
            "scenario_id": scenario.scenario_id,
            "product_id": result.product_id,
            "created": result.created,
        }
    finally:
        state.close()


def status(config: FactoryConfig, contract: CanaryFaultContract) -> dict[str, Any]:
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        products = state.list_products()
        if len(products) > 1:
            raise CanaryCandidateError("clean canary database contains multiple products")
        product = products[0] if products else None
        faults = {fault: CanaryFaultJournal(contract).consumed(fault) for fault in contract.faults}
        return {
            "scenario_id": contract.scenario_id,
            "product_id": str(product["product_id"]) if product else None,
            "product_status": str(product["status"]) if product else "EMPTY",
            "faults": faults,
        }
    finally:
        state.close()


def run_worker(
    config: FactoryConfig,
    contract: CanaryFaultContract,
    *,
    worker_id: str,
    once: bool,
) -> int:
    state = StateStore(
        config.database_path,
        max_active_workers=config.max_active_workers,
        max_active_products=config.max_active_products,
    )
    try:
        state.recover_expired_leases()
        CapabilityBroker(config, state).preflight_all()
        journal = CanaryFaultJournal(contract)
        worker = AgentWorker(
            config,
            state,
            repository_root=Path.cwd(),
            release_executor=IsolatedCanaryReleaseExecutor(config, journal),
            repository_bootstrapper=build_repository_bootstrapper(config, state),
            worker_id=worker_id,
        )
        worker.runner = FaultInjectingHermesRunner(worker.runner, journal)
        worker.planning_runner = FaultInjectingHermesRunner(
            worker.planning_runner,
            journal,
        )
        worker.quality = cast(
            Any,
            FaultInjectingQualityGate(
                worker.quality,
                journal,
                task_lookup=state.get_task,
            ),
        )
        busy_delay = 0.25
        while True:
            try:
                result = worker.run_once()
                busy_delay = 0.25
            except Exception as error:
                if not is_sqlite_busy(error):
                    raise
                state.record_sqlite_busy_event()
                time.sleep(busy_delay)
                busy_delay = min(busy_delay * 2, 5.0)
                continue
            if (
                result is not None
                and result.reason_code == "agent_execution_timeout"
                and "ONE_PROCESS_RESTART" in contract.faults
                and not journal.consumed("ONE_PROCESS_RESTART")
            ):
                task = state.get_task(result.task_id)
                journal.consume(
                    "ONE_PROCESS_RESTART",
                    point="after_durable_transient_retry",
                    product_id=str((task or {}).get("product_id") or ""),
                    task_id=result.task_id,
                    observed={
                        "worker_id": worker_id,
                        "result_status": result.status,
                        "reason_code": result.reason_code,
                    },
                )
                return 75
            if once:
                print(
                    stable_json(
                        {
                            "status": "IDLE" if result is None else result.status,
                            "task_id": result.task_id if result else None,
                        }
                    )
                )
                return 0 if result is None or result.status == "completed" else 2
            if result is None:
                time.sleep(worker.poll_seconds)
    finally:
        state.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare")
    commands.add_parser("submit")
    commands.add_parser("status")
    worker = commands.add_parser("worker")
    worker.add_argument("--worker-id", default="clean-canary-worker-1")
    worker.add_argument("--once", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config, contract = _runtime(args.config)
        if args.command == "prepare":
            result = prepare(config, contract)
        elif args.command == "submit":
            result = submit(config, contract)
        elif args.command == "status":
            result = status(config, contract)
        else:
            return run_worker(
                config,
                contract,
                worker_id=args.worker_id,
                once=args.once,
            )
    except (
        CanaryCandidateError,
        CanaryFaultError,
        CanaryObservationError,
        ConfigError,
        IntakeRejected,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        print(
            stable_json({"status": "FAIL", "error_type": type(error).__name__}),
            file=sys.stderr,
        )
        return 1
    print(stable_json({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
