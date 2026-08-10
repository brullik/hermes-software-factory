from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import pre_q8_runtime

ROOT = Path(__file__).parents[1]


class FakeSystemd:
    def __init__(self, *, active: str = "", jobs: str = "") -> None:
        self.active = active
        self.jobs = jobs
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        command: list[str],
        *,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        normalized = tuple(command)
        self.calls.append(normalized)
        if normalized[:2] == ("systemctl", "list-units"):
            return subprocess.CompletedProcess(command, 0, self.active, "")
        if normalized[:2] == ("systemctl", "list-jobs"):
            return subprocess.CompletedProcess(command, 0, self.jobs, "")
        return subprocess.CompletedProcess(command, 0, "", "")


def test_epoch_switch_rejects_active_pre_q8_units() -> None:
    stubborn_unit = (
        "hermes-factory-pre-q8-convergence-worker@run-a--telegram-bot.service "
        "loaded active running"
    )
    fake = FakeSystemd(active=stubborn_unit)
    with pytest.raises(
        pre_q8_runtime.RuntimeControlError,
        match="units are still active",
    ):
        pre_q8_runtime.epoch_switch_guard(runner=fake.run)

    stop = fake.calls[0]
    for required_pattern in (
        "hermes-factory-pre-q8@*.service",
        "hermes-factory-pre-q8-controller@*.service",
        "hermes-factory-pre-q8-worker@*.service",
        "hermes-factory-pre-q8-convergence@*.service",
        "hermes-factory-pre-q8-convergence-controller@*.service",
        "hermes-factory-pre-q8-convergence-worker@*.service",
        "hermes-factory-pre-q8-convergence-scenario@*.service",
        "hermes-factory-pre-q8-official.service",
        "hermes-factory-golden-*.service",
    ):
        assert required_pattern in stop


def test_epoch_switch_rejects_pending_restart_jobs() -> None:
    fake = FakeSystemd(
        jobs="17 hermes-factory-pre-q8@telegram-bot.service restart running"
    )
    with pytest.raises(
        pre_q8_runtime.RuntimeControlError,
        match="restart jobs are still scheduled",
    ):
        pre_q8_runtime.epoch_switch_guard(runner=fake.run)


def test_epoch_switch_accepts_drained_systemd() -> None:
    fake = FakeSystemd()

    result = pre_q8_runtime.epoch_switch_guard(runner=fake.run)

    assert result["active_units"] == []
    assert [call[1] for call in fake.calls] == ["stop", "list-units", "list-jobs"]


def test_epoch_switch_recreates_pre_q8_mount_roots_after_archive() -> None:
    bootstrap = (ROOT / "scripts" / "bootstrap" / "prepare-candidate-plane.sh").read_text(
        encoding="utf-8"
    )
    archive = bootstrap.index('if [[ -d "${CONFIG_ROOT}/pre-q8-convergence" ]]')
    recreate = bootstrap.index("# The old-epoch archive above moves these roots wholesale")
    daemon_reload = bootstrap.index("systemctl daemon-reload")
    recreated_block = bootstrap[recreate:daemon_reload]

    assert archive < recreate < daemon_reload
    assert '"${CONFIG_ROOT}/pre-q8"' in recreated_block
    assert '"${CONFIG_ROOT}/pre-q8-convergence"' in recreated_block


def test_convergence_orchestrator_has_only_required_dac_groups() -> None:
    unit = (
        ROOT / "config" / "systemd" / "hermes-factory-pre-q8-convergence@.service"
    ).read_text(encoding="utf-8")

    assert "SupplementaryGroups=hermesverifier hermesfunctional" in unit
    assert "CapabilityBoundingSet=CAP_SETUID CAP_SETGID" in unit
    assert "CAP_CHOWN" not in unit
    assert "CAP_DAC_OVERRIDE" not in unit

    runner = (
        ROOT / "scripts" / "qualification" / "run-pre-q8-convergence.sh"
    ).read_text(encoding="utf-8")
    assert "umask 0007" in runner
    assert 'run_as_verifier /usr/bin/mkdir -p -- \\\n' in runner
    assert "run_as_verifier /usr/bin/install" not in runner
    assert "install -d -o hermesverifier" not in runner
