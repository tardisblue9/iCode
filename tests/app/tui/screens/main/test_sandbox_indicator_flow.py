# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The footer's sandbox indicator and the sandbox panel, in the real app.

The process under test is not confined: the sandbox status is set directly,
the way ``icode_sandbox/bootstrap.py`` leaves it.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from chrys.foundation import guard as core_guard
from chrys.foundation.events.bus import EventBus
from icode_sandbox import client as sandbox_client
from icode_sandbox.guard import GUARD
from icode_sandbox.tui.indicator import SandboxIndicator
from icode_sandbox.tui.panel import SandboxDialog
from tests.support.waiting import wait_for

from .test_hook_indicator_flow import _frame, _make_app, _ready


@pytest.fixture
def sandbox_status() -> Iterator[None]:
    """Shows a made-up status; under ``CHRYS_TEST_SANDBOX`` the live runtime comes back afterwards."""
    live, saved, installed = sandbox_client.runtime(), sandbox_client.status(), core_guard.current()
    yield
    sandbox_client._set_runtime(live, saved)
    core_guard.set_current(installed)


def _set(state: str, *, requested: bool, reasons: list[str] | None = None) -> None:
    sandbox_client._set_runtime(
        None, sandbox_client.Status(state=state, requested=requested, mechanism="Seatbelt", reasons=reasons or [])
    )
    # iCode installs the package's guard only when the sandbox was asked for.
    core_guard.set_current(GUARD if requested else core_guard._NoGuard())


async def test_hidden_when_the_sandbox_is_off(tmp_path: Path, sandbox_status: None) -> None:
    _set("inactive", requested=False)
    app = _make_app(tmp_path, EventBus())
    async with app.run_test(size=(160, 40)) as pilot:
        main = await _ready(pilot)
        assert not main.query(SandboxIndicator)
        assert "Sandbox" not in _frame(app).splitlines()[-1]


@pytest.mark.parametrize(
    ("state", "requested", "shown"),
    [
        ("active", True, "🛡"),
        ("degraded", True, "Sandbox: degraded"),
        ("inactive", True, "Sandbox NOT active"),
    ],
)
async def test_every_requested_state_is_visible(
    tmp_path: Path, sandbox_status: None, state: str, requested: bool, shown: str
) -> None:
    _set(state, requested=requested, reasons=["probe"])
    app = _make_app(tmp_path, EventBus())
    async with app.run_test(size=(160, 40)) as pilot:
        await _ready(pilot)
        await wait_for(
            lambda: shown in _frame(app).splitlines()[-1], pilot=pilot, description=f"footer shows {shown!r}"
        )


async def test_clicking_opens_the_panel_with_the_state(tmp_path: Path, sandbox_status: None) -> None:
    _set("inactive", requested=True, reasons=["Landlock is not available in this kernel"])
    app = _make_app(tmp_path, EventBus())
    async with app.run_test(size=(160, 40)) as pilot:
        main = await _ready(pilot)
        await pilot.click(SandboxIndicator)
        await wait_for(
            lambda: isinstance(app.screen, SandboxDialog) and app.screen.is_mounted,
            pilot=pilot,
            description="panel opens",
        )
        frame = _frame(app)
        assert "requested-not-active" in frame
        assert "Landlock is not available" in frame
        assert "not confined" in frame
        await pilot.press("escape")
        await wait_for(lambda: app.screen is main, pilot=pilot, description="panel closes")
        await pilot.press("f7")
        await wait_for(
            lambda: isinstance(app.screen, SandboxDialog) and app.screen.is_mounted,
            pilot=pilot,
            description="F7 opens the panel",
        )
