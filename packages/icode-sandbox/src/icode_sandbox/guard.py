# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The file-access sandbox as iCode's process guard (``chrys.foundation.guard.Guard``).

iCode finds :func:`install` through the ``chrys.runtime_guards`` entry point of
this distribution and calls it first thing at startup, once it has decided the
sandbox is wanted.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from chrys.foundation import guard as core_guard
from icode_sandbox import client as sandbox_client

if TYPE_CHECKING:
    from pathlib import Path

    from chrys.foundation.guard import Decision, ToolCallHost, ToolCalls


class SandboxGuard:
    """The live sandbox of this process, or the status of one that was asked for and isn't running here."""

    def active_runtime(self) -> sandbox_client.Runtime | None:
        return sandbox_client.runtime()

    @property
    def active(self) -> bool:
        return sandbox_client.runtime() is not None

    def status(self) -> core_guard.GuardStatus:
        st = sandbox_client.status()
        from icode_sandbox.backends import current_backend

        return core_guard.GuardStatus(
            state=st.state,
            requested=st.requested,
            mechanism=st.mechanism,
            reasons=list(st.reasons),
            inherited=st.inherited,
            capabilities=dict(current_backend().capabilities),
        )

    def tool_calls(self, host: ToolCallHost) -> ToolCalls:
        rt = sandbox_client.runtime()
        if rt is None:
            return core_guard._NoToolCalls()
        from icode_sandbox.tool_calls import SandboxToolCalls

        return SandboxToolCalls(rt, host)

    def session_scope(
        self, session_id: str | None, roots: list[str], cwd: str | None
    ) -> contextlib.AbstractContextManager[None]:
        from icode_sandbox.reads import session_scope

        return session_scope(session_id, roots, cwd)

    def user_reads(self) -> contextlib.AbstractContextManager[None]:
        return sandbox_client.user_reads()

    def launching_configured(
        self,
        command: str | None = None,
        args: tuple[str, ...] | list[str] = (),
        cwd: str | None = None,
        *,
        reads: list[str] | tuple[str, ...] = (),
        writes: list[str] | tuple[str, ...] = (),
    ) -> contextlib.AbstractContextManager[None]:
        paths = sandbox_client.configured_program_paths(command, args, cwd) if command else []
        return sandbox_client.launching_configured([*paths, *reads], writes=writes)

    def controlling_terminal(self) -> contextlib.AbstractContextManager[None]:
        return sandbox_client.controlling_terminal()

    def walk_start(self, directory: str) -> str | None:
        return sandbox_client.walk_start(directory)

    def cli(self, argv: list[str]) -> int:
        from icode_sandbox.cli import main

        return main(argv)

    def indicator(self) -> Any:
        from icode_sandbox.tui.indicator import SandboxIndicator

        return SandboxIndicator()

    def panel(self) -> Any:
        from icode_sandbox.tui.panel import SandboxDialog

        return SandboxDialog()


GUARD = SandboxGuard()


def install(argv: list[str], decision: Decision, config_dir: Path) -> SandboxGuard:
    """Start the sandbox for this process (iCode decided it is wanted); the guard to install."""
    from icode_sandbox import bootstrap

    bootstrap.start(argv, decision, config_dir)
    return GUARD
