# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The places the core hands work to the sandbox through ``chrys.foundation.guard``, with real processes.

Each test drives one core call site (not the guard's own function), so taking
the call out of the core turns it red.
"""

from __future__ import annotations

from .conftest import Sandbox, needs_kernel
from .test_tools_and_attacks import _run

pytestmark = needs_kernel


def test_closing_the_approval_middleware_lets_go_of_its_scope(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware(session="sess-close")
    await call(mw, "read_file", path=os.path.join(WS, "f.txt"))
    results["held"] = {"ok": True, "value": RT._holders.get("sess-close", 0)}
    await mw.close()
    results["after"] = {"ok": True, "value": RT._holders.get("sess-close", 0)}
run(scenario)
""",
    )
    assert (r["held"]["value"], r["after"]["value"]) == (1, 0), r


def test_a_terminal_command_gets_its_terminal_as_controlling_terminal(sandbox: Sandbox) -> None:
    """The TUI's terminal panel: ``/dev/tty`` only opens for a program that has a controlling terminal."""
    r = sandbox.run(
        r"""
import asyncio
from chrys.app.tui.terminal.pty_process import spawn_pty_process

async def main():
    proc = await spawn_pty_process(
        ["sh", "-c", "echo hello > /dev/tty && echo TTY-OK || echo TTY-NONE"],
        env=dict(os.environ), cwd=WS, columns=80, lines=24,
    )
    out = ""
    while chunk := await asyncio.wait_for(proc.read(), 20):
        out += chunk
    await proc.close()
    return out

results["out"] = {"ok": True, "value": asyncio.run(main())}
"""
    )
    assert "TTY-OK" in r["out"]["value"], r


def test_a_file_under_the_home_folder_is_written_by_secure_walk(sandbox: Sandbox) -> None:
    """``files.py`` opens each parent without following links; under the sandbox it starts inside the scope."""
    r = sandbox.run(
        r"""
from pathlib import Path
from chrys.foundation.platform import files

target = Path(WS) / "deep" / "state.json"
target.parent.mkdir()
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    files.atomic_write_owner_only_text(target, "{}")
results["written"] = {"ok": True, "value": target.read_text()}
"""
    )
    assert r["written"]["value"] == "{}", r


def test_an_external_acp_agent_reads_its_own_program(sandbox: Sandbox) -> None:
    """The person configured this agent: its script outside the workspace is readable to it, and only it."""
    (sandbox.other / "agent.py").write_text("print('AGENT-RAN')\n", encoding="utf-8")
    r = sandbox.run(
        r"""
import asyncio, sys
from pathlib import Path
from chrys.service.acp_client.spawn import spawn_acp_process
from chrys.service.acp_client.spec import AcpAgentSpec

async def main():
    spec = AcpAgentSpec(
        command=sys.executable, cwd=WS, args=(os.path.join(OTHER, "agent.py"),),
        stderr_log_path=Path(WS) / "agent.log",
    )
    spawned = await spawn_acp_process(spec)
    out = await asyncio.wait_for(spawned.process.stdout.read(), 20)
    return out.decode(), spawned.stderr_tail

out, err = asyncio.run(main())
results["out"] = {"ok": True, "value": [out, err]}
"""
    )
    assert "AGENT-RAN" in r["out"]["value"][0], r
