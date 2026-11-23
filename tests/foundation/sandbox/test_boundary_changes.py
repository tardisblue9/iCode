# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Real-kernel: boundaries that change, and refusals reaching the session's records."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from chrys.foundation.util.session_ids import session_short_id

from .conftest import Sandbox, needs_kernel
from .test_tools_and_attacks import _run

pytestmark = needs_kernel

ROOTS = r"""
def session(roots, key="sess-1", mode=ApprovalMode.BYPASS):
    policy_ = ApprovalPolicy(ApprovalConfig(default="auto", overrides={}))
    return ApprovalMiddleware(policy_, BUS, session_id=key, workspace_roots=roots, workspace_cwd=roots[0], approval_mode=mode)

async def attempts(mw, folder):
    path = os.path.join(folder, "f.txt")
    return {
        "read": await call(mw, "read_file", path=path),
        "grep": await call(mw, "grep", pattern="[A-Z]", path=folder),
        "shell": await call(mw, SHELL, command=f"cat {path}", reason="t"),
    }
"""


def _text(rows: dict) -> dict[str, bool]:
    return {name: name_text.upper().find("OTHER") >= 0 for name, name_text in rows.items()}


def test_additional_directories_are_readable_and_nothing_else(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        ROOTS
        + """
async def scenario():
    mw = session([WS, GRANT])
    results["added"] = {"ok": True, "value": json.dumps(await attempts(mw, GRANT))}
    results["other"] = {"ok": True, "value": json.dumps(await attempts(mw, OTHER))}
    results["panel"] = {"ok": True, "value": json.dumps(RT.snapshot()["scopes"]["sess-1"]["roots"])}
    await mw.close()
run(scenario)
""",
    )
    added, other = json.loads(r["added"]["value"]), json.loads(r["other"]["value"])
    for tool in ("read", "grep", "shell"):
        assert "GRANTED" in added[tool], tool
        assert "OTHER\n" not in other[tool].replace(str(sandbox.other), ""), tool
        assert ":OTHER" not in other[tool], tool
    assert other["read"].startswith("Error: sandbox")
    assert len(json.loads(r["panel"]["value"])) == 2


def test_without_the_additional_directory_it_is_refused(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        ROOTS
        + """
async def scenario():
    mw = session([WS])
    results["added"] = {"ok": True, "value": json.dumps(await attempts(mw, GRANT))}
    await mw.close()
run(scenario)
""",
    )
    for tool, out in json.loads(r["added"]["value"]).items():
        assert "GRANTED" not in out, tool


def test_one_sessions_additional_directory_is_not_anothers(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        ROOTS
        + """
async def scenario():
    one, two = session([WS, GRANT], "s1"), session([WS], "s2")
    results["one"] = {"ok": True, "value": await call(one, "read_file", path=os.path.join(GRANT, "f.txt"))}
    results["two"] = {"ok": True, "value": json.dumps(await attempts(two, GRANT))}
    await one.close(); await two.close()
run(scenario)
""",
    )
    assert "GRANTED" in r["one"]["value"]
    for tool, out in json.loads(r["two"]["value"]).items():
        assert "GRANTED" not in out, tool


def test_switching_workspace_opens_the_new_one_and_closes_the_old(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        ROOTS
        + """
async def scenario():
    old = session([WS])
    results["before"] = {"ok": True, "value": await call(old, "read_file", path=os.path.join(WS, "f.txt"))}
    helper = RT._scope_helpers["sess-1"].pid
    new = session([GRANT])  # a rebuild builds the new middleware first, then closes the old
    results["new"] = {"ok": True, "value": json.dumps(await attempts(new, GRANT))}
    await old.close()
    results["old"] = {"ok": True, "value": json.dumps(await attempts(new, WS))}
    results["helper replaced"] = {"ok": True, "value": RT._scope_helpers["sess-1"].pid != helper}
    await new.close()
    results["all gone"] = {"ok": True, "value": "sess-1" not in RT._scope_helpers}
run(scenario)
""",
    )
    assert "WS" in r["before"]["value"]
    for tool, out in json.loads(r["new"]["value"]).items():
        assert "GRANTED" in out, tool
    old = json.loads(r["old"]["value"])
    assert old["read"].startswith("Error: sandbox")
    assert "\nWS" not in old["shell"] and "1\tWS" not in old["read"]
    assert r["helper replaced"]["value"] is True
    assert r["all gone"]["value"] is True


REPORTS = r"""
from chrys.foundation.events.types import SandboxAccessDenied
from chrys.foundation.trajectory.context import TrajectoryContext, bind_trajectory, main_actor
EMITTED, PUBLISHED = [], []

class Sink:
    fingerprint_key = None
    async def emit(self, draft, *, payload_factory=None): EMITTED.append(draft)
    def emit_blocking(self, draft, *, payload_factory=None): EMITTED.append(draft)
    def emit_soon(self, draft, *, payload_factory=None): EMITTED.append(draft)

async def on_denied(event):
    PUBLISHED.append([event.session_id, event.path, event.tool, event.outcome])

async def scenario():
    await BUS.subscribe(SandboxAccessDenied, on_denied)
    bind_trajectory(TrajectoryContext(sink=Sink(), session_id="sess-1", actor=main_actor("sess-1")))
    mw = middleware(MODE)
    ANSWER.update(approved=False)
    results["out"] = {"ok": True, "value": await call(mw, "read_file", path=TARGET)}
    results["published"] = {"ok": True, "value": PUBLISHED}
    results["emitted"] = {"ok": True, "value": [[d.event_type, dict(d.payload)["path"], dict(d.payload)["tool"], dict(d.payload)["outcome"]] for d in EMITTED]}
    await BUS.unsubscribe(SandboxAccessDenied, on_denied)
    await mw.close()
run(scenario)
"""


def _reported(sandbox: Sandbox, mode: str, target: str) -> dict:
    return _run(sandbox, f"MODE = ApprovalMode.{mode}\nTARGET = {target}\n" + REPORTS)


def test_a_refused_read_reaches_the_trajectory_and_the_bus(sandbox: Sandbox) -> None:
    r = _reported(sandbox, "BYPASS", 'os.path.join(OTHER, "f.txt")')
    path = str(sandbox.other.resolve() / "f.txt")
    assert r["published"]["value"] == [["sess-1", path, "read_file", "refused"]]
    assert r["emitted"]["value"] == [["sandbox.access.denied", path, "read_file", "refused"]]


def test_a_declined_read_is_reported_as_declined(sandbox: Sandbox) -> None:
    r = _reported(sandbox, "MANUAL", 'os.path.join(OTHER, "f.txt")')
    assert r["published"]["value"][0][3] == "declined"


def test_a_protected_read_is_reported_as_protected(sandbox: Sandbox) -> None:
    r = _reported(sandbox, "BYPASS", 'os.path.expanduser("~/.ssh/config")')
    if not r["out"]["value"].startswith("Error: sandbox"):
        return  # no ~/.ssh/config on this machine: nothing to refuse
    assert r["published"]["value"][0][3] == "protected"


def test_a_read_inside_the_workspace_reports_nothing(sandbox: Sandbox) -> None:
    r = _reported(sandbox, "BYPASS", 'os.path.join(WS, "f.txt")')
    assert r["published"]["value"] == [] and r["emitted"]["value"] == []


def test_a_refusal_after_the_tool_started_is_reported_with_the_tool(sandbox: Sandbox) -> None:
    """The in-process hook, not the pre-check: the path isn't named as an argument."""
    r = _run(
        sandbox,
        r"""
from chrys.foundation.events.types import SandboxAccessDenied
from chrys.kernel.tools import FunctionTool
PUBLISHED = []
async def on_denied(event):
    PUBLISHED.append([event.tool, event.outcome])
def sneaky() -> str:
    try:
        return open(os.path.join(OTHER, "f.txt")).read()
    except OSError as exc:
        return f"Error: {type(exc).__name__}"
async def scenario():
    await BUS.subscribe(SandboxAccessDenied, on_denied)
    tool = FunctionTool(name="sneaky", description="x", func=sneaky)
    TOOLSET["sneaky"] = tool
    mw = middleware(ApprovalMode.BYPASS)
    results["out"] = {"ok": True, "value": await call(mw, "sneaky")}
    results["published"] = {"ok": True, "value": PUBLISHED}
    await mw.close()
run(scenario)
""",
    )
    assert "OTHER" not in r["out"]["value"]
    assert r["published"]["value"] == [["sneaky", "denied"]]


def test_redacted_session_logs_hold_no_path(sandbox: Sandbox) -> None:
    (sandbox.root / "config" / "settings.yaml").write_text("sandbox.files.audit.redact_paths: true\n", encoding="utf-8")
    (sandbox.root / "config" / "sessions" / session_short_id("sess-1")).mkdir(parents=True)
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    results["out"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))}
    await mw.close()
run(scenario)
""",
    )
    assert r["out"]["value"].startswith("Error: sandbox")
    logs = [
        sandbox.root / "config" / "sandbox" / "audit.jsonl",
        sandbox.root / "config" / "sessions" / session_short_id("sess-1") / "sandbox_events.jsonl",
    ]
    for log in logs:
        text = log.read_text(encoding="utf-8")
        assert '"deny"' in text and "hmac:" in text, log
        assert str(sandbox.root) not in text, log


def test_changing_the_setting_mid_session_changes_nothing(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
scope = policy.Scope(key="s", roots=(WS,))
check("before", lambda: open(os.path.join(OTHER, "f.txt")).read())
with open(os.path.join(CONFIG, "settings.yaml"), "w") as f:
    f.write("sandbox.files.enabled: false\\n")
os.environ["CHRYS_FILE_SANDBOX"] = "0"
_argv, again = bootstrap.install_at_startup(["--no-sandbox"], config_dir=__import__("pathlib").Path(CONFIG))
check("after", lambda: open(os.path.join(OTHER, "f.txt")).read())
check("command after", lambda: cat(os.path.join(OTHER, "f.txt")))
check("still", lambda: [client.status().label(), again.label()])
"""
    )
    assert r["before"]["error"] == "PermissionError"
    assert r["after"]["error"] == "PermissionError"
    assert r["command after"]["ok"] is False
    assert r["still"]["value"] == ["active", "active"]


def test_the_panel_follows_refusal_grant_and_revoke(sandbox: Sandbox) -> None:
    (sandbox.root / "config" / "sessions" / session_short_id("sess-1")).mkdir(parents=True)
    r = _run(
        sandbox,
        r"""
from icode_sandbox.tui.panel import SandboxDialog
from textual.app import App
from textual.widgets import Button, Static
from chrys.app.tui.theme import TuiVariableDefaultsMixin

class Host(TuiVariableDefaultsMixin, App):
    pass

def text(screen):
    return "\n".join(str(w.render()) for w in screen.query(Static))

async def scenario():
    mw = middleware()
    target = os.path.join(OTHER, "f.txt")
    ANSWER.update(approved=False)
    results["refused"] = {"ok": True, "value": await call(mw, "read_file", path=target)}
    ANSWER.update(approved=True, remember="EXACT_SESSION")
    results["granted"] = {"ok": True, "value": await call(mw, "read_file", path=target)}
    app = Host()
    async with app.run_test(size=(180, 90)) as pilot:
        dialog = SandboxDialog()
        await app.push_screen(dialog)
        await pilot.pause()
        results["panel"] = {"ok": True, "value": text(dialog)}
        button = [b for b in dialog.query(Button) if (b.id or "").startswith("revoke-")][0]
        await dialog._revoke(Button.Pressed(button))
        await pilot.pause()
        results["panel after"] = {"ok": True, "value": text(dialog)}
    ANSWER.update(approved=False)
    results["after revoke"] = {"ok": True, "value": await call(mw, "read_file", path=target)}
    from chrys.foundation.util.session_ids import session_short_id
    log = os.path.join(CONFIG, "sessions", session_short_id("sess-1"), "sandbox_events.jsonl")
    results["log"] = {"ok": True, "value": [json.loads(l) for l in open(log)]}
    await mw.close()
run(scenario)
""",
    )
    other = str(sandbox.other.resolve())
    assert r["refused"]["value"].startswith("Error: sandbox")
    assert "OTHER" in r["granted"]["value"].replace(other, "")
    panel = r["panel"]["value"]
    assert other in panel and "declined" in panel and "granted" in panel and "This session" in panel
    assert "This session" not in r["panel after"]["value"]
    assert r["after revoke"]["value"].startswith("Error: sandbox")
    events = [(e["event"], e.get("outcome") or e.get("kind")) for e in r["log"]["value"]]
    assert ("deny", "declined") in events
    assert ("grant", "session") in events
    assert ("deny", "granted") in events
    assert ("revoke", "session") in events


def test_a_workdir_asking_to_turn_it_off_is_told_no_at_startup(sandbox: Sandbox) -> None:
    config = sandbox.root / "config"
    (config / "settings.yaml").write_text(
        "sandbox.files.enabled: true\nworkdir.config_enabled: true\n", encoding="utf-8"
    )
    (sandbox.ws / ".chrys").mkdir()
    (sandbox.ws / ".chrys" / "settings.yaml").write_text("sandbox.files.enabled: false\n", encoding="utf-8")
    script = f"""
import pathlib
from icode_sandbox import bootstrap, client
_, status = bootstrap.install_at_startup(["-C", {str(sandbox.ws)!r}], config_dir=pathlib.Path({str(config)!r}))
print("STATE", status.label())
try:
    open({str(sandbox.other / "f.txt")!r}).read()
    print("READ")
except PermissionError:
    print("REFUSED")
"""
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert "STATE active" in proc.stdout and "REFUSED" in proc.stdout, proc.stdout + proc.stderr
    assert "cannot, so it stays on" in proc.stderr


MCP_SERVER = """
from mcp.server.fastmcp import FastMCP
server = FastMCP("probe")
@server.tool()
def cat(path: str) -> str:
    try:
        return open(path).read()
    except OSError as exc:
        return f"refused {type(exc).__name__}"
server.run()
"""

MCP_CLIENT = r"""
import asyncio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters
from chrys.service.mcp._stdio_transport import tolerant_stdio_client

async def read_with(read_paths, path):
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(WS, "server.py")])
    async with tolerant_stdio_client(params, sandbox_read_paths=read_paths) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool("cat", {"path": path})
            return result.content[0].text

async def main():
    target = os.path.join(GRANT, "f.txt")
    results["configured"] = {"ok": True, "value": await read_with([GRANT], target)}
    results["other server"] = {"ok": True, "value": await read_with([], target)}
    results["other folder"] = {"ok": True, "value": await read_with([GRANT], os.path.join(OTHER, "f.txt"))}
    results["protected"] = {"ok": True, "value": await read_with([FLOOR], os.path.join(FLOOR, "id_rsa"))}
asyncio.run(main())
"""


def test_an_mcp_server_reads_its_own_folders_only(sandbox: Sandbox) -> None:
    (sandbox.ws / "server.py").write_text(MCP_SERVER, encoding="utf-8")
    floor = Path.home() / ".ssh"
    r = sandbox.run(f"FLOOR = {str(floor)!r}\n" + MCP_CLIENT, timeout=90)
    assert r["configured"]["value"] == "GRANTED"
    assert r["other server"]["value"].startswith("refused")
    assert r["other folder"]["value"].startswith("refused")
    assert r["protected"]["value"].startswith("refused")


MCP_CWD_CLIENT = r"""
import asyncio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters
from chrys.service.mcp._stdio_transport import tolerant_stdio_client

async def read_in(cwd):
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(WS, "server.py")], cwd=cwd)
    async with tolerant_stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool("cat", {"path": os.path.join(GRANT, "f.txt")})
            return result.content[0].text

async def main():
    results["started there"] = {"ok": True, "value": await read_in(GRANT)}
    results["started in the workspace"] = {"ok": True, "value": await read_in(WS)}
asyncio.run(main())
"""


def test_an_mcp_server_reads_the_folder_it_is_configured_to_start_in(sandbox: Sandbox) -> None:
    """A stdio server's ``cwd`` is the person's choice, like its command: that server may read it, others may not."""
    (sandbox.ws / "server.py").write_text(MCP_SERVER, encoding="utf-8")
    r = sandbox.run(MCP_CWD_CLIENT, timeout=90)
    assert r["started there"]["value"] == "GRANTED", r
    assert r["started in the workspace"]["value"].startswith("refused"), r


def test_read_paths_change_the_connection_key_and_load_from_profiles() -> None:
    from chrys.service.mcp.cache import resolve_mcp_effective_config
    from chrys.service.profiles.agents.schema import MCPServerConfig

    plain = MCPServerConfig(name="m", transport="stdio", command="x")
    wide = MCPServerConfig(name="m", transport="stdio", command="x", read_paths=["/a"])
    key = lambda config: resolve_mcp_effective_config(config, stdio_cwd="/").key  # noqa: E731
    assert key(plain) != key(wide)


def test_a_session_saved_after_its_first_refusal_keeps_it(sandbox: Sandbox) -> None:
    """A session has no folder until its first save; what happened before that isn't lost."""
    folder = sandbox.root / "config" / "sessions" / session_short_id("sess-1")
    r = _run(
        sandbox,
        f"""
async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    results["out"] = {{"ok": True, "value": await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))}}
    os.makedirs({str(folder)!r})
    results["second"] = {{"ok": True, "value": await call(mw, "grep", pattern="O", path=OTHER)}}
    await mw.close()
run(scenario)
""",
    )
    assert r["out"]["value"].startswith("Error: sandbox")
    events = [json.loads(line) for line in (folder / "sandbox_events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [e["tool"] for e in events if e["event"] == "deny"] == ["read_file", "grep"]


def test_icodes_own_path_walks_are_not_reported_as_refusals(sandbox: Sandbox) -> None:
    """A secure write under the config dir, in a tool's scope, walks down from the top; only a real refusal counts."""
    r = sandbox.run(
        """
scope = policy.Scope(key="s", roots=(WS,))
with client.scoped(scope):
    for path in (os.path.dirname(CONFIG), CONFIG):
        for walk in (lambda: os.close(os.open(path, os.O_RDONLY | os.O_DIRECTORY)), lambda: os.listdir(path)):
            try:
                walk()
            except PermissionError:
                pass
    try:
        os.close(os.open(OTHER, os.O_RDONLY | os.O_DIRECTORY))
    except PermissionError:
        pass
results["denials"] = {"ok": True, "value": [d.path for d in RT.take_unreported("s")]}
"""
    )
    assert r["denials"]["value"] == [str(sandbox.other.resolve())]


def test_a_workflow_worker_can_read_what_it_runs_from(sandbox: Sandbox) -> None:
    """The injected SDK and the person's workflows live in the config dir, which is otherwise private."""
    workflows = sandbox.root / "config" / "workflows"
    workflows.mkdir()
    (workflows / "w.py").write_text("WORKFLOW", encoding="utf-8")
    (sandbox.root / "config" / "other.txt").write_text("CONFIG", encoding="utf-8")
    r = sandbox.run(
        f"""
check("workflow", lambda: cat({str(workflows / "w.py")!r}))
check("rest of config", lambda: cat({str(sandbox.root / "config" / "other.txt")!r}))
"""
    )
    assert r["workflow"]["value"] == "WORKFLOW"
    assert r["rest of config"]["ok"] is False


def test_the_panel_shows_additional_folders_apart_from_the_workspace(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        ROOTS
        + r"""
from icode_sandbox.tui.panel import SandboxDialog
from chrys.app.tui.theme import TuiVariableDefaultsMixin
from rich.console import Console
from textual.app import App
from textual.widgets import Static
import io

class Host(TuiVariableDefaultsMixin, App):
    pass

async def scenario():
    mw = session([WS, GRANT])
    await call(mw, "read_file", path=os.path.join(GRANT, "f.txt"))
    app = Host()
    async with app.run_test(size=(180, 90)) as pilot:
        dialog = SandboxDialog()
        await app.push_screen(dialog)
        await pilot.pause()
        console = Console(width=170, file=io.StringIO(), force_terminal=False, _environ={})
        for widget in dialog.query(Static):
            console.print(widget.content)
            console.print("@@ROW@@")
        results["rows"] = {"ok": True, "value": console.file.getvalue().split("@@ROW@@")}
    await mw.close()
run(scenario)
""",
    )
    rows = r["rows"]["value"]
    working = next(row for row in rows if "Working folders" in row)
    additional = next(row for row in rows if "Additional working folders" in row)
    assert str(sandbox.ws.resolve()) in working and str(sandbox.granted.resolve()) not in working
    assert str(sandbox.granted.resolve()) in additional


@pytest.mark.parametrize("value", ["~/notes", [1], {"a": "b"}])
def test_an_mcp_servers_paths_must_be_a_list_of_strings(value: object) -> None:
    from chrys.service.profiles.agents.loader import AgentProfileLoadError, _parse_mcp_servers

    with pytest.raises(AgentProfileLoadError):
        _parse_mcp_servers([{"name": "m", "transport": "stdio", "command": "x", "read_paths": value}])
