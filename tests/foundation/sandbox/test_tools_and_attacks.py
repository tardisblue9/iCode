# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Real tools through the real approval middleware, in a confined process.

Each scenario is what an injected model would try. The tools are iCode's own
(``read_file``, ``grep``/``glob``, ``convert_document``, the shell); the
approval middleware runs them in the session's scope exactly as a turn does;
a scripted person answers any dialog. Every scenario runs in a fresh process
that enables the sandbox like ``icode``.
"""

from __future__ import annotations

import pytest

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel

TOOLS = r"""
import asyncio
from dataclasses import replace
from chrys.foundation.events.bus import EventBus
from chrys.foundation.events.types import ApprovalRequest, ApprovalResponse
from chrys.foundation.models.session_env import SessionEnvironment
from chrys.foundation.models.workspace import Workspace
from chrys.kernel.middleware import FunctionInvocationContext
from chrys.service.agent_middleware.control.approval import ApprovalMiddleware
from chrys.service.approval.policy import ApprovalMode, ApprovalPolicy
from chrys.service.profiles.agents.schema import ApprovalConfig
from chrys.service.tools.builtins.filesystem import FilesystemTools
from chrys.service.tools.builtins.search import SearchTools
from chrys.service.tools.builtins.shell import ShellTools

env = SessionEnvironment.capture("sess-1", Workspace.from_cwd(WS))
env = replace(env, platform=replace(env.platform, config_dir=__import__("pathlib").Path(CONFIG)))
TOOLSET = {t.name: t for t in [*FilesystemTools(env).tools(), *SearchTools(env).tools(), *ShellTools(env).tools()]}
SHELL = env.platform.shell.name
BUS = EventBus()
ASKED = []
ANSWER = {"approved": False, "remember": ""}

async def _respond(event):
    ASKED.append({"kind": event.tool_kind or event.presentation_kind, "path": event.args.get("path"), "tool": event.args.get("tool", event.tool_name)})
    await BUS.publish(ApprovalResponse(request_id=event.request_id, approved=ANSWER["approved"], remember_choice=ANSWER["remember"]))

def middleware(mode=ApprovalMode.MANUAL, session="sess-1", *, child=False):
    policy = ApprovalPolicy(ApprovalConfig(default="auto", overrides={}))
    return ApprovalMiddleware(policy, BUS, session_id=session, workspace_roots=[WS], workspace_cwd=WS,
                              approval_mode=mode, sandbox_can_request=not child)

async def call(mw, name, **args):
    tool = TOOLSET[name]
    ctx = FunctionInvocationContext(tool, dict(args))
    async def run():
        result = await tool.invoke(arguments=ctx.arguments, context=ctx)
        ctx.result = "".join(getattr(c, "text", "") or "" for c in result)
    await mw.process(ctx, run)
    return ctx.result if isinstance(ctx.result, str) else str(ctx.result)

async def main_scenarios():
    await BUS.subscribe(ApprovalRequest, _respond)
    try:
        await SCENARIO()
    finally:
        await BUS.unsubscribe(ApprovalRequest, _respond)

def run(fn):
    globals()["SCENARIO"] = fn
    asyncio.run(main_scenarios())
"""


def _run(sandbox: Sandbox, body: str) -> dict:
    return sandbox.run(TOOLS + body)


def test_injected_read_outside_workspace_is_asked_then_refused(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware()
    results["ws"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(WS, "f.txt"))}
    ANSWER.update(approved=False)
    results["other declined"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))}
    results["asked"] = {"ok": True, "value": ASKED[:]}
run(scenario)
""",
    )
    assert "WS" in r["ws"]["value"]
    assert r["other declined"]["value"].startswith("Error: sandbox:")
    assert "OTHER" not in r["other declined"]["value"]
    assert r["asked"]["value"] == [{"kind": "sandbox.read", "path": str(sandbox.other / "f.txt"), "tool": "read_file"}]


def test_grants_follow_the_dialog_answer_and_turn_end(sandbox: Sandbox) -> None:
    """The four answers: only this call / this turn / this session (/ working directory) / decline."""
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware()
    G = os.path.join(GRANT, "f.txt")
    ANSWER.update(approved=True, remember="")
    results["only this call"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    ANSWER.update(approved=False)
    results["next call, same turn"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    results["asked twice"] = {"ok": True, "value": len(ASKED)}
    ANSWER.update(approved=True, remember="EXACT_TURN")
    results["turn grant"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    ANSWER.update(approved=False)
    results["same turn again"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    results["shell same turn"] = {"ok": True, "value": await call(mw, SHELL, command=f"cat {G}", reason="t")}
    results["asked after turn grant"] = {"ok": True, "value": len(ASKED)}
    mw.reset()   # the next turn begins
    results["next turn"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    results["shell next turn"] = {"ok": True, "value": await call(mw, SHELL, command=f"cat {G}", reason="t")}
    ANSWER.update(approved=True, remember="EXACT_SESSION")
    results["session grant"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    mw.reset()
    ANSWER.update(approved=False)
    results["after session grant + turn end"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    other_session = middleware(session="sess-2")
    results["other session"] = {"ok": True, "value": await call(other_session, "read_file", path=G)}
    ANSWER.update(approved=True, remember="EXACT_WORKDIR")
    results["workdir grant"] = {"ok": True, "value": await call(other_session, "read_file", path=G)}
    third = middleware(session="sess-3")
    ANSWER.update(approved=False)
    results["workdir grant, new session"] = {"ok": True, "value": await call(third, "read_file", path=G)}
    for grant in RT.grants.entries("sess-3"):
        RT.revoke(grant.id)
    for grant in RT.grants.entries("sess-1"):
        RT.revoke(grant.id)
    results["after revoke"] = {"ok": True, "value": await call(third, "read_file", path=G)}
    results["after revoke, session"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
run(scenario)
""",
    )
    assert "GRANTED" in r["only this call"]["value"]
    assert r["next call, same turn"]["value"].startswith("Error: sandbox:")
    assert r["asked twice"]["value"] == 2
    assert "GRANTED" in r["turn grant"]["value"]
    assert "GRANTED" in r["same turn again"]["value"]
    assert "GRANTED" in r["shell same turn"]["value"]
    assert r["asked after turn grant"]["value"] == 3
    assert r["next turn"]["value"].startswith("Error: sandbox:")
    assert "GRANTED" not in r["shell next turn"]["value"]
    assert "GRANTED" in r["session grant"]["value"]
    assert "GRANTED" in r["after session grant + turn end"]["value"]
    assert r["other session"]["value"].startswith("Error: sandbox:")
    assert "GRANTED" in r["workdir grant"]["value"]
    assert "GRANTED" in r["workdir grant, new session"]["value"]
    assert r["after revoke"]["value"].startswith("Error: sandbox:")
    assert r["after revoke, session"]["value"].startswith("Error: sandbox:")


def test_paths_the_person_mentions_are_readable_for_the_turn(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware()
    G = os.path.join(GRANT, "f.txt")
    mw.set_user_messages([f"please look at @{G}"])
    results["mentioned"] = {"ok": True, "value": await call(mw, "read_file", path=G)}
    results["not mentioned"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))}
    mw.set_user_messages(["look at @~ and @/"])
    results["@~ opens nothing"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))}
    os.makedirs(os.path.expanduser("~/.ssh"), exist_ok=True)  # a protected folder that exists, as on most machines
    mw.set_user_messages([f"@{os.path.expanduser('~/.ssh')}"])
    results["@~/.ssh still protected"] = {"ok": True, "value": await call(mw, "grep", pattern="x", path=os.path.expanduser("~/.ssh"))}
    results["asked"] = {"ok": True, "value": len(ASKED)}
run(scenario)
""",
    )
    assert "GRANTED" in r["mentioned"]["value"]
    assert r["not mentioned"]["value"].startswith("Error: sandbox:")
    assert r["@~ opens nothing"]["value"].startswith("Error: sandbox:")
    assert r["@~/.ssh still protected"]["value"].startswith("Error: sandbox:")
    assert "protected" in r["@~/.ssh still protected"]["value"]
    assert r["asked"]["value"] == 2  # the two unmentioned reads asked (and were declined)


def test_non_interactive_modes_refuse_without_asking(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    for mode in (ApprovalMode.BYPASS, ApprovalMode.AUTO):
        mw = middleware(mode)
        results[mode.value] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))}
    results["asked"] = {"ok": True, "value": len(ASKED)}
run(scenario)
""",
    )
    assert r["bypass"]["value"].startswith("Error: sandbox:")
    assert r["auto"]["value"].startswith("Error: sandbox:")
    assert "cannot ask the user" in r["bypass"]["value"]
    assert r["asked"]["value"] == 0


def test_protected_paths_are_never_asked_or_granted(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware()
    ANSWER.update(approved=True, remember="EXACT_WORKDIR")
    ssh = os.path.expanduser("~/.ssh")
    os.makedirs(os.path.join(WS, "x"), exist_ok=True)
    try:
        os.symlink(ssh, os.path.join(WS, "keys"))
    except FileExistsError:
        pass
    results["read ~/.ssh"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(ssh, "config"))}
    results["grep ~/.ssh"] = {"ok": True, "value": await call(mw, "grep", pattern="Host", path=ssh)}
    results["via workspace symlink"] = {"ok": True, "value": await call(mw, "read_file", path=os.path.join(WS, "keys", "config"))}
    results["asked"] = {"ok": True, "value": len(ASKED)}
run(scenario)
""",
    )
    for name in ("read ~/.ssh", "grep ~/.ssh", "via workspace symlink"):
        value = r[name]["value"]
        assert value.startswith("Error:"), (name, value)
        assert "protected" in value or "not found" in value or "denied" in value, (name, value)
    assert r["asked"]["value"] == 0


def test_shell_and_search_cannot_reach_outside_the_scope(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    q = lambda c: call(mw, SHELL, command=c, reason="t")
    results["cat"] = {"ok": True, "value": await q(f"cat {OTHER}/f.txt")}
    results["find home"] = {"ok": True, "value": await q("find ~ -maxdepth 1 -name '*.txt' 2>&1 | head -3")}
    results["python"] = {"ok": True, "value": await q(f"python3 -c \\"print(open('{OTHER}/f.txt').read())\\"")}
    results["cp then read"] = {"ok": True, "value": await q(f"cp {OTHER}/f.txt {WS}/stolen.txt; cat {WS}/stolen.txt")}
    results["grep other"] = {"ok": True, "value": await call(mw, "grep", pattern="OTHER", path=OTHER)}
    results["glob other"] = {"ok": True, "value": await call(mw, "glob", pattern="*.txt", path=OTHER)}
    results["grep ws"] = {"ok": True, "value": await call(mw, "grep", pattern="WS", path=WS)}
    results["shell ws"] = {"ok": True, "value": await q("cat f.txt")}
run(scenario)
""",
    )
    for name in ("cat", "python", "cp then read"):
        assert "OTHER" not in r[name]["value"], (name, r[name]["value"])
    assert "f.txt" not in r["find home"]["value"]
    assert r["grep other"]["value"].startswith("Error: sandbox:")
    assert r["glob other"]["value"].startswith("Error: sandbox:")
    assert "WS" in r["grep ws"]["value"]
    assert "WS" in r["shell ws"]["value"]


def test_sub_agents_share_grants_but_cannot_ask(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
async def scenario():
    parent = middleware()
    child = middleware(child=True)
    ANSWER.update(approved=True, remember="EXACT_TURN")
    results["child asks"] = {"ok": True, "value": await call(child, "read_file", path=os.path.join(GRANT, "f.txt"))}
    results["asked by child"] = {"ok": True, "value": len(ASKED)}
    await call(parent, "read_file", path=os.path.join(GRANT, "f.txt"))
    results["child after parent grant"] = {"ok": True, "value": await call(child, "read_file", path=os.path.join(GRANT, "f.txt"))}
run(scenario)
""",
    )
    assert r["child asks"]["value"].startswith("Error: sandbox:")
    assert r["asked by child"]["value"] == 0
    assert "GRANTED" in r["child after parent grant"]["value"]


def test_compromised_main_process_limits(sandbox: Sandbox) -> None:
    """Accepted risk: code running inside iCode can obtain grantable paths, never protected ones."""
    r = sandbox.run(
        """
import ctypes
def widen():
    if sys.platform == "darwin":
        lib = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")
        err = ctypes.c_char_p()
        lib.sandbox_init(b"(version 1)(allow default)", 0, ctypes.byref(err))
    else:
        # Landlock layers only stack: a wider ruleset can't undo the first one.
        confine.apply(confine.Profile(mode="except", allow=[os.path.expanduser("~")], deny_roots=["/mnt"]))
    return open(os.path.join(OTHER, "f.txt")).read()
check("direct open", lambda: client._raw_os_open(os.path.join(OTHER, "f.txt"), os.O_RDONLY))
check("widen own sandbox", widen)
check("ask broker for ~/.ssh", lambda: RT._call({"op": "helper", "profile": {"mode": "only", "allow": [os.path.expanduser("~/.ssh")]}}).get("ok"))
scope = policy.Scope(key="evil", roots=(WS,))
def forge_grant():
    RT.grant(scope, "session", OTHER)
    return os.read(RT.open_scoped(scope, os.path.join(OTHER, "f.txt"), os.O_RDONLY), 20).decode()
check("forge a grant for a grantable path", forge_grant)
"""
    )
    assert not r["direct open"]["ok"]
    assert not r["widen own sandbox"]["ok"]
    assert r["ask broker for ~/.ssh"]["value"] is False
    # Known residual risk: pinned so a change in behaviour is noticed.
    assert r["forge a grant for a grantable path"]["value"] == "OTHER"


@pytest.mark.parametrize("tool", ["read_file", "grep", "glob"])
def test_every_path_tool_is_covered(sandbox: Sandbox, tool: str) -> None:
    args = {
        "read_file": "path=os.path.join(OTHER, 'f.txt')",
        "grep": "pattern='O', path=OTHER",
        "glob": "pattern='*', path=OTHER",
    }[tool]
    r = _run(
        sandbox,
        f"""
async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    results["r"] = {{"ok": True, "value": await call(mw, {tool!r}, {args})}}
run(scenario)
""",
    )
    assert r["r"]["value"].startswith("Error: sandbox:"), r["r"]["value"]
    assert "OTHER" not in r["r"]["value"].split("sandbox:", 1)[1].replace(str(sandbox.other), "")


REGISTRY = r"""
from chrys.service.tools.builtins.doc_converter import DocConverterTools
from chrys.service.tools.kinds import get_tool_kind
ALL = [*FilesystemTools(env).tools(), *SearchTools(env).tools(), *DocConverterTools(env).tools()]
FILLER = {"string": "x", "integer": 1, "boolean": True}

def args_for(tool, path):
    schema = tool.parameters()
    props = schema.get("properties", {})
    args = {}
    for name in schema.get("required", []):
        kind = props.get(name, {}).get("type", "string")
        args[name] = FILLER.get(kind, "x")
    args["path"] = path
    if "pattern" in props:
        args["pattern"] = "*" if tool.name == "glob" else "O"
    return args

async def call_tool(mw, tool, **args):
    ctx = FunctionInvocationContext(tool, dict(args))
    async def run():
        result = await tool.invoke(arguments=ctx.arguments, context=ctx)
        ctx.result = "".join(getattr(c, "text", "") or "" for c in result)
    await mw.process(ctx, run)
    return ctx.result if isinstance(ctx.result, str) else str(ctx.result)
"""


def test_every_registered_path_tool_is_refused_outside_the_scope(sandbox: Sandbox) -> None:
    """Built from the tool classes themselves: a new path tool is covered without editing this test."""
    for name in ("f.txt", "f.png"):
        (sandbox.other / name).write_bytes(b"OTHER")
    r = _run(
        sandbox,
        REGISTRY
        + """
async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    seen = []
    for tool in ALL:
        if "path" not in tool.parameters().get("properties", {}):
            continue
        target = os.path.join(OTHER, "f.png" if tool.name == "view_image" else "f.txt")
        for path in (target, OTHER):
            out = await call_tool(mw, tool, **args_for(tool, path))
            seen.append([tool.name, get_tool_kind(tool), path == OTHER, out[:200]])
    results["seen"] = {"ok": True, "value": seen}
run(scenario)
""",
    )
    seen = r["seen"]["value"]
    names = {row[0] for row in seen}
    assert {"read_file", "view_image", "write_file", "edit_file", "grep", "glob", "convert_document"} <= names
    for tool, _kind, _is_dir, out in seen:
        assert out.startswith("Error:"), (tool, out)
        assert "OTHER" not in out.replace(str(sandbox.other), ""), (tool, out)
    assert (sandbox.other / "f.txt").read_bytes() == b"OTHER"  # write tools changed nothing


def test_documents_in_granted_folders_convert(sandbox: Sandbox) -> None:
    import docx

    document = docx.Document()
    document.add_paragraph("GRANTED-DOCUMENT-BODY")
    document.save(str(sandbox.granted / "spec.docx"))
    r = _run(
        sandbox,
        REGISTRY
        + """
async def scenario():
    mw = middleware()
    tool = next(t for t in ALL if t.name == "convert_document")
    ANSWER.update(approved=False)
    results["before grant"] = {"ok": True, "value": await call_tool(mw, tool, path=os.path.join(GRANT, "spec.docx"))}
    ANSWER.update(approved=True, remember="EXACT_TURN")
    results["after grant"] = {"ok": True, "value": await call_tool(mw, tool, path=os.path.join(GRANT, "spec.docx"))}
    grep = next(t for t in ALL if t.name == "grep")
    results["grep granted"] = {"ok": True, "value": await call_tool(mw, grep, pattern="GRANTED", path=GRANT)}
run(scenario)
""",
    )
    assert r["before grant"]["value"].startswith("Error: sandbox:")
    assert "GRANTED-DOCUMENT-BODY" in r["after grant"]["value"]
    assert "GRANTED" in r["grep granted"]["value"]
