# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Tools from Python extensions run inside iCode, yet get the same limits as built-in tools.

An extension's tool is bound the way iCode binds it and called through the
approval middleware, so it runs in the session's scope: what it opens goes
through the session's helper and the kernel decides. Unlike a built-in file
tool, it gets no approval prompt (iCode doesn't know which of its arguments
are paths): a refusal ends the call, as it does for a shell command.
"""

from __future__ import annotations

from .conftest import Sandbox, needs_kernel
from .test_tools_and_attacks import _run

pytestmark = needs_kernel

EXTENSION = r"""
from typing import Annotated
from chrys.extensions import Extension, ToolContext
from chrys.service.extensions import _bind

ext = Extension()

@ext.tool(requires_approval=False)
async def ext_read(path: Annotated[str, "file"]) -> str:
    with open(path, encoding="utf-8") as stream:
        return stream.read()

@ext.tool(requires_approval=False)
async def ext_write(path: Annotated[str, "file"], text: Annotated[str, "text"]) -> str:
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(text)
    return "written"

async def attempt(mw, name, **args):
    # What the call gives back, or the exception iCode turns into "the tool failed" for the model.
    try:
        return await call(mw, name, **args)
    except Exception as exc:
        return f"raised {type(exc).__name__}: {exc}"

TOOLSET.update({d.name: _bind("probe", d, lambda: ToolContext.for_testing(__import__("pathlib").Path(WS)), None) for d in ext.tools})
"""


def test_an_extension_tool_reads_and_writes_only_inside_the_scope(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        EXTENSION
        + """
async def scenario():
    mw = middleware()
    results["read ws"] = {"ok": True, "value": await attempt(mw, "ext_read", path=os.path.join(WS, "f.txt"))}
    results["read other"] = {"ok": True, "value": await attempt(mw, "ext_read", path=os.path.join(OTHER, "f.txt"))}
    results["write ws"] = {"ok": True, "value": await attempt(mw, "ext_write", path=os.path.join(WS, "made.txt"), text="E")}
    results["write other"] = {"ok": True, "value": await attempt(mw, "ext_write", path=os.path.join(OTHER, "made.txt"), text="E")}
run(scenario)
""",
    )
    assert r["read ws"]["value"] == "WS", r["read ws"]
    assert r["read other"]["value"].startswith("raised SandboxDenied"), r["read other"]
    assert "OTHER" not in r["read other"]["value"]
    assert r["write ws"]["value"] == "written", r["write ws"]
    assert r["write other"]["value"].startswith("raised SandboxDenied"), r["write other"]
    assert (sandbox.ws / "made.txt").read_text(encoding="utf-8") == "E"
    assert not (sandbox.other / "made.txt").exists()
