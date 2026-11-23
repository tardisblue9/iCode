# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Every built-in tool that takes a path is walked against the sandbox.

Nothing here lists the tools to test. :func:`path_tool_owners` finds them by
scanning the source for tool parameters named like a path, and the scenario
instantiates each owning class and calls each of its tools with a path outside
the scope. A new tool class is therefore covered without editing this file; one
that can't be driven this way fails the guard until it is given a reason here.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from .conftest import Sandbox, needs_kernel
from .test_tools_and_attacks import _run

SRC = Path(__file__).resolve().parents[3] / "src" / "chrys"
PATH_PARAM = re.compile(r"(^|_)(path|paths|file|files|filename|dir|dirs|directory|folder|cwd|root|resource)($|_)")

WALKED = {
    "chrys.service.tools.builtins.filesystem": "FilesystemTools",
    "chrys.service.tools.builtins.search": "SearchTools",
    "chrys.service.tools.builtins.doc_converter": "DocConverterTools",
}
"""Tool classes the scenario calls directly, by module."""

ELSEWHERE = {
    "chrys.service.tools.builtins.shell": "runs a command: enforced by the kernel, see test_shell_working_dir_*",
}
"""Modules with path parameters that are not read by iCode itself, and why that is safe."""


def path_tool_owners(root: Path = SRC) -> set[str]:
    """Modules that define a tool parameter named like a path (``name: Annotated[...]``)."""
    owners = set()
    for file in root.rglob("*.py"):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for arg in [*node.args.args, *node.args.kwonlyargs]:
                note = arg.annotation
                is_annotated = isinstance(note, ast.Subscript) and getattr(note.value, "id", "") == "Annotated"
                if is_annotated and PATH_PARAM.search(arg.arg):
                    relative = file.relative_to(root.parent).with_suffix("")
                    parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
                    owners.add(".".join(parts))
    return owners


def test_every_module_with_path_parameters_is_accounted_for() -> None:
    owners = path_tool_owners()
    assert set(WALKED) <= owners, "a walked module no longer takes paths: drop it"
    unknown = owners - set(WALKED) - set(ELSEWHERE)
    assert not unknown, f"new tool module takes a path; add it to WALKED or give a reason in ELSEWHERE: {unknown}"


def test_the_scan_notices_a_new_path_tool(tmp_path: Path) -> None:
    package = tmp_path / "chrys" / "service"
    package.mkdir(parents=True)
    (package / "fresh.py").write_text(
        "from typing import Annotated\ndef peek(target_file: Annotated[str, 'x']) -> str: ...\n", encoding="utf-8"
    )
    assert path_tool_owners(tmp_path / "chrys") == {"chrys.service.fresh"}


WALK = (
    r"""
import importlib, re
from chrys.service.tools.kinds import get_tool_kind
PATH_PARAM = re.compile(r"""
    + repr(PATH_PARAM.pattern)
    + """)
WALKED = """
    + repr(WALKED)
    + r"""
ALL = []
for module, name in WALKED.items():
    ALL.extend(getattr(importlib.import_module(module), name)(env).tools())
FILLER = {"string": "x", "integer": 1, "boolean": True}

def args_for(tool, param, path):
    schema = tool.parameters()
    props = schema.get("properties", {})
    args = {}
    for name in schema.get("required", []):
        args[name] = FILLER.get(props.get(name, {}).get("type", "string"), "x")
    args[param] = [path] if props.get(param, {}).get("type") == "array" else path
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

async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    seen, inside = [], []
    for tool in ALL:
        for param in tool.parameters().get("properties", {}):
            if not PATH_PARAM.search(param):
                continue
            name = "f.png" if tool.name == "view_image" else "f.txt"
            for path in (os.path.join(OTHER, name), OTHER):
                out = await call_tool(mw, tool, **args_for(tool, param, path))
                seen.append([tool.name, param, out[:200]])
    results["seen"] = {"ok": True, "value": seen}
run(scenario)
"""
)


@needs_kernel
def test_every_path_tool_is_refused_outside_the_scope(sandbox: Sandbox) -> None:
    for name in ("f.txt", "f.png"):
        (sandbox.other / name).write_bytes(b"OTHER")
    rows = _run(sandbox, WALK)["seen"]["value"]
    assert {"read_file", "write_file", "edit_file", "grep", "glob", "convert_document"} <= {row[0] for row in rows}
    for tool, param, out in rows:
        assert out.startswith("Error:"), (tool, param, out)
        assert "OTHER" not in out.replace(str(sandbox.other), ""), (tool, param, out)
    assert (sandbox.other / "f.txt").read_bytes() == b"OTHER"


@needs_kernel
@pytest.mark.parametrize("outside", ["other", "other/f.txt"])
def test_shell_working_dir_outside_the_scope_cannot_be_read(sandbox: Sandbox, outside: str) -> None:
    r = _run(
        sandbox,
        f"""
async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    results["out"] = {{"ok": True, "value": await call(mw, SHELL, command="cat f.txt; ls", workdir=os.path.join(ROOT, {outside!r}), reason="t")}}
run(scenario)
""",
    )
    assert "OTHER" not in r["out"]["value"]
