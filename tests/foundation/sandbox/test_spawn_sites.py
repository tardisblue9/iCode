# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Every way iCode starts a program goes through ``subprocess.Popen``, where the sandbox takes it over.

``patches.py`` replaces ``Popen._execute_child`` so each command is started by
the broker, confined. ``asyncio``'s subprocesses and the PTY backend use Popen
too. A call that starts a program some other way (``os.fork``, ``os.exec*``,
``os.posix_spawn``, ``multiprocessing``, Windows ``CreateProcessW``) would run
unconfined, so the scan below lists them and each must be accounted for.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests.support.ci import CI_LINUX_ONLY

SRC = Path(__file__).resolve().parents[3] / "src" / "chrys"
PACKAGE = Path(__file__).resolve().parents[3] / "packages" / "icode-sandbox" / "src" / "icode_sandbox"

OS_SPAWNERS = {
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "system",
    *(f"exec{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"spawn{suffix}" for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
}
MODULE_SPAWNERS = {("pty", "fork"), ("pty", "spawn"), ("_posixsubprocess", "fork_exec"), ("_winapi", "CreateProcess")}
FORBIDDEN_IMPORTS = {"multiprocessing", "_posixsubprocess"}

ACCOUNTED = {
    ("icode_sandbox/runtime/trampoline.py", "os.execve"): "the sandbox's own launcher, already confined",
    ("icode_sandbox/runtime/trampoline.py", "os.execvpe"): "the sandbox's own launcher, already confined",
    ("foundation/platform/process.py", "CreateProcessW"): "Windows only; the sandbox does not run there yet",
    ("app/tui/terminal/pty_process.py", "pty.spawn"): "Windows ConPTY (pywinpty); not run there yet",
}
"""Each call that starts a program without Popen, and why that is safe for now."""


def spawn_sites(root: Path = SRC) -> dict[str, list[str]]:
    """Files that start a program without Popen, with what they call."""
    found: dict[str, list[str]] = {}
    for file in root.rglob("*.py"):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                owner = node.func.value
                owner_name = owner.id if isinstance(owner, ast.Name) else getattr(owner, "attr", "")
                if (owner_name == "os" and node.func.attr in OS_SPAWNERS) or (
                    (owner_name, node.func.attr) in MODULE_SPAWNERS
                ):
                    calls.append(f"{owner_name}.{node.func.attr}")
                elif node.func.attr == "CreateProcessW":
                    calls.append("CreateProcessW")
            elif isinstance(node, ast.Import | ast.ImportFrom):
                names = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
                calls.extend(f"import {n}" for n in names if n.split(".")[0] in FORBIDDEN_IMPORTS)
        if calls:
            found[file.relative_to(root).as_posix()] = calls
    return found


@CI_LINUX_ONLY
def test_every_way_to_start_a_program_is_accounted_for() -> None:
    found = {(path, call) for path, calls in spawn_sites().items() for call in calls}
    found |= {(f"icode_sandbox/{path}", call) for path, calls in spawn_sites(PACKAGE).items() for call in calls}
    assert set(ACCOUNTED) <= found, f"no longer starts programs, drop it: {set(ACCOUNTED) - found}"
    unknown = sorted(found - set(ACCOUNTED))
    assert not unknown, f"starts a program without subprocess.Popen, so unconfined: {unknown}"


def test_the_scan_notices_a_fork(tmp_path: Path) -> None:
    (tmp_path / "fresh.py").write_text("import os\nos.posix_spawn('/bin/sh', ['sh'], {})\n", encoding="utf-8")
    (tmp_path / "pool.py").write_text("from multiprocessing import Pool\n", encoding="utf-8")
    assert spawn_sites(tmp_path) == {"fresh.py": ["os.posix_spawn"], "pool.py": ["import multiprocessing"]}


# Opening or renaming a file without the functions ``patches.py`` hooks: in a tool call the
# kernel still confines reads, but iCode's own process may write anywhere, so each must be
# iCode's own state, never a path a tool was given.
UNHOOKED_FILE_CALLS = {
    ("io", "FileIO"),
    ("_io", "FileIO"),
    ("_io", "open"),
    ("libc", "renamex_np"),
    ("libc", "renameat2"),
}
NATIVE_RENAME_HELPERS = {"publish_file_no_replace", "atomic_create_text"}

ACCOUNTED_FILE_CALLS = {
    ("foundation/platform/files.py", "libc.renamex_np"): "publish_file_no_replace, below",
    ("foundation/platform/files.py", "libc.renameat2"): "publish_file_no_replace, below",
    ("foundation/platform/files.py", "publish_file_no_replace"): "its own definition and atomic create",
    ("foundation/platform/key_files.py", "publish_file_no_replace"): "iCode's key files in its config folder",
    ("service/profiles/reload.py", "publish_file_no_replace"): "agent profiles in iCode's config folder",
    (
        "service/profiles/agents/prompt_migration.py",
        "publish_file_no_replace",
    ): "agent profiles in iCode's config folder",
    ("app/cli/trajectory.py", "atomic_create_text"): "`icode trajectory` export, a command the person runs, not a tool",
}
"""Each way iCode writes a file name past the hooks, and why no tool's path reaches it."""


def unhooked_file_sites(root: Path = SRC) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for file in root.rglob("*.py"):
        calls: list[str] = []
        for node in ast.walk(ast.parse(file.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                owner = func.value.id if isinstance(func.value, ast.Name) else getattr(func.value, "attr", "")
                if (owner, func.attr) in UNHOOKED_FILE_CALLS:
                    calls.append(f"{owner}.{func.attr}")
                elif func.attr in NATIVE_RENAME_HELPERS:
                    calls.append(func.attr)
            elif isinstance(func, ast.Name) and func.id in {"FileIO", *NATIVE_RENAME_HELPERS}:
                calls.append(func.id)
        if calls:
            found[file.relative_to(root).as_posix()] = calls
    return found


@CI_LINUX_ONLY
def test_every_file_write_past_the_hooks_is_accounted_for() -> None:
    found = {(path, call) for path, calls in unhooked_file_sites().items() for call in calls}
    assert set(ACCOUNTED_FILE_CALLS) <= found, f"no longer used there, drop it: {set(ACCOUNTED_FILE_CALLS) - found}"
    unknown = sorted(found - set(ACCOUNTED_FILE_CALLS))
    assert not unknown, f"opens or renames a file past the sandbox's hooks: {unknown}"


def test_the_file_scan_notices_a_raw_open(tmp_path: Path) -> None:
    (tmp_path / "raw.py").write_text("import _io\n_io.FileIO('/x', 'w')\n", encoding="utf-8")
    (tmp_path / "tool.py").write_text("publish_file_no_replace(a, b)\n", encoding="utf-8")
    assert unhooked_file_sites(tmp_path) == {"raw.py": ["_io.FileIO"], "tool.py": ["publish_file_no_replace"]}
