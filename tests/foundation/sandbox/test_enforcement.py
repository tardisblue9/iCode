# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The kernel really refuses — main process, commands, file helpers, broker.

Every scenario runs in a fresh process that enables the sandbox like ``icode``.
"""

from __future__ import annotations

import pytest

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel


def _ok(results: dict, name: str) -> bool:
    return results[name]["ok"]


def test_startup_reports_active(sandbox: Sandbox) -> None:
    r = sandbox.run("")
    assert r["__status__"]["value"] == "active"


def test_main_process_reads_workspace_but_nothing_else_private(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
check("ws file", lambda: open(os.path.join(WS, "f.txt")).read())
check("ws listdir", lambda: os.listdir(WS))
check("ws scandir", lambda: [e.name for e in os.scandir(WS)])
check("ws walk", lambda: sorted(f for _d, _s, fs in os.walk(WS) for f in fs))
check("ws pathlib", lambda: __import__("pathlib").Path(WS, "f.txt").read_text())
check("other file", lambda: open(os.path.join(OTHER, "f.txt")).read())
check("other listdir", lambda: os.listdir(OTHER))
check("home listdir", lambda: os.listdir(os.path.expanduser("~")))
check("getcwd", lambda: os.getcwd())
"""
    )
    assert r["ws file"]["value"] == "WS"
    assert sorted(r["ws listdir"]["value"]) == ["f.txt", "sub"]
    assert r["ws walk"]["value"] == ["f.txt", "g.txt"]
    assert _ok(r, "ws scandir") and _ok(r, "ws pathlib")
    assert not _ok(r, "other file") and not _ok(r, "other listdir") and not _ok(r, "home listdir")
    assert r["getcwd"]["value"].endswith("/ws")


def test_commands_see_the_workspace_and_inherit_the_boundary(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
check("cat ws", lambda: cat(os.path.join(WS, "f.txt")))
check("cat other", lambda: cat(os.path.join(OTHER, "f.txt")))
check("shell ls ~", lambda: subprocess.run("ls ~", shell=True, capture_output=True, check=True, stdin=subprocess.DEVNULL).stdout)
check("grandchild cat other", lambda: subprocess.run(["sh", "-c", f"bash -c 'cat {OTHER}/f.txt'"], capture_output=True, check=True, stdin=subprocess.DEVNULL).stdout)
check("exit code", lambda: subprocess.run(["sh", "-c", "exit 7"], stdin=subprocess.DEVNULL).returncode)
check("missing program", lambda: subprocess.run(["no-such-program-xyz"], stdin=subprocess.DEVNULL))
check("cwd honoured", lambda: subprocess.run(["pwd"], capture_output=True, text=True, cwd=os.path.join(WS, "sub"), check=True, stdin=subprocess.DEVNULL).stdout.strip())
"""
    )
    assert r["cat ws"]["value"] == "WS"
    assert not _ok(r, "cat other")
    assert not _ok(r, "shell ls ~")
    assert not _ok(r, "grandchild cat other")
    assert r["exit code"]["value"] == 7
    assert r["missing program"]["error"] == "FileNotFoundError"
    assert r["cwd honoured"]["value"].endswith("/ws/sub")


def test_signals_reach_the_command(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import time
def term():
    p = subprocess.Popen(["sleep", "30"], stdin=subprocess.DEVNULL); time.sleep(0.5); p.terminate(); return p.wait(10)
def kill():
    # The command prints its own pid, then becomes the sleep; the stub is what iCode holds.
    p = subprocess.Popen(["sh", "-c", "echo $$; exec sleep 37"], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True)
    pid = int(p.stdout.readline())
    p.kill(); p.wait(10)
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "gone"
        time.sleep(0.1)
    return "still running"
check("terminate", term)
check("kill leaves nothing", kill)
"""
    )
    assert r["terminate"]["value"] == -15
    assert r["kill leaves nothing"]["value"] == "gone"


def test_asyncio_subprocesses_work(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import asyncio
async def go():
    p = await asyncio.create_subprocess_exec("sh", "-c", "cat f.txt; echo E >&2; exit 3", stdout=-1, stderr=-1, stdin=-3, cwd=WS)
    out, err = await p.communicate()
    return [p.returncode, out.decode(), err.decode()]
check("aio", lambda: asyncio.run(go()))
"""
    )
    assert r["aio"]["value"] == [3, "WS", "E\n"]


def test_the_process_cannot_widen_or_escape_its_sandbox(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
def reconfine():
    confine.apply(confine.Profile(mode="except", allow=[os.path.expanduser("~")], deny_roots=["/Volumes"]))
    return open(os.path.join(OTHER, "f.txt")).read()
check("re-confine wider then read", reconfine)
check("nested sandbox-exec", lambda: subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/cat", os.path.join(OTHER, "f.txt")], capture_output=True, check=True, stdin=subprocess.DEVNULL).stdout)
check("python child reads other", lambda: subprocess.run([sys.executable, "-c", f"print(open('{OTHER}/f.txt').read())"], capture_output=True, check=True, stdin=subprocess.DEVNULL).stdout)
"""
    )
    assert not _ok(r, "re-confine wider then read")
    assert not _ok(r, "nested sandbox-exec")
    assert not _ok(r, "python child reads other")


def test_broker_refuses_floor_and_overbroad_profiles(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import json as _j
def ask(profile):
    reply = RT._call({"op": "helper", "profile": profile})
    return reply.get("ok", False), reply.get("error", "")
check("ssh", lambda: ask({"mode": "only", "allow": [os.path.expanduser("~/.ssh")]}))
check("home", lambda: ask({"mode": "only", "allow": [os.path.expanduser("~")]}))
check("root", lambda: ask({"mode": "only", "allow": ["/"]}))
check("ssh child", lambda: ask({"mode": "only", "allow": [os.path.expanduser("~/.ssh/config")]}))
PAIR = __import__("socket").socketpair()
check("except w/o home", lambda: RT._call({"op": "slot", "profile": {"mode": "except", "allow": [os.path.expanduser("~")], "deny_roots": []}}, [PAIR[0].fileno()]).get("ok"))
check("garbage op", lambda: RT._call({"op": "exec", "argv": ["sh"]}).get("ok"))
check("ok profile", lambda: ask({"mode": "only", "allow": [OTHER]}))
"""
    )
    for name in ("ssh", "home", "root", "ssh child"):
        assert r[name]["value"][0] is False, name
    assert r["except w/o home"]["value"] is False
    assert r["garbage op"]["value"] is False
    assert r["ok profile"]["value"][0] is True


def test_file_helper_is_confined_to_its_profile(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
scope = policy.Scope(key="s", roots=(WS,))
check("ws", lambda: os.read(RT.open_scoped(scope, os.path.join(WS, "f.txt"), os.O_RDONLY), 10).decode())
check("other", lambda: RT.open_scoped(scope, os.path.join(OTHER, "f.txt"), os.O_RDONLY))
os.symlink(os.path.join(OTHER, "f.txt"), os.path.join(WS, "link"))
os.symlink(OTHER, os.path.join(WS, "dirlink"))
check("file symlink", lambda: RT.open_scoped(scope, os.path.join(WS, "link"), os.O_RDONLY))
check("dir symlink", lambda: RT.open_scoped(scope, os.path.join(WS, "dirlink", "f.txt"), os.O_RDONLY))
check("dotdot", lambda: RT.open_scoped(scope, os.path.join(WS, "..", "other", "f.txt"), os.O_RDONLY))
check("list other", lambda: RT.opendir_scoped(scope, OTHER))
"""
    )
    assert r["ws"]["value"] == "WS"
    for name in ("other", "file symlink", "dir symlink", "dotdot", "list other"):
        assert r[name]["error"] in {"SandboxDenied", "PermissionError"}, (name, r[name])


@pytest.mark.parametrize("raw", ["1", "true", "on"])
def test_env_enables_and_flags_override(sandbox: Sandbox, raw: str) -> None:
    r = sandbox.run(
        """
from pathlib import Path
_, s1 = bootstrap.resolve_settings([], Path(CONFIG), env={"CHRYS_FILE_SANDBOX": RAW})
_, s2 = bootstrap.resolve_settings(["--no-sandbox"], Path(CONFIG), env={"CHRYS_FILE_SANDBOX": RAW})
_, s3 = bootstrap.resolve_settings(["--sandbox"], Path(CONFIG), env={"CHRYS_FILE_SANDBOX": "0"})
check("env", lambda: [s1.enabled, s1.source])
check("cli off", lambda: [s2.enabled, s2.source])
check("cli on", lambda: [s3.enabled, s3.source])
""".replace("RAW", repr(raw))
    )
    assert r["env"]["value"] == [True, "env"]
    assert r["cli off"]["value"] == [False, "cli"]
    assert r["cli on"]["value"] == [True, "cli"]
