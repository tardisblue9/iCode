# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Write control: what commands and file tools may change, through the real kernel.

Everything runs under a throwaway ``HOME`` inside the real one, so a failure here
writes to a fake ``.zshrc``, not to the person's.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from icode_sandbox import policy
from icode_sandbox.client import _running_binary
from icode_sandbox.runtime import confine

from .conftest import Sandbox, needs_kernel
from .test_tools_and_attacks import TOOLS

pytestmark = needs_kernel

RUNTIME = Path(confine.__file__).resolve().parent

WRITE_FLOOR_SAMPLES = [
    ".zshrc",
    ".bashrc",
    ".profile",
    ".config/fish/config.fish",
    "Library/LaunchAgents/evil.plist",
    ".config/systemd/user/evil.service",
    ".config/autostart/evil.desktop",
    ".gitconfig",
    ".config/git/config",
    ".cargo/config.toml",
    ".config/nvim/init.lua",
    ".local/bin/evil",
    ".cargo/bin/evil",
    "bin/evil",
    ".claude/settings.json",
    ".ssh/authorized_keys",
    ".aws/credentials",
    ".chrys-config/settings.yaml",
]


@pytest.fixture
def home(sandbox: Sandbox) -> Path:
    path = sandbox.root / "fakehome"
    path.mkdir()
    for sample in WRITE_FLOOR_SAMPLES:
        (path / sample).parent.mkdir(parents=True, exist_ok=True)
    return path


def _env(home: Path) -> dict[str, str]:
    return {"HOME": str(home)}


PRE = r"""
def sh(command, **kw):
    done = subprocess.run(["sh", "-c", command], capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)
    return [done.returncode, done.stdout + done.stderr]
"""


def _run(sandbox: Sandbox, home: Path, body: str) -> dict:
    return sandbox.run(PRE + body, env=_env(home))


def _config_settings(sandbox: Sandbox, text: str) -> None:
    (sandbox.root / "config" / "settings.yaml").write_text(text, encoding="utf-8")


def test_commands_write_only_where_they_should(sandbox: Sandbox, home: Path) -> None:
    r = _run(
        sandbox,
        home,
        r"""
import tempfile
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
H = os.environ["HOME"]
os.makedirs(H + "/.cache", exist_ok=True)
with client.scoped(scope):
    results["workspace"] = {"ok": True, "value": sh(f"echo x > {WS}/n && mkdir {WS}/d && mv {WS}/n {WS}/d/m && rm {WS}/d/m")}
    results["temp"] = {"ok": True, "value": sh(f"echo x > {tempfile.gettempdir()}/icode-w-probe && rm {tempfile.gettempdir()}/icode-w-probe")}
    results["/tmp"] = {"ok": True, "value": sh("echo x > /tmp/icode-w-probe && rm /tmp/icode-w-probe")}
    results["cache"] = {"ok": True, "value": sh(f"echo x > {H}/.cache/f && cat {H}/.cache/f")}
    results["devnull"] = {"ok": True, "value": sh("echo x > /dev/null; echo x > /dev/stdout")}
    results["home"] = {"ok": True, "value": sh(f"echo x > {H}/new")}
    results["mkdir home"] = {"ok": True, "value": sh(f"mkdir {H}/newdir")}
    results["other"] = {"ok": True, "value": sh(f"echo x > {OTHER}/new")}
    results["overwrite other"] = {"ok": True, "value": sh(f"echo x >> {OTHER}/f.txt")}
    results["delete other"] = {"ok": True, "value": sh(f"rm {OTHER}/f.txt")}
    results["chmod other"] = {"ok": True, "value": sh(f"chmod 777 {OTHER}/f.txt")}
""",
    )
    for allowed in ("workspace", "temp", "/tmp", "cache", "devnull"):
        assert r[allowed]["value"][0] == 0, (allowed, r[allowed])
    for denied in ("home", "mkdir home", "other", "overwrite other", "delete other"):
        assert r[denied]["value"][0] != 0, (denied, r[denied])
    # Known limit: Landlock has no right for changing a file's mode, times or extended attributes.
    assert (r["chmod other"]["value"][0] != 0) is (confine.PLATFORM == "macos"), r["chmod other"]
    assert not (home / "new").exists()
    assert not (sandbox.other / "new").exists()
    assert (sandbox.other / "f.txt").read_text(encoding="utf-8") == "OTHER"


def test_nothing_on_the_write_floor_can_be_changed_or_granted(sandbox: Sandbox, home: Path) -> None:
    samples = json.dumps(WRITE_FLOOR_SAMPLES)
    r = _run(
        sandbox,
        home,
        f"""
SAMPLES = {samples}
H = os.environ["HOME"]
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
rows = []
with client.scoped(scope):
    for sample in SAMPLES:
        path = os.path.join(H, sample)
        wrote = sh(f"echo x >> '{{path}}'")[0] == 0
        try:
            RT.grant(scope, "session", path, access="write")
            granted_file = True
        except client.SandboxDenied:
            granted_file = False
        try:
            RT.grant(scope, "session", os.path.dirname(path), access="write")
            granted_dir = os.path.dirname(path)
        except client.SandboxDenied:
            granted_dir = ""
        rows.append([sample, wrote, granted_file, granted_dir])
results["rows"] = {{"ok": True, "value": rows}}
""",
    )
    for sample, wrote, granted_file, granted_dir in r["rows"]["value"]:
        assert not wrote, sample
        # ``.chrys-config`` stands for any other folder: only the real config dir is on the floor.
        if not sample.startswith(".chrys-config"):
            assert not granted_file, sample
            assert not granted_dir, (sample, granted_dir)
    for sample in WRITE_FLOOR_SAMPLES:
        assert not (home / sample).exists(), sample


def test_icode_config_and_install_cannot_be_changed_by_commands(sandbox: Sandbox, home: Path) -> None:
    config = sandbox.root / "config"
    r = _run(
        sandbox,
        home,
        f"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["settings"] = {{"ok": True, "value": sh("echo x >> {config}/settings.yaml")}}
    results["hook"] = {{"ok": True, "value": sh("mkdir -p {config}/hooks && echo x > {config}/hooks/hooks.yaml")}}
    results["install"] = {{"ok": True, "value": sh("echo x > {RUNTIME}/broker.py.evil")}}
    results["interpreter"] = {{"ok": True, "value": sh(f"echo x > {{sys.prefix}}/evil")}}
    for name, target in (("grant config", {str(config)!r}), ("grant install", {str(RUNTIME)!r})):
        try:
            RT.grant(scope, "session", target, access="write")
            results[name] = {{"ok": True, "value": "granted"}}
        except client.SandboxDenied:
            results[name] = {{"ok": True, "value": "refused"}}
""",
    )
    for name in ("settings", "hook", "install", "interpreter"):
        assert r[name]["value"][0] != 0, (name, r[name])
    assert r["grant config"]["value"] == "refused"
    assert r["grant install"]["value"] == "refused"
    assert not (RUNTIME / "broker.py.evil").exists()
    assert not (Path(sys.prefix) / "evil").exists()


def test_writes_cannot_take_a_way_around(sandbox: Sandbox, home: Path) -> None:
    (sandbox.ws / "to_other").symlink_to(sandbox.other)
    (sandbox.ws / "to_home_file").symlink_to(home / ".zshrc")
    r = _run(
        sandbox,
        home,
        r"""
H = os.environ["HOME"]
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["symlink dir"] = {"ok": True, "value": sh(f"echo x > {WS}/to_other/new")}
    results["symlink file"] = {"ok": True, "value": sh(f"echo x > {WS}/to_home_file")}
    results["dotdot"] = {"ok": True, "value": sh(f"echo x > {WS}/../other/new")}
    results["move out"] = {"ok": True, "value": sh(f"echo x > {WS}/m && mv {WS}/m {OTHER}/m")}
    results["hard link in"] = {"ok": True, "value": sh(f"ln {OTHER}/f.txt {WS}/l && echo x >> {WS}/l")}
    results["rename the folder away"] = {"ok": True, "value": sh(f"mv {OTHER} {WS}/stolen")}
    results["new symlink, then through it"] = {"ok": True, "value": sh(f"ln -s {H} {WS}/h && echo x > {WS}/h/.zshrc")}
    results["cp"] = {"ok": True, "value": sh(f"cp {WS}/f.txt {H}/.zshrc")}
    results["tee"] = {"ok": True, "value": sh(f"echo x | tee -a {H}/.zshrc")}
    results["python"] = {"ok": True, "value": sh(f"{sys.executable} -c \"open('{H}/.zshrc','a').write('x')\"")}
    if confine.PLATFORM == "macos":
        results["other case"] = {"ok": True, "value": sh(f"echo x > {OTHER.upper()}/new; echo x > {H.upper()}/.ZSHRC")}
""",
    )
    for name, row in r.items():
        if name.startswith("__"):
            continue
        assert row["value"][0] != 0, (name, row)
    assert sorted(p.name for p in sandbox.other.iterdir()) == ["f.txt"]
    assert (sandbox.other / "f.txt").read_text(encoding="utf-8") == "OTHER"
    assert not (home / ".zshrc").exists()


def _broker(config: dict) -> tuple[socket.socket, subprocess.Popen]:
    mine, theirs = socket.socketpair()
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", str(RUNTIME / "broker.py"), str(theirs.fileno()), json.dumps(config)],
        pass_fds=[theirs.fileno()],
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    theirs.close()
    return mine, process


def _ask(control: socket.socket, profile: dict) -> dict:
    theirs, keep = socket.socketpair()
    confine.send(control, {"op": "slot", "profile": profile}, [theirs.fileno()])
    theirs.close()
    reply, _ = confine.recv(control)
    keep.close()
    assert reply is not None
    return reply


@pytest.fixture
def write_broker(sandbox: Sandbox, home: Path):
    env_home = os.environ.get("HOME")
    os.environ["HOME"] = str(home)  # the broker reads it at startup, as at launch
    try:
        control, process = _broker(
            {
                "python": sys.executable,
                "python_binary": _running_binary(),
                "floor": [],
                "private_roots": [str(sandbox.root)],
                "write_floor": [str(sandbox.root / "config")],
                "write_never_under": [str(RUNTIME)],
                "write_exceptions": [str(sandbox.root / "config" / "workflows" / ".pycache")],
            }
        )
    finally:
        os.environ["HOME"] = env_home or ""
    try:
        confine.send(control, {"op": "ping"})
        assert confine.recv(control)[0]["ok"] is True
        yield control
    finally:
        control.close()
        process.wait(timeout=20)


@pytest.mark.parametrize(
    "relative",
    [
        "fakehome/.zshrc",
        "fakehome/.config",
        "fakehome/.config/systemd",
        "fakehome/Library",
        "fakehome/.gitconfig",
        "fakehome/.local/bin",
        "fakehome/.local",
        "config",
        "config/hooks",
        "fakehome",
        ".",
    ],
)
def test_a_compromised_main_process_cannot_ask_for_write_floor(
    sandbox: Sandbox, write_broker: socket.socket, relative: str
) -> None:
    target = str((sandbox.root / relative).resolve())
    reply = _ask(
        write_broker, {"mode": "except", "allow": [], "deny_roots": [str(sandbox.root)], "write_allow": [target]}
    )
    assert reply["ok"] is False, target


@pytest.mark.parametrize("levels", [0, 1, 2])
def test_nor_for_a_folder_holding_the_private_roots(sandbox: Sandbox, write_broker: socket.socket, levels: int) -> None:
    target = confine.real(os.path.expanduser("~"))
    for _ in range(levels):
        target = os.path.dirname(target)
    reply = _ask(
        write_broker, {"mode": "except", "allow": [], "deny_roots": [str(sandbox.root)], "write_allow": [target]}
    )
    assert reply["ok"] is False, target


def test_nor_for_a_whole_private_root(sandbox: Sandbox, write_broker: socket.socket) -> None:
    """Even one with nothing on the floor in it."""
    private = str(sandbox.other.resolve())
    reply = _ask(write_broker, {"mode": "except", "allow": [], "deny_roots": [private], "write_allow": [private]})
    assert reply["ok"] is False


def test_nor_under_the_install_but_the_worker_cache_is_allowed(sandbox: Sandbox, write_broker: socket.socket) -> None:
    base = {"mode": "except", "allow": [], "deny_roots": [str(sandbox.root)]}
    assert _ask(write_broker, {**base, "write_allow": [str(RUNTIME / "x")]})["ok"] is False
    cache = sandbox.root / "config" / "workflows" / ".pycache"
    cache.mkdir(parents=True)
    assert _ask(write_broker, {**base, "write_allow": [str(cache)]})["ok"] is True
    assert _ask(write_broker, {**base, "write_allow": [str(cache.parent)]})["ok"] is False


def test_a_renamed_or_linked_startup_file_is_still_refused(
    sandbox: Sandbox, home: Path, write_broker: socket.socket
) -> None:
    """Identity, not spelling. Exists only after the broker's first look, so it is seen at the next one."""
    base = {"mode": "except", "allow": [], "deny_roots": [str(sandbox.root)]}
    alias = sandbox.root / "alias"
    alias.symlink_to(home / ".config")
    assert _ask(write_broker, {**base, "write_allow": [str(alias)]})["ok"] is False


def test_a_command_cannot_opt_out_of_write_limits(sandbox: Sandbox, home: Path) -> None:
    """Whatever the caller sends, the broker runs commands with writes restricted."""
    r = _run(
        sandbox,
        home,
        r"""
mine, theirs = __import__("socket").socketpair()
hostile = {"mode": "except", "allow": [], "deny_roots": [], "restrict_writes": False, "write_allow": []}
reply = RT._call({"op": "slot", "profile": hostile}, [theirs.fileno()])
theirs.close()
read_end, write_end = os.pipe()
confine.send(mine, {"op": "run", "argv": ["sh", "-c", f"echo x > {OTHER}/hostile; echo rc=$?"], "cwd": WS, "env": dict(os.environ), "fd_targets": [1, 2]}, [write_end, write_end])
os.close(write_end)
out = b""
while chunk := os.read(read_end, 65536):
    out += chunk
results["out"] = {"ok": True, "value": out.decode()}
""",
    )
    assert "rc=0" not in r["out"]["value"], r["out"]
    assert not (sandbox.other / "hostile").exists()


def test_settings_can_add_folders_but_not_the_floor(sandbox: Sandbox, home: Path) -> None:
    extra = sandbox.root / "builds"
    extra.mkdir()
    _config_settings(
        sandbox, f"sandbox:\n  files:\n    commands:\n      write_paths: '{extra},{home}/.zshrc,{home}/.config'\n"
    )
    r = _run(
        sandbox,
        home,
        f"""
H = os.environ["HOME"]
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["added"] = {{"ok": True, "value": sh("echo x > {extra}/n && cat {extra}/n")}}
    results["floor"] = {{"ok": True, "value": sh(f"echo x >> {{H}}/.zshrc")}}
    results["floor folder"] = {{"ok": True, "value": sh(f"echo x > {{H}}/.config/new")}}
    results["others unaffected"] = {{"ok": True, "value": sh(f"echo x > {{OTHER}}/new")}}
""",
    )
    assert r["added"]["value"][0] == 0, r["added"]
    for name in ("floor", "floor folder", "others unaffected"):
        assert r[name]["value"][0] != 0, (name, r[name])


def test_a_workdir_cannot_add_write_paths(tmp_path: Path) -> None:
    from chrys.foundation.config.settings import Settings
    from chrys.foundation.config.spec import METADATA_KEY, WorkdirMerge
    from icode_sandbox import bootstrap

    spec = Settings.__dataclass_fields__["sandbox_files_commands_write_paths"].metadata[METADATA_KEY]
    assert spec.workdir_merge is WorkdirMerge.DENY
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "settings.yaml").write_text("workdir.config_enabled: true\n", encoding="utf-8")
    workdir = tmp_path / "proj" / ".chrys"
    workdir.mkdir(parents=True)
    (workdir / "settings.yaml").write_text("sandbox.files.commands.write_paths: /etc\n", encoding="utf-8")
    _, settings = bootstrap.resolve_settings(["-C", str(tmp_path / "proj")], tmp_path / "home", env={})
    assert settings.shell_write == []


GIT_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={**os.environ, **GIT_ENV},
    )


def _commit_in(sandbox: Sandbox, home: Path, workspace: Path) -> list:
    body = f"""
WSX = {str(workspace.resolve())!r}
scope = policy.Scope(key="git", roots=(WSX,), workdir_root=WSX)
with client.scoped(scope):
    results["commit"] = {{"ok": True, "value": sh(
        "echo more >> tracked && git add tracked && git -c user.name=t -c user.email=t@t commit -qm next",
        cwd=WSX,
    )}}
"""
    return sandbox.run(PRE + body, env={**_env(home), **GIT_ENV})["commit"]["value"]


def _repo_with_a_subfolder(sandbox: Sandbox) -> Path:
    repo = sandbox.root / "repo"
    (repo / "sub").mkdir(parents=True)
    (repo / "sub" / "tracked").write_text("a\n", encoding="utf-8")
    (repo / "sibling.txt").write_text("SIBLING\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    return repo


def test_a_subfolder_keeps_the_rest_of_its_repository_out_of_reach(sandbox: Sandbox, home: Path) -> None:
    """Git can't work there without the repository's root, and opening that is the person's call."""
    repo = _repo_with_a_subfolder(sandbox)
    done = _commit_in(sandbox, home, repo / "sub")
    assert done[0] != 0, done
    assert (
        "next"
        not in subprocess.run(
            ["git", "log", "--format=%s"],
            cwd=repo,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            check=True,
        ).stdout
    )


def test_a_subfolder_commits_once_the_repository_is_opened_to_reads(sandbox: Sandbox, home: Path) -> None:
    repo = _repo_with_a_subfolder(sandbox)
    _config_settings(sandbox, f"sandbox:\n  files:\n    commands:\n      allow_paths: '{repo.resolve()}'\n")
    done = _commit_in(sandbox, home, repo / "sub")
    assert done[0] == 0, done


def test_git_commits_in_a_linked_worktree(sandbox: Sandbox, home: Path) -> None:
    repo = sandbox.root / "repo"
    repo.mkdir()
    (repo / "tracked").write_text("a\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    _git(repo, "worktree", "add", "-q", str(sandbox.root / "wt"), "-b", "wt")
    assert _commit_in(sandbox, home, sandbox.root / "wt")[0] == 0


def test_git_commits_in_a_submodule(sandbox: Sandbox, home: Path) -> None:
    source = sandbox.root / "source"
    source.mkdir()
    (source / "tracked").write_text("a\n", encoding="utf-8")
    _git(source, "init", "-q")
    _git(source, "add", "-A")
    _git(source, "commit", "-qm", "first")
    repo = sandbox.root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(source), "mod")
    assert _commit_in(sandbox, home, repo / "mod")[0] == 0


@pytest.mark.parametrize("named", [".config/systemd", "Library/LaunchAgents", "plain", "plain/.git/x"])
def test_a_git_file_naming_another_folder_opens_nothing(sandbox: Sandbox, home: Path, named: str) -> None:
    """A ``.git`` file is workspace content, so it says nothing about what may be written."""
    target = home / named
    target.mkdir(parents=True, exist_ok=True)
    (sandbox.ws / ".git").write_text(f"gitdir: {target}\n", encoding="utf-8")
    assert policy.git_write_paths(str(sandbox.ws)) == []


def test_a_git_file_naming_the_wrong_part_of_a_repository_opens_nothing(sandbox: Sandbox, home: Path) -> None:
    """Shaped like a repository, but only ``worktrees`` and ``modules`` are what git links to."""
    fake = home / "plain" / ".git"
    for name in ("objects", "refs", "hooks/x"):
        (fake / name).mkdir(parents=True)
    (fake / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (fake / "hooks" / "x" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (sandbox.ws / ".git").write_text(f"gitdir: {fake / 'hooks' / 'x'}\n", encoding="utf-8")
    assert policy.git_write_paths(str(sandbox.ws)) == []


def test_a_git_file_written_later_changes_nothing(sandbox: Sandbox, home: Path) -> None:
    """A real repository elsewhere, named after the session started: it stays unwritable."""
    repo = sandbox.root / "repo"
    repo.mkdir()
    (repo / "tracked").write_text("a\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    _git(repo, "worktree", "add", "-q", str(sandbox.root / "wt"), "-b", "wt")
    r = _run(
        sandbox,
        home,
        f"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["first"] = {{"ok": True, "value": sh("echo x > {sandbox.ws}/f2")}}
    with open(os.path.join(WS, ".git"), "w") as stream:
        stream.write("gitdir: {repo}/.git/worktrees/wt\\n")
    results["after"] = {{"ok": True, "value": sh("echo x > {repo}/.git/hooks/pre-commit")}}
""",
    )
    assert r["first"]["value"][0] == 0, r["first"]
    assert r["after"]["value"][0] != 0, r["after"]
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def _tools(sandbox: Sandbox, home: Path, body: str) -> dict:
    return sandbox.run(TOOLS + body, env=_env(home))


def test_a_read_grant_does_not_let_anything_write(sandbox: Sandbox, home: Path) -> None:
    r = _tools(
        sandbox,
        home,
        r"""
async def scenario():
    mw = middleware()
    target = os.path.join(GRANT, "f.txt")
    ANSWER.update(approved=True, remember="EXACT_SESSION")
    results["read"] = {"ok": True, "value": await call(mw, "read_file", path=target)}
    results["cat"] = {"ok": True, "value": await call(mw, SHELL, command=f"cat {target}", reason="t")}
    results["shell write"] = {"ok": True, "value": await call(mw, SHELL, command=f"echo x >> {target}; echo rc=$?", reason="t")}
    ANSWER.update(approved=False)
    results["tool write"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(GRANT, "new.txt"), content="x")}
    results["asked"] = {"ok": True, "value": ASKED}
    await mw.close()
run(scenario)
""",
    )
    assert "GRANTED" in r["read"]["value"] and "GRANTED" in r["cat"]["value"]
    assert "rc=0" not in r["shell write"]["value"], r["shell write"]
    assert r["tool write"]["value"].startswith("Error: sandbox"), r["tool write"]
    assert [a["kind"] for a in r["asked"]["value"]] == ["sandbox.read", "sandbox.write"]
    assert (sandbox.granted / "f.txt").read_text(encoding="utf-8") == "GRANTED"
    assert not (sandbox.granted / "new.txt").exists()


def test_a_write_grant_follows_the_dialog_and_turn_end(sandbox: Sandbox, home: Path) -> None:
    r = _tools(
        sandbox,
        home,
        r"""
async def scenario():
    mw = middleware()
    new = os.path.join(GRANT, "a.txt")
    ANSWER.update(approved=True, remember="")
    results["only this call"] = {"ok": True, "value": await call(mw, "write_file", path=new, content="one")}
    ANSWER.update(approved=False)
    results["next call"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(GRANT, "b.txt"), content="x")}
    results["shell next call"] = {"ok": True, "value": await call(mw, SHELL, command=f"echo x > {GRANT}/s1; echo rc=$?", reason="t")}
    ANSWER.update(approved=True, remember="EXACT_TURN")
    results["turn"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(GRANT, "c.txt"), content="x")}
    results["shell in turn"] = {"ok": True, "value": await call(mw, SHELL, command=f"echo x > {GRANT}/s2; echo rc=$?", reason="t")}
    results["edit in turn"] = {"ok": True, "value": await call(mw, "edit_file", path=os.path.join(GRANT, "c.txt"), old_string="x", new_string="y")}
    mw.reset()
    ANSWER.update(approved=False)
    results["next turn"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(GRANT, "d.txt"), content="x")}
    results["shell next turn"] = {"ok": True, "value": await call(mw, SHELL, command=f"echo x > {GRANT}/s3; echo rc=$?", reason="t")}
    ANSWER.update(approved=True, remember="EXACT_SESSION")
    results["session"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(GRANT, "e.txt"), content="x")}
    grant = [g for g in RT.grants.entries("sess-1") if g.access == "write"][0]
    results["kind"] = {"ok": True, "value": grant.kind}
    RT.revoke(grant.id)
    ANSWER.update(approved=False)
    results["after revoke"] = {"ok": True, "value": await call(mw, SHELL, command=f"echo x > {GRANT}/s4; echo rc=$?", reason="t")}
    ANSWER.update(approved=True, remember="EXACT_WORKDIR")
    results["workdir"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(GRANT, "p.txt"), content="x")}
    results["asked"] = {"ok": True, "value": ASKED}
    await mw.close()
run(scenario)
""",
    )
    assert not r["only this call"]["value"].startswith("Error"), r["only this call"]
    assert (sandbox.granted / "a.txt").read_text(encoding="utf-8") == "one"
    assert r["next call"]["value"].startswith("Error: sandbox")
    assert "rc=0" not in r["shell next call"]["value"]
    assert not r["turn"]["value"].startswith("Error"), r["turn"]
    assert "rc=0" in r["shell in turn"]["value"], r["shell in turn"]
    assert not r["edit in turn"]["value"].startswith("Error"), r["edit in turn"]
    assert r["next turn"]["value"].startswith("Error: sandbox")
    assert "rc=0" not in r["shell next turn"]["value"]
    assert r["kind"]["value"] == "session"
    assert "rc=0" not in r["after revoke"]["value"]
    assert r["workdir"]["value"].startswith("Error: sandbox"), r["workdir"]  # never outlives the session
    assert not (sandbox.granted / "p.txt").exists()
    assert all(a["kind"] == "sandbox.write" for a in r["asked"]["value"] if a["tool"] != "read_file")


@pytest.mark.parametrize("mode", ["BYPASS", "AUTO"])
def test_nobody_to_ask_means_refused(sandbox: Sandbox, home: Path, mode: str) -> None:
    r = _tools(
        sandbox,
        home,
        f"""
async def scenario():
    mw = middleware(ApprovalMode.{mode})
    results["new"] = {{"ok": True, "value": await call(mw, "write_file", path=os.path.join(OTHER, "new.txt"), content="x")}}
    results["existing"] = {{"ok": True, "value": await call(mw, "edit_file", path=os.path.join(OTHER, "f.txt"), old_string="O", new_string="Z")}}
    results["inside"] = {{"ok": True, "value": await call(mw, "write_file", path=os.path.join(WS, "new.txt"), content="x")}}
    results["asked"] = {{"ok": True, "value": ASKED}}
    await mw.close()
run(scenario)
""",
    )
    assert r["new"]["value"].startswith("Error: sandbox"), r["new"]
    assert r["existing"]["value"].startswith("Error: sandbox"), r["existing"]
    assert not r["inside"]["value"].startswith("Error"), r["inside"]
    assert r["asked"]["value"] == []
    assert not (sandbox.other / "new.txt").exists()
    assert (sandbox.other / "f.txt").read_text(encoding="utf-8") == "OTHER"


def test_a_sub_agent_cannot_ask(sandbox: Sandbox, home: Path) -> None:
    r = _tools(
        sandbox,
        home,
        r"""
async def scenario():
    mw = middleware(child=True)
    results["write"] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(OTHER, "new.txt"), content="x")}
    results["asked"] = {"ok": True, "value": ASKED}
    await mw.close()
run(scenario)
""",
    )
    assert r["write"]["value"].startswith("Error: sandbox")
    assert r["asked"]["value"] == []


def test_startup_files_are_refused_without_asking(sandbox: Sandbox, home: Path) -> None:
    r = _tools(
        sandbox,
        home,
        r"""
async def scenario():
    mw = middleware()
    H = os.environ["HOME"]
    ANSWER.update(approved=True, remember="EXACT_SESSION")
    for name in (".zshrc", ".config/systemd/user/x.service", ".local/bin/x", "note.txt"):
        results[name] = {"ok": True, "value": await call(mw, "write_file", path=os.path.join(H, name), content="x")}
    results["asked"] = {"ok": True, "value": ASKED}
    await mw.close()
run(scenario)
""",
    )
    for name in (".zshrc", ".config/systemd/user/x.service", ".local/bin/x", "note.txt"):
        assert r[name]["value"].startswith("Error: sandbox"), (name, r[name])
        assert not (home / name).exists(), name
    assert r["asked"]["value"] == []


def test_a_refused_write_is_recorded_as_one(sandbox: Sandbox, home: Path) -> None:
    r = _tools(
        sandbox,
        home,
        r"""
from chrys.foundation.events.types import SandboxAccessDenied
PUBLISHED = []
async def on_denied(event):
    PUBLISHED.append([event.tool, event.outcome, event.access])
async def scenario():
    await BUS.subscribe(SandboxAccessDenied, on_denied)
    mw = middleware(ApprovalMode.BYPASS)
    await call(mw, "write_file", path=os.path.join(OTHER, "new.txt"), content="x")
    results["published"] = {"ok": True, "value": PUBLISHED}
    await BUS.unsubscribe(SandboxAccessDenied, on_denied)
    await mw.close()
run(scenario)
""",
    )
    assert r["published"]["value"] == [["write_file", "refused", "write"]]


def test_grants_stored_before_write_control_stay_read_only(sandbox: Sandbox, home: Path) -> None:
    folder = sandbox.root / "config" / "sandbox" / "sessions"
    folder.mkdir(parents=True)
    old = {
        "grants": [
            {
                "id": "old1",
                "kind": "session",
                "path": str(sandbox.granted.resolve()),
                "scope_key": "s",
                "workdir_root": "",
                "created_at": 1.0,
                "source": "user",
            }
        ]
    }
    (folder / "s.json").write_text(json.dumps(old), encoding="utf-8")
    r = _run(
        sandbox,
        home,
        r"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["read"] = {"ok": True, "value": sh(f"cat {GRANT}/f.txt")}
    results["write"] = {"ok": True, "value": sh(f"echo x >> {GRANT}/f.txt")}
""",
    )
    assert r["read"]["value"] == [0, "GRANTED"]
    assert r["write"]["value"][0] != 0


MCP_SERVER = """
from mcp.server.fastmcp import FastMCP
server = FastMCP("probe")
@server.tool()
def put(path: str) -> str:
    try:
        open(path, "w").write("x")
        return "wrote"
    except OSError as exc:
        return f"refused {type(exc).__name__}"
server.run()
"""

MCP_CLIENT = r"""
import asyncio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters
from chrys.service.mcp._stdio_transport import tolerant_stdio_client

async def write_with(writes, path):
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(WS, "server.py")])
    async with tolerant_stdio_client(params, sandbox_write_paths=writes) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool("put", {"path": path})
            return result.content[0].text

async def main():
    H = os.environ["HOME"]
    results["configured"] = {"ok": True, "value": await write_with([GRANT], os.path.join(GRANT, "n"))}
    results["other server"] = {"ok": True, "value": await write_with([], os.path.join(GRANT, "m"))}
    results["other folder"] = {"ok": True, "value": await write_with([GRANT], os.path.join(OTHER, "n"))}
    results["floor"] = {"ok": True, "value": await write_with([H + "/.config"], H + "/.config/n")}
asyncio.run(main())
"""


def test_an_mcp_server_writes_its_own_folders_only(sandbox: Sandbox, home: Path) -> None:
    (sandbox.ws / "server.py").write_text(MCP_SERVER, encoding="utf-8")
    r = sandbox.run(MCP_CLIENT, env=_env(home), timeout=90)
    assert r["configured"]["value"] == "wrote"
    assert r["other server"]["value"].startswith("refused")
    assert r["other folder"]["value"].startswith("refused")
    assert r["floor"]["value"].startswith("refused")


def test_write_paths_change_the_connection_key() -> None:
    from chrys.service.mcp.cache import resolve_mcp_effective_config
    from chrys.service.profiles.agents.schema import MCPServerConfig

    plain = MCPServerConfig(name="m", transport="stdio", command="x")
    wide = MCPServerConfig(name="m", transport="stdio", command="x", write_paths=["/a"])
    key = lambda config: resolve_mcp_effective_config(config, stdio_cwd="/").key  # noqa: E731
    assert key(plain) != key(wide)


def test_the_two_write_floor_copies_agree() -> None:
    """The broker can't import ``policy``; a path added to one list alone would quietly not be enforced."""
    import importlib.util

    sys.path.insert(0, str(RUNTIME))
    try:
        spec = importlib.util.spec_from_file_location("broker_copy", RUNTIME / "broker.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(RUNTIME))
    assert set(module._BUILTIN_WRITE_FLOOR) == set(policy.BUILTIN_WRITE_FLOOR)
    assert set(module._BUILTIN_FLOOR) == set(policy.BUILTIN_FLOOR)


def test_a_git_folder_created_later_opens_nothing_above_a_subfolder(sandbox: Sandbox, home: Path) -> None:
    """Review: ``mkdir .git`` in a subfolder made the repository's real ``.git`` writable."""
    repo = _repo_with_a_subfolder(sandbox)
    r = _run(
        sandbox,
        home,
        f"""
WSX = {str((repo / "sub").resolve())!r}
scope = policy.Scope(key="s", roots=(WSX,), workdir_root=WSX)
with client.scoped(scope):
    results["before"] = {{"ok": True, "value": sh("echo x > {repo}/.git/hooks/pre-commit", cwd=WSX)}}
    os.makedirs(os.path.join(WSX, ".git"))
    results["after"] = {{"ok": True, "value": sh("echo x > {repo}/.git/hooks/pre-commit", cwd=WSX)}}
""",
    )
    assert r["before"]["value"][0] != 0
    assert r["after"]["value"][0] != 0, r["after"]
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_a_git_file_planted_before_the_session_opens_no_other_repository(sandbox: Sandbox, home: Path) -> None:
    """Review: a real worktree elsewhere doesn't name this workspace back, so it isn't this workspace's."""
    repo = sandbox.root / "repo"
    repo.mkdir()
    (repo / "tracked").write_text("a\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "first")
    _git(repo, "worktree", "add", "-q", str(sandbox.root / "wt"), "-b", "wt")
    (sandbox.ws / ".git").write_text(f"gitdir: {repo}/.git/worktrees/wt\n", encoding="utf-8")
    assert policy.git_write_paths(str(sandbox.ws)) == []
    assert policy.git_write_paths(str(sandbox.root / "wt")) == [str((repo / ".git").resolve())]


def _writable_outside_everything() -> Path | None:
    """A folder this user can write that the sandbox doesn't treat as private or scratch."""
    for candidate in ("/Users/Shared", "/run/lock", "/var/lock"):
        if os.access(candidate, os.W_OK) and not confine.real(candidate).startswith(("/tmp", "/private/tmp", "/dev")):
            return Path(candidate)
    return None


def test_a_tool_write_lands_where_the_kernel_says_not_where_a_check_said(sandbox: Sandbox, home: Path) -> None:
    """Review: outside the private roots a file tool opened directly, so swapping a folder after the check won."""
    outside = _writable_outside_everything()
    if outside is None:
        pytest.skip("no writable folder outside the private roots and scratch space here")
    target = outside / f"icode-write-probe-{os.getpid()}"
    target.mkdir()
    try:
        r = _run(
            sandbox,
            home,
            f"""
from chrys.service.tools.builtins.filesystem import _write_file_impl
import tempfile
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    # As if the check had passed and the folder was swapped right after: the tool itself writes outside.
    results["tool"] = {{"ok": True, "value": _write_file_impl({str(target / "landed.txt")!r}, "x")}}
    results["inside"] = {{"ok": True, "value": _write_file_impl(os.path.join(WS, "fine.txt"), "x")}}
    results["scratch"] = {{"ok": True, "value": _write_file_impl(os.path.join(tempfile.gettempdir(), "icode-w-{os.getpid()}.txt"), "x")}}
""",
        )
        assert r["tool"]["value"].startswith("Error"), r["tool"]
        assert not (target / "landed.txt").exists()
        assert not r["inside"]["value"].startswith("Error"), r["inside"]
        assert not r["scratch"]["value"].startswith("Error"), r["scratch"]
    finally:
        import shutil
        import tempfile

        shutil.rmtree(target, ignore_errors=True)
        Path(tempfile.gettempdir(), f"icode-w-{os.getpid()}.txt").unlink(missing_ok=True)


@pytest.mark.skipif(confine.PLATFORM != "macos", reason="disk images are macOS's")
def test_a_command_cannot_mount_a_disk_image_over_a_path(sandbox: Sandbox, home: Path, tmp_path: Path) -> None:
    """Review: mounting over ``~/.local/bin`` changes what it holds without any write."""
    image = tmp_path / "evil.dmg"
    source = tmp_path / "content"
    source.mkdir()
    (source / "evil").write_text("EVIL", encoding="utf-8")
    subprocess.run(
        ["hdiutil", "create", "-quiet", "-srcfolder", str(source), "-format", "UDRO", str(image)],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    mountpoint = sandbox.ws / "mnt"
    mountpoint.mkdir()
    try:
        r = _run(
            sandbox,
            home,
            f"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["attach"] = {{"ok": True, "value": sh("hdiutil attach -quiet -nobrowse -mountpoint {mountpoint} {image}")}}
""",
        )
        # ``hdiutil -quiet`` exits 0 either way: what counts is whether anything is there.
        assert not (mountpoint / "evil").exists(), r["attach"]
    finally:
        subprocess.run(
            ["hdiutil", "detach", "-quiet", str(mountpoint)], stdin=subprocess.DEVNULL, capture_output=True, check=False
        )


def test_commands_outside_a_tool_call_write_only_their_own_workspace(sandbox: Sandbox, home: Path) -> None:
    """Review: without a scope a command could change other sessions' workspaces and ancestor project files."""
    second = sandbox.root / "second"
    second.mkdir()
    (sandbox.root / "Makefile").write_text("ok:\n", encoding="utf-8")
    r = _run(
        sandbox,
        home,
        f"""
first = policy.Scope(key="a", roots=(WS,), workdir_root=WS)
two = policy.Scope(key="b", roots=({str(second)!r},), workdir_root={str(second)!r})
RT.bind_scope(first)
RT.bind_scope(two)
results["own"] = {{"ok": True, "value": sh(f"echo x > {{WS}}/own", cwd=WS)}}
results["other session"] = {{"ok": True, "value": sh("echo x > {second}/n", cwd=WS)}}
results["ancestor file"] = {{"ok": True, "value": sh("echo x >> {sandbox.root}/Makefile", cwd=WS)}}
results["elsewhere cwd"] = {{"ok": True, "value": sh(f"echo x > {{WS}}/n2", cwd="/")}}
""",
    )
    assert r["own"]["value"][0] == 0, r["own"]
    assert r["other session"]["value"][0] != 0, r["other session"]
    assert r["ancestor file"]["value"][0] != 0, r["ancestor file"]
    assert r["elsewhere cwd"]["value"][0] != 0, r["elsewhere cwd"]
    assert not (second / "n").exists()


def test_a_grant_or_setting_cannot_hold_the_install(sandbox: Sandbox, home: Path) -> None:
    """Review: only the workspace may hold iCode's install (a checkout being worked on)."""
    import chrys.foundation

    package = confine.real(str(Path(chrys.foundation.__file__).resolve().parents[1]))  # .../chrys
    r = _run(
        sandbox,
        home,
        f"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
def attempt(path):
    try:
        RT.grant(scope, "session", path, access="write")
        return "granted"
    except client.SandboxDenied:
        return "refused"
results["package"] = {{"ok": True, "value": attempt({package!r})}}
results["service"] = {{"ok": True, "value": attempt({os.path.join(package, "service")!r})}}
results["parent"] = {{"ok": True, "value": attempt({os.path.dirname(package)!r})}}
results["as a setting"] = {{"ok": True, "value": policy.child_write(RT.config_dir, [], [{os.path.dirname(package)!r}])}}
results["as a workspace"] = {{"ok": True, "value": policy.child_write(RT.config_dir, [{os.path.dirname(package)!r}], [])}}
""",
    )
    for name in ("package", "service", "parent"):
        assert r[name]["value"] == "refused", name
    assert os.path.dirname(package) not in r["as a setting"]["value"]
    assert os.path.dirname(package) in r["as a workspace"]["value"]


def test_a_stored_workdir_write_grant_counts_for_nothing(tmp_path: Path) -> None:
    from icode_sandbox.grants import GrantStore

    (tmp_path / "state").mkdir()
    stored = {
        "grants": [
            {
                "id": "x",
                "kind": "workdir",
                "path": str(tmp_path),
                "scope_key": "s",
                "workdir_root": str(tmp_path),
                "created_at": 1.0,
                "source": "user",
                "access": "write",
            }
        ]
    }
    (tmp_path / "state" / "workdirs.json").write_text(json.dumps(stored), encoding="utf-8")
    store = GrantStore(tmp_path / "state")
    assert store.paths("s", str(tmp_path), "write") == []


def test_a_tools_mkdir_and_rename_land_where_the_kernel_says(sandbox: Sandbox, home: Path) -> None:
    """Review: the file open went through the helper, but a swapped folder could still catch the final rename."""
    outside = _writable_outside_everything()
    if outside is None:
        pytest.skip("no writable folder outside the private roots and scratch space here")
    target = outside / f"icode-write-probe2-{os.getpid()}"
    target.mkdir()
    try:
        r = _run(
            sandbox,
            home,
            f"""
T = {str(target)!r}
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
def attempt(fn):
    try:
        fn()
        return "done"
    except OSError as exc:
        return type(exc).__name__
fresh = os.path.join(WS, "t.tmp")
open(fresh, "w").write("x")
os.symlink(T, os.path.join(WS, "swapped"))
with client.scoped(scope):
    results["rename out"] = {{"ok": True, "value": attempt(lambda: os.replace(fresh, os.path.join(T, "landed")))}}
    results["rename through a link"] = {{"ok": True, "value": attempt(lambda: os.replace(fresh, os.path.join(WS, "swapped", "landed2")))}}
    results["open out"] = {{"ok": True, "value": attempt(lambda: os.close(os.open(os.path.join(T, "opened"), os.O_WRONLY | os.O_CREAT)))}}
    results["mkdir out"] = {{"ok": True, "value": attempt(lambda: os.mkdir(os.path.join(T, "made")))}}
    results["makedirs through a link"] = {{"ok": True, "value": attempt(lambda: os.makedirs(os.path.join(WS, "swapped", "a", "b")))}}
    results["unlink out"] = {{"ok": True, "value": attempt(lambda: os.unlink(os.path.join(T, "keep")))}}
    results["rmdir out"] = {{"ok": True, "value": attempt(lambda: os.rmdir(T))}}
    results["inside"] = {{"ok": True, "value": attempt(lambda: (os.mkdir(os.path.join(WS, "d")), os.replace(fresh, os.path.join(WS, "d", "m")), os.unlink(os.path.join(WS, "d", "m")), os.rmdir(os.path.join(WS, "d"))))}}
    results["unlink a link in place"] = {{"ok": True, "value": attempt(lambda: os.unlink(os.path.join(WS, "swapped")))}}
results["iCode's own, outside a tool"] = {{"ok": True, "value": attempt(lambda: os.mkdir(os.path.join(T, "own")))}}
""".replace('os.unlink(os.path.join(T, "keep"))', 'os.unlink(os.path.join(T, "keep"))'),
        )
    finally:
        made = sorted(p.name for p in target.iterdir()) if target.exists() else []
        import shutil

        shutil.rmtree(target, ignore_errors=True)
    for name in (
        "rename out",
        "rename through a link",
        "open out",
        "mkdir out",
        "makedirs through a link",
        "unlink out",
        "rmdir out",
    ):
        assert r[name]["value"] != "done", (name, r[name])
    assert r["inside"]["value"] == "done", r["inside"]
    assert r["unlink a link in place"]["value"] == "done", r["unlink a link in place"]
    assert r["iCode's own, outside a tool"]["value"] == "done"  # known limit: see WRITE_PLAN W3
    assert made == ["own"]


def test_the_panel_and_the_cli_tell_write_grants_from_read_grants(sandbox: Sandbox, home: Path) -> None:
    r = _tools(
        sandbox,
        home,
        r"""
from icode_sandbox.tui.panel import SandboxDialog
from chrys.app.tui.theme import TuiVariableDefaultsMixin
from rich.console import Console
from textual.app import App
from textual.widgets import Static
import io

class Host(TuiVariableDefaultsMixin, App):
    pass

async def scenario():
    mw = middleware()
    ANSWER.update(approved=True, remember="EXACT_SESSION")
    await call(mw, "write_file", path=os.path.join(GRANT, "w.txt"), content="x")
    await call(mw, "read_file", path=os.path.join(OTHER, "f.txt"))
    app = Host()
    async with app.run_test(size=(180, 90)) as pilot:
        dialog = SandboxDialog()
        await app.push_screen(dialog)
        await pilot.pause()
        console = Console(width=170, file=io.StringIO(), force_terminal=False, _environ={})
        for widget in dialog.query(Static):
            console.print(widget.content)
        results["panel"] = {"ok": True, "value": console.file.getvalue()}
    await mw.close()
run(scenario)
results["cli"] = {"ok": True, "value": [g.access + " " + g.path for g in RT.grants.list_persisted()]}
""",
    )
    lines = r["panel"]["value"].splitlines()
    granted, other = str(sandbox.granted.resolve()), str(sandbox.other.resolve())
    assert any("can write" in line and granted in line for line in lines), r["panel"]
    assert not any("can write" in line and other in line for line in lines), r["panel"]
    assert sorted(r["cli"]["value"]) == sorted([f"write {granted}", f"read {other}"])


ROLLBACK = r"""
from chrys.service.mutations.store import SnapshotStore
from chrys.service.mutations.types import MutationOp, MutationSource
from chrys.service.mutations.tracker import MutationTracker
from icode_sandbox.reads import session_scope

def outcome(results):
    return {os.path.relpath(r.path, WS): [r.outcome.value, r.reason or ""] for r in results}

store = SnapshotStore(pathlib.Path(CONFIG) / "sessions" / "sessrb")  # where iCode keeps it: its own session folder
tracker = MutationTracker(store)
tracker.start_turn(1)
"""


def _rollback(sandbox: Sandbox, home: Path, body: str) -> dict:
    return _run(sandbox, home, "import pathlib\n" + ROLLBACK + body)


def test_rollback_stays_inside_the_session_when_a_folder_was_swapped(sandbox: Sandbox, home: Path) -> None:
    """A folder on a recorded path, swapped for a link after the turn: the rollback can't follow it out."""
    for name in ("kept", "made", "linkdir"):
        (sandbox.ws / name).mkdir()
    (sandbox.ws / "kept" / "f.txt").write_text("BEFORE", encoding="utf-8")
    (sandbox.ws / "plain.txt").write_text("BEFORE", encoding="utf-8")
    (sandbox.other / "new.txt").write_text("OTHER-NEW", encoding="utf-8")
    r = _rollback(
        sandbox,
        home,
        r"""
def change(path, text):
    m = tracker.record(path, MutationOp.MODIFY if os.path.exists(path) else MutationOp.CREATE, MutationSource.WRITE_FILE, "t")
    with open(path, "w") as stream:
        stream.write(text)
    tracker.record_after(m)

change(os.path.join(WS, "kept", "f.txt"), "AFTER")
change(os.path.join(WS, "made", "new.txt"), "AFTER")
change(os.path.join(WS, "plain.txt"), "AFTER")
link = os.path.join(WS, "linkdir", "l")
os.symlink("first", link)
m = tracker.record(link, MutationOp.MODIFY, MutationSource.WRITE_FILE, "t")
os.unlink(link)
os.symlink("second", link)
tracker.record_after(m)
# Swapped after the turn: each recorded folder now leads out of the workspace.
for name in ("kept", "made", "linkdir"):
    os.rename(os.path.join(WS, name), os.path.join(WS, name + ".old"))
    os.symlink(OTHER, os.path.join(WS, name))
with session_scope("sess-rb", [WS], WS):
    results["out"] = {"ok": True, "value": outcome(tracker.rollback_turns({1}))}
""",
    )
    out = r["out"]["value"]
    assert out["plain.txt"][0] == "applied", out
    for name in ("kept/f.txt", "made/new.txt", "linkdir/l"):
        assert out[name][0] == "failed", (name, out)
        assert "sandbox" in out[name][1], (name, out)
    assert (sandbox.ws / "plain.txt").read_text(encoding="utf-8") == "BEFORE"
    assert sorted(p.name for p in sandbox.other.iterdir()) == ["f.txt", "new.txt"]
    assert (sandbox.other / "f.txt").read_text(encoding="utf-8") == "OTHER"
    assert (sandbox.other / "new.txt").read_text(encoding="utf-8") == "OTHER-NEW"
    events = (sandbox.root / "config" / "sandbox" / "audit.jsonl").read_text(encoding="utf-8")
    assert '"access": "write"' in events and str(sandbox.other.resolve()) in events


def test_a_normal_rollback_still_restores_everything(sandbox: Sandbox, home: Path) -> None:
    (sandbox.ws / "d").mkdir()
    (sandbox.ws / "d" / "f.txt").write_text("BEFORE", encoding="utf-8")
    (sandbox.ws / "inner").mkdir()
    (sandbox.ws / "via").symlink_to(sandbox.ws / "inner")
    (sandbox.ws / "inner" / "g.txt").write_text("BEFORE", encoding="utf-8")
    r = _rollback(
        sandbox,
        home,
        r"""
def change(path, text):
    m = tracker.record(path, MutationOp.MODIFY if os.path.exists(path) else MutationOp.CREATE, MutationSource.WRITE_FILE, "t")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as stream:
        stream.write(text)
    tracker.record_after(m)

change(os.path.join(WS, "d", "f.txt"), "AFTER")
change(os.path.join(WS, "fresh", "deep", "n.txt"), "NEW")
change(os.path.join(WS, "via", "g.txt"), "AFTER")
link = os.path.join(WS, "l")
os.symlink("first", link)
m = tracker.record(link, MutationOp.MODIFY, MutationSource.WRITE_FILE, "t")
os.unlink(link)
os.symlink("second", link)
tracker.record_after(m)
with session_scope("sess-rb", [WS], WS):
    results["out"] = {"ok": True, "value": outcome(tracker.rollback_turns({1}))}
results["link"] = {"ok": True, "value": os.readlink(link)}
""",
    )
    out = r["out"]["value"]
    assert all(v[0] in ("applied", "noop") for v in out.values()), out
    assert (sandbox.ws / "d" / "f.txt").read_text(encoding="utf-8") == "BEFORE"
    assert not (sandbox.ws / "fresh" / "deep" / "n.txt").exists()
    assert (sandbox.ws / "inner" / "g.txt").read_text(encoding="utf-8") == "BEFORE"  # a link that stays inside
    assert r["link"]["value"] == "first"


LOW_LEVEL_WRITES = r"""
import stat
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
target = os.path.join(OTHER, "f.txt")
with client.scoped(scope):
    ws_fd = os.open(WS, os.O_RDONLY | os.O_DIRECTORY)
    check("open absolute with dir_fd", lambda: os.open(os.path.join(OTHER, "new1"), os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=ws_fd))
    check("link", lambda: os.link(os.path.join(WS, "f.txt"), os.path.join(OTHER, "new2")))
    check("truncate", lambda: os.truncate(target, 0))
    check("chmod", lambda: os.chmod(target, 0o777))
    check("utime", lambda: os.utime(target, (0, 0)))
    if hasattr(os, "mkfifo"):
        check("mkfifo", lambda: os.mkfifo(os.path.join(OTHER, "new3")))
    check("system", lambda: os.system(f"echo X > {os.path.join(OTHER, 'new4')}"))
    os.symlink(os.path.join(WS, "f.txt"), os.path.join(WS, "lnk"))
    check("O_NOFOLLOW on a link", lambda: os.open(os.path.join(WS, "lnk"), os.O_RDONLY | os.O_NOFOLLOW))
    check("O_EXCL on an existing name", lambda: os.open(os.path.join(WS, "f.txt"), os.O_WRONLY | os.O_CREAT | os.O_EXCL))
    # Inside the workspace these still work.
    check("truncate inside", lambda: os.truncate(os.path.join(WS, "f.txt"), 1))
    check("link inside", lambda: os.link(os.path.join(WS, "f.txt"), os.path.join(WS, "hard")))
    check("system inside", lambda: os.system(f"echo Y > {os.path.join(WS, 'made.txt')}"))
st = os.stat(target)
made = [n for n in ("new1", "new2", "new3", "new4") if os.path.lexists(os.path.join(OTHER, n))]
results["outside after"] = {"ok": True, "value": [made, st.st_size, oct(st.st_mode & 0o777), st.st_mtime > 0]}
results["inside after"] = {"ok": True, "value": [open(os.path.join(WS, "made.txt")).read().strip(), os.path.exists(os.path.join(WS, "hard"))]}
"""


@needs_kernel
def test_low_level_writes_in_a_tool_call_stay_inside(sandbox: Sandbox) -> None:
    """Calls the file helper doesn't carry (dir_fd with an absolute path, link, truncate, mode, times, FIFOs,
    os.system) are held to the write set too, and the flags that refuse a link or an existing name keep meaning it."""
    r = sandbox.run(LOW_LEVEL_WRITES)
    for name in ("open absolute with dir_fd", "link", "truncate", "chmod", "utime", "mkfifo"):
        if name in r:
            assert r[name]["ok"] is False and r[name]["error"] in ("SandboxDenied", "PermissionError"), (name, r[name])
    assert r["system"]["ok"] and r["system"]["value"] != 0, r["system"]  # the confined shell couldn't write there
    assert r["O_NOFOLLOW on a link"]["ok"] is False and r["O_NOFOLLOW on a link"]["error"] == "OSError", r
    assert r["O_EXCL on an existing name"]["error"] == "FileExistsError", r
    files, size, mode, _ = r["outside after"]["value"]
    assert (files, size, mode) == ([], 5, oct(os.stat(sandbox.other / "f.txt").st_mode & 0o777)), r
    assert r["truncate inside"]["ok"] and r["link inside"]["ok"] and r["system inside"]["value"] == 0, r
    assert r["inside after"]["value"] == ["Y", True], r


SPAWNS = r"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
target = os.path.join(OTHER, "spawned")
argv = ["/bin/sh", "-c", f"echo X > {target}"]
with client.scoped(scope):
    check("posix_spawn", lambda: os.posix_spawn("/bin/sh", argv, dict(os.environ)))
    check("posix_spawnp", lambda: os.posix_spawnp("sh", argv, dict(os.environ)))
    # subprocess still works, confined: it may use posix_spawn underneath.
    check("subprocess", lambda: subprocess.run(argv, stdin=subprocess.DEVNULL).returncode)
    check("subprocess inside", lambda: subprocess.run(["/bin/sh", "-c", "echo Y > made"], cwd=WS, stdin=subprocess.DEVNULL).returncode)
import time
time.sleep(0.5)
results["spawned"] = {"ok": True, "value": os.path.lexists(target)}
# Outside a tool call it is iCode's own code: allowed (the control).
pid = os.posix_spawn("/usr/bin/true", ["true"], dict(os.environ))
results["own"] = {"ok": True, "value": os.waitpid(pid, 0)[1]}
"""


@needs_kernel
def test_a_tool_call_cannot_start_a_program_with_posix_spawn(sandbox: Sandbox) -> None:
    """What ``os.posix_spawn`` starts would bypass the broker: refused in a tool call; subprocess still works."""
    if not hasattr(os, "posix_spawn"):
        pytest.skip("no posix_spawn here")
    r = sandbox.run(SPAWNS)
    assert r["posix_spawn"]["ok"] is False and r["posix_spawn"]["error"] == "PermissionError", r
    assert r["posix_spawnp"]["ok"] is False and r["posix_spawnp"]["error"] == "PermissionError", r
    assert r["subprocess"]["ok"] and r["subprocess"]["value"] != 0, r  # started confined: the write was refused
    assert r["subprocess inside"]["value"] == 0 and (sandbox.ws / "made").exists(), r
    assert r["spawned"]["value"] is False, r
    assert r["own"]["value"] == 0, r
