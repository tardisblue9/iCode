# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The sandbox's decisions, without confining anything.

Path matching, the broker's profile checks, Seatbelt rendering, the grant
store's lifetimes and the settings precedence — the parts every kernel test
builds on.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

import pytest

from icode_sandbox import bootstrap, policy
from icode_sandbox import reads as sandbox_reads
from icode_sandbox.client import _running_binary
from icode_sandbox.grants import GrantStore
from icode_sandbox.runtime import confine

RUNTIME = Path(confine.__file__).resolve().parent


def _load_broker():
    """The broker as the standalone process loads it (its own ``confine`` copy)."""
    spec = importlib.util.spec_from_file_location("sandbox_broker_under_test", RUNTIME / "broker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # ty: ignore[possibly-missing-attribute]
    return module


# ----------------------------------------------------------------------- paths


@pytest.mark.parametrize(
    ("path", "root", "within"),
    [
        ("/a/b", "/a", True),
        ("/a", "/a", True),
        ("/ab", "/a", False),
        ("/a/b/c", "/a/b/", True),
        ("/x", "/", True),
        ("/a", "/a/b", False),
    ],
)
def test_is_within(path: str, root: str, within: bool) -> None:
    assert confine.is_within(path, root) is within


def test_same_or_nested_sees_through_aliases(tmp_path: Path) -> None:
    real = tmp_path / 'Secret Dir "quoted" ünï'
    (real / "inner").mkdir(parents=True)
    link = tmp_path / "alias"
    link.symlink_to(real)
    assert confine.same_or_nested(str(link / "inner"), str(real))
    assert confine.same_or_nested(str(real), str(link / "inner"))
    assert not confine.same_or_nested(str(tmp_path / "other"), str(real))
    if sys.platform == "darwin":
        upper = str(real).replace("Secret", "SECRET")
        assert confine.same_or_nested(upper, str(real))


def test_floor_covers_both_homes_and_aliases(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    account = policy.account_home()
    monkeypatch.setattr(policy, "_frozen_home", [])  # as before any confinement
    monkeypatch.setenv("HOME", str(tmp_path))
    floor = policy.floor()
    assert os.path.join(account, ".ssh") in floor
    assert confine.real(str(tmp_path / ".ssh")) in floor
    assert policy.is_protected(os.path.join(account, ".ssh", "id_rsa"))
    assert policy.is_protected(account)  # contains the floor
    assert account in policy.private_roots()
    assert confine.real(str(tmp_path)) in policy.private_roots()


def test_mentions_never_open_a_whole_private_root(tmp_path: Path) -> None:
    home = policy.home()
    found = sandbox_reads.mentioned_paths([f"see @{tmp_path} and @~ and @/ and @{home}"], str(tmp_path))
    assert found == [confine.real(str(tmp_path))]
    assert sandbox_reads.mentioned_by_user(confine.real(str(tmp_path / "x.txt")), found)
    assert not sandbox_reads.mentioned_by_user("/elsewhere/x.txt", found)


def test_ancestor_configs_are_project_files_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy, "_frozen_home", [])
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("//registry:_authToken=x", encoding="utf-8")
    (tmp_path / "a" / "ws").mkdir(parents=True)
    (tmp_path / "a" / "package.json").write_text("{}", encoding="utf-8")
    found = policy.ancestor_configs([str(tmp_path / "a" / "ws")])
    assert found == sorted(
        [confine.real(str(tmp_path / "a" / "package.json")), confine.real(str(tmp_path / "pyproject.toml"))]
    )


# --------------------------------------------------------------- broker checks


@pytest.fixture
def broker():
    module = _load_broker()
    return module.Broker(
        {"python": sys.executable, "python_binary": _running_binary(), "floor": [], "private_roots": []}
    ), module


@pytest.mark.parametrize(
    "allow",
    [
        ["~/.ssh"],
        ["~/.ssh/config"],
        ["~"],
        ["/"],
        ["~/Library/Keychains/login.keychain-db"],
        ["~/.SSH"] if sys.platform == "darwin" else ["~/.gnupg"],
    ],
)
def test_broker_refuses_the_floor_in_any_spelling(broker, allow: list[str]) -> None:
    instance, module = broker
    with pytest.raises(module.Refused):
        instance.check({"mode": "only", "allow": [os.path.expanduser(p) for p in allow]})


def test_broker_hardens_except_profiles(broker, tmp_path: Path) -> None:
    instance, module = broker
    profile = instance.check({"mode": "except", "allow": [str(tmp_path)], "deny_roots": []})
    assert profile.protect_moves is True
    assert policy.account_home() in profile.deny_roots  # can't be dropped by the caller
    with pytest.raises(module.Refused):
        instance.check({"mode": "except", "allow": [policy.account_home()], "deny_roots": []})
    with pytest.raises(module.Refused):
        instance.check({"mode": "except", "write": [str(tmp_path)]})
    with pytest.raises(module.Refused):
        instance.check({"mode": "exec"})
    assert instance.check({"mode": "only", "allow": [str(tmp_path)]}).protect_moves is False


# --------------------------------------------------------------- seatbelt text


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is macOS-only")
@pytest.mark.skipif(os.environ.get("CHRYS_TEST_SANDBOX") == "1", reason="a confined runner can't apply another profile")
def test_seatbelt_profiles_parse_with_hostile_paths(tmp_path: Path) -> None:
    odd = tmp_path / 'we"ird\\ (path) ünï'
    odd.mkdir()
    for profile in (
        confine.Profile(mode="except", allow=[str(odd)], deny_roots=[str(tmp_path)], protect_moves=True),
        confine.Profile(mode="only", allow=[str(odd)], write=[str(odd)]),
    ):
        source = confine.seatbelt_profile(profile)
        result = subprocess.run(
            ["/usr/bin/sandbox-exec", "-p", source, "/bin/ls", str(odd)],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        if profile.mode == "only":
            # Parsed and applied: then exec itself is refused, as helpers want.
            assert "execvp" in result.stderr and "Operation not permitted" in result.stderr, result.stderr
        else:
            assert result.returncode == 0, (source, result.stderr)


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt is macOS-only")
@pytest.mark.skipif(os.environ.get("CHRYS_TEST_SANDBOX") == "1", reason="a confined runner can't apply another profile")
def test_lock_files_beside_a_readable_file_can_be_renamed(tmp_path: Path) -> None:
    """``git config --global`` writes ``~/.gitconfig.lock`` and renames it over ``~/.gitconfig``."""
    private = tmp_path / "home"
    private.mkdir()
    config = private / ".gitconfig"  # not created yet, as on a fresh machine
    profile = confine.Profile(mode="except", allow=[str(config)], deny_roots=[str(private)], protect_moves=True)
    script = f"echo a > {config}.lock && mv {config}.lock {config} && echo s > {private}/other && mv {private}/other {tmp_path}/out"
    result = subprocess.run(
        ["/usr/bin/sandbox-exec", "-p", confine.seatbelt_profile(profile), "/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert config.read_text() == "a\n"
    assert (private / "other").exists() and not (tmp_path / "out").exists(), result.stderr


def test_profile_round_trips_through_json() -> None:
    profile = confine.Profile(
        mode="except", allow=["/a"], write=[], deny_roots=["/h"], protect_moves=True, refer=["/w"]
    )
    assert confine.Profile.from_json(profile.to_json()) == profile
    assert json.loads(profile.to_json())["protect_moves"] is True


# ------------------------------------------------------------------ grants


def test_grant_lifetimes(tmp_path: Path) -> None:
    store = GrantStore(tmp_path)
    call = store.add("s1", "call", str(tmp_path / "c"))
    store.add("s1", "turn", str(tmp_path / "t"))
    store.add("s1", "session", str(tmp_path / "s"))
    store.add("s1", "workdir", str(tmp_path / "p"), workdir_root=str(tmp_path / "proj"))
    store.add("s2", "session", str(tmp_path / "other"))
    paths = store.paths("s1", str(tmp_path / "proj"))
    assert {os.path.basename(p) for p in paths} == {"c", "t", "s", "p"}
    assert "other" not in {os.path.basename(p) for p in paths}
    store.revoke(call.id)
    ended = store.end_turn("s1")
    assert {g.kind for g in ended} == {"turn"}
    assert {os.path.basename(p) for p in store.paths("s1", str(tmp_path / "proj"))} == {"s", "p"}
    # Durable kinds survive a restart; the working directory grant follows the working directory, not the session.
    reloaded = GrantStore(tmp_path)
    assert {os.path.basename(p) for p in reloaded.paths("s1", str(tmp_path / "proj"))} == {"s", "p"}
    assert {os.path.basename(p) for p in reloaded.paths("s9", str(tmp_path / "proj"))} == {"p"}
    assert {os.path.basename(p) for p in reloaded.paths("s9", str(tmp_path / "elsewhere"))} == set()
    assert {g.kind for g in reloaded.list_persisted()} == {"session", "workdir"}
    for grant in reloaded.list_persisted():
        assert reloaded.revoke_persisted(grant.id) is not None
    assert GrantStore(tmp_path).list_persisted() == []


def test_once_grant_is_consumed(tmp_path: Path) -> None:
    store = GrantStore(None)
    store.add("s", "once", str(tmp_path / "f"))
    assert store.take_once("s", str(tmp_path / "f")) is not None
    assert store.take_once("s", str(tmp_path / "f")) is None


# ---------------------------------------------------------------- settings


def _settings_dir(tmp_path: Path, text: str) -> Path:
    (tmp_path / "settings.yaml").write_text(text, encoding="utf-8")
    return tmp_path


def test_settings_precedence(tmp_path: Path) -> None:
    config = _settings_dir(
        tmp_path, "sandbox:\n  files:\n    enabled: true\n    on_unavailable: warn\n    floor:\n      extra: /x\n"
    )
    _, s = bootstrap.resolve_settings([], config, env={})
    assert (s.enabled, s.source, s.on_unavailable, s.floor_extra) == (True, "settings", "warn", ["/x"])
    _, s = bootstrap.resolve_settings([], config, env={"CHRYS_FILE_SANDBOX": "0"})
    assert (s.enabled, s.source) == (False, "env")
    rest, s = bootstrap.resolve_settings(["run", "--sandbox", "x"], config, env={"CHRYS_FILE_SANDBOX": "0"})
    assert (s.enabled, s.source, rest) == (True, "cli", ["run", "x"])
    _, s = bootstrap.resolve_settings([], config, env={"CHRYS_FILE_SANDBOX": "maybe"})
    assert (s.enabled, s.source) == (True, "settings")  # an invalid value doesn't override


def test_a_workdir_cannot_turn_the_sandbox_off(tmp_path: Path) -> None:
    config = (
        _settings_dir(tmp_path / "home", "sandbox.files.enabled: true\n")
        if (tmp_path / "home").mkdir() is None
        else None
    )
    workdir = tmp_path / "proj" / ".chrys"
    workdir.mkdir(parents=True)
    (workdir / "settings.yaml").write_text("sandbox:\n  files:\n    enabled: false\n", encoding="utf-8")
    _, s = bootstrap.resolve_settings(["-C", str(tmp_path / "proj")], config, env={})
    assert s.enabled is True


@pytest.mark.parametrize(
    ("user", "workdir", "trusted", "enabled", "source", "ignored"),
    [
        ("true", "false", True, True, "settings", True),
        ("false", "false", True, False, "settings", True),
        ("false", "true", True, True, "workdir", False),
        ("true", "true", True, True, "workdir", False),
        ("false", "true", False, False, "settings", False),
        ("true", "false", False, True, "settings", False),
    ],
)
def test_a_workdir_can_turn_the_sandbox_on_but_not_off(
    tmp_path: Path, user: str, workdir: str, trusted: bool, enabled: bool, source: str, ignored: bool
) -> None:
    (tmp_path / "home").mkdir()
    doc = f"sandbox:\n  files:\n    enabled: {user}\nworkdir:\n  config_enabled: {str(trusted).lower()}\n"
    config = _settings_dir(tmp_path / "home", doc)
    (tmp_path / "proj" / ".chrys").mkdir(parents=True)
    (tmp_path / "proj" / ".chrys" / "settings.yaml").write_text(f"sandbox.files.enabled: {workdir}\n", encoding="utf-8")
    _, s = bootstrap.resolve_settings(["-C", str(tmp_path / "proj")], config, env={})
    assert (s.enabled, s.source, s.workdir_off_ignored) == (enabled, source, ignored)


def test_the_command_line_still_outranks_a_workdir(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    config = _settings_dir(tmp_path / "home", "workdir.config_enabled: true\n")
    (tmp_path / "proj" / ".chrys").mkdir(parents=True)
    (tmp_path / "proj" / ".chrys" / "settings.yaml").write_text("sandbox.files.enabled: true\n", encoding="utf-8")
    _, s = bootstrap.resolve_settings(["--no-sandbox", "-C", str(tmp_path / "proj")], config, env={})
    assert (s.enabled, s.source) == (False, "cli")


def test_redaction_is_read_from_the_user_settings_only(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    config = _settings_dir(tmp_path / "home", "sandbox.files.audit.redact_paths: true\nworkdir.config_enabled: true\n")
    assert bootstrap.resolve_settings([], config, env={})[1].audit_redact_paths is True
    (tmp_path / "home2").mkdir()
    config = _settings_dir(tmp_path / "home2", "workdir.config_enabled: true\n")
    (tmp_path / "proj" / ".chrys").mkdir(parents=True)
    (tmp_path / "proj" / ".chrys" / "settings.yaml").write_text(
        "sandbox.files.audit.redact_paths: true\n", encoding="utf-8"
    )
    assert bootstrap.resolve_settings(["-C", str(tmp_path / "proj")], config, env={})[1].audit_redact_paths is False


def test_settings_declare_what_a_workdir_may_do() -> None:
    from chrys.foundation.config.settings import Settings
    from chrys.foundation.config.spec import METADATA_KEY, WorkdirMerge

    rules = {
        f.metadata[METADATA_KEY].key: f.metadata[METADATA_KEY].workdir_merge
        for f in fields(Settings)
        if METADATA_KEY in f.metadata
    }
    assert rules["sandbox.files.enabled"] is WorkdirMerge.ENABLE_ONLY
    for key in ("sandbox.files.on_unavailable", "sandbox.files.main.allow_paths", "sandbox.files.audit.redact_paths"):
        assert rules[key] is WorkdirMerge.DENY


def test_refusal_messages_tell_the_model_what_to_do() -> None:
    protected = sandbox_reads.refusal(sandbox_reads.Blocked("/h/.ssh/id", True), "read_file", can_ask=True)
    assert "protected" in protected and "Do not try other ways" in protected
    headless = sandbox_reads.refusal(sandbox_reads.Blocked("/h/x", False), "read_file", can_ask=False)
    assert "cannot ask the user" in headless and "working directory" in headless
    declined = sandbox_reads.refusal(sandbox_reads.Blocked("/h/x", False), "read_file", can_ask=True, rejected=True)
    assert "declined" in declined
    for text in (protected, headless, declined):
        assert text.startswith("Error: sandbox:")


def test_icode_s_own_code_is_its_install_wherever_it_is_installed() -> None:
    """``chrys`` and ``icode_sandbox`` are found from their modules: a source checkout keeps them in two trees."""
    import chrys.foundation
    import icode_sandbox

    chrys_dir = confine.real(str(Path(chrys.foundation.__file__).resolve().parent.parent))
    sandbox_dir = confine.real(str(Path(icode_sandbox.__file__).resolve().parent))
    assert {chrys_dir, sandbox_dir} <= set(policy.install_paths())
    assert policy.is_write_protected(os.path.join(chrys_dir, "foundation", "guard.py"))
    assert policy.is_write_protected(os.path.join(sandbox_dir, "policy.py"))
    roots = {confine.real(root) for root in policy.package_roots()}
    assert {str(Path(chrys_dir).parent), str(Path(sandbox_dir).parent)} <= roots


@pytest.mark.skipif(
    os.environ.get("CHRYS_TEST_SANDBOX") == "1", reason="checks an unconfined process; this one is confined"
)
def test_uninstall_restores_every_function_install_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hooks are the sandbox's whole footprint in the process: each one put in must come out again."""
    import builtins
    import io
    import subprocess

    from icode_sandbox import patches

    names = [(os, n) for n in ("getcwd", "getcwdb", "chdir", "open", "listdir", "scandir", "mkdir", "unlink",
                               "remove", "rmdir", "replace", "rename", "symlink", "link", "truncate", "chmod",
                               "utime", "system") + (("mkfifo", "mknod", "chown", "posix_spawn", "posix_spawnp") if hasattr(os, "mkfifo") else ())]  # fmt: skip
    names += [(builtins, "open"), (io, "open"), (subprocess.Popen, "_execute_child")]
    before = {(id(owner), name): getattr(owner, name) for owner, name in names}
    monkeypatch.setattr(patches, "_installed", False)
    monkeypatch.setattr(patches, "_cwd", [os.getcwd()])
    try:
        patches.install()
        replaced = [name for owner, name in names if getattr(owner, name) is not before[(id(owner), name)]]
    finally:
        patches.uninstall()
    left = [name for owner, name in names if getattr(owner, name) is not before[(id(owner), name)]]
    assert len(replaced) == len(names), replaced
    assert left == []


@pytest.mark.skipif(os.environ.get("CHRYS_TEST_SANDBOX") == "1", reason="its children would be the broker's")
def test_a_linked_command_lasts_while_its_session_has_a_member() -> None:
    """A command's session outlives its leader while what it started runs; empty, its number may be reused."""
    import subprocess
    import sys

    from icode_sandbox import patches

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    try:
        assert patches._still_the_command(child.pid, os.getpid())
        assert not patches._still_the_command(os.getpid(), os.getppid())  # not a session leader
    finally:
        child.kill()
        child.wait()
    assert not patches._still_the_command(child.pid, os.getpid())  # gone
    # A leader that exits leaving a process in its session: the session is still there.
    leader = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess, sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])",
        ],
        start_new_session=True,
    )
    leader.wait()
    try:
        assert patches._still_the_command(leader.pid, os.getpid())
    finally:
        import psutil

        for proc in psutil.process_iter():
            with contextlib.suppress(OSError, psutil.Error):
                if os.getsid(proc.pid) == leader.pid:
                    proc.kill()


@pytest.mark.parametrize(("abi", "ok"), [(0, False), (1, False), (2, True), (4, True)])
def test_linux_needs_landlock_abi_2(monkeypatch: pytest.MonkeyPatch, abi: int, ok: bool) -> None:
    """ABI 1 refuses every move into another folder from a confined process: tools that rename their
    files into place (uv, pip, cargo) fail. The sandbox says it is unavailable there, with the reason."""
    from icode_sandbox.runtime import confine as c

    monkeypatch.setattr(c, "PLATFORM", "linux")
    monkeypatch.setattr(c, "_landlock_abi", lambda: abi)
    available, why = c.available()
    assert available is ok, why
    if abi == 1:
        assert "5.19" in why and "ABI 1" in why


def test_toolchain_folders_of_the_account_home_count_when_home_points_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook's ``uv run`` finds uv in the account's ``~/.local/bin`` even when ``$HOME`` was moved."""
    account = tmp_path / "account"
    moved = tmp_path / "moved"
    for folder in (account / ".local" / "bin", moved):
        folder.mkdir(parents=True)
    monkeypatch.setattr(policy, "home", lambda: str(moved))
    monkeypatch.setattr(policy, "account_home", lambda: str(account))
    monkeypatch.setattr(policy, "is_private", lambda p: str(p).startswith(str(tmp_path)))
    allowed = policy.child_allow(tmp_path / "config", [str(tmp_path / "ws")])
    assert confine.real(str(account / ".local" / "bin")) in allowed
    assert confine.real(str(moved / ".local" / "bin")) in allowed
