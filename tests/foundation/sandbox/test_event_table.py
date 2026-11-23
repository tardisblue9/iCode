# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""What each boundary event does to a session's read set and its helper.

One test per kind of event (session start and end, grants, revocations, turn ends). No
process starts: the helper is a stand-in that records being retired, so these
pin the bookkeeping that the real-kernel tests then exercise.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from icode_sandbox import client, policy
from icode_sandbox.runtime import confine


class _Helper:
    def __init__(self, paths: list[str]) -> None:
        self.paths = frozenset(paths)
        self.writes: frozenset[str] = frozenset()
        self.closed = False

    def retire(self) -> None:
        self.closed = True


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home directory of its own: everything under it is private."""
    root = Path(confine.real(str(tmp_path)))
    for name in ("config", "ws", "ws2", "extra", "other"):
        (root / name).mkdir()
    (root / "other" / "f.txt").write_text("x", encoding="utf-8")
    (root / "other" / "g.txt").write_text("y", encoding="utf-8")
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setattr(policy, "private_roots", lambda: [str(root)])
    monkeypatch.setattr(policy, "is_private", lambda p: confine.is_within(p, str(root)))
    return root


@pytest.fixture
def rt(home: Path) -> client.Runtime:
    runtime = client.Runtime(config_dir=home / "config", settings=client.SandboxSettings(enabled=True))

    def spawn(paths: list[str], *, writes: list[str]) -> _Helper:
        helper = _Helper(paths)
        helper.writes = frozenset(writes)
        return helper

    runtime._spawn_helper = spawn  # type: ignore[assignment,method-assign]
    return runtime


def _scope(home: Path, *roots: str, key: str = "s1") -> policy.Scope:
    paths = tuple(str(home / r) for r in roots)
    return policy.Scope(key=key, roots=paths, workdir_root=paths[0])


def _reads(rt: client.Runtime, scope: policy.Scope) -> set[str]:
    return set(rt.access_set(scope).paths())


def _helper(rt: client.Runtime, scope: policy.Scope) -> _Helper:
    """The scope's helper; ``paths`` leaves out the scratch and cache folders every helper may write."""
    helper = rt._scope_helper(scope)
    assert isinstance(helper, _Helper)
    if not getattr(helper, "scratch_dropped", False):
        access = rt.access_set(scope)
        helper.scratch_dropped = True  # type: ignore[attr-defined]
        helper.paths = frozenset(helper.paths - (set(rt.write_set(scope)) - set(access.paths())))
    return helper


def test_session_start_sets_the_workspace(rt: client.Runtime, home: Path) -> None:
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    assert _reads(rt, scope) == {str(home / "ws")}
    assert _helper(rt, scope).paths == {str(home / "ws")}


def test_switching_workspace_replaces_it_and_retires_the_helper(rt: client.Runtime, home: Path) -> None:
    old = _scope(home, "ws")
    rt.bind_scope(old)
    first = _helper(rt, old)
    new = _scope(home, "ws2")
    rt.bind_scope(new)
    assert first.closed
    assert _reads(rt, new) == {str(home / "ws2")}
    assert _helper(rt, new).paths == {str(home / "ws2")}


def test_additional_directories_add_to_it_and_retire_the_helper(rt: client.Runtime, home: Path) -> None:
    only = _scope(home, "ws")
    rt.bind_scope(only)
    first = _helper(rt, only)
    both = _scope(home, "ws", "extra")
    rt.bind_scope(both)
    assert first.closed
    assert _helper(rt, both).paths == {str(home / "ws"), str(home / "extra")}


def test_this_call_only_covers_one_file_until_revoked(rt: client.Runtime, home: Path) -> None:
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    target = str(home / "other" / "f.txt")
    grant = rt.grant(scope, "call", target)
    access = rt.access_set(scope)
    assert access.covers(target)
    assert not access.covers(str(home / "other" / "g.txt"))
    rt.revoke(grant.id)
    assert not rt.access_set(scope).covers(target)


@pytest.mark.parametrize("kind", ["turn", "session"])
def test_a_grant_widens_the_set_and_retires_the_helper(rt: client.Runtime, home: Path, kind: str) -> None:
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    first = _helper(rt, scope)
    rt.grant(scope, kind, str(home / "other"))
    assert first.closed
    assert _helper(rt, scope).paths == {str(home / "ws"), str(home / "other")}


def test_turn_end_removes_turn_grants_only_and_retires_the_helper(rt: client.Runtime, home: Path) -> None:
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    rt.grant(scope, "turn", str(home / "other"))
    rt.grant(scope, "session", str(home / "extra"))
    widened = _helper(rt, scope)
    rt.end_turn(scope.key)
    assert widened.closed
    assert _reads(rt, scope) == {str(home / "ws"), str(home / "extra")}
    assert _helper(rt, scope).paths == {str(home / "ws"), str(home / "extra")}


def test_revoking_narrows_at_once_and_retires_the_helper(rt: client.Runtime, home: Path) -> None:
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    grant = rt.grant(scope, "session", str(home / "other"))
    widened = _helper(rt, scope)
    rt.revoke(grant.id)
    assert widened.closed
    assert _reads(rt, scope) == {str(home / "ws")}


def test_a_workdir_grant_reaches_other_sessions_of_the_workdir_only(rt: client.Runtime, home: Path) -> None:
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    rt.grant(scope, "workdir", str(home / "other"))
    assert str(home / "other") in _reads(rt, _scope(home, "ws", key="s2"))
    assert str(home / "other") not in _reads(rt, _scope(home, "ws2", key="s3"))


def test_session_end_stops_the_helper_after_its_last_owner(rt: client.Runtime, home: Path) -> None:
    scope = _scope(home, "ws")
    rt.hold_scope(scope.key)
    rt.hold_scope(scope.key)
    rt.bind_scope(scope)
    helper = _helper(rt, scope)
    rt.release_scope(scope.key)
    assert not helper.closed
    rt.release_scope(scope.key)
    assert helper.closed
    assert scope.key not in rt.snapshot()["scopes"]


def test_a_protected_path_is_never_added(home: Path) -> None:
    (home / "keys").mkdir()
    settings = client.SandboxSettings(enabled=True, floor_extra=[str(home / "keys")])
    rt = client.Runtime(config_dir=home / "config", settings=settings)
    scope = _scope(home, "ws")
    rt.bind_scope(scope)
    with pytest.raises(client.SandboxDenied):
        rt.grant(scope, "session", str(home / "keys"))
    assert str(home / "keys") not in _reads(rt, scope)


def test_sessions_do_not_see_each_others_set(rt: client.Runtime, home: Path) -> None:
    one, two = _scope(home, "ws", key="s1"), _scope(home, "ws2", key="s2")
    rt.bind_scope(one)
    rt.bind_scope(two)
    rt.grant(one, "session", str(home / "other"))
    assert _reads(rt, two) == {str(home / "ws2")}


def test_denials_are_reported_once_and_to_their_own_session(rt: client.Runtime) -> None:
    rt.record_denial("/a", "s1", "read_file", "refused")
    rt.record_denial("/b", "s2", "grep", "protected")
    assert [d.path for d in rt.take_unreported("s1")] == ["/a"]
    assert rt.take_unreported("s1") == []
    assert [d.path for d in rt.take_unreported("s2")] == ["/b"]


def test_redacted_logs_keep_paths_out_and_digests_stable(home: Path) -> None:
    settings = client.SandboxSettings(enabled=True, audit_redact_paths=True)
    runtime = client.Runtime(config_dir=home / "config", settings=settings)
    runtime.audit("deny", path=str(home / "other"), scope="s1")
    runtime.audit("deny", path=str(home / "other"), scope="s1")
    runtime.audit("helper_started", paths=[str(home / "ws")])
    text = runtime.audit_path.read_text(encoding="utf-8")
    assert str(home) not in text
    digests = [line for line in text.splitlines() if '"deny"' in line]
    digest = runtime.logged_path(str(home / "other"))
    assert digest.startswith("hmac:") and all(digest in line for line in digests)
    key = (home / "config" / "sandbox" / "audit.key").stat()
    assert key.st_mode & 0o077 == 0
    again = client.Runtime(config_dir=home / "config", settings=settings)
    assert again.logged_path(str(home / "other")) == digest


def test_logs_hold_paths_when_redaction_is_off(rt: client.Runtime, home: Path) -> None:
    rt.audit("deny", path=str(home / "other"), scope="s1")
    assert str(home / "other") in rt.audit_path.read_text(encoding="utf-8")
