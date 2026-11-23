# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Sandbox runtime inside the main process: broker connection, helpers, scopes.

One :class:`Runtime` exists per confined iCode process. It owns

- the control socket to the broker (started before the process confined itself),
- the *service* file helper, whose read set is the union of every workspace this
  process currently serves — iCode's own code falls back to it when the kernel
  refuses a direct read (see :mod:`icode_sandbox.patches`),
- one *scope* helper per scope key (a session), whose read set is that
  session's workspace plus its grants — model-directed reads go through it,
- slots for commands: a broker-side reservation a stub process redeems.

A helper is never modified: a changed read set retires the old helper and
starts a new one. Narrowing retires first (no request is served with the old
set once the change returns); widening starts the new one first.
"""

from __future__ import annotations

import contextlib
import contextvars
import errno as errno_mod
import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chrys.foundation.util.session_ids import session_short_id
from icode_sandbox import policy
from icode_sandbox.grants import Grant, GrantAccess, GrantKind, GrantStore
from icode_sandbox.runtime import confine

RUNTIME_DIR = Path(__file__).resolve().parent / "runtime"
SESSION_EVENTS_FILE = "sandbox_events.jsonl"
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_FD_LESS_OPS = frozenset({"mkdir", "unlink", "rmdir", "rename", "symlink"})
_AUDIT_PATH_FIELDS = frozenset({"path", "paths", "write_paths", "revoked", "main_allow", "private_roots"})

# The runtime's own bookkeeping must never go through the read hooks it serves.
_raw_os_open = os.open

current_scope: contextvars.ContextVar[policy.Scope | None] = contextvars.ContextVar("sandbox_scope", default=None)
"""The scope whose read set applies to model-directed work in this context."""

wants_controlling_tty: contextvars.ContextVar[bool] = contextvars.ContextVar("sandbox_ctty", default=False)
"""Set while iCode starts a program on a terminal it should control (the TUI's own terminal)."""

launch_writes: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar("sandbox_launch_writes", default=())
"""Paths the program started in this context, and no other, may also change."""
launch_reads: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar("sandbox_launch_reads", default=())
"""Extra paths a program *the person configured* (an ACP agent, an MCP server)
may read when iCode starts it: its own files. Never set for model-chosen commands."""

user_reading: contextvars.ContextVar[bool] = contextvars.ContextVar("sandbox_user_reading", default=False)
"""Set while iCode reads a file the *person* chose (an attached image): such a
read goes through a one-shot helper for exactly that file, floor still applied."""


class SandboxDenied(PermissionError):
    """A read the sandbox refused, with what the user can do about it."""

    def __init__(self, path: str, *, protected: bool = False, reason: str = "", writing: bool = False) -> None:
        self.path = path
        self.protected = protected
        if protected:
            message = f"sandbox: {path} is in a protected location and cannot be granted"
        else:
            what = "write" if writing else "read"
            message = reason or f"sandbox: {what} of {path} denied (outside the workspace and grants)"
        super().__init__(errno_mod.EACCES, message, path)


class HelperGone(ConnectionError):
    """The helper was retired or died; the caller should retry with the current one."""


@dataclass
class Denial:
    at: float
    path: str
    scope: str
    tool: str
    outcome: str
    access: str = "read"


@dataclass
class Status:
    state: str = "inactive"  # active | degraded | inactive
    requested: bool = False
    mechanism: str = ""
    reasons: list[str] = field(default_factory=list)
    inherited: bool = False

    def label(self) -> str:
        if self.state == "inactive" and self.requested:
            return "requested-not-active"
        return self.state


def _running_binary() -> str:
    """The interpreter binary this process runs, which ``sys.executable`` may only launch (macOS framework builds)."""
    import psutil

    try:
        return psutil.Process().exe()
    except psutil.Error:
        return sys.executable


class _Helper:
    """One confined file helper and the read set it was started with."""

    def __init__(
        self, sock: socket.socket, paths: frozenset[str], version: int, writes: frozenset[str] = frozenset()
    ) -> None:
        self.sock = sock
        self.paths = paths
        self.writes = writes
        self.version = version
        self.lock = threading.Lock()
        self.ready = False
        self.closed = False
        self.pid = 0

    def _await_ready(self) -> None:
        if self.ready:
            return
        message, _fds = confine.recv(self.sock)
        if not message or not message.get("ready"):
            self.closed = True
            raise HelperGone((message or {}).get("error", "file helper failed to start"))
        self.ready = True
        self.pid = int(message.get("pid", 0))

    def request(self, message: dict[str, Any]) -> int:
        with self.lock:
            if self.closed:
                raise HelperGone("retired")
            try:
                self._await_ready()
                confine.send(self.sock, message)
                reply, fds = confine.recv(self.sock)
            except (OSError, ConnectionError) as exc:
                self.closed = True
                raise HelperGone(str(exc)) from exc
            if reply is None:
                self.closed = True
                raise HelperGone("file helper exited")
            if reply.get("ok") and not fds and message.get("op") in _FD_LESS_OPS:
                return -1
            if not reply.get("ok") or not fds:
                for fd in fds:
                    os.close(fd)
                code = int(reply.get("errno") or errno_mod.EACCES)
                raise OSError(code, reply.get("error") or os.strerror(code), message.get("path"))
            for extra in fds[1:]:
                os.close(extra)
            return fds[0]

    def retire(self) -> None:
        with self.lock:
            if not self.closed:
                self.closed = True
                with contextlib.suppress(OSError):
                    self.sock.close()


class Runtime:
    """The sandbox as seen from the confined main process."""

    def __init__(self, *, config_dir: Path, settings: SandboxSettings) -> None:
        self.config_dir = Path(confine.real(str(config_dir)))
        self.settings = settings
        self.status = Status(requested=True)
        self.grants = GrantStore(self.config_dir / "sandbox")
        self._control: socket.socket | None = None
        self._control_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self._service_roots: dict[str, tuple[str, ...]] = {}
        self._service_helper: _Helper | None = None
        self._scopes: dict[str, policy.Scope] = {}
        self._scope_helpers: dict[str, _Helper] = {}
        self._holders: dict[str, int] = {}
        self.readable_tops: list[str] = []
        self._sessions_dir: Path | None = None
        self._self_check = ""
        self._version = 0
        self.denials: deque[Denial] = deque(maxlen=200)
        self._unreported: deque[Denial] = deque(maxlen=200)
        self._session_lines: dict[str, deque[bytes]] = {}
        self._redact_key: bytes | None = None
        self.main_allow: list[str] = []
        self.private_roots = policy.private_roots()
        self.audit_path = self.config_dir / "sandbox" / "audit.jsonl"
        self._broker_pid = 0
        self.main_confined = False
        self._started = time.time()
        self._child_profiles: dict[tuple[str, ...], confine.Profile] = {}
        self._git_write_paths: dict[str, list[str]] = {}
        self._child_write_sets: dict[tuple[tuple[str, ...], tuple[str, ...]], list[str]] = {}
        self._write_protected: dict[str, bool] = {}

    # ---------------------------------------------------------------- startup

    def start_broker(self) -> None:
        policy.freeze_home()
        mine, theirs = socket.socketpair()
        config = {
            "python": sys.executable,
            "python_binary": _running_binary(),
            "floor": policy.floor(self.settings.floor_extra),
            "private_roots": self.private_roots,
            "write_floor": policy.write_floor(self.config_dir),
            "write_never_under": policy.install_paths(),
            # A workflow worker's own bytecode cache, given only to the worker it serves.
            "write_exceptions": [str(self.config_dir / "workflows" / ".pycache")],
        }
        try:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(RUNTIME_DIR / "broker.py"),
                    str(theirs.fileno()),
                    json.dumps(config),
                ],
                pass_fds=[theirs.fileno()],
                stdin=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        finally:
            theirs.close()
        self._control = mine
        self._broker_pid = proc.pid
        reply = self._call({"op": "ping"})
        if not reply.get("ok"):
            raise confine.ConfineError("sandbox broker did not answer")

    def confine_main(self) -> None:
        policy.ensure_user_cache_dirs()
        policy.temp_write_paths()
        self.main_allow = policy.main_allow(self.config_dir, self.settings.main_allow)
        profile = confine.Profile(
            mode="except",
            allow=self.main_allow,
            # A protected path the person added outside the private roots is denied too.
            deny_roots=[
                *self.private_roots,
                *(p for p in policy.floor(self.settings.floor_extra) if not policy.is_private(p)),
            ],
            refer=self.service_paths(),
            no_move=policy.floor(self.settings.floor_extra),
            no_move_literal=policy.floor_ancestors(self.settings.floor_extra),
        )
        if confine.PLATFORM == "linux":
            self.readable_tops = [p for p in confine.linux_allow_except(self.private_roots) if os.path.isdir(p)]
        confine.apply(profile)
        self.main_confined = True  # for good: from here a failure can't fall back to running unconfined
        from chrys.foundation import guard as core_guard

        core_guard.note_confined()
        confine.self_check(policy.home())
        self._self_check = f"passed: {policy.home()} unreadable after confinement"

    # ---------------------------------------------------------------- broker

    def _call(self, message: dict[str, Any], fds: list[int] | None = None) -> dict[str, Any]:
        reply, got = self._call_fds(message, fds)
        for fd in got:
            os.close(fd)
        return reply

    def _call_fds(self, message: dict[str, Any], fds: list[int] | None = None) -> tuple[dict[str, Any], list[int]]:
        with self._control_lock:
            if self._control is None:
                raise confine.ConfineError("sandbox broker is not running")
            try:
                confine.send(self._control, message, fds or [])
                reply, got = confine.recv(self._control)
            except (OSError, ConnectionError) as exc:
                self._broker_lost(str(exc))
                raise confine.ConfineError(f"sandbox broker connection failed: {exc}") from exc
            if reply is None:
                self._broker_lost("broker exited")
                raise confine.ConfineError("sandbox broker exited")
            return reply, got

    def _broker_lost(self, why: str) -> None:
        self._control = None
        if self.status.state == "active":
            self.status.state = "degraded"
        self.status.reasons.append(f"broker lost: {why}")
        self.audit("broker_lost", reason=why)

    def broker_pid(self) -> int:
        return self._broker_pid

    def floor_from_broker(self) -> list[str]:
        return list(self._call({"op": "ping"}).get("floor", []))

    def _spawn_helper(self, paths: list[str], *, writes: list[str]) -> _Helper:
        profile = confine.Profile(mode="only", allow=paths, write=writes)
        reply, fds = self._call_fds({"op": "helper", "profile": json.loads(profile.to_json())})
        if not reply.get("ok") or not fds:
            for fd in fds:
                os.close(fd)
            if reply.get("refused"):
                raise SandboxDenied(paths[0] if paths else "", protected=True, reason=reply.get("error", ""))
            raise confine.ConfineError(reply.get("error", "broker refused to start a file helper"))
        self._version += 1
        self.audit("helper_started", paths=paths, write_paths=writes, version=self._version)
        return _Helper(socket.socket(fileno=fds[0]), frozenset(paths), self._version, frozenset(writes))

    # -------------------------------------------------------------- service

    def register_roots(self, owner: str, roots: list[str] | tuple[str, ...]) -> list[str]:
        """Serve *roots* to iCode's own code; returns the roots refused as protected."""
        accepted, refused = [], []
        for root in roots:
            resolved = confine.real(root)
            if not policy.is_private(resolved):
                continue  # readable directly
            if policy.is_home(resolved) or policy.is_protected(resolved, self.settings.floor_extra):
                refused.append(resolved)
                continue
            accepted.append(resolved)
        with self._state_lock:
            if self._service_roots.get(owner) == tuple(sorted(accepted)):
                return refused
            self._service_roots[owner] = tuple(sorted(accepted))
            self._refresh_service()
        for path in refused:
            self.audit("root_refused", path=path, owner=owner)
            if self.status.state == "active":
                self.status.state = "degraded"
            self.status.reasons.append(f"workspace {path} contains protected directories; it is not served")
        return refused

    def unregister_roots(self, owner: str) -> None:
        with self._state_lock:
            if self._service_roots.pop(owner, None) is not None:
                self._refresh_service()

    def service_paths(self) -> list[str]:
        """What iCode's own code may read through the service helper: served roots and their ancestors' configs."""
        with self._state_lock:
            roots = sorted({p for roots in self._service_roots.values() for p in roots})
        return sorted({*roots, *policy.ancestor_configs(roots)})

    def _refresh_service(self) -> None:
        paths = frozenset(self.service_paths())
        old = self._service_helper
        if old is not None and old.paths == paths:
            return
        narrowing = old is not None and not paths >= old.paths
        if narrowing and old is not None:
            old.retire()
        self._service_helper = None  # started lazily on first use
        if not narrowing and old is not None:
            old.retire()

    def _service(self) -> _Helper:
        with self._state_lock:
            helper = self._service_helper
            if helper is None or helper.closed:
                paths = self.service_paths()
                if not paths:
                    raise SandboxDenied("", reason="sandbox: no workspace is being served")
                helper = self._spawn_helper(paths, writes=self._writable_only(paths))
                self._service_helper = helper
            return helper

    def service_covers(self, path: str) -> bool:
        return any(confine.is_within(path, root) for root in self.service_paths())

    # --------------------------------------------------------------- scopes

    def hold_scope(self, key: str) -> None:
        """Count one more owner (an approval middleware) of scope *key*."""
        with self._state_lock:
            self._holders[key] = self._holders.get(key, 0) + 1

    def release_scope(self, key: str) -> None:
        """Drop one owner of *key*; the last one stops its helper and serving its roots.

        Harmless if an owner remains unnoticed: the next scoped call binds the
        scope again and starts a helper on demand.
        """
        with self._state_lock:
            remaining = self._holders.get(key, 0) - 1
            if remaining > 0:
                self._holders[key] = remaining
                return
            self._holders.pop(key, None)
            self._scopes.pop(key, None)
            helper = self._scope_helpers.pop(key, None)
        if helper is not None:
            helper.retire()
        self.unregister_roots(f"scope:{key}")
        self.audit("scope_released", scope=key)

    def bind_scope(self, scope: policy.Scope) -> None:
        with self._state_lock:
            self._scopes[scope.key] = scope
        self.register_roots(f"scope:{scope.key}", list(scope.roots))
        self._refresh_scope(scope.key)

    def access_set(self, scope: policy.Scope) -> policy.AccessSet:
        roots = [
            confine.real(r) for r in scope.roots if not policy.is_protected(confine.real(r), self.settings.floor_extra)
        ]
        allowed = lambda g: not policy.is_protected(g, self.settings.floor_extra)  # noqa: E731
        return policy.AccessSet(
            roots=[r for r in roots if not policy.is_home(r)],
            grants=[g for g in self.grants.paths(scope.key, scope.workdir_root, "read") if allowed(g)],
            write_grants=[g for g in self.grants.paths(scope.key, scope.workdir_root, "write") if allowed(g)],
        )

    def _writable_only(self, paths: list[str]) -> list[str]:
        """*paths* less what can't be made writable (a workspace may hold or be such a folder)."""
        kept = []
        for path in paths:
            if path not in self._write_protected:
                self._write_protected[path] = policy.is_write_protected(
                    path, self.config_dir, self.settings.floor_extra
                )
            if not self._write_protected[path]:
                kept.append(path)
        return kept

    def _git_dirs(self, roots: list[str]) -> list[str]:
        """Git folders outside *roots*; each root's are decided once, so a later ``.git`` changes nothing."""
        found: list[str] = []
        for root in roots:
            cached = self._git_write_paths.get(root)
            if cached is None:
                named = policy.git_write_paths(root, self._read_once)
                cached = self._git_write_paths[root] = [p for p in named if self._git_dir_usable(root, p)]
            found += cached
        return found

    def _read_once(self, path: str) -> str:
        """A small file's text through a helper for it alone; empty when it can't be read."""
        try:
            fd = self._open_once(confine.real(path), os.O_RDONLY)
        except OSError, confine.ConfineError, SandboxDenied, HelperGone:
            return ""
        with os.fdopen(fd, encoding="utf-8", errors="replace") as stream:
            return stream.read(65536)

    def _git_dir_usable(self, root: str, git_dir: str) -> bool:
        """A workspace with its own ``.git`` always; the ``.git`` above a subfolder only if opened.

        For a workspace that is a subfolder of a repository, git also needs the
        repository's root. Opening that to reads widens the boundary to the whole
        repository, so it is the person's call (``sandbox.files.commands.allow_paths``).
        """
        if os.path.lexists(os.path.join(confine.real(root), ".git")):
            return True
        repo = os.path.dirname(git_dir)
        return any(confine.is_within(repo, confine.real(p)) for p in self.settings.shell_allow)

    def write_set(self, scope: policy.Scope) -> list[str]:
        """What a command in *scope* may change, and so what a file tool may too."""
        return self._child_writes(self.access_set(scope), launch=False)

    def _child_writes(self, access: policy.AccessSet, *, launch: bool = True) -> list[str]:
        roots = (*access.writable(), *self._git_dirs(access.roots))
        extra = (*self.settings.shell_write, *(launch_writes.get() if launch else ()))
        # Checking a path against the write floor stats dozens of others; commands run often.
        cached = self._child_write_sets.get((roots, extra))
        if cached is None:
            cached = policy.child_write(self.config_dir, roots, extra, self.settings.floor_extra)
            if len(self._child_write_sets) > 64:
                self._child_write_sets.clear()
            self._child_write_sets[(roots, extra)] = cached
        return cached

    def _served_access(self, cwd: str | None) -> policy.AccessSet:
        """A command iCode starts outside any tool call may change the workspace it runs in, no other."""
        with self._state_lock:
            served = {p for roots in self._service_roots.values() for p in roots}
        return policy.AccessSet(roots=sorted(r for r in served if cwd and confine.is_within(confine.real(cwd), r)))

    def _refresh_scope(self, key: str) -> None:
        with self._state_lock:
            scope = self._scopes.get(key)
            old = self._scope_helpers.get(key)
            if scope is None:
                if old is not None:
                    old.retire()
                    self._scope_helpers.pop(key, None)
                return
            writes = frozenset(self.write_set(scope))
            paths = frozenset({*(p for p in self.access_set(scope).paths() if policy.is_private(p)), *writes})
            if old is not None and old.paths == paths and old.writes == writes:
                return
            if old is not None:
                # Narrowing must not leave a window: retire before anything else.
                old.retire()
            self._scope_helpers.pop(key, None)

    def _scope_helper(self, scope: policy.Scope) -> _Helper | None:
        with self._state_lock:
            helper = self._scope_helpers.get(scope.key)
            if helper is not None and not helper.closed:
                return helper
            paths = sorted(p for p in self.access_set(scope).paths() if policy.is_private(p))
            # All a file tool may change goes through here, in the private roots or not:
            # the helper's kernel boundary, not a check made earlier, decides where it lands.
            writes = self.write_set(scope)
            helper = self._spawn_helper(sorted({*paths, *writes}), writes=writes)
            self._scope_helpers[scope.key] = helper
            return helper

    def scope_covers(self, scope: policy.Scope, path: str) -> bool:
        return self.access_set(scope).covers(path)

    # --------------------------------------------------------------- grants

    def grant(
        self, scope: policy.Scope, kind: GrantKind, path: str, *, source: str = "user", access: GrantAccess = "read"
    ) -> Grant:
        resolved = confine.real(path)
        refused = policy.is_protected(resolved, self.settings.floor_extra) or policy.is_home(resolved)
        if access == "write":
            # Across sessions a write grant would outlive what it was given for.
            refused = (
                refused
                or kind == "workdir"
                or resolved in self.private_roots
                or policy.is_write_protected(resolved, self.config_dir, self.settings.floor_extra, holding_install=True)
            )
        if refused:
            self.audit("grant_refused", scope=scope.key, path=resolved, kind=kind, access=access)
            raise SandboxDenied(resolved, protected=True)
        grant = self.grants.add(scope.key, kind, resolved, scope.workdir_root, source, access)
        self.audit("grant", scope=scope.key, path=resolved, kind=kind, id=grant.id, access=access)
        if kind != "once":
            self._refresh_scope(scope.key)
        return grant

    def revoke(self, grant_id: str) -> Grant | None:
        grant = self.grants.revoke(grant_id)
        if grant is not None:
            self.audit("revoke", scope=grant.scope_key, path=grant.path, kind=grant.kind, id=grant.id)
            self._refresh_scope(grant.scope_key)
        return grant

    def end_turn(self, scope_key: str) -> None:
        ended = self.grants.end_turn(scope_key)
        if ended:
            self.audit("turn_end", scope=scope_key, revoked=[g.path for g in ended])
            self._refresh_scope(scope_key)

    # ------------------------------------------------------------------ IO

    def _with_retry(self, pick, message: dict[str, Any]) -> int:
        for _attempt in range(3):
            helper = pick()
            if helper is None:
                raise PermissionError(
                    errno_mod.EACCES, "sandbox: nothing is readable in this scope", message.get("path")
                )
            try:
                return helper.request(message)
            except HelperGone:
                continue
        raise confine.ConfineError("file helper keeps failing")

    def open_service(self, path: str, flags: int, mode: int = 0o666) -> int:
        return self._with_retry(self._service, {"op": "open", "path": path, "flags": flags, "mode": mode})

    def opendir_service(self, path: str) -> int:
        return self._with_retry(self._service, {"op": "list", "path": path})

    def open_scoped(self, scope: policy.Scope, path: str, flags: int, mode: int = 0o666, *, tool: str = "") -> int:
        """Open *path* for model-directed work in *scope* (kernel-checked)."""
        resolved = confine.real(path)
        if flags & _O_DIRECTORY and self._on_way_to_config(resolved):
            # iCode's own secure path walk retries from a shallower folder; not a refusal of anything.
            raise SandboxDenied(resolved)
        if policy.is_protected(resolved, self.settings.floor_extra):
            self.record_denial(resolved, scope.key, tool, "protected")
            raise SandboxDenied(resolved, protected=True)
        once = self.grants.take_once(scope.key, resolved)
        if once is not None:
            fd = self._open_once(resolved, flags)
            self.audit("once_used", scope=scope.key, path=resolved)
            return fd
        try:
            return self._with_retry(
                lambda: self._scope_helper(scope), {"op": "open", "path": resolved, "flags": flags, "mode": mode}
            )
        except PermissionError as exc:
            self.record_denial(resolved, scope.key, tool, "denied", access="write" if flags & _WRITE_FLAGS else "read")
            raise SandboxDenied(resolved, writing=bool(flags & _WRITE_FLAGS)) from exc

    def change_scoped(self, scope: policy.Scope, message: dict[str, Any]) -> None:
        """Make a file tool's change through the scope's helper, so the kernel decides where it lands."""
        try:
            self._with_retry(lambda: self._scope_helper(scope), message)
        except PermissionError as exc:
            self.record_denial(str(message["path"]), scope.key, "", "denied", access="write")
            raise SandboxDenied(str(message["path"]), writing=True) from exc

    def _on_way_to_config(self, path: str) -> bool:
        return path == str(self.config_dir) or confine.is_within(str(self.config_dir), path)

    def opendir_scoped(self, scope: policy.Scope, path: str, *, tool: str = "") -> int:
        resolved = confine.real(path)
        if self._on_way_to_config(resolved):
            raise SandboxDenied(resolved)
        if policy.is_protected(resolved, self.settings.floor_extra):
            self.record_denial(resolved, scope.key, tool, "protected")
            raise SandboxDenied(resolved, protected=True)
        try:
            return self._with_retry(lambda: self._scope_helper(scope), {"op": "list", "path": resolved})
        except PermissionError as exc:
            self.record_denial(resolved, scope.key, tool, "denied")
            raise SandboxDenied(resolved) from exc

    def _open_once(self, path: str, flags: int) -> int:
        # A helper that dies before it is ready is replaced, as for a scope's helper (``_with_retry``).
        for _attempt in range(3):
            helper = self._spawn_helper([path], writes=[])
            try:
                return helper.request({"op": "open", "path": path, "flags": flags & ~(os.O_WRONLY | os.O_RDWR)})
            except HelperGone:
                continue
            finally:
                helper.retire()
        raise confine.ConfineError("file helper keeps failing")

    def open_user(self, path: str) -> int:
        """Open a file the *user* picked (mention, drop, paste): one-shot, floor still applies."""
        resolved = confine.real(path)
        if policy.is_protected(resolved, self.settings.floor_extra):
            raise SandboxDenied(resolved, protected=True)
        self.audit("user_open", path=resolved)
        return self._open_once(resolved, os.O_RDONLY)

    # -------------------------------------------------------------- commands

    def child_profile(self, scope: policy.Scope | None, cwd: str | None = None) -> confine.Profile:
        roots = self.service_paths() if scope is None else self.access_set(scope).paths()
        extra = [p for p in launch_reads.get() if not policy.is_protected(p, self.settings.floor_extra)]
        writable_extra = [*self.settings.shell_write, *launch_writes.get()]
        access = self._served_access(cwd) if scope is None else self.access_set(scope)
        git_dirs = self._git_dirs(access.roots)
        roots = [*roots, *git_dirs, *(p for p in [*extra, *writable_extra] if not policy.is_home(p))]
        writes = self._child_writes(access)
        key = (*roots, "\0", *writes)
        cached = self._child_profiles.get(key)
        if cached is None:
            # Computing the allow list stats a few dozen paths; commands run often.
            allow = policy.child_allow(self.config_dir, roots, self.settings.shell_allow)
            cached = confine.Profile(
                mode="except", allow=allow, deny_roots=self.private_roots, restrict_writes=True, write_allow=writes
            )
            if len(self._child_profiles) > 64:
                self._child_profiles.clear()
            self._child_profiles[key] = cached
        return cached

    def reserve_slot(
        self, scope: policy.Scope | None, *, unconfined: bool = False, cwd: str | None = None
    ) -> tuple[socket.socket, int]:
        """Reserve a broker slot for one command; returns the stub's end of its socket.

        *unconfined* asks for one of the broker's fixed unconfined programs; the
        broker checks the program itself when the stub names it.
        """
        mine, theirs = socket.socketpair()
        try:
            if unconfined:
                message: dict[str, Any] = {"op": "slot", "unconfined": True}
            else:
                message = {"op": "slot", "profile": json.loads(self.child_profile(scope, cwd).to_json())}
            reply = self._call(message, [mine.fileno()])
        finally:
            mine.close()
        if not reply.get("ok"):
            theirs.close()
            raise confine.ConfineError(reply.get("error", "broker refused the command"))
        return theirs, int(reply.get("slot", 0))

    def slot_pid(self, slot_id: int) -> int:
        """The pid of the command a slot started (its session id too), 0 if not started yet."""
        try:
            return int(self._call({"op": "slot_pid", "slot": slot_id}).get("pid", 0))
        except confine.ConfineError:
            return 0

    # ------------------------------------------------------------- reporting

    def record_denial(self, path: str, scope: str, tool: str, outcome: str, access: str = "read") -> None:
        denial = Denial(time.time(), path, scope, tool, outcome, access)
        self.denials.append(denial)
        self._unreported.append(denial)
        self.audit("deny", path=path, scope=scope, tool=tool, outcome=outcome, access=access)

    def take_unreported(self, scope: str) -> list[Denial]:
        """Denials of *scope* not yet passed on to the session's trajectory and frontends."""
        with self._state_lock:
            taken = [d for d in self._unreported if d.scope == scope]
            kept = [d for d in self._unreported if d.scope != scope]
            self._unreported.clear()
            self._unreported.extend(kept)
        return taken

    def logged_path(self, path: str) -> str:
        """*path* as logs may hold it: a keyed digest under ``sandbox.files.audit.redact_paths``.

        Keyed, because an unkeyed digest of a path can be confirmed by guessing it.
        The same path keeps the same digest, so a log can still be followed.
        """
        if not self.settings.audit_redact_paths:
            return path
        digest = hmac.new(self._audit_key(), os.fsencode(path), hashlib.sha256).hexdigest()
        return f"hmac:{digest[:16]}"

    def _audit_key(self) -> bytes:
        if self._redact_key is None:
            target = self.audit_path.with_name("audit.key")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = _raw_os_open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                fd = _raw_os_open(target, os.O_RDONLY)
                try:
                    self._redact_key = os.read(fd, 32)
                finally:
                    os.close(fd)
            else:
                key = secrets.token_bytes(32)
                try:
                    os.write(fd, key)
                finally:
                    os.close(fd)
                self._redact_key = key
        return self._redact_key

    def _logged_field(self, name: str, value: Any) -> Any:
        if name not in _AUDIT_PATH_FIELDS or not self.settings.audit_redact_paths:
            return value
        if isinstance(value, str):
            return self.logged_path(value)
        if isinstance(value, (list, tuple)):
            return [self.logged_path(item) if isinstance(item, str) else item for item in value]
        return value

    def audit(self, event: str, **fields: Any) -> None:
        """Append an event to the process-wide log, and to its session's own log when it names one.

        Both files are owner-only and hold paths, as the session transcripts do.
        """
        logged = {name: self._logged_field(name, value) for name, value in fields.items()}
        record = {"t": round(time.time(), 3), "pid": os.getpid(), "version": self._version, "event": event, **logged}
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode()
        self._append_line(self.audit_path, line)
        scope = fields.get("scope")
        if isinstance(scope, str) and scope:
            self._log_to_session(scope, line)

    @staticmethod
    def _append_line(target: Path, line: bytes) -> None:
        with contextlib.suppress(OSError):
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = _raw_os_open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)

    def _log_to_session(self, scope: str, line: bytes) -> None:
        """Write to the session's own log; a session not yet saved has no folder, so its lines wait."""
        with self._state_lock:
            pending = self._session_lines.setdefault(scope, deque(maxlen=200))
            pending.append(line)
            target = self._session_log(scope)
            if target is None:
                return
            lines = b"".join(pending)
            self._session_lines.pop(scope, None)
        self._append_line(target, lines)

    def _session_log(self, scope: str) -> Path | None:
        """``<sessions>/<short id>/sandbox_events.jsonl`` when that session folder exists."""
        if self._sessions_dir is None:
            try:
                from chrys.foundation.config.settings import resolve_sessions_dir

                self._sessions_dir = resolve_sessions_dir(self.config_dir, create=False)
            except Exception:
                return None
        if not scope.replace("-", "").replace("_", "").isalnum():
            return None
        folder = self._sessions_dir / session_short_id(scope)
        return folder / SESSION_EVENTS_FILE if folder.is_dir() else None

    def snapshot(self) -> dict[str, Any]:
        with self._state_lock:
            scopes = {
                key: {
                    "roots": list(scope.roots),
                    "workdir_root": scope.workdir_root,
                    "access": self.access_set(scope).paths(),
                    "grants": [g.__dict__ for g in self.grants.entries(key)],
                }
                for key, scope in self._scopes.items()
            }
        return {
            "self_check": self._self_check,
            "state": self.status.label(),
            "mechanism": self.status.mechanism,
            "reasons": list(self.status.reasons),
            "broker_pid": self._broker_pid,
            "private_roots": self.private_roots,
            "main_allow": self.main_allow,
            "service_paths": self.service_paths(),
            "floor": policy.floor(self.settings.floor_extra),
            "scopes": scopes,
            "denials": [d.__dict__ for d in list(self.denials)[-20:]],
        }


@dataclass
class SandboxSettings:
    """The sandbox's own settings, read before the settings system loads."""

    enabled: bool = False
    on_unavailable: str = "refuse"  # refuse | warn
    main_allow: list[str] = field(default_factory=list)
    shell_allow: list[str] = field(default_factory=list)
    shell_write: list[str] = field(default_factory=list)
    floor_extra: list[str] = field(default_factory=list)
    source: str = "default"
    audit_redact_paths: bool = False
    workdir_off_ignored: bool = False
    """A working directory's settings asked to switch the sandbox off; refused, and said so at startup."""


_runtime: Runtime | None = None
_status = Status()


def runtime() -> Runtime | None:
    """The live runtime, or ``None`` when this process is not sandboxed."""
    return _runtime


def status() -> Status:
    return _runtime.status if _runtime is not None else _status


def status_line() -> str | None:
    """One line on the sandbox for headless output, or ``None`` when it was not requested."""
    st = status()
    if not st.requested:
        return None
    line = f"Sandbox: {st.label()}" + (f" ({st.mechanism})" if st.mechanism else "")
    if st.reasons:
        line += " — " + "; ".join(st.reasons[-2:])
    return line


def status_report() -> dict[str, Any]:
    """The sandbox status as data (ACP ``initialize`` metadata, JSON output)."""
    st = status()
    return {"state": st.label(), "requested": st.requested, "mechanism": st.mechanism, "reasons": list(st.reasons)}


def _set_runtime(value: Runtime | None, fallback: Status | None = None) -> None:
    global _runtime, _status
    _runtime = value
    if fallback is not None:
        _status = fallback


def walk_start(directory: str) -> str | None:
    """Deepest directory containing *directory* that this process may open, if any.

    For code that walks a path one component at a time from ``/``: inside the
    sandbox the private roots themselves can't be opened, so such a walk has
    to start below them.
    """
    rt = _runtime
    if rt is None:
        return None
    target = confine.real(directory)
    readable = [*rt.main_allow, *rt.service_paths(), *_readable_tops(rt)]
    candidates = [p for p in readable if confine.is_within(target, p) and os.path.isdir(p)]
    return max(candidates, key=len) if candidates else None


def _readable_tops(rt: Runtime) -> list[str]:
    """Linux: the readable children of ``/`` (Landlock can't let ``/`` itself be read without all below it).

    Computed before confinement (``/`` can't be listed afterwards).
    """
    return rt.readable_tops


def configured_program_paths(command: str, args: tuple[str, ...] | list[str] = (), cwd: str | None = None) -> list[str]:
    """The files a configured program needs: its executable's folder, the files its arguments name, and the folder it starts in."""
    import shutil

    found: list[str] = []
    if cwd and os.path.isdir(cwd):
        # The person chose where it runs (an MCP server's or ACP agent's ``cwd``).
        found.append(confine.real(cwd))
    resolved = command if os.sep in command else shutil.which(command)
    if resolved:
        found.append(os.path.dirname(confine.real(resolved)))
    for arg in args:
        candidate = arg if os.path.isabs(arg) or cwd is None else os.path.join(cwd, arg)
        if os.path.exists(candidate):
            target = confine.real(candidate)
            found.append(target if os.path.isdir(target) else os.path.dirname(target))
    return found


@contextlib.contextmanager
def controlling_terminal() -> Generator[None]:
    """The program started in this block takes its stdin terminal as controlling terminal.

    Outside the sandbox the caller's ``preexec_fn`` does that in the child;
    under it the child iCode holds is a stub, so the real program — a session
    leader in the broker — must take the terminal instead, and the stub must not.
    """
    token = wants_controlling_tty.set(True)
    try:
        yield
    finally:
        wants_controlling_tty.reset(token)


@contextlib.contextmanager
def launching_configured(paths: list[str], *, writes: list[str] | tuple[str, ...] = ()) -> Generator[None]:
    """Commands started in this block may also read *paths* and change *writes* (the floors still apply)."""
    token = launch_reads.set(tuple(paths))
    write_token = launch_writes.set(tuple(writes))
    try:
        yield
    finally:
        launch_writes.reset(write_token)
        launch_reads.reset(token)


@contextlib.contextmanager
def user_reads() -> Generator[None]:
    """Reads in this block are of files the person picked themselves (attachments)."""
    token = user_reading.set(True)
    try:
        yield
    finally:
        user_reading.reset(token)


@contextlib.contextmanager
def scoped(scope: policy.Scope | None) -> Generator[None]:
    """Run model-directed work under *scope* (binds it to the runtime first)."""
    rt = _runtime
    if rt is None or scope is None:
        yield
        return
    rt.bind_scope(scope)
    token = current_scope.set(scope)
    try:
        yield
    finally:
        current_scope.reset(token)
