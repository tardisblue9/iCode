# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Process-wide hooks that keep iCode working inside its own sandbox.

The main process can't read the private roots (home, volumes) beyond a small
allow list. Two hooks bridge the gap, both only active while a runtime is live:

**Reads** (``open``, ``io.open``, ``os.open``, ``os.listdir``, ``os.scandir``):

- In a *scope* (model-directed work: a tool call), a path inside the private
  roots is never opened directly — except iCode's own install and its session
  files — but through the scope's file helper, so the kernel checks it against
  that session's workspace and grants.
- Outside a scope, a direct read is tried first; if the kernel refuses it and
  the path lies in a workspace this process serves, the service helper opens it.

**Commands** (``subprocess.Popen``, which ``asyncio`` subprocesses use too):
every child is started as a stub whose real command the broker runs under the
current scope's profile (see ``runtime/stub.py``). A few fixed system utilities
that read nothing private run directly.
"""

from __future__ import annotations

import builtins
import contextlib
import contextvars
import errno as errno_mod
import io
import os
import shutil
import stat as stat_mod
import subprocess
import sys
from typing import Any, cast

from icode_sandbox import client as sandbox_client
from icode_sandbox import policy
from icode_sandbox.runtime import confine

_original_open = builtins.open
_original_io_open = io.open
_original_os_open = os.open
_original_listdir = os.listdir
_original_scandir = os.scandir
_original_execute_child = subprocess.Popen._execute_child  # type: ignore[attr-defined]
_original_getcwd = os.getcwd
_original_getcwdb = os.getcwdb
_original_chdir = os.chdir
_original_mkdir = os.mkdir
_original_unlink = os.unlink
_original_remove = os.remove
_original_rmdir = os.rmdir
_original_replace = os.replace
_original_rename = os.rename
_original_symlink = os.symlink
_original_link = os.link
_original_truncate = os.truncate
_original_mkfifo = getattr(os, "mkfifo", None)
_original_mknod = getattr(os, "mknod", None)
_original_chmod = os.chmod
_original_chown = getattr(os, "chown", None)
_original_utime = os.utime
_original_system = os.system
_original_posix_spawn = getattr(os, "posix_spawn", None)
_original_posix_spawnp = getattr(os, "posix_spawnp", None)
# Set while this module starts a stub itself: subprocess may use posix_spawn underneath, and that start is confined.
_starting_stub: contextvars.ContextVar[bool] = contextvars.ContextVar("sandbox_starting_stub", default=False)
_installed = False
# Seatbelt refuses ``getcwd`` when the working directory lies in a denied
# region (the workspace usually does), so the process tracks it itself: it is
# recorded before confinement and kept current by the ``chdir`` hook.
_cwd: list[str] = []

# Programs a sandboxed process can't exec (macOS refuses setuid binaries in a
# sandbox) that read no files: the broker runs them unconfined, after checking
# the resolved program against its own copy of this list.
UNCONFINED_COMMANDS = frozenset({"/bin/ps"})

_MODE_FLAGS = {
    "r": os.O_RDONLY,
    "r+": os.O_RDWR,
    "w": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
    "w+": os.O_RDWR | os.O_CREAT | os.O_TRUNC,
    "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
    "a+": os.O_RDWR | os.O_CREAT | os.O_APPEND,
    "x": os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    "x+": os.O_RDWR | os.O_CREAT | os.O_EXCL,
}


def _flags_for(mode: str) -> int:
    core = "".join(c for c in mode if c in "rwax+")
    return _MODE_FLAGS.get(core, os.O_RDONLY)


def _resolve(file: Any) -> str | None:
    if isinstance(file, int):
        return None
    try:
        raw = os.fsdecode(os.fspath(file))
    except TypeError:
        return None
    if not raw:
        return None
    return confine.real(raw)


def _internal_paths(rt: sandbox_client.Runtime) -> list[str]:
    """iCode's own files that stay directly readable inside a scope.

    The install (packages, interpreter) and the session/sandbox state iCode
    writes itself — not the rest of the config directory, which holds API keys.
    """
    config = str(rt.config_dir)
    internal = [p for p in rt.main_allow if not confine.overlaps(p, config)]
    internal += [os.path.join(config, "sessions"), os.path.join(config, "sandbox")]
    return internal


_WRITE_BITS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _route(path: str) -> tuple[str, policy.Scope | None]:
    """How to open *path*: ``direct``, ``scope`` (via its helper) or ``service-fallback``."""
    rt = sandbox_client.runtime()
    if rt is None or not policy.is_private(path):
        return "direct", None
    scope = sandbox_client.current_scope.get()
    if scope is not None:
        if any(confine.is_within(path, p) for p in _internal_paths(rt)):
            return "direct", None
        return "scope", scope
    return "service-fallback", None


def _own_state(rt: sandbox_client.Runtime) -> list[str]:
    """The folders iCode itself writes to during a tool call: the session and sandbox state."""
    config = str(rt.config_dir)
    return [os.path.join(config, "sessions"), os.path.join(config, "sandbox")]


def _lexical(path: Any) -> str | None:
    """*path* as named, made absolute without following any link."""
    if isinstance(path, int):
        return None
    name = os.fsdecode(os.fspath(path))
    if os.path.isabs(name):
        return os.path.normpath(name)
    try:
        return os.path.normpath(os.path.join(_patched_getcwd(), name))
    except OSError:  # the working directory is gone: the name says nothing about where it leads
        return None


def _writes_own_state(rt: sandbox_client.Runtime, resolved: str, given: str | None) -> bool:
    """Whether a change during a tool call is iCode writing its own state, so it may skip the helper.

    Both the name iCode used and where it leads must be in that state: a name in
    the workspace that leads there through a link is the model's write, not iCode's.
    Everything else iCode may read (git config, its install) is never written this way.
    """
    state = _own_state(rt)
    return (
        given is not None
        and any(confine.is_within(given, p) for p in state)
        and any(confine.is_within(resolved, p) for p in state)
    )


def _writing_for_a_tool(
    rt: sandbox_client.Runtime, path: str, flags: int, given: str | None = None
) -> policy.Scope | None:
    """The tool call's scope when this opens *path* to change it, unless iCode is writing its own state."""
    scope = sandbox_client.current_scope.get()
    if scope is None or not flags & _WRITE_BITS or _writes_own_state(rt, path, given):
        return None
    return scope


def _helper_fd(path: str, flags: int, mode: int = 0o666, given: str | None = None) -> int | None:
    """An fd for *path* (named *given*) through the right helper, or ``None`` to open directly."""
    route, scope = _route(path)
    rt = sandbox_client.runtime()
    if rt is None:
        return None
    if route == "direct":
        scope = _writing_for_a_tool(rt, path, flags, given)
        return None if scope is None else rt.open_scoped(scope, path, flags, mode)
    if route == "scope" and scope is not None:
        return rt.open_scoped(scope, path, flags, mode)
    return None


def _fallback_fd(path: str, flags: int, mode: int = 0o666) -> int | None:
    rt = sandbox_client.runtime()
    if rt is None or not policy.is_private(path):
        return None
    if sandbox_client.user_reading.get() and not flags & (os.O_WRONLY | os.O_RDWR):
        return rt.open_user(path)
    scope = sandbox_client.current_scope.get()
    if scope is not None:
        return rt.open_scoped(scope, path, flags, mode)
    if not rt.service_covers(path):
        return None
    return rt.open_service(path, flags, mode)


def _wrap_fd(fd: int, path: str, mode: str, buffering: int, encoding, errors, newline) -> Any:
    try:
        stream = _original_io_open(fd, mode, buffering, encoding, errors, newline, closefd=True)
    except BaseException:
        os.close(fd)
        raise
    raw = getattr(getattr(stream, "buffer", stream), "raw", stream)
    with contextlib.suppress(AttributeError, TypeError):
        raw.name = path
    return stream


def _patched_open(file, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    path = None if opener is not None or not closefd else _resolve(file)
    if path is not None:
        fd = _helper_fd(path, _flags_for(mode), given=_lexical(file))
        if fd is not None:
            return _wrap_fd(fd, path, mode, buffering, encoding, errors, newline)
    try:
        return _original_io_open(file, mode, buffering, encoding, errors, newline, closefd, opener)
    except PermissionError:
        if path is None:
            raise
        fd = _fallback_fd(path, _flags_for(mode))
        if fd is None:
            raise
        return _wrap_fd(fd, path, mode, buffering, encoding, errors, newline)


def _dirfd_path(dir_fd: int) -> str | None:
    """The path an open directory fd refers to (``F_GETPATH`` / ``/proc``)."""
    try:
        if sys.platform == "darwin":
            import fcntl

            raw = fcntl.fcntl(dir_fd, 50, b"\0" * 1024)  # F_GETPATH
            return os.fsdecode(raw.split(b"\0", 1)[0]) or None
        return os.readlink(f"/proc/self/fd/{dir_fd}")
    except OSError:
        return None


def _patched_os_open(path, flags, mode=0o777, *, dir_fd=None):
    if dir_fd is not None and isinstance(path, (str, bytes)) and os.path.isabs(os.fsdecode(path)):
        dir_fd = None  # the kernel ignores dir_fd for an absolute path: so does the check
    resolved = None
    if dir_fd is None:
        resolved = _resolve(path)
    elif isinstance(path, (str, bytes)):
        parent = _dirfd_path(dir_fd)
        resolved = confine.real(os.path.join(parent, os.fsdecode(path))) if parent else None
        if parent is None:
            _refuse_unplaceable_write(flags, os.fsdecode(path))
    if resolved is not None and dir_fd is None:
        _keep_flag_meaning(_lexical(path), flags)
        fd = _helper_fd(resolved, flags, mode, given=_lexical(path))
        if fd is not None:
            return fd
    elif resolved is not None:
        # Relative to a folder already open: that folder, whatever its name says now, is where this lands.
        rt = sandbox_client.runtime()
        scope = None if rt is None else _writing_for_a_tool(rt, resolved, flags, given=resolved)
        if (
            rt is not None
            and scope is not None
            and not any(confine.is_within(resolved, p) for p in rt.write_set(scope))
        ):
            rt.record_denial(resolved, scope.key, "", "denied", access="write")
            raise sandbox_client.SandboxDenied(resolved, writing=True)
    try:
        return _original_os_open(path, flags, mode, dir_fd=dir_fd)
    except PermissionError:
        if resolved is None:
            raise
        fd = _fallback_fd(resolved, flags, mode)
        if fd is None:
            raise
        return fd


def _keep_flag_meaning(given: str | None, flags: int) -> None:
    """The helper opens the resolved path: refuse here what the flags would have refused on the name itself."""
    if given is None:
        return
    if flags & getattr(os, "O_NOFOLLOW", 0) and os.path.islink(given):
        raise OSError(errno_mod.ELOOP, os.strerror(errno_mod.ELOOP), given)
    if flags & os.O_CREAT and flags & os.O_EXCL and os.path.lexists(given):
        raise FileExistsError(errno_mod.EEXIST, os.strerror(errno_mod.EEXIST), given)


def _refuse_unplaceable_write(flags: int, name: str) -> None:
    """A tool's write relative to a folder whose path can't be told: nothing says it lands inside, so it doesn't."""
    rt = sandbox_client.runtime()
    scope = sandbox_client.current_scope.get()
    if rt is not None and scope is not None and flags & _WRITE_BITS:
        rt.record_denial(name, scope.key, "", "denied", access="write")
        raise sandbox_client.SandboxDenied(name, writing=True)


def _refuse_change_outside(path: Any, *, dir_fd: int | None = None, follow: bool = True) -> None:
    """In a tool call, refuse a change (a link, a size, a mode, times) whose target is outside the write set.

    These have no file-helper operation: the write set is checked here, in
    this process. An open descriptor (an int) was checked when it was opened.
    """
    rt = sandbox_client.runtime()
    scope = sandbox_client.current_scope.get()
    if rt is None or scope is None or isinstance(path, int):
        return
    name = os.fsdecode(os.fspath(path))
    if dir_fd is not None and not os.path.isabs(name):
        parent = _dirfd_path(dir_fd)
        if parent is None:
            _refuse_unplaceable_write(_WRITE_BITS, name)
            return
        name = os.path.join(parent, name)
    named = _named(name)
    if named is None:
        return
    target = confine.real(named) if follow else named
    if _writes_own_state(rt, target, _lexical(name)):
        return
    if not any(confine.is_within(target, root) for root in rt.write_set(scope)):
        rt.record_denial(target, scope.key, "", "denied", access="write")
        raise sandbox_client.SandboxDenied(target, writing=True)


def _patched_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
    _refuse_change_outside(dst, dir_fd=dst_dir_fd, follow=False)
    return _original_link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, follow_symlinks=follow_symlinks)


def _patched_truncate(path, length):
    _refuse_change_outside(path)
    return _original_truncate(path, length)


def _patched_mkfifo(path, mode=0o666, *, dir_fd=None):
    _refuse_change_outside(path, dir_fd=dir_fd, follow=False)
    return cast(Any, _original_mkfifo)(path, mode, dir_fd=dir_fd)


def _patched_mknod(path, mode=0o600, device=0, *, dir_fd=None):
    _refuse_change_outside(path, dir_fd=dir_fd, follow=False)
    return cast(Any, _original_mknod)(path, mode, device, dir_fd=dir_fd)


def _patched_chmod(path, mode, *, dir_fd=None, follow_symlinks=True):
    _refuse_change_outside(path, dir_fd=dir_fd, follow=follow_symlinks)
    return _original_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)


def _patched_chown(path, uid, gid, *, dir_fd=None, follow_symlinks=True):
    _refuse_change_outside(path, dir_fd=dir_fd, follow=follow_symlinks)
    return cast(Any, _original_chown)(path, uid, gid, dir_fd=dir_fd, follow_symlinks=follow_symlinks)


def _patched_utime(path, *args, dir_fd=None, follow_symlinks=True, **kwargs):
    _refuse_change_outside(path, dir_fd=dir_fd, follow=follow_symlinks)
    return _original_utime(path, *args, dir_fd=dir_fd, follow_symlinks=follow_symlinks, **kwargs)


def _patched_system(command):
    """In a tool call, a shell command goes through ``subprocess``, so it starts confined like any command."""
    if sandbox_client.current_scope.get() is None or sandbox_client.runtime() is None:
        return _original_system(command)
    code = subprocess.call(command, shell=True)  # noqa: S602 — os.system's own contract
    return (-code) & 0x7F if code < 0 else (code & 0xFF) << 8  # a wait status, as os.system returns


def _guarded_spawn(original: Any) -> Any:
    """``os.posix_spawn[p]`` in a tool call: refused, since what it starts would bypass the broker.

    A tool's programs start through ``subprocess``, which this module hands to
    the broker, confined; only that path may reach ``posix_spawn`` underneath.
    """

    def spawn(*args: Any, **kwargs: Any) -> Any:
        if (
            not _starting_stub.get()
            and sandbox_client.runtime() is not None
            and sandbox_client.current_scope.get() is not None
        ):
            raise PermissionError(
                errno_mod.EPERM,
                "sandbox: start programs with subprocess in a tool call; posix_spawn would run unconfined",
            )
        return original(*args, **kwargs)

    return spawn


def _tool_change_scope(*paths: Any) -> tuple[sandbox_client.Runtime, policy.Scope] | None:
    """Runtime and scope when a tool call is changing names, unless iCode is changing its own state."""
    rt = sandbox_client.runtime()
    scope = sandbox_client.current_scope.get()
    if rt is None or scope is None:
        return None
    for path in paths:
        named = _named(path)
        if named is not None and not _writes_own_state(rt, named, _lexical(path)):
            return rt, scope
    return None


def _named(path: Any) -> str | None:
    """*path* with its folder resolved and its own name kept: changing a link's name doesn't follow it."""
    if isinstance(path, int):
        return None
    raw = os.path.abspath(os.path.join(_patched_getcwd(), os.fsdecode(os.fspath(path))))
    return os.path.join(confine.real(os.path.dirname(raw)), os.path.basename(raw))


def _refuse_relative_change(rt: sandbox_client.Runtime, scope: policy.Scope, dir_fd: int, path: Any) -> None:
    """A change relative to an open folder happens here; that folder is what the write set must hold."""
    parent = _dirfd_path(dir_fd)
    name = os.fsdecode(os.fspath(path))
    target = confine.real(os.path.join(parent, name)) if parent else ""
    if not any(confine.is_within(target, root) for root in rt.write_set(scope)):
        rt.record_denial(target, scope.key, "", "denied", access="write")
        raise sandbox_client.SandboxDenied(target, writing=True)


def _patched_mkdir(path, mode=0o777, *, dir_fd=None):
    held = (
        _tool_change_scope(path)
        if dir_fd is None
        else _tool_change_scope(os.path.join(_dirfd_path(dir_fd) or "/", os.fsdecode(path)))
    )
    if held is None:
        return _original_mkdir(path, mode, dir_fd=dir_fd)
    if dir_fd is not None:
        _refuse_relative_change(*held, dir_fd, path)
        return _original_mkdir(path, mode, dir_fd=dir_fd)
    return held[0].change_scoped(held[1], {"op": "mkdir", "path": _named(path), "mode": mode})


def _patched_unlink(path, *, dir_fd=None):
    held = (
        _tool_change_scope(path)
        if dir_fd is None
        else _tool_change_scope(os.path.join(_dirfd_path(dir_fd) or "/", os.fsdecode(path)))
    )
    if held is None:
        return _original_unlink(path, dir_fd=dir_fd)
    if dir_fd is not None:
        _refuse_relative_change(*held, dir_fd, path)
        return _original_unlink(path, dir_fd=dir_fd)
    return held[0].change_scoped(held[1], {"op": "unlink", "path": _named(path)})


def _patched_rmdir(path, *, dir_fd=None):
    held = (
        _tool_change_scope(path)
        if dir_fd is None
        else _tool_change_scope(os.path.join(_dirfd_path(dir_fd) or "/", os.fsdecode(path)))
    )
    if held is None:
        return _original_rmdir(path, dir_fd=dir_fd)
    if dir_fd is not None:
        _refuse_relative_change(*held, dir_fd, path)
        return _original_rmdir(path, dir_fd=dir_fd)
    return held[0].change_scoped(held[1], {"op": "rmdir", "path": _named(path)})


def _patched_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
    if src_dir_fd is not None or dst_dir_fd is not None:
        held = _tool_change_scope(
            *(
                os.path.join(_dirfd_path(fd) or "/", os.fsdecode(p)) if fd is not None else p
                for p, fd in ((src, src_dir_fd), (dst, dst_dir_fd))
            )
        )
        if held is not None:
            for path, fd in ((src, src_dir_fd), (dst, dst_dir_fd)):
                if fd is not None:
                    _refuse_relative_change(*held, fd, path)
                elif not any(confine.is_within(_named(path) or "", r) for r in held[0].write_set(held[1])):
                    raise sandbox_client.SandboxDenied(_named(path) or "", writing=True)
        return _original_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
    held = _tool_change_scope(src, dst)
    if held is None:
        return _original_replace(src, dst)
    return held[0].change_scoped(held[1], {"op": "rename", "path": _named(src), "dest": _named(dst)})


def _patched_symlink(src, dst, target_is_directory=False, *, dir_fd=None):
    held = _tool_change_scope(dst) if dir_fd is None else None
    if held is None:
        if dir_fd is not None:
            rt = sandbox_client.runtime()
            scope = sandbox_client.current_scope.get()
            if rt is not None and scope is not None:
                _refuse_relative_change(rt, scope, dir_fd, dst)
        return _original_symlink(src, dst, target_is_directory, dir_fd=dir_fd)
    return held[0].change_scoped(held[1], {"op": "symlink", "path": _named(dst), "target": os.fsdecode(src)})


def _dir_fd(path: str) -> int | None:
    route, scope = _route(path)
    rt = sandbox_client.runtime()
    if rt is not None and route == "scope" and scope is not None:
        return rt.opendir_scoped(scope, path)
    return None


def _fallback_dir_fd(path: str) -> int | None:
    rt = sandbox_client.runtime()
    if rt is None or not policy.is_private(path) or not rt.service_covers(path):
        return None
    return rt.opendir_service(path)


def _patched_listdir(path="."):
    resolved = _resolve(path)
    if resolved is not None:
        fd = _dir_fd(resolved)
        if fd is not None:
            try:
                names = _original_listdir(fd)
            finally:
                os.close(fd)
            return [os.fsencode(n) for n in names] if isinstance(path, bytes) else names
    try:
        return _original_listdir(path)
    except PermissionError:
        if resolved is None:
            raise
        fd = _fallback_dir_fd(resolved)
        if fd is None:
            raise
        try:
            names = _original_listdir(fd)
        finally:
            os.close(fd)
        return [os.fsencode(n) for n in names] if isinstance(path, bytes) else names


class _Entry:
    """A ``DirEntry`` stand-in for listings served through a helper fd."""

    __slots__ = ("_bytes", "name", "path")

    def __init__(self, name: str, parent: Any, as_bytes: bool) -> None:
        self._bytes = as_bytes
        joined = os.path.join(os.fsdecode(parent), name)
        self.name = os.fsencode(name) if as_bytes else name
        self.path = os.fsencode(joined) if as_bytes else joined

    def __fspath__(self):
        return self.path

    def __repr__(self) -> str:
        return f"<DirEntry {self.name!r}>"

    def stat(self, *, follow_symlinks: bool = True):
        return os.stat(self.path) if follow_symlinks else os.lstat(self.path)

    def inode(self) -> int:
        return os.lstat(self.path).st_ino

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        try:
            return stat_mod.S_ISDIR(self.stat(follow_symlinks=follow_symlinks).st_mode)
        except OSError:
            return False

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        try:
            return stat_mod.S_ISREG(self.stat(follow_symlinks=follow_symlinks).st_mode)
        except OSError:
            return False

    def is_symlink(self) -> bool:
        try:
            return stat_mod.S_ISLNK(os.lstat(self.path).st_mode)
        except OSError:
            return False

    def is_junction(self) -> bool:
        return False


class _Listing:
    def __init__(self, names: list[str], parent: Any, as_bytes: bool) -> None:
        self._entries = iter([_Entry(n, parent, as_bytes) for n in names])

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._entries)

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        self._entries = iter(())


def _listing_from_fd(fd: int, path: Any) -> _Listing:
    try:
        names = _original_listdir(fd)
    finally:
        os.close(fd)
    return _Listing(names, path, isinstance(path, bytes))


def _patched_scandir(path="."):
    if isinstance(path, int):
        return _original_scandir(path)
    resolved = _resolve(path)
    if resolved is not None:
        fd = _dir_fd(resolved)
        if fd is not None:
            return _listing_from_fd(fd, path)
    try:
        return _original_scandir(path)
    except PermissionError:
        if resolved is None:
            raise
        fd = _fallback_dir_fd(resolved)
        if fd is None:
            raise
        return _listing_from_fd(fd, path)


def _patched_getcwd() -> str:
    try:
        return _original_getcwd()
    except PermissionError:
        if not _cwd:
            raise
        # Metadata stays visible in a denied region, so a deleted directory
        # still reports as missing — as the original does outside the sandbox.
        if not os.path.isdir(_cwd[0]):
            raise FileNotFoundError(2, "No such file or directory") from None
        return _cwd[0]


def _patched_getcwdb() -> bytes:
    return os.fsencode(_patched_getcwd())


def _patched_chdir(path) -> None:
    # Change first, exactly as the original would (an absolute path works even
    # when the old directory is gone); work out the new name afterwards.
    previous = _cwd[0] if _cwd else None
    _original_chdir(path)
    try:
        _cwd[:] = [_original_getcwd()]
        return
    except PermissionError:
        pass  # the new directory lies in a denied region: track it ourselves
    if isinstance(path, int):
        return
    raw = os.fsdecode(os.fspath(path))
    if os.path.isabs(raw):
        _cwd[:] = [os.path.normpath(raw)]
    elif previous is not None:
        _cwd[:] = [os.path.normpath(os.path.join(previous, raw))]


# ------------------------------------------------------------------ commands


def _program_and_args(args: Any, executable: Any, shell: bool) -> tuple[str, list[str]]:
    argv = [os.fsdecode(args)] if isinstance(args, (str, bytes, os.PathLike)) else [os.fsdecode(a) for a in args]
    if shell:
        argv = ["/bin/sh", "-c", *argv]
    program = os.fsdecode(executable) if executable else argv[0]
    # ``Popen`` refuses these before starting anything; the stub's JSON spec would carry them.
    if any("\0" in arg for arg in (program, *argv)):
        raise ValueError("embedded null byte")
    return program, argv


def _resolve_program(program: str, env: Any) -> str:
    """Fail like ``Popen`` would when the program can't be found."""
    if os.sep in program:
        if not os.path.exists(program):
            raise FileNotFoundError(2, "No such file or directory", program)
        return program
    search = None
    if env is not None:
        search = (env.get("PATH") if isinstance(env, dict) else None) or (
            os.fsdecode(env.get(b"PATH")) if isinstance(env, dict) and env.get(b"PATH") else None
        )
    found = shutil.which(program, path=search if search is not None else os.environ.get("PATH", os.defpath))
    if found is None:
        raise FileNotFoundError(2, "No such file or directory", program)
    return found


def _patched_execute_child(self, args, executable, preexec_fn, close_fds, pass_fds, cwd, env, *rest):
    rt = sandbox_client.runtime()
    if rt is None:
        return _original_execute_child(self, args, executable, preexec_fn, close_fds, pass_fds, cwd, env, *rest)
    # *rest* starts at ``startupinfo, creationflags, shell``.
    rest = list(rest)
    shell = bool(rest[2]) if len(rest) > 2 else False
    program, argv = _program_and_args(args, executable, shell)
    if cwd is not None:
        cwd_text = os.fsdecode(cwd)
        if not os.path.isdir(cwd_text):
            raise FileNotFoundError(2, "No such file or directory", cwd_text)
    else:
        cwd_text = _patched_getcwd()
    resolved = _resolve_program(program, env)
    unconfined = os.path.realpath(resolved) in UNCONFINED_COMMANDS
    stub_sock, slot_id = rt.reserve_slot(sandbox_client.current_scope.get(), unconfined=unconfined, cwd=cwd_text)
    spec = {"argv": argv, "program": resolved if unconfined else program, "cwd": cwd_text, "pass_fds": list(pass_fds)}
    if sandbox_client.wants_controlling_tty.get():
        # The stub leads a session of its own but leaves the terminal to the command.
        spec["ctty"] = True
        preexec_fn = cast(Any, os).setsid
    stub_argv = [
        sys.executable,
        "-I",
        "-S",
        str(sandbox_client.RUNTIME_DIR / "stub.py"),
        str(stub_sock.fileno()),
        _json(spec),
    ]
    if len(rest) > 2:
        rest[2] = False  # the stub argv is never a shell string
    starting = _starting_stub.set(True)
    try:
        _original_execute_child(
            self,
            stub_argv,
            sys.executable,
            preexec_fn,
            close_fds,
            (*pass_fds, stub_sock.fileno()),
            None,
            env,
            *rest,
        )
        _link_session(self.pid, rt, slot_id)
    finally:
        _starting_stub.reset(starting)
        stub_sock.close()


def _link_session(stub_pid: int, rt: sandbox_client.Runtime, slot_id: int) -> None:
    """Make iCode's process handling of the stub reach the command behind it."""
    from chrys.foundation.platform import process

    found: list[int] = []

    def resolve() -> int:
        """The command's session; 0 while it hasn't started, -1 once it is gone (its pid may be reused)."""
        if not found:
            pid = rt.slot_pid(slot_id)
            if pid <= 0:
                return 0
            found.append(pid)
        pid = found[0]
        if pid < 0 or not _still_the_command(pid, rt.broker_pid()):
            found[0] = -1
            return -1
        return pid

    process.link_process_session(stub_pid, resolve)


def _still_the_command(pid: int, broker_pid: int) -> bool:
    """Whether the session the broker started as *pid* still has a member.

    Its leader may have exited while what it started lives on in the session;
    the kernel doesn't hand out a pid still in use as a session id, so while a
    member remains the number can't belong to anyone else. Empty, it is gone.
    """
    import psutil

    try:
        if os.getsid(pid) == pid and psutil.Process(pid).ppid() == broker_pid:
            return True
    except OSError, psutil.Error:
        pass
    for other in psutil.pids():
        try:
            if other != pid and os.getsid(other) == pid:
                return True
        except OSError:
            continue
    return False


def _json(value: Any) -> str:
    import json

    return json.dumps(value, separators=(",", ":"))


# -------------------------------------------------------------------- install


def remember_cwd() -> None:
    """Record the working directory; call before the process is confined."""
    _cwd[:] = [_original_getcwd()]


_alarm_busy: contextvars.ContextVar[bool] = contextvars.ContextVar("sandbox_alarm_busy", default=False)


def _dev_alarm(event: str, args: tuple) -> None:
    """Development alarm: a scoped open of a private path that bypassed the hooks.

    Every path open in a scope goes through the patched functions, which hand
    the helper's fd (an int) to the original; a *path* reaching the ``open``
    audit event for an uncovered private file means some code holds an
    unpatched opener. The kernel still refuses it — this only says where.
    """
    if event != "open" or _alarm_busy.get():
        return
    scope = sandbox_client.current_scope.get()
    target = args[0] if args else None
    if scope is None or not isinstance(target, (str, bytes)):
        return
    token = _alarm_busy.set(True)  # the checks below open files themselves
    try:
        path = _resolve(target)
        rt = sandbox_client.runtime()
        if path is None or rt is None or not policy.is_private(path):
            return
        if any(confine.is_within(path, p) for p in _internal_paths(rt)) or rt.scope_covers(scope, path):
            return
        rt.audit("bypass_suspect", scope=scope.key, path=path)
    finally:
        _alarm_busy.reset(token)
    import logging
    import traceback

    logging.getLogger(__name__).warning(
        "sandbox: %s was opened by path inside a tool call, bypassing the read hooks:\n%s",
        path,
        "".join(traceback.format_stack(limit=8)),
    )


def install() -> None:
    """Install every hook (idempotent). Only call once a runtime is live.

    ``CHRYS_FILE_SANDBOX_DEV_ALARM=1`` adds :func:`_dev_alarm` (development and tests).
    """
    global _installed
    if _installed:
        return
    _installed = True
    if os.environ.get("CHRYS_FILE_SANDBOX_DEV_ALARM") == "1":
        sys.addaudithook(_dev_alarm)
    if not _cwd:
        remember_cwd()
    os.getcwd = _patched_getcwd
    os.getcwdb = _patched_getcwdb
    os.chdir = _patched_chdir
    builtins.open = _patched_open
    io.open = _patched_open
    os.open = _patched_os_open
    os.listdir = _patched_listdir
    os.scandir = _patched_scandir
    os.mkdir = _patched_mkdir
    os.unlink = _patched_unlink
    os.remove = _patched_unlink
    os.rmdir = _patched_rmdir
    os.replace = _patched_replace
    os.rename = _patched_replace
    os.symlink = _patched_symlink
    os.link = _patched_link
    os.truncate = _patched_truncate
    if _original_mkfifo is not None:
        os.mkfifo = _patched_mkfifo
    if _original_mknod is not None:
        os.mknod = _patched_mknod
    os.chmod = _patched_chmod
    if _original_chown is not None:
        os.chown = _patched_chown
    os.utime = _patched_utime
    os.system = _patched_system
    if _original_posix_spawn is not None:
        os.posix_spawn = _guarded_spawn(_original_posix_spawn)
    if _original_posix_spawnp is not None:
        os.posix_spawnp = _guarded_spawn(_original_posix_spawnp)
    subprocess.Popen._execute_child = _patched_execute_child  # type: ignore[attr-defined]


def uninstall() -> None:
    """Restore the originals (tests only)."""
    global _installed
    _installed = False
    builtins.open = _original_open
    io.open = _original_io_open
    os.open = _original_os_open
    os.listdir = _original_listdir
    os.scandir = _original_scandir
    subprocess.Popen._execute_child = _original_execute_child  # type: ignore[attr-defined]
    os.getcwd = _original_getcwd
    os.getcwdb = _original_getcwdb
    os.chdir = _original_chdir
    os.mkdir = _original_mkdir
    os.unlink = _original_unlink
    os.remove = _original_remove
    os.rmdir = _original_rmdir
    os.replace = _original_replace
    os.rename = _original_rename
    os.symlink = _original_symlink
    os.link = _original_link
    os.truncate = _original_truncate
    if _original_mkfifo is not None:
        os.mkfifo = _original_mkfifo
    if _original_mknod is not None:
        os.mknod = _original_mknod
    os.chmod = _original_chmod
    if _original_chown is not None:
        os.chown = _original_chown
    os.utime = _original_utime
    os.system = _original_system
    if _original_posix_spawn is not None:
        os.posix_spawn = _original_posix_spawn
    if _original_posix_spawnp is not None:
        os.posix_spawnp = _original_posix_spawnp
