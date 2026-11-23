# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Kernel confinement primitives shared by the main process, the broker and its children.

This module is imported two ways: as ``icode_sandbox.runtime.confine``
inside iCode, and as a plain ``confine`` module by the standalone broker, file
helper, stub and exec trampoline, which run as ``python -I -S <script>`` and never
import chrys. It must therefore depend on the standard library only.

Two platform backends restrict the *calling* process; the restriction is
inherited by every child and can never be widened again:

- macOS: Seatbelt through ``sandbox_init`` (the same engine as ``sandbox-exec``).
- Linux: Landlock (ABI 1+), read rights only unless a profile asks for more.

A :class:`Profile` describes what the process may read (and, for file helpers,
write); :func:`apply` installs it and :func:`self_check` proves it took effect.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import stat
import struct
import sys
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

PLATFORM = "macos" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unsupported"

# Read-only data roots that a Linux "everything except" profile never opens up
# beyond the explicit allow list, in addition to the user's home directory.
LINUX_PRIVATE_ROOTS = ("/home", "/root", "/mnt", "/media", "/run/media")
MACOS_PRIVATE_ROOTS = ("/Volumes",)


class ConfineError(RuntimeError):
    """The kernel refused to install a profile, or it did not take effect."""


@dataclass
class Profile:
    """What a confined process may touch.

    ``mode`` selects the shape:

    - ``"except"``: everything is readable except ``deny_roots`` (the user's
      home, external volumes); inside those, only ``allow`` is readable. With
      ``restrict_writes`` (every command; not the main process), only
      ``write_allow`` is writable. Exec and network stay unrestricted. Used for
      the main process and for commands run on its behalf.
    - ``"only"``: only ``allow`` is readable (and ``write`` writable); no exec,
      no network. Used for file helpers. ``runtime`` and ``executable`` let a
      helper start under it: the broker confines it *before* its interpreter
      runs, so nothing the main process could have overwritten ever runs
      unconfined. On Linux the started helper then narrows itself to the same
      profile without them.

    ``protect_moves`` (``"except"`` only) also stops a file from leaving the
    unreadable region by rename or hard link: moved next to the workspace, it
    would be readable there, since the kernel checks the path at open time.
    Deleting or renaming inside that region is refused with it (macOS), or
    moving across directories (Linux). The broker sets it on every command.
    """

    mode: str
    allow: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)
    deny_roots: list[str] = field(default_factory=list)
    protect_moves: bool = False
    no_move: list[str] = field(default_factory=list)
    """macOS, ``"except"``: trees nothing may be renamed or hard-linked out of, even
    without ``protect_moves`` (the main process: its workspace needs atomic writes,
    the floor must not be movable to where it would be readable)."""
    no_move_literal: list[str] = field(default_factory=list)
    """macOS: exact directories that may not be renamed themselves (ancestors of
    ``no_move``: moving ``~/.config`` would carry ``~/.config/gcloud`` along)."""
    refer: list[str] = field(default_factory=list)
    """Linux, ``"except"``: trees where files may also be moved or linked across
    directories without being readable (the main process's workspace, served
    through a helper). Landlock refuses such moves everywhere else."""
    restrict_writes: bool = False
    write_allow: list[str] = field(default_factory=list)
    """``"except"``: the only trees and files a command may change."""
    runtime: list[str] = field(default_factory=list)
    """``"only"``: trees an interpreter needs to start (read, and on Linux execute)."""
    executable: list[str] = field(default_factory=list)
    """``"only"``, macOS: the programs that may be executed, by exact path."""

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> Profile:
        data = json.loads(raw)
        return cls(
            mode=str(data["mode"]),
            allow=[str(p) for p in data.get("allow", [])],
            write=[str(p) for p in data.get("write", [])],
            deny_roots=[str(p) for p in data.get("deny_roots", [])],
            protect_moves=bool(data.get("protect_moves", False)),
            no_move=[str(p) for p in data.get("no_move", [])],
            no_move_literal=[str(p) for p in data.get("no_move_literal", [])],
            refer=[str(p) for p in data.get("refer", [])],
            restrict_writes=bool(data.get("restrict_writes", False)),
            write_allow=[str(p) for p in data.get("write_allow", [])],
            runtime=[str(p) for p in data.get("runtime", [])],
            executable=[str(p) for p in data.get("executable", [])],
        )


def real(path: str) -> str:
    """Absolute, symlink-resolved path (missing tails are kept lexically)."""
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def is_within(path: str, root: str) -> bool:
    """True when *path* is *root* or lies below it (both already resolved)."""
    if root == "/":
        return True
    return path == root or path.startswith(root.rstrip("/") + "/")


def overlaps(a: str, b: str) -> bool:
    """True when one path contains the other."""
    return is_within(a, b) or is_within(b, a)


def _ids(path: str) -> set[tuple[int, int]]:
    """(device, inode) of *path* and each of its existing ancestors."""
    found: set[tuple[int, int]] = set()
    current = path
    while True:
        try:
            info = os.stat(current)
        except OSError:
            pass
        else:
            found.add((info.st_dev, info.st_ino))
        parent = os.path.dirname(current)
        if parent == current:
            return found
        current = parent


def _identity(path: str) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return info.st_dev, info.st_ino


def same_or_nested(a: str, b: str) -> bool:
    """True when one path contains the other, under any spelling of either.

    Compares resolved paths, case-folded where the file system usually is
    case-insensitive (macOS), and also by (device, inode) along both ancestor
    chains, so an alias (different case, a bind mount, a firmlink) can't slip a
    path past a check written against another spelling of it.
    """
    a, b = real(a), real(b)
    if overlaps(a, b):
        return True
    if PLATFORM == "macos" and overlaps(a.casefold(), b.casefold()):
        return True
    a_id, b_id = _identity(a), _identity(b)
    return (b_id is not None and b_id in _ids(a)) or (a_id is not None and a_id in _ids(b))


MINIMUM_LANDLOCK_ABI = 2
"""Below it, a confined process can't move a file into another folder (no ``REFER`` right)."""


def available() -> tuple[bool, str]:
    """Whether this platform can confine a process, and why not when it cannot."""
    if PLATFORM == "macos":
        # The library lives in the dyld shared cache, not on disk.
        try:
            ctypes.CDLL("/usr/lib/libsandbox.1.dylib").sandbox_init  # noqa: B018
        except (OSError, AttributeError) as exc:
            return False, f"libsandbox is unavailable: {exc}"
        return True, "Seatbelt"
    if PLATFORM == "linux":
        abi = _landlock_abi()
        if abi < 1:
            return False, "Landlock is not available in this kernel (needs Linux 5.19+ with the LSM enabled)"
        if abi < MINIMUM_LANDLOCK_ABI:
            # ABI 1 refuses every move or link into another folder from a confined process, whatever the
            # rules: package managers and build tools (which publish files by renaming) fail under it.
            return False, f"Landlock ABI {abi} is too old (needs ABI 2, Linux 5.19+: moving files between folders)"
        return True, f"Landlock ABI {abi}"
    return False, f"no sandbox backend for {sys.platform}"


def thread_count() -> int:
    """Kernel-level thread count of this process (Linux), else Python's view."""
    if PLATFORM == "linux":
        try:
            return len(os.listdir("/proc/self/task"))
        except OSError:
            return threading.active_count()
    return threading.active_count()


def apply(profile: Profile) -> None:
    """Confine the calling process (and every future child) to *profile*."""
    if PLATFORM == "macos":
        _apply_seatbelt(seatbelt_profile(profile))
    elif PLATFORM == "linux":
        _apply_landlock(profile)
    else:
        raise ConfineError(f"no sandbox backend for {sys.platform}")


def self_check(denied_probe: str) -> None:
    """Fail unless reading *denied_probe* (an existing directory) is now refused."""
    try:
        os.listdir(denied_probe)
    except PermissionError:
        return
    except OSError as exc:
        raise ConfineError(f"self-check probe {denied_probe!r} is unusable: {exc}") from exc
    raise ConfineError(f"sandbox self-check failed: {denied_probe!r} is still readable")


# --------------------------------------------------------------------------- macOS


def _sb_str(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sb_filters(paths: list[str]) -> str:
    parts = []
    for path in paths:
        kind = "subpath" if os.path.isdir(path) or not os.path.exists(path) else "literal"
        parts.append(f"({kind} {_sb_str(path)})")
    return " ".join(parts)


def _sb_regex(path: str) -> str:
    """*path* as a literal inside a Seatbelt ``#"..."`` regex."""
    special = set('\\.^$|?*+()[]{}"')
    return "".join("\\" + c if c in special else c for c in path)


def _regex_safe(path: str) -> bool:
    """Whether *path* can sit in a ``#"..."`` literal: Seatbelt has no escape for its closing quote."""
    return not any(c in '"\\' or ord(c) < 32 for c in path)


def _sb_pinned_roots(paths: list[str]) -> list[str]:
    """Keep each writable folder's own entry in place.

    A ``subpath`` rule covers the folder's own name too, so without these a
    process could move a writable folder away and put a link in its place: the
    next process, given the same name, would write wherever the link points.
    """
    roots = " ".join(f"(literal {_sb_str(p)})" for p in paths if os.path.isdir(p))
    if not roots:
        return []
    return [f"(deny file-write-unlink (require-any {roots}))", f"(deny file-write-create (require-any {roots}))"]


def seatbelt_profile(profile: Profile) -> str:
    """Render *profile* as Seatbelt profile source."""
    # A confined process must not get another process to act for it: LaunchServices
    # (``open``) and Apple events start programs outside this sandbox, which read
    # whatever they like. Every profile, so no caller can leave it out.
    rules = [
        "(version 1)",
        "(allow default)",
        "(deny file-issue-extension)",
        "(deny lsopen)",
        "(deny appleevent-send)",
        "(deny mach-priv-task-port)",
    ]
    allow = _sb_filters(profile.allow)
    if profile.mode == "except":
        roots = _sb_filters(profile.deny_roots)
        region = f"(require-any {roots})"
        if allow:
            region = f"(require-all {region} (require-not (require-any {allow})))"
        # Only content is denied: metadata (stat, exists) stays visible so code
        # that probes paths keeps working; nothing can be opened or listed.
        rules.append(f"(deny file-read-data {region})")
        if profile.restrict_writes:
            writable = _sb_filters(profile.write_allow)
            rules.append(
                f"(deny file-write* (require-not (require-any {writable})))" if writable else "(deny file-write*)"
            )
            rules.extend(_sb_pinned_roots(profile.write_allow))
            # Mounting a disk image over a path changes what it holds without writing to it.
            rules.append(
                '(deny mach-lookup (global-name "com.apple.DiskArbitration.diskarbitrationd")'
                ' (global-name-prefix "com.apple.diskimages"))'
            )
        if profile.protect_moves:
            # A rename or link removes nothing readable unless its source is
            # here; ``file-write-unlink`` covers both (and deletion). A readable
            # single file keeps its lock and temp names next to it movable: tools
            # update one by writing ``F.lock`` and renaming it over ``F`` (git config).
            beside = [
                f'(regex #"^{_sb_regex(p)}\\.(lock|tmp[^/]*)$")'
                for p in profile.allow
                # A file, or one not created yet (~/.gitconfig on first use).
                if not os.path.isdir(p) and _regex_safe(p)
            ]
            unlink_region = region
            if beside:
                unlink_region = f"(require-all {region} (require-not (require-any {' '.join(beside)})))"
            rules.append(f"(deny file-write-unlink {unlink_region})")
        if profile.no_move:
            guarded = f"(require-any {_sb_filters(profile.no_move)})"
            rules.append(f"(deny file-write-unlink {guarded})")
            rules.append(f"(deny file-link {guarded})")
        if profile.no_move_literal:
            literals = " ".join(f"(literal {_sb_str(p)})" for p in profile.no_move_literal)
            rules.append(f"(deny file-write-unlink (require-any {literals}))")
    elif profile.mode == "only":
        readable = _sb_filters([*profile.allow, *profile.runtime])
        if profile.runtime:
            readable += ' (literal "/")'  # an interpreter aborts at startup without the root's own entry
        if readable:
            rules.append(f"(deny file-read-data (require-not (require-any {readable})))")
        else:
            rules.append("(deny file-read-data)")
        write = _sb_filters(profile.write)
        if write:
            rules.append(f"(deny file-write* (require-not (require-any {write})))")
            rules.extend(_sb_pinned_roots(profile.write))
        else:
            rules.append("(deny file-write*)")
        if profile.executable:
            programs = " ".join(f"(literal {_sb_str(p)})" for p in profile.executable)
            rules.append(f"(deny process-exec* (require-not (require-any {programs})))")
        else:
            rules.append("(deny process-exec*)")
        rules.append("(deny network*)")
    else:
        raise ConfineError(f"unknown profile mode {profile.mode!r}")
    return "".join(rules)


def _apply_seatbelt(source: str) -> None:
    lib = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")
    lib.sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
    lib.sandbox_init.restype = ctypes.c_int
    error = ctypes.c_char_p()
    if lib.sandbox_init(source.encode(), 0, ctypes.byref(error)) != 0:
        message = error.value.decode(errors="replace") if error.value else "unknown error"
        raise ConfineError(f"sandbox_init failed: {message}")


# --------------------------------------------------------------------------- Linux

_SYS_CREATE, _SYS_ADD_RULE, _SYS_RESTRICT = 444, 445, 446
_O_PATH = getattr(os, "O_PATH", 0)  # Linux-only
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_PR_SET_NO_NEW_PRIVS = 38
_RULE_PATH_BENEATH = 1

_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_DIR_ONLY_WRITE = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12)
_REFER = 1 << 13  # ABI 2
_TRUNCATE = 1 << 14  # ABI 3
_IOCTL_DEV = 1 << 15  # ABI 5
_NET_BIND_TCP, _NET_CONNECT_TCP = 1 << 0, 1 << 1  # ABI 4


_libc_handle: ctypes.CDLL | None = None


def _libc() -> ctypes.CDLL:
    global _libc_handle
    if _libc_handle is None:
        _libc_handle = ctypes.CDLL(None, use_errno=True)
    return _libc_handle


def _landlock_abi() -> int:
    if PLATFORM != "linux":
        return 0
    try:
        return int(_libc().syscall(_SYS_CREATE, None, ctypes.c_size_t(0), ctypes.c_uint32(1)))
    except OSError:
        return 0


def _fs_rights(abi: int) -> int:
    rights = _EXECUTE | _WRITE_FILE | _READ_FILE | _READ_DIR | _DIR_ONLY_WRITE
    if abi >= 2:
        rights |= _REFER
    if abi >= 3:
        rights |= _TRUNCATE
    if abi >= 5:
        rights |= _IOCTL_DEV
    return rights


def _file_rights(rights: int) -> int:
    return rights & (_EXECUTE | _WRITE_FILE | _READ_FILE | _TRUNCATE | _IOCTL_DEV)


def linux_allow_except(deny_roots: list[str]) -> list[str]:
    """Paths whose union is the whole tree minus *deny_roots* (resolved)."""
    denied = sorted({real(p) for p in deny_roots if os.path.exists(p)})
    result: list[str] = []

    def visit(directory: str) -> None:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            return
        for name in names:
            child = os.path.join(directory, name)
            resolved = real(child)
            if any(is_within(resolved, d) for d in denied):
                continue
            if any(is_within(d, child) and d != child for d in denied) and not os.path.islink(child):
                visit(child)
                continue
            if any(is_within(d, resolved) for d in denied):
                # A symlink whose target contains a denied root: skip it.
                continue
            result.append(child)

    if not denied:
        return ["/"]
    visit("/")
    return result


def _apply_landlock(profile: Profile) -> None:
    ruleset = linux_prepare(profile)
    try:
        linux_restrict(ruleset)
    finally:
        os.close(ruleset)


def looks_confined() -> bool:
    """Whether the kernel says this process runs under a sandbox (best effort; ``False`` when unsure).

    macOS: ``sandbox_check`` on our own pid. Linux: the no-new-privileges bit
    and a seccomp filter, which every process the broker confines has (Landlock
    itself can't be queried).
    """
    if PLATFORM == "macos":
        try:
            lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            return bool(lib.sandbox_check(os.getpid(), None, 0))
        except OSError, AttributeError:
            return False
    if PLATFORM == "linux":
        try:
            with open("/proc/self/status", encoding="ascii", errors="replace") as status:
                fields = dict(line.split(":", 1) for line in status if ":" in line)
        except OSError:
            return False
        return fields.get("NoNewPrivs", "").strip() == "1" and fields.get("Seccomp", "").strip() == "2"
    return False


def linux_restrict(ruleset: int, syscalls: SyscallFilter | None = None) -> None:
    """Put the calling thread under *ruleset*, and *syscalls* when given.

    Safe between ``fork`` and ``exec``: it only makes syscalls, through a
    handle and a filter built before the fork.
    """
    libc = _libc()
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise ConfineError(f"prctl(NO_NEW_PRIVS) failed: errno {ctypes.get_errno()}")
    if libc.syscall(_SYS_RESTRICT, ruleset, ctypes.c_uint32(0)) != 0:
        raise ConfineError(f"landlock_restrict_self failed: errno {ctypes.get_errno()}")
    if syscalls is not None and libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(syscalls.prog), 0, 0):
        raise ConfineError(f"seccomp filter failed: errno {ctypes.get_errno()}")


_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER = 22, 2
_X32_SYSCALL_BIT = 0x40000000
# Syscalls no command needs, refused with EPERM: they change mounts or the
# kernel, trace processes, reach the kernel keyring, or open kernel interfaces
# (BPF, perf, io_uring, userfaultfd) that exploits start from. Landlock already
# stops a confined process from changing mounts or tracing one outside its
# domain; this is the second line, and the only one for the keyring and the
# kernel interfaces.
BLOCKED_SYSCALLS = (
    "mount", "umount2", "pivot_root", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "mount_setattr",
    "unshare", "setns", "ptrace", "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "userfaultfd",
    "io_uring_setup", "io_uring_enter", "io_uring_register", "open_by_handle_at", "name_to_handle_at",
    "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
    "swapon", "swapoff", "reboot", "acct",
)  # fmt: skip
# (audit arch, syscall numbers) per machine: arch/x86/entry/syscalls/syscall_64.tbl, include/uapi/asm-generic/unistd.h
_SYSCALL_TABLES: dict[str, tuple[int, dict[str, int]]] = {
    "x86_64": (0xC000003E, {
        "mount": 165, "umount2": 166, "pivot_root": 155, "open_tree": 428, "move_mount": 429, "fsopen": 430,
        "fsconfig": 431, "fsmount": 432, "mount_setattr": 442, "unshare": 272, "setns": 308, "ptrace": 101,
        "keyctl": 250, "add_key": 248, "request_key": 249, "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "open_by_handle_at": 304,
        "name_to_handle_at": 303, "kexec_load": 246, "kexec_file_load": 320, "init_module": 175,
        "finit_module": 313, "delete_module": 176, "swapon": 167, "swapoff": 168, "reboot": 169, "acct": 163,
    }),
    "aarch64": (0xC00000B7, {
        "mount": 40, "umount2": 39, "pivot_root": 41, "open_tree": 428, "move_mount": 429, "fsopen": 430,
        "fsconfig": 431, "fsmount": 432, "mount_setattr": 442, "unshare": 97, "setns": 268, "ptrace": 117,
        "keyctl": 219, "add_key": 217, "request_key": 218, "bpf": 280, "perf_event_open": 241, "userfaultfd": 282,
        "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427, "open_by_handle_at": 265,
        "name_to_handle_at": 264, "kexec_load": 104, "kexec_file_load": 294, "init_module": 105,
        "finit_module": 273, "delete_module": 106, "swapon": 224, "swapoff": 225, "reboot": 142, "acct": 89,
    }),
}  # fmt: skip


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


class SyscallFilter:
    """A built seccomp program; keeps its buffer alive for the child that installs it."""

    def __init__(self, raw: bytes, count: int) -> None:
        self.buffer = ctypes.create_string_buffer(raw, len(raw))
        self.prog = _SockFprog(count, ctypes.addressof(self.buffer))


def linux_syscall_filter(machine: str | None = None) -> SyscallFilter | None:
    """The seccomp filter for commands and helpers, built before ``fork``; ``None`` on a machine with no table.

    A syscall of another architecture (32-bit, x32) is refused outright: it
    has numbers of its own, which this filter would not recognize.
    """
    table = _SYSCALL_TABLES.get(machine or platform.machine())
    if table is None:
        return None
    audit, numbers = table
    allow, refuse = 0x7FFF0000, 0x00050000 | 1  # SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO | EPERM
    ld, ret, jeq, jset = 0x20, 0x06, 0x15, 0x45
    blocked = [numbers[name] for name in BLOCKED_SYSCALLS]
    # Instructions, with jumps by index: the refusal is the last one.
    code: list[tuple[int, int, int, int]] = [(ld, 0, 0, 4), (jeq, 0, -1, audit), (ld, 0, 0, 0)]
    if machine == "x86_64" or (machine is None and platform.machine() == "x86_64"):
        code.append((jset, -1, 0, _X32_SYSCALL_BIT))
    code += [(jeq, -1, 0, nr) for nr in blocked]
    code += [(ret, 0, 0, allow), (ret, 0, 0, refuse)]
    last = len(code) - 1
    prog = []
    for index, (op, jt, jf, k) in enumerate(code):
        jt = last - index - 1 if jt == -1 else jt
        jf = last - index - 1 if jf == -1 else jf
        if not (0 <= jt <= 255 and 0 <= jf <= 255):
            raise ConfineError("syscall filter jump out of range")
        prog.append(struct.pack("HBBI", op, jt, jf, k))
    return SyscallFilter(b"".join(prog), len(prog))


def linux_prepare(profile: Profile, guard: Callable[[str, list[os.stat_result]], None] | None = None) -> int:
    """Build the Landlock ruleset of *profile* without applying it; the caller closes the returned fd.

    The paths a request named are opened one component at a time without
    following a link, so one swapped in since they were resolved grants nothing,
    and *guard* sees the identity of each component of what is really opened.
    """
    libc = _libc()
    abi = _landlock_abi()
    if abi < 1:
        raise ConfineError("Landlock is not available")
    all_fs = _fs_rights(abi)
    read = _READ_FILE | _READ_DIR
    if profile.mode == "except":
        # Landlock refuses linking or renaming across directories under *any*
        # ruleset unless REFER is granted (ABI 2+), handled or not: grant it on
        # the readable tree (and ``refer``), never on the unreadable region, so
        # nothing can be moved out of it to where it would be readable.
        handled_fs = read | (_REFER if abi >= 2 else 0)
        allow_paths = linux_allow_except(profile.deny_roots) + profile.allow
        write_paths: list[str] = []
        handled_net = 0
        if profile.restrict_writes:
            # Execute and device ioctls stay unhandled: commands run programs and use terminals.
            handled_fs |= all_fs & ~(read | _EXECUTE | _IOCTL_DEV)
    elif profile.mode == "only":
        handled_fs = all_fs
        allow_paths = list(profile.allow)
        write_paths = list(profile.write)
        handled_net = (_NET_BIND_TCP | _NET_CONNECT_TCP) if abi >= 4 else 0
    else:
        raise ConfineError(f"unknown profile mode {profile.mode!r}")

    attr = struct.pack("QQ", handled_fs, handled_net) if handled_net else struct.pack("Q", handled_fs)
    ruleset = libc.syscall(_SYS_CREATE, attr, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if ruleset < 0:
        raise ConfineError(f"landlock_create_ruleset failed: errno {ctypes.get_errno()}")
    try:
        write_rights = all_fs & ~(read | _EXECUTE)
        readable = read | _REFER
        refer_only = list(profile.refer) if profile.mode == "except" else []
        requested = set(profile.allow) | set(profile.write) | set(profile.write_allow)
        rules = [(p, readable) for p in allow_paths] + [(p, read | write_rights) for p in write_paths]
        rules += [(p, _REFER) for p in refer_only]
        rules += [(p, read | _EXECUTE) for p in profile.runtime]
        if profile.restrict_writes:
            rules += [(p, (write_rights & ~_IOCTL_DEV) | _REFER) for p in profile.write_allow]
        for path, rights in rules:
            _add_rule(libc, ruleset, path, rights & handled_fs, strict=path in requested, guard=guard)
    except BaseException:
        os.close(ruleset)
        raise
    return ruleset


def _open_without_links(path: str, guard: Callable[[str, list[os.stat_result]], None] | None) -> int:
    """``O_PATH`` fd of *path*, refusing a symlink at any component; ``-1`` when it isn't there."""
    current = os.open("/", _O_PATH | _O_CLOEXEC | _O_DIRECTORY)
    chain = [os.fstat(current)]
    try:
        for part in [p for p in path.split("/") if p]:
            following = os.open(part, _O_PATH | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
            info = os.fstat(current)
            if stat.S_ISLNK(info.st_mode):
                os.close(current)
                return -1
            chain.append(info)
        if guard is not None:
            guard(path, chain)
    except OSError:
        os.close(current)
        return -1
    except BaseException:
        os.close(current)
        raise
    return current


def _add_rule(
    libc: ctypes.CDLL,
    ruleset: int,
    path: str,
    rights: int,
    *,
    strict: bool = False,
    guard: Callable[[str, list[os.stat_result]], None] | None = None,
) -> None:
    if strict:
        fd = _open_without_links(path, guard)
        if fd < 0:
            return  # a missing path, or one that became a link, grants nothing
    else:
        try:
            fd = os.open(path, _O_PATH | _O_CLOEXEC)
        except OSError:
            return  # a missing path grants nothing
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            rights = _file_rights(rights)
        if not rights:
            return
        rule = struct.pack("=Qi", rights, fd)
        if libc.syscall(_SYS_ADD_RULE, ruleset, ctypes.c_int(_RULE_PATH_BENEATH), rule, ctypes.c_uint32(0)) != 0:
            raise ConfineError(f"landlock_add_rule({path!r}) failed: errno {ctypes.get_errno()}")
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- wire

if __package__:  # inside the chrys package
    from icode_sandbox.runtime.wire import HEADER, MAX_FDS, MAX_MESSAGE, recv, send
else:  # a standalone process: its own directory leads ``sys.path``
    from wire import HEADER, MAX_FDS, MAX_MESSAGE, recv, send  # ty: ignore[unresolved-import]

_ = (HEADER, MAX_FDS, MAX_MESSAGE, recv, send)  # re-exported
