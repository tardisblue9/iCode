# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Sandbox broker: the only unconfined process, a factory for confined ones.

Started by iCode *before* the main process confines itself, as
``python -I -S broker.py <control-fd> <config-json>``. It never reads files for
anyone and never parses untrusted content; it only

- validates a requested profile against the floor (paths that are never
  granted) and the private roots (which an ``except`` profile can't drop),
- starts a confined file helper and hands its socket back (``helper``),
- runs one confined command for a stub process (``slot``): the stub sends its
  argv, cwd, environment and stdio fds; the command runs under the profile and
  its exit status goes back to the stub.

Every access check afterwards is the kernel's. The broker exits once the
control socket is closed and no command it started is still running.
"""

import array  # noqa: F401 — loaded before ``_no_late_imports`` is armed
import fcntl  # noqa: F401
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from functools import partial
from typing import Any, cast

with __import__("contextlib").suppress(ImportError):
    import pwd  # noqa: F401
    import termios  # noqa: F401

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import contextlib

import confine

_HERE = os.path.dirname(os.path.abspath(__file__))
_live: dict[int, subprocess.Popen] = {}
_live_lock = threading.Lock()
_idle = threading.Condition(_live_lock)


def _account_home(fallback: str) -> str:
    try:
        import pwd

        return confine.real(cast(Any, pwd).getpwuid(cast(Any, os).getuid()).pw_dir)
    except ImportError, KeyError, OSError:
        return fallback


def session_members(session_id: int) -> list[int]:
    """Live processes of POSIX session *session_id* (this process is unconfined: it can list them)."""
    pids: list[int] = []
    if sys.platform.startswith("linux"):
        candidates = [int(name) for name in os.listdir("/proc") if name.isdigit()]
    else:
        try:
            listing = subprocess.run(
                ["/bin/ps", "-A", "-o", "pid="],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=5,
                check=False,
            ).stdout
        except OSError, subprocess.SubprocessError:
            return pids
        candidates = [int(token) for token in listing.split() if token.isdigit()]
    for pid in candidates:
        with contextlib.suppress(OSError):
            if cast(Any, os).getsid(pid) == session_id:
                pids.append(pid)
    return pids


def kill_session(session_id: int) -> None:
    """SIGKILL every process of a command's session (its group alone may not be all)."""
    sigkill = cast(Any, signal).SIGKILL
    with contextlib.suppress(OSError):
        cast(Any, os).killpg(session_id, sigkill)
    for pid in session_members(session_id):
        with contextlib.suppress(OSError):
            os.kill(pid, sigkill)


class Refused(Exception):
    """A request the broker will not serve."""


class Broker:
    def __init__(self, config: dict) -> None:
        self.python = str(config["python"])
        # The binary that really runs: a launcher (python.org's macOS framework build, some venvs) starts it in turn.
        self.python_binary = str(config.get("python_binary") or self.python)
        # Built once, before any fork: every helper and command installs it after its Landlock rules.
        self.syscalls = confine.linux_syscall_filter() if confine.PLATFORM == "linux" else None
        self._next_slot = 0
        self._slot_pids: dict[int, int] = {}
        home = confine.real(os.path.expanduser("~"))
        homes = {home, _account_home(home)}
        builtin_floor = [os.path.join(h, p) for h in homes for p in _BUILTIN_FLOOR]
        self.floor = sorted({confine.real(p) for p in [*config.get("floor", []), *builtin_floor]})
        self.floor_keys = [p.casefold() if confine.PLATFORM == "macos" else p for p in self.floor]
        builtin_write_floor = [os.path.join(h, p) for h in homes for p in _BUILTIN_WRITE_FLOOR]
        self.write_floor = sorted({confine.real(p) for p in [*config.get("write_floor", []), *builtin_write_floor]})
        self.write_floor_keys = [p.casefold() if confine.PLATFORM == "macos" else p for p in self.write_floor]
        # iCode's own install: nothing under it, though a workspace may hold one (a checkout of iCode).
        self.write_never_under = sorted({confine.real(p) for p in config.get("write_never_under", [])})
        self.write_exceptions = {confine.real(p) for p in config.get("write_exceptions", [])}
        private = [
            *homes,
            *(confine.LINUX_PRIVATE_ROOTS if confine.PLATFORM == "linux" else confine.MACOS_PRIVATE_ROOTS),
        ]
        self.private_roots = sorted({confine.real(p) for p in [*config.get("private_roots", []), *private]})
        # Taken now, while nothing has run yet: a path can be renamed later, its
        # identity can't. Only ever added to, so a renamed one stays known.
        self.floor_ids: set[tuple[int, int]] = set()
        self.floor_containers: set[tuple[int, int]] = set()
        self.write_floor_ids: set[tuple[int, int]] = set()
        self.write_floor_containers: set[tuple[int, int]] = set()
        self._floor_seen = 0.0
        self._refresh_floor()
        self.write_opened: set[str] = set()
        self._slot_threads = 0
        # Unreadable under any helper profile (it may not open a whole private root), so it proves one took effect.
        self.probe = home
        self._runtime = sorted(
            {confine.real(p) for p in (sys.prefix, sys.base_prefix, os.path.dirname(confine.real(self.python)), _HERE)}
        )

    # ------------------------------------------------------------- validation

    def _refresh_floor(self) -> None:
        """Note the floor's identities again, at most once a second: one may have been created since."""
        now = time.monotonic()
        if self._floor_seen and now - self._floor_seen < 1:
            return
        self._floor_seen = now
        with _live_lock:
            for path in self.floor:
                own = confine._identity(path)
                if own is not None:
                    self.floor_ids.add(own)
                self.floor_containers |= confine._ids(os.path.dirname(path))
            for path in self.write_floor:
                own = confine._identity(path)
                if own is not None:
                    self.write_floor_ids.add(own)
                self.write_floor_containers |= confine._ids(os.path.dirname(path))

    def _refuse_floor(self, path: str, chains: dict[str, set[tuple[int, int]]]) -> None:
        """Refuse *path* if it overlaps the floor: by any spelling, or by identity under any name.

        Commands start often and a profile lists dozens of paths, so this compares
        against identities already taken instead of asking the disk for each pair.
        """
        folded = path.casefold() if confine.PLATFORM == "macos" else path
        for floor in self.floor_keys:
            if confine.overlaps(folded, floor):
                raise Refused(f"{path} overlaps a protected path")
        own = confine._identity(path)
        if own is not None and own in self.floor_containers:
            raise Refused(f"{path} holds a protected path")
        if _chain(path, chains) & self.floor_ids:
            raise Refused(f"{path} is, or lies in, a protected path under another name")

    def _refuse_write(self, path: str, chains: dict[str, set[tuple[int, int]]]) -> None:
        """Refuse a writable *path* over the write floor: inside it, around it, or under another name."""
        if path in self.write_exceptions:
            return
        folded = path.casefold() if confine.PLATFORM == "macos" else path
        for floor in self.write_floor_keys:
            if confine.overlaps(folded, floor):
                raise Refused(f"{path} overlaps a path that can't be written")
        own = confine._identity(path)
        if own is not None and own in self.write_floor_containers:
            raise Refused(f"{path} holds a path that can't be written")
        if _chain(path, chains) & self.write_floor_ids:
            raise Refused(f"{path} is, or lies in, a path that can't be written, under another name")
        for root in self.write_never_under:
            if confine.is_within(path, root):
                raise Refused(f"{path} is part of iCode's own install")

    def _guard_opened(self, path: str, chain: list[os.stat_result]) -> None:
        """What a request's path turned out to be when opened (Linux); it may have changed since the check."""
        ids = {(info.st_dev, info.st_ino) for info in chain}
        if ids & self.floor_ids or (chain[-1].st_dev, chain[-1].st_ino) in self.floor_containers:
            raise Refused(f"{path} became a protected path")
        if path in self.write_opened and path not in self.write_exceptions:
            last = (chain[-1].st_dev, chain[-1].st_ino)
            if ids & self.write_floor_ids or last in self.write_floor_containers:
                raise Refused(f"{path} became a path that can't be written")

    def check(self, raw: dict) -> confine.Profile:
        if not isinstance(raw, dict):
            raise Refused("malformed profile")
        profile = confine.Profile(
            mode=str(raw.get("mode")),
            allow=[confine.real(p) for p in _strings(raw.get("allow"))],
            write=[confine.real(p) for p in _strings(raw.get("write"))],
            deny_roots=[confine.real(p) for p in _strings(raw.get("deny_roots"))],
            # Every command the broker runs: a caller can't opt out of either.
            protect_moves=raw.get("mode") == "except",
            restrict_writes=raw.get("mode") == "except",
            write_allow=[confine.real(p) for p in _strings(raw.get("write_allow"))],
        )
        if profile.mode not in {"only", "except"}:
            raise Refused(f"unknown profile mode {profile.mode!r}")
        self._refresh_floor()
        chains: dict[str, set[tuple[int, int]]] = {}
        for path in [*profile.allow, *profile.write, *profile.write_allow]:
            if path == "/":
                raise Refused("the filesystem root cannot be granted")
            self._refuse_floor(path, chains)
        for path in [*profile.write, *profile.write_allow]:
            self._refuse_write(path, chains)
        self.write_opened |= {*profile.write, *profile.write_allow}
        if profile.mode == "except":
            if profile.write:
                raise Refused("except profiles do not restrict writes")
            # The caller may add roots but never drop the broker's own, and a
            # protected path outside them (one the person added) is denied too.
            outside = [f for f in self.floor if not any(confine.is_within(f, r) for r in self.private_roots)]
            profile.deny_roots = sorted({*profile.deny_roots, *self.private_roots, *outside})
            for path in profile.allow:
                for root in profile.deny_roots:
                    if confine.is_within(root, path):
                        raise Refused(f"{path} would expose all of {root}")
            # A linked name of a file elsewhere: what it opens isn't what was checked.
            profile.allow = [p for p in profile.allow if not _is_hard_linked(p)]
            for path in profile.write_allow:
                for root in profile.deny_roots:
                    if confine.is_within(root, path):
                        raise Refused(f"{path} would make all of {root} writable")
            profile.write_allow = [p for p in profile.write_allow if not _is_hard_linked(p)]
        else:
            for path in [*profile.allow, *profile.write]:
                if _is_hard_linked(path):
                    raise Refused(f"{path} has other names on disk, so it cannot be granted by name")
        return profile

    # ---------------------------------------------------------------- helper

    def helper(self, raw: dict) -> int:
        profile = self.check(raw)
        if profile.mode != "only":
            raise Refused("file helpers use 'only' profiles")
        interpreter = [confine.real(self.python)]
        for name in (self.python, confine.real(self.python_binary)):
            if name not in interpreter:
                interpreter.append(name)
        system = _MACOS_START_PATHS if confine.PLATFORM == "macos" else _LINUX_START_PATHS
        start = confine.Profile(
            mode="only",
            allow=profile.allow,
            write=profile.write,
            runtime=[*self._runtime, *system],
            executable=interpreter,
        )
        script = [self.python, "-I", "-S", os.path.join(_HERE, "helper.py")]
        mine, theirs = socket.socketpair()
        ruleset = -1
        try:
            argv = [*script, str(theirs.fileno()), profile.to_json(), self.probe]
            preexec = None
            if confine.PLATFORM == "macos":
                argv = [_SANDBOX_EXEC, "-p", confine.seatbelt_profile(start), *argv]
            else:
                ruleset = confine.linux_prepare(start, self._guard_opened)
                preexec = partial(confine.linux_restrict, ruleset, self.syscalls)
            subprocess.Popen(
                argv,
                pass_fds=[theirs.fileno()],
                stdin=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                preexec_fn=preexec,  # noqa: PLW1509 — two syscalls through a handle already loaded
            )
        except BaseException:
            mine.close()
            raise
        finally:
            theirs.close()
            if ruleset >= 0:
                os.close(ruleset)
        fd = mine.detach()
        return fd

    # ------------------------------------------------------------------ slot

    def _new_slot(self) -> int:
        with _live_lock:
            if self._slot_threads >= _MAX_SLOT_THREADS:
                raise Refused("too many commands are running")
            self._slot_threads += 1
            self._next_slot += 1
            slot_id = self._next_slot
            self._slot_pids[slot_id] = 0
            while len(self._slot_pids) > 4096:
                self._slot_pids.pop(next(iter(self._slot_pids)))
        return slot_id

    def slot(self, raw: dict, stub_fd: int) -> int:
        self.check(raw)  # refused now if it can be; checked again when it runs
        return self._start_slot(raw, stub_fd)

    def unconfined_slot(self, stub_fd: int) -> int:
        """A slot for one of :data:`UNCONFINED_PROGRAMS`, run without a sandbox."""
        return self._start_slot(None, stub_fd)

    def _start_slot(self, raw: dict | None, stub_fd: int) -> int:
        slot_id = self._new_slot()
        stub = socket.socket(fileno=stub_fd)
        threading.Thread(target=self._run_slot, args=(raw, stub, slot_id), daemon=True).start()
        return slot_id

    def slot_pid(self, slot_id: int) -> int:
        """The command's pid (it leads its own session), or 0 before it started."""
        with _live_lock:
            return self._slot_pids.get(slot_id, 0)

    def _launch(
        self, profile: confine.Profile, request: dict, argv: list[str], extra: list[list[int]], env: dict
    ) -> tuple[list[str], Any, int]:
        """The command line starting *argv* confined from its first instruction, its preexec and its ruleset fd.

        Nothing the main process can write may run unconfined: not the
        trampoline, not the interpreter, not a library its environment names.
        """
        program = request.get("program")
        direct = not extra and not request.get("ctty")
        env["CHRYS_FILE_SANDBOX_INHERITED"] = "1"
        spec = {"argv": argv, "program": program, "fd_map": extra, "ctty": bool(request.get("ctty"))}
        trampoline = [self.python, "-I", "-S", os.path.join(_HERE, "trampoline.py"), json.dumps(spec)]
        if confine.PLATFORM == "macos":
            target = argv if direct and program in (None, argv[0]) else trampoline
            return [_SANDBOX_EXEC, "-p", confine.seatbelt_profile(profile), *target], None, -1
        ruleset = confine.linux_prepare(profile, self._guard_opened)
        return (argv if direct else trampoline), partial(confine.linux_restrict, ruleset, self.syscalls), ruleset

    def _run_slot(self, raw: dict | None, stub: socket.socket, slot_id: int) -> None:
        received: list[int] = []
        ruleset = -1
        try:
            request, received = confine.recv(stub)
            if not isinstance(request, dict) or request.get("op") != "run":
                return
            argv = [str(a) for a in _strings(request.get("argv"))]
            targets = [int(t) for t in request.get("fd_targets", [])]
            if len(targets) != len(received) or not argv:
                confine.send(stub, {"exit": 127, "error": "malformed run request"})
                return
            fds = dict(zip(targets, received, strict=True))
            extra = [[fds[t], t] for t in targets if t > 2]
            env = {str(k): str(v) for k, v in request.get("env", {}).items()}
            preexec = None
            executable = None
            if raw is None:
                program = os.path.realpath(str(request.get("program") or argv[0]))
                if program not in UNCONFINED_PROGRAMS or extra:
                    confine.send(stub, {"exit": 126, "error": f"{program} may not run outside the sandbox"})
                    return
                command = [program, *argv[1:]]
                # It runs with the broker's rights: nothing of the caller's environment may load into it.
                env = {k: v for k, v in env.items() if k in _UNCONFINED_ENV}
            else:
                # Checked again now: the time between reserving a slot and running in it is the caller's to choose.
                profile = self.check(raw)
                command, preexec, ruleset = self._launch(profile, request, argv, extra, env)
                if ruleset >= 0 and command is argv:
                    executable = request.get("program") or None
            try:
                proc = subprocess.Popen(
                    command,
                    executable=executable,
                    stdin=fds.get(0, subprocess.DEVNULL),
                    stdout=fds.get(1, subprocess.DEVNULL),
                    stderr=fds.get(2, subprocess.DEVNULL),
                    cwd=request.get("cwd") or None,
                    env=env,
                    pass_fds=[pair[0] for pair in extra],
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=preexec,  # noqa: PLW1509 — two syscalls through a handle already loaded
                )
            except (OSError, subprocess.SubprocessError) as exc:
                confine.send(stub, {"exit": 127, "error": str(exc)})
                return
            finally:
                for fd in received:
                    os.close(fd)
                received = []
                if ruleset >= 0:
                    os.close(ruleset)
                    ruleset = -1
            with _live_lock:
                _live[proc.pid] = proc
                self._slot_pids[slot_id] = proc.pid
            try:
                # Watching first: a stub that died while this command started must still take it along.
                threading.Thread(target=self._watch_stub, args=(stub, proc), daemon=True).start()
                with contextlib.suppress(OSError):
                    confine.send(stub, {"pid": proc.pid})
                code = proc.wait()
                confine.send(stub, {"exit": code})
            finally:
                with _live_lock:
                    _live.pop(proc.pid, None)
                    _idle.notify_all()
        except Refused as exc:
            with contextlib.suppress(OSError):
                confine.send(stub, {"exit": 126, "error": str(exc)})
        except Exception:  # a malformed request ends this slot, never the broker
            with contextlib.suppress(OSError):
                confine.send(stub, {"exit": 127, "error": "malformed run request"})
        finally:
            for fd in received:
                os.close(fd)
            if ruleset >= 0:
                os.close(ruleset)
            stub.close()
            with _live_lock:
                self._slot_threads -= 1
                _idle.notify_all()

    @staticmethod
    def _watch_stub(stub: socket.socket, proc: subprocess.Popen) -> None:
        # The stub is the process iCode waits on; if it dies (SIGKILL included)
        # while the command runs, nothing of the command may outlive it.
        try:
            while stub.recv(1):
                pass
        except OSError:
            pass
        if proc.poll() is None:
            kill_session(proc.pid)

    # ------------------------------------------------------------------ loop

    def serve(self, control: socket.socket) -> None:
        while True:
            try:
                request, fds = confine.recv(control)
            except OSError, ConnectionError, ValueError:
                break
            if request is None:
                break
            try:
                if not isinstance(request, dict):
                    raise Refused("malformed request")
                op = request.get("op")
                if op == "helper":
                    fd = self.helper(request.get("profile", {}))
                    try:
                        confine.send(control, {"ok": True}, [fd])
                    finally:
                        os.close(fd)
                elif op == "slot":
                    if len(fds) != 1:
                        raise Refused("slot needs exactly one socket")
                    if request.get("unconfined"):
                        slot_id = self.unconfined_slot(fds[0])
                    else:
                        slot_id = self.slot(request.get("profile", {}), fds[0])
                    fds.pop()
                    confine.send(control, {"ok": True, "slot": slot_id})
                elif op == "slot_pid":
                    confine.send(control, {"ok": True, "pid": self.slot_pid(int(request.get("slot", 0)))})
                elif op == "ping":
                    confine.send(
                        control,
                        {"ok": True, "pid": os.getpid(), "floor": self.floor, "private_roots": self.private_roots},
                    )
                else:
                    raise Refused(f"unknown op {op!r}")
            except Refused as exc:
                confine.send(control, {"ok": False, "refused": True, "error": str(exc)})
            except (OSError, confine.ConfineError) as exc:
                confine.send(control, {"ok": False, "error": str(exc)})
            except Exception:  # a malformed request is refused, and must not stop the broker
                confine.send(control, {"ok": False, "refused": True, "error": "malformed request"})
            finally:
                for fd in fds:
                    os.close(fd)
        # A slot still starting has a command that isn't in ``_live`` yet.
        with _live_lock:
            while _live or self._slot_threads:
                _idle.wait()


def _strings(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and "\0" not in item for item in value):
        if value is None:
            return []
        raise Refused("expected a list of paths")
    return value


def _chain(path: str, seen: dict[str, set[tuple[int, int]]]) -> set[tuple[int, int]]:
    """(device, inode) of *path* and its ancestors; *seen* spares what paths in one profile share."""
    known = seen.get(path)
    if known is not None:
        return known
    own = confine._identity(path)
    parent = os.path.dirname(path)
    chain = set() if parent == path else set(_chain(parent, seen))
    if own is not None:
        chain.add(own)
    seen[path] = chain
    return chain


def _is_hard_linked(path: str) -> bool:
    try:
        info = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1


# Programs a confined process can't run at all (macOS refuses setuid binaries
# inside a sandbox) that read no files of their own: the broker runs them as
# they are. Resolved paths, fixed here — never taken from a request.
UNCONFINED_PROGRAMS = frozenset({"/bin/ps"})

# Only the system copy: a ``sandbox-exec`` found on PATH could be anything.
_SANDBOX_EXEC = "/usr/bin/sandbox-exec"

_UNCONFINED_ENV = frozenset({"PATH", "LANG", "LC_ALL", "COLUMNS", "TERM"})
_MAX_SLOT_THREADS = 1024

# What an interpreter reads while it starts, besides its own installation.
_MACOS_START_PATHS = ("/usr", "/System", "/bin", "/dev", "/private/var/db/dyld", "/private/etc")
_LINUX_START_PATHS = ("/usr", "/lib", "/lib64", "/bin", "/etc", "/dev", "/proc")

_BUILTIN_FLOOR = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".netrc",
    ".git-credentials",
    ".password-store",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Safari",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/com.operasoftware.Opera",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/microsoft-edge",
    ".config/vivaldi",
    ".config/opera",
    ".local/share/keyrings",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".pypirc",
    ".npmrc",
)


def _no_late_imports(event: str, _args: tuple) -> None:
    # The standard library can be overwritten by the main process once it runs:
    # after startup this process must not load another line of code from disk.
    if event == "import":
        raise ImportError("the sandbox broker imports nothing after startup")


# What runs with the person's full rights later, so a command changing it escapes
# the sandbox. Never writable, whatever is asked; kept in sync with
# ``policy.BUILTIN_WRITE_FLOOR``.
_BUILTIN_WRITE_FLOOR = (
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".config/fish",
    "Library/LaunchAgents",
    ".config/systemd",
    ".config/autostart",
    ".config/environment.d",
    ".gitconfig",
    ".config/git",
    ".cargo/config",
    ".cargo/config.toml",
    ".vimrc",
    ".config/nvim",
    ".local/bin",
    ".cargo/bin",
    "bin",
    ".claude",
    ".codex",
    ".bash_aliases",
    ".config/zsh",
    ".oh-my-zsh",
    ".tmux.conf",
    ".vim",
    ".emacs.d",
    ".local/lib",
    ".agents",
    ".pyenv",
    ".nvm",
    "go/bin",
    ".bun/bin",
    ".config/pip",
    ".config/uv",
    ".ipython",
    ".gradle/init.d",
    ".m2/settings.xml",
    "Library/Application Support/Code/User",
    ".config/Code/User",
    ".cursor",
    ".gemini",
    ".hgrc",
    ".config/direnv",
    ".hammerspoon",
    "Library/Application Support/iTerm2/Scripts",
    "Library/Application Support/Cursor/User",
    ".config/Cursor/User",
)


def main() -> int:
    control = socket.socket(fileno=int(sys.argv[1]))
    config = json.loads(sys.argv[2])
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ctrl-C belongs to iCode
    broker = Broker(config)
    sys.addaudithook(_no_late_imports)
    try:
        broker.serve(control)
    except BaseException:
        # Nothing watches their stubs any more.
        with _live_lock:
            for pid in list(_live):
                kill_session(pid)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
