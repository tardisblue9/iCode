# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The broker against a fully compromised main process.

Each test talks to a real broker, started from a copy of ``runtime/`` it can
overwrite, over its control socket: exactly what arbitrary Python in the main
process could do. Fake credentials stand in for the floor, in a fake home.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import psutil
import pytest

from icode_sandbox.client import _running_binary
from icode_sandbox.runtime import confine

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel

RUNTIME = Path(confine.__file__).resolve().parent
SECRET = "FAKE-PRIVATE-KEY"


@dataclass
class Broker:
    root: Path
    runtime: Path
    control: socket.socket
    process: subprocess.Popen
    floor: Path

    @property
    def key(self) -> Path:
        return self.floor / "id_rsa"

    def call(self, message: object, fds: list[int] | None = None) -> tuple[dict, list[int]]:
        confine.send(self.control, message, fds or [])  # type: ignore[arg-type]
        reply, received = confine.recv(self.control)
        assert reply is not None, "the broker went away"
        return reply, received

    def alive(self) -> bool:
        return self.call({"op": "ping"})[0].get("ok") is True and self.process.poll() is None

    def profile(self, *allow: str, write: tuple[str, ...] = ()) -> dict:
        runtime = [sys.prefix, sys.base_prefix, str(self.runtime), *allow]
        return {
            "mode": "except",
            "allow": runtime,
            "deny_roots": [str(self.root)],
            "write": list(write),
            "write_allow": [str(self.root / "ws")],
        }

    def run(
        self, profile: dict, argv: list[str], *, program: str | None = None, env: dict | None = None
    ) -> tuple[int, str]:
        """Reserve a slot and run *argv* in it; returns its exit code and output."""
        return self.redeem(self.reserve(profile), argv, program=program, env=env)

    def reserve(self, profile: dict) -> socket.socket:
        mine, theirs = socket.socketpair()
        reply, _ = self.call({"op": "slot", "profile": profile}, [theirs.fileno()])
        theirs.close()
        if not reply.get("ok"):
            mine.close()
            raise PermissionError(reply.get("error"))
        return mine

    def redeem(
        self,
        stub: socket.socket,
        argv: list[str],
        *,
        program: str | None = None,
        env: dict | None = None,
        extra_fd: bool = False,
    ) -> tuple[int, str]:
        read_end, write_end = os.pipe()
        targets, sent = [1, 2], [write_end, write_end]
        if extra_fd:  # fds beyond stdio have to be placed by the trampoline
            targets.append(3)
            sent.append(write_end)
        message = {
            "op": "run",
            "argv": argv,
            "program": program,
            "cwd": str(self.root),
            "env": {**os.environ, **(env or {})},
            "fd_targets": targets,
        }
        confine.send(stub, message, sent)
        os.close(write_end)
        output = b""
        while chunk := os.read(read_end, 65536):
            output += chunk
        os.close(read_end)
        code = 127
        while True:
            reply, _ = confine.recv(stub)
            if reply is None:
                break
            if "exit" in reply:
                code = int(reply["exit"])
                output += str(reply.get("error", "")).encode()
                break
        stub.close()
        return code, output.decode(errors="replace")


@pytest.fixture
def broker(sandbox: Sandbox) -> Iterator[Broker]:
    root = sandbox.root
    runtime = root / "runtime"
    shutil.copytree(RUNTIME, runtime, ignore=shutil.ignore_patterns("__pycache__"))
    floor = root / "fake-ssh"
    floor.mkdir()
    (floor / "id_rsa").write_text(SECRET, encoding="utf-8")
    mine, theirs = socket.socketpair()
    config = {
        "python": sys.executable,
        "python_binary": _running_binary(),
        "floor": [str(floor)],
        "private_roots": [str(root)],
    }
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", str(runtime / "broker.py"), str(theirs.fileno()), json.dumps(config)],
        pass_fds=[theirs.fileno()],
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    theirs.close()
    handle = Broker(root, runtime, mine, process, floor)
    try:
        assert handle.alive()  # it has taken the floor's identity by the time it answers
        yield handle
    finally:
        mine.close()
        process.wait(timeout=20)


def _start_helper(broker: Broker) -> socket.socket | None:
    reply, fds = broker.call(
        {
            "op": "helper",
            "profile": {"mode": "only", "allow": [str(broker.root / "ws")], "write": [str(broker.root / "ws")]},
        }
    )
    if not reply.get("ok"):
        return None
    return socket.socket(fileno=fds[0])


def test_commands_still_run_and_are_confined(broker: Broker) -> None:
    allowed = broker.profile(str(broker.root / "ws"))
    code, out = broker.run(allowed, ["/bin/cat", str(broker.root / "ws" / "f.txt")])
    assert (code, out) == (0, "WS")
    code, out = broker.run(allowed, ["/bin/cat", str(broker.key)])
    assert code != 0 and SECRET not in out
    code, out = broker.run(allowed, ["/bin/cat", str(broker.root / "other" / "f.txt")])
    assert code != 0 and "OTHER" not in out


def test_the_trampoline_path_still_runs_and_is_confined(broker: Broker) -> None:
    allowed = broker.profile(str(broker.root / "ws"))
    code, out = broker.run(allowed, ["renamed-cat", str(broker.root / "ws" / "f.txt")], program="/bin/cat")
    assert (code, out) == (0, "WS")
    code, out = broker.run(allowed, ["renamed-cat", str(broker.key)], program="/bin/cat")
    assert code != 0 and SECRET not in out


def test_an_overwritten_trampoline_runs_confined(broker: Broker) -> None:
    """The main process can write anywhere, the broker's own scripts included."""
    ran = broker.root / "ws" / "ran"
    (broker.runtime / "trampoline.py").write_text(
        f"import sys\nopen({str(ran)!r}, 'w').write('yes')\nprint(open({str(broker.key)!r}).read())\n",
        encoding="utf-8",
    )
    stub = broker.reserve(broker.profile(str(broker.root / "ws")))
    _code, out = broker.redeem(stub, ["x", "y"], program="/bin/cat", extra_fd=True)
    assert ran.read_text(encoding="utf-8") == "yes", out  # the tampered script did run
    assert SECRET not in out


def test_an_overwritten_helper_runs_confined(broker: Broker) -> None:
    """The same for the file helper: what it could read is what its profile says."""
    ws = broker.root / "ws"
    (broker.runtime / "helper.py").write_text(
        "import os\n"
        f"ws = {str(ws)!r}\n"
        "open(os.path.join(ws, 'ran'), 'w').write('yes')\n"
        f"for name, path in (('key', {str(broker.key)!r}), ('other', {str(broker.root / 'other' / 'f.txt')!r})):\n"
        "    try:\n"
        "        data = open(path).read()\n"
        "    except OSError as exc:\n"
        "        data = 'refused'\n"
        "    open(os.path.join(ws, name), 'w').write(data)\n",
        encoding="utf-8",
    )
    helper = _start_helper(broker)
    assert helper is not None
    helper.close()
    for _ in range(100):
        if (ws / "other").exists():
            break
        time.sleep(0.05)
    assert (ws / "ran").read_text(encoding="utf-8") == "yes"
    assert (ws / "key").read_text(encoding="utf-8") == "refused"
    assert (ws / "other").read_text(encoding="utf-8") == "refused"


@pytest.mark.skipif(shutil.which("cc") is None, reason="needs a C compiler")
def test_a_library_named_in_the_environment_loads_confined(broker: Broker, tmp_path: Path) -> None:
    """``DYLD_INSERT_LIBRARIES``/``LD_PRELOAD`` run code before the interpreter's first line."""
    leak = broker.root / "ws" / "leak"
    source = tmp_path / "evil.c"
    source.write_text(
        "#include <stdio.h>\n__attribute__((constructor)) static void run(void) {\n"
        f'  FILE *in = fopen("{broker.key}", "r");\n'
        f'  FILE *out = fopen("{leak}", "a");\n'
        '  if (!out) return;\n  if (!in) { fputs("refused\\n", out); fclose(out); return; }\n'
        "  char line[128]; while (fgets(line, sizeof line, in)) fputs(line, out);\n  fclose(out);\n}\n",
        encoding="utf-8",
    )
    library = broker.root / "ws" / ("evil.dylib" if sys.platform == "darwin" else "evil.so")
    flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC"]
    subprocess.run(["cc", *flags, "-o", str(library), str(source)], check=True, stdin=subprocess.DEVNULL)
    name = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
    # Outside the sandbox the library does get in: this attack is a real one.
    subprocess.run(
        [sys.executable, "-I", "-S", "-c", "pass"],
        env={**os.environ, name: str(library)},
        stdin=subprocess.DEVNULL,
        check=True,
    )
    assert SECRET in leak.read_text(encoding="utf-8")
    leak.unlink()
    broker.run(
        broker.profile(str(broker.root / "ws")),
        ["renamed-cat", str(broker.root / "ws" / "f.txt")],
        program="/bin/cat",
        env={name: str(library)},
    )
    # macOS: dyld drops the variable for a protected program, so it never loads. Linux: it loads, confined.
    written = leak.read_text(encoding="utf-8") if leak.exists() else ""
    assert SECRET not in written


@pytest.mark.parametrize("via", ["helper", "command"])
def test_a_renamed_floor_is_still_the_floor(broker: Broker, via: str) -> None:
    """The broker remembers what the floor is, not only what it is called."""
    moved = broker.root / "renamed"
    broker.floor.rename(moved)
    if via == "helper":
        reply, fds = broker.call({"op": "helper", "profile": {"mode": "only", "allow": [str(moved)]}})
        for fd in fds:
            os.close(fd)
        assert reply.get("ok") is not True
    else:
        with pytest.raises(PermissionError):
            broker.reserve(broker.profile(str(moved)))


def test_a_folder_holding_the_floor_cannot_be_renamed_and_granted(sandbox: Sandbox) -> None:
    """Nor can what holds it: a grant of the new name would open everything below."""
    outer = sandbox.root / "outer"
    (outer / "inner").mkdir(parents=True)
    (outer / "inner" / "id_rsa").write_text(SECRET, encoding="utf-8")
    mine, theirs = socket.socketpair()
    config = {
        "python": sys.executable,
        "python_binary": _running_binary(),
        "floor": [str(outer / "inner")],
        "private_roots": [str(sandbox.root)],
    }
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", str(RUNTIME / "broker.py"), str(theirs.fileno()), json.dumps(config)],
        pass_fds=[theirs.fileno()],
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    theirs.close()
    try:
        confine.send(mine, {"op": "ping"})
        assert confine.recv(mine)[0]["ok"] is True
        outer.rename(sandbox.root / "moved")
        confine.send(mine, {"op": "helper", "profile": {"mode": "only", "allow": [str(sandbox.root / "moved")]}})
        reply, fds = confine.recv(mine)
        for fd in fds:
            os.close(fd)
        assert reply["ok"] is False and reply.get("refused") is True
    finally:
        mine.close()
        process.wait(timeout=20)


def test_a_path_swapped_for_a_link_after_the_check_opens_nothing(broker: Broker) -> None:
    """The caller chooses when a reserved slot runs, so the check is made again then."""
    swap = broker.root / "swap"
    swap.mkdir()
    (swap / "id_rsa").write_text("HARMLESS", encoding="utf-8")
    stub = broker.reserve(broker.profile(str(swap)))
    (swap / "id_rsa").unlink()
    swap.rmdir()
    swap.symlink_to(broker.floor)
    code, out = broker.redeem(stub, ["/bin/cat", str(swap / "id_rsa")])
    assert code != 0 and SECRET not in out


def test_a_protected_path_outside_the_private_roots_is_denied(tmp_path: Path, sandbox: Sandbox) -> None:
    """The floor is what can never be read, not just what can never be granted."""
    outside = tmp_path / "secrets"
    outside.mkdir()
    (outside / "k").write_text(SECRET, encoding="utf-8")
    (sandbox.root / "config" / "settings.yaml").write_text(f"sandbox.files.floor.extra: {outside}\n", encoding="utf-8")
    r = sandbox.run(
        f"""
check("main", lambda: open({str(outside / "k")!r}).read())
check("command", lambda: cat({str(outside / "k")!r}))
"""
    )
    assert r["main"]["ok"] is False
    assert r["command"]["ok"] is False


@pytest.mark.parametrize(
    "message",
    [
        [1],
        "text",
        {"op": "helper", "profile": 5},
        {"op": "helper", "profile": {"mode": "only", "allow": 5}},
        {"op": "helper", "profile": {"mode": "only", "allow": ["/tmp/a\0b"]}},
        {"op": "slot_pid", "slot": "x"},
        {"op": "nonsense"},
    ],
)
def test_a_malformed_request_is_refused_and_the_broker_stays(broker: Broker, message: object) -> None:
    """Garbage on the broker socket is refused, and the broker keeps serving."""
    reply, fds = broker.call(message)
    for fd in fds:
        os.close(fd)
    assert reply["ok"] is False
    assert broker.alive()


def test_a_malformed_run_request_ends_only_its_slot(broker: Broker) -> None:
    stub = broker.reserve(broker.profile())
    confine.send(stub, {"op": "run", "argv": 5, "fd_targets": []})
    reply, _ = confine.recv(stub)
    assert reply is not None and reply.get("exit") in (126, 127)
    stub.close()
    assert broker.alive()


def test_a_refused_slot_does_not_leak_its_socket(broker: Broker) -> None:
    mine, theirs = socket.socketpair()
    reply, _ = broker.call({"op": "slot", "profile": {"mode": "except", "allow": [str(broker.key)]}}, [theirs.fileno()])
    theirs.close()
    assert reply["ok"] is False
    mine.settimeout(5)
    assert mine.recv(1) == b""  # the broker closed its end
    mine.close()


def test_hostile_characters_in_a_path_do_not_change_the_rules(broker: Broker) -> None:
    """Seatbelt has no escape for the closing quote of a regex literal."""
    hostile = broker.root / 'x";(allow file-read-data);"'
    code, out = broker.run(broker.profile(str(hostile), str(broker.root / "ws")), ["/bin/cat", str(broker.key)])
    assert code != 0 and SECRET not in out
    code, out = broker.run(
        broker.profile(str(hostile), str(broker.root / "ws")), ["/bin/cat", str(broker.root / "ws" / "f.txt")]
    )
    assert (code, out) == (0, "WS")


def test_a_hard_link_to_something_else_is_not_granted_by_name(broker: Broker) -> None:
    """Its name is outside the floor, its contents aren't."""
    link = broker.root / "ws" / "link"
    os.link(broker.key, link)
    reply, fds = broker.call({"op": "helper", "profile": {"mode": "only", "allow": [str(link)]}})
    for fd in fds:
        os.close(fd)
    assert reply["ok"] is False
    code, out = broker.run(broker.profile(str(link)), ["/bin/cat", str(link)])
    assert code != 0 and SECRET not in out


def test_the_broker_loads_no_code_after_startup(broker: Broker) -> None:
    """The standard library can be overwritten too; every code path it needs is loaded up front."""
    allowed = broker.profile(str(broker.root / "ws"))
    assert broker.run(allowed, ["/bin/cat", str(broker.root / "ws" / "f.txt")]) == (0, "WS")
    assert broker.run(allowed, ["renamed", str(broker.root / "ws" / "f.txt")], program="/bin/cat") == (0, "WS")
    helper = _start_helper(broker)
    assert helper is not None
    assert confine.recv(helper)[0]["ready"] is True  # type: ignore[index]
    helper.close()
    assert broker.alive()


def test_a_floor_path_created_later_is_known_by_identity_too(sandbox: Sandbox) -> None:
    """A protected folder that didn't exist at startup still can't be renamed and granted."""
    later = sandbox.root / "later-keys"
    mine, theirs = socket.socketpair()
    config = {
        "python": sys.executable,
        "python_binary": _running_binary(),
        "floor": [str(later)],
        "private_roots": [str(sandbox.root)],
    }
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", str(RUNTIME / "broker.py"), str(theirs.fileno()), json.dumps(config)],
        pass_fds=[theirs.fileno()],
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    theirs.close()
    try:
        confine.send(mine, {"op": "ping"})
        assert confine.recv(mine)[0]["ok"] is True
        later.mkdir()
        time.sleep(1.1)  # the broker notes the floor again at most once a second
        confine.send(mine, {"op": "helper", "profile": {"mode": "only", "allow": [str(sandbox.root / "ws")]}})
        _, fds = confine.recv(mine)
        for fd in fds:
            os.close(fd)
        moved = sandbox.root / "moved-keys"
        later.rename(moved)
        confine.send(mine, {"op": "helper", "profile": {"mode": "only", "allow": [str(moved)]}})
        reply, fds = confine.recv(mine)
        for fd in fds:
            os.close(fd)
        assert reply["ok"] is False and reply.get("refused") is True
    finally:
        mine.close()
        process.wait(timeout=20)


@pytest.mark.skipif(
    confine.PLATFORM != "linux", reason="Landlock rules attach to what is opened; Seatbelt matches paths"
)
def test_rule_paths_are_opened_without_following_links(tmp_path: Path) -> None:
    """Whatever a request's path has become by now, a link in it grants nothing."""
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "link").symlink_to(target)
    fd = confine._open_without_links(str(target), None)
    assert fd >= 0
    os.close(fd)
    assert confine._open_without_links(str(tmp_path / "link"), None) == -1
    assert confine._open_without_links(str(tmp_path / "link" / "below"), None) == -1
    assert confine._open_without_links(str(tmp_path / "missing"), None) == -1


def test_a_signal_before_the_command_started_still_reaches_it(tmp_path: Path) -> None:
    """The stub is what iCode holds: a stop sent to it at once must not be lost while the broker starts the command."""
    mine, theirs = socket.socketpair()
    stub = subprocess.Popen(
        [sys.executable, "-I", "-S", str(RUNTIME / "stub.py"), str(theirs.fileno()), json.dumps({"argv": ["x"]})],
        pass_fds=[theirs.fileno()],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    theirs.close()
    command = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], stdin=subprocess.DEVNULL, start_new_session=True
    )
    try:
        request, fds = confine.recv(mine)  # the stub is up, its handlers are installed, nothing has a pid yet
        assert request is not None and request["op"] == "run"
        for fd in fds:
            os.close(fd)
        stub.terminate()
        time.sleep(0.2)
        assert command.poll() is None
        assert stub.poll() is None  # it waits for the command, as it always does
        confine.send(mine, {"pid": command.pid})
        assert command.wait(10) == -15
        confine.send(mine, {"exit": -15})
        assert stub.wait(10) == -15
    finally:
        command.kill()
        command.wait(10)
        stub.kill()
        stub.wait(10)
        mine.close()


def test_a_command_whose_stub_died_as_it_started_does_not_outlive_it(broker: Broker) -> None:
    """The stub dies with no one reading the broker's reply: the command must still go with it."""
    allowed = broker.profile(str(broker.root / "ws"))
    # Stopped by its reader going away: the frame is in flight when the stub's end closes, whichever gets there first.
    stub = broker.reserve(allowed)
    confine.send(
        stub,
        {
            "op": "run",
            "argv": [sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)"],
            "cwd": str(broker.root / "ws"),
            "env": dict(os.environ),
            "fd_targets": [],
        },
    )
    stub.shutdown(socket.SHUT_RD)
    stub.close()

    def running() -> list[psutil.Process]:
        # This broker started nothing else, but for the ``ps`` it lists sessions with.
        # A confined process's command line isn't readable from here.
        children = psutil.Process(broker.process.pid).children(recursive=True)
        return [p for p in children if p.status() != psutil.STATUS_ZOMBIE and p.name() != "ps"]

    # Long enough for the command to have started; once the fix is gone it stays for its full minute.
    time.sleep(1)
    deadline = time.monotonic() + 10
    while running() and time.monotonic() < deadline:
        time.sleep(0.05)
    left = running()
    for process in left:
        process.kill()
    assert not left


def test_the_broker_stays_until_a_starting_command_is_watched(broker: Broker) -> None:
    """Closing the control socket while a slot is reserved must not leave what it starts unwatched."""
    stub = broker.reserve(broker.profile())
    broker.control.close()
    time.sleep(0.2)
    assert broker.process.poll() is None  # the slot is still open
    stub.close()
    assert broker.process.wait(timeout=10) == 0


_LAUNCHER_C = r"""
#include <unistd.h>
int main(int argc, char **argv) { (void)argc; execv(REAL, argv); return 127; }
"""


@pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("cc") is None,
    reason="macOS framework builds launch the real binary; needs cc",
)
def test_a_helper_starts_when_the_interpreter_is_a_launcher(sandbox: Sandbox) -> None:
    """``sys.executable`` may only launch the binary that runs (python.org's macOS build execs Python.app's).

    A helper may execute only its interpreter: the binary the launcher starts must be allowed too, or
    every helper dies before its first line.
    """
    import psutil

    real = psutil.Process().exe()
    root = sandbox.root
    runtime = root / "runtime"
    shutil.copytree(RUNTIME, runtime, ignore=shutil.ignore_patterns("__pycache__"))
    source = root / "launcher.c"
    source.write_text(_LAUNCHER_C.replace("REAL", json.dumps(real)), encoding="utf-8")
    launcher = runtime / "python"  # beside the runtime: readable to the helper, as an interpreter's folder is
    subprocess.run(["cc", "-o", str(launcher), str(source)], check=True, capture_output=True, stdin=subprocess.DEVNULL)
    for config in ({"python": str(launcher), "python_binary": real}, {"python": str(launcher)}):
        mine, theirs = socket.socketpair()
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", str(runtime / "broker.py"), str(theirs.fileno()), json.dumps(config)],
            pass_fds=[theirs.fileno()],
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        theirs.close()
        ok = False
        try:
            handle = Broker(root, runtime, mine, process, root)
            helper = _start_helper(handle)
            if helper is not None:
                helper.settimeout(20)
                try:
                    confine.send(helper, {"op": "open", "path": str(root / "ws" / "f.txt"), "flags": os.O_RDONLY})
                    reply, fds = confine.recv(helper)
                    for fd in fds:
                        os.close(fd)
                    ok = bool(reply and reply.get("ok"))
                except OSError:
                    ok = False
                helper.close()
        finally:
            mine.close()
            process.wait(timeout=20)
        if "python_binary" in config:
            assert ok, "the helper did not start with its interpreter's binary allowed"
        else:
            assert not ok  # control: without the binary allowed, the launcher's exec is refused
