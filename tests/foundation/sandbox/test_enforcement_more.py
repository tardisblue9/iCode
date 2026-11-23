# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The kernel really refuses, the rest: moves and links, one-shot reads, helper confinement,
narrowing under concurrency, failure handling and the off switch.

Each scenario runs in a fresh process that enables the sandbox like ``icode``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel


def test_files_cannot_be_moved_or_linked_out_of_the_private_region(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
for name in ("a", "b", "c"):
    open(os.path.join(OTHER, name), "w").write("SECRET-" + name)
sh = lambda c: subprocess.run(["sh", "-c", c], capture_output=True, text=True, stdin=subprocess.DEVNULL)
check("mv out", lambda: sh(f"mv {OTHER}/a {WS}/a; cat {WS}/a").stdout)
check("ln out", lambda: sh(f"ln {OTHER}/b {WS}/b; cat {WS}/b").stdout)
check("python rename in a command", lambda: sh(f"python3 -c \\"import os; os.rename('{OTHER}/c', '{WS}/c'); print(open('{WS}/c').read())\\"").stdout)
check("mv inside workspace", lambda: sh(f"echo x > {WS}/m && mv {WS}/m {WS}/m2 && cat {WS}/m2").stdout)
fresh_cache = os.path.join(os.path.expanduser("~"), ".cache", "icode-sbtest-" + str(os.getpid()))
check("new toolchain cache is usable", lambda: sh(f"mkdir -p {fresh_cache} && echo y > {fresh_cache}/t && mv {fresh_cache}/t {fresh_cache}/u && cat {fresh_cache}/u; rm -rf {fresh_cache}").stdout)
check("rm inside workspace", lambda: sh(f"rm {WS}/m2 && echo gone").stdout)
"""
    )
    for name in ("mv out", "ln out", "python rename in a command"):
        assert "SECRET" not in r[name]["value"], (name, r[name])
    assert r["mv inside workspace"]["value"].strip() == "x"
    assert r["rm inside workspace"]["value"].strip() == "gone"
    assert r["new toolchain cache is usable"]["value"].strip() == "y"
    for name in ("a", "b", "c"):
        assert (sandbox.other / name).exists(), name


def test_user_reads_open_exactly_the_picked_file(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
open(os.path.join(OTHER, "g.txt"), "w").write("SIBLING")
def picked(path):
    with client.user_reads():
        return open(path).read()
check("picked file", lambda: picked(os.path.join(OTHER, "f.txt")))
check("sibling afterwards", lambda: open(os.path.join(OTHER, "g.txt")).read())
check("picked protected file", lambda: picked(os.path.expanduser("~/.ssh/config")))
"""
    )
    assert r["picked file"]["value"] == "OTHER"
    assert not r["sibling afterwards"]["ok"]
    assert not r["picked protected file"]["ok"]


def test_attached_images_outside_the_workspace_load(sandbox: Sandbox) -> None:
    import base64

    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="
    )
    (sandbox.other / "pic.png").write_bytes(png)
    r = sandbox.run(
        """
from pathlib import Path
from chrys.orchestration.engine.run.attachments import parse_image_mentions
res = parse_image_mentions(f"see @{OTHER}/pic.png", Path(WS))
check("attachments", lambda: [len(res.attachments), list(res.errors)])
res2 = parse_image_mentions(f"see @{os.path.expanduser('~/.ssh/nope.png')}", Path(WS))
check("no stray reads", lambda: len(res2.attachments))
"""
    )
    assert r["attachments"]["value"] == [1, []]
    assert r["no stray reads"]["value"] == 0


def test_helper_profile_forbids_exec_network_and_writes(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "f").write_text("ok", encoding="utf-8")
    script = f"""
import os, socket, subprocess, sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[3] / "packages" / "icode-sandbox" / "src" / "icode_sandbox" / "runtime")!r})
import confine
confine.apply(confine.Profile(mode="only", allow=[{str(allowed)!r}]))
out = {{}}
def t(name, fn):
    try:
        fn(); out[name] = "allowed"
    except Exception as exc:
        out[name] = type(exc).__name__
t("read allowed", lambda: open({str(allowed / "f")!r}).read())
t("write allowed dir", lambda: open({str(allowed / "w")!r}, "w").write("x"))
t("read /etc", lambda: open("/etc/hosts").read())
t("exec", lambda: subprocess.run(["/bin/echo", "x"], check=True, stdin=subprocess.DEVNULL))
t("connect", lambda: socket.create_connection(("1.1.1.1", 443), 3))
print(out)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script], capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False
    )
    out = eval(result.stdout.strip().splitlines()[-1])
    assert out["read allowed"] == "allowed"
    for name in ("write allowed dir", "read /etc", "exec", "connect"):
        assert out[name] != "allowed", (name, out)


def test_narrowing_leaves_no_window_under_concurrency(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import threading, time
scope = policy.Scope(key="race", roots=(WS,))
target = os.path.join(OTHER, "f.txt")
RT.grant(scope, "turn", OTHER)
stop = threading.Event(); successes = []
def reader():
    while not stop.is_set():
        started = time.monotonic()  # a read that *starts* after narrowing must fail
        try:
            fd = RT.open_scoped(scope, target, os.O_RDONLY); os.close(fd); successes.append(started)
        except PermissionError:
            pass
threads = [threading.Thread(target=reader) for _ in range(4)]
[t.start() for t in threads]
time.sleep(0.3)
RT.end_turn("race")
ended = time.monotonic()  # end_turn has returned: narrowing is complete
time.sleep(0.3)
stop.set(); [t.join() for t in threads]
check("reads before", lambda: sum(1 for s in successes if s < ended) > 0)
check("reads after narrowing", lambda: sum(1 for s in successes if s > ended))
"""
    )
    assert r["reads before"]["value"] is True
    assert r["reads after narrowing"]["value"] == 0


def test_a_crashed_helper_is_replaced(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import signal
scope = policy.Scope(key="crash", roots=(WS,))
read = lambda: os.read(RT.open_scoped(scope, os.path.join(WS, "f.txt"), os.O_RDONLY), 10).decode()
check("before", read)
pid = RT._scope_helpers["crash"].pid
assert pid > 0, "kill(0) would hit the whole test run"
os.kill(pid, signal.SIGKILL)
check("after crash", read)
check("new helper", lambda: RT._scope_helpers["crash"].pid != pid)
"""
    )
    assert r["before"]["value"] == "WS"
    assert r["after crash"]["value"] == "WS"
    assert r["new helper"]["value"] is True


def test_a_lost_broker_fails_closed_and_degrades(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import signal, time
os.kill(RT.broker_pid(), signal.SIGKILL)
time.sleep(0.3)
scope = policy.Scope(key="lost", roots=(WS,))
check("scoped read", lambda: RT.open_scoped(scope, os.path.join(WS, "f.txt"), os.O_RDONLY))
check("command", lambda: cat(os.path.join(WS, "f.txt")))
check("main still confined", lambda: open(os.path.join(OTHER, "f.txt")).read())
check("state", lambda: client.status().label())
"""
    )
    assert not r["scoped read"]["ok"]
    assert not r["command"]["ok"]
    assert not r["main still confined"]["ok"]
    assert r["state"]["value"] == "degraded"


def test_self_check_failure_refuses_to_start(sandbox: Sandbox) -> None:
    script = """
import sys
from pathlib import Path
from icode_sandbox.runtime import confine
confine.apply = lambda profile: None   # simulate a kernel that silently ignores the profile
from icode_sandbox import bootstrap
bootstrap.install_at_startup(["--sandbox", "-C", sys.argv[1]], config_dir=Path(sys.argv[2]))
print("STARTED")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(sandbox.ws), str(sandbox.root / "config")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "CHRYS_FILE_SANDBOX_ON_UNAVAILABLE": "refuse"},
        check=False,
    )
    assert result.returncode == 78, result
    assert "STARTED" not in result.stdout
    assert "self-check" in result.stderr


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the thread check guards Landlock")
def test_linux_refuses_when_threads_already_run(sandbox: Sandbox) -> None:
    script = """
import sys, threading, time
from pathlib import Path
threading.Thread(target=time.sleep, args=(5,), daemon=True).start()
from icode_sandbox import bootstrap
bootstrap.install_at_startup(["--sandbox", "-C", sys.argv[1]], config_dir=Path(sys.argv[2]))
print("STARTED")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(sandbox.ws), str(sandbox.root / "config")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
        env={**os.environ, "CHRYS_FILE_SANDBOX_ON_UNAVAILABLE": "refuse"},
    )
    assert result.returncode == 78 and "threads" in result.stderr, result


def test_unavailable_with_warn_starts_unconfined_and_says_so(sandbox: Sandbox) -> None:
    script = """
import builtins, sys
from pathlib import Path
from icode_sandbox.runtime import confine
confine.available = lambda: (False, "simulated: no backend")
from icode_sandbox import bootstrap, client
_, status = bootstrap.install_at_startup(["--sandbox", "-C", sys.argv[1]], config_dir=Path(sys.argv[2]))
print(status.label(), client.runtime() is None, client.status_line())
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(sandbox.ws), str(sandbox.root / "config")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
        env={**os.environ, "CHRYS_FILE_SANDBOX_ON_UNAVAILABLE": "warn"},
    )
    assert result.returncode == 0, result
    assert "requested-not-active True Sandbox: requested-not-active" in result.stdout
    assert "WARNING: sandbox requested but NOT active" in result.stderr


def test_off_means_untouched(sandbox: Sandbox) -> None:
    script = """
import builtins, io, os, subprocess, sys
from pathlib import Path
originals = (builtins.open, os.open, os.listdir, subprocess.Popen._execute_child)
from icode_sandbox import bootstrap, client
_, status = bootstrap.install_at_startup(["--no-sandbox", "-C", sys.argv[1]], config_dir=Path(sys.argv[2]))
same = originals == (builtins.open, os.open, os.listdir, subprocess.Popen._execute_child)
kids = subprocess.run(["pgrep", "-P", str(os.getpid())], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.split()
print(status.label(), client.runtime() is None, same, len(kids) <= 1, open(sys.argv[3]).read(), client.status_line())
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(sandbox.ws), str(sandbox.root / "config"), str(sandbox.other / "f.txt")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert result.stdout.split() == ["inactive", "True", "True", "True", "OTHER", "None"], result


def test_probe_reports_an_unsupported_platform(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from icode_sandbox import cli as sandbox_cli
    from icode_sandbox.runtime import confine

    monkeypatch.setattr(confine, "available", lambda: (False, "simulated: no backend"))
    assert sandbox_cli._probe(type("Args", (), {"json": False})()) == 2
    assert "not supported" in capsys.readouterr().out


def test_sessions_are_isolated_from_each_other(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
a = policy.Scope(key="A", roots=(WS,))
b = policy.Scope(key="B", roots=(OTHER,))
with client.scoped(a):
    check("A reads its own", lambda: open(os.path.join(WS, "f.txt")).read())
    check("A reads B's", lambda: open(os.path.join(OTHER, "f.txt")).read())
    check("A command reads B's", lambda: cat(os.path.join(OTHER, "f.txt")))
with client.scoped(b):
    check("B reads its own", lambda: open(os.path.join(OTHER, "f.txt")).read())
    check("B reads A's", lambda: open(os.path.join(WS, "f.txt")).read())
RT.release_scope("B")
check("released scope stops serving", lambda: "B" in RT._scope_helpers)
"""
    )
    assert r["A reads its own"]["value"] == "WS"
    assert not r["A reads B's"]["ok"]
    assert not r["A command reads B's"]["ok"]
    assert r["B reads its own"]["value"] == "OTHER"
    assert not r["B reads A's"]["ok"]
    assert r["released scope stops serving"]["value"] is False


def test_dev_alarm_names_a_bypassing_opener(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
from icode_sandbox import patches
scope = policy.Scope(key="alarm", roots=(WS,))
with client.scoped(scope):
    check("bypass", lambda: patches._original_io_open(os.path.join(OTHER, "f.txt")).read())
    check("normal", lambda: open(os.path.join(WS, "f.txt")).read())
events = [json.loads(line) for line in open(RT.audit_path)]
check("flagged", lambda: [e["path"].endswith("other/f.txt") for e in events if e["event"] == "bypass_suspect"])
"""
    )
    assert not r["bypass"]["ok"]  # the kernel still refused it
    assert r["normal"]["value"] == "WS"
    assert r["flagged"]["value"] == [True]


def test_working_directory_follows_chdir_even_after_deletion(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
import shutil, tempfile
gone = os.path.join(WS, "gone"); os.makedirs(gone)
os.chdir(gone)
check("cwd in workspace", lambda: os.getcwd())
shutil.rmtree(gone)
check("cwd deleted", lambda: os.getcwd())
os.chdir(OTHER)   # absolute: must work although the old directory is gone
check("cwd in private dir", lambda: os.getcwd())
os.chdir("..")
check("relative", lambda: os.getcwd())
os.chdir(tempfile.gettempdir())
check("public", lambda: os.getcwd())
"""
    )
    assert r["cwd in workspace"]["value"].endswith("/ws/gone")
    assert r["cwd deleted"]["error"] == "FileNotFoundError"
    assert r["cwd in private dir"]["value"].endswith("/other")
    assert r["relative"]["value"] == str(sandbox.root)
    assert r["public"]["ok"]


def test_terminal_programs_own_their_terminal(sandbox: Sandbox) -> None:
    """The TUI's terminal: the real program, not the stub, controls the pty (job control, Ctrl-C, resize).

    The master is read while the program runs, as the TUI does: a terminal's
    session leader waits for its output to be read before it can exit.
    """
    r = sandbox.run(
        """
import select, time
from functools import partial
from chrys.app.tui.terminal._pty_backend import kill_posix_process, prepare_child_pty
import pty
def spawn(code):
    master, slave = pty.openpty()
    with client.controlling_terminal():
        proc = subprocess.Popen([sys.executable, "-c", code], stdin=slave, stdout=slave, stderr=slave,
                                preexec_fn=partial(prepare_child_pty, slave))
    os.close(slave)
    return master, proc
def read_words(master, proc, count):
    out = b""
    deadline = time.monotonic() + 10
    while len(out.split()) < count and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 1024)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    return out.decode(errors="replace").split()
def controls():
    master, proc = spawn("import os; print(os.tcgetpgrp(0) == os.getpgrp(), os.getsid(0) == os.getpid(), flush=True)")
    words = read_words(master, proc, 99)  # to end of output: the program exits once it is read
    proc.wait(10)
    os.close(master)
    return words
check("controls its terminal", controls)
def killed():
    master, proc = spawn("import os, signal; print(os.getpid(), flush=True); signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.pause()")
    pid = int(read_words(master, proc, 1)[0])
    kill_posix_process(proc.pid, fallback_to_process=True)
    proc.wait(10)
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            os.close(master)
            return "gone"
        time.sleep(0.1)
    return "alive"
check("kill reaches it", killed)
"""
    )
    assert r["controls its terminal"]["value"] == ["True", "True"]
    assert r["kill reaches it"]["value"] == "gone"


def test_a_second_startup_in_the_process_keeps_the_sandbox(sandbox: Sandbox) -> None:
    r = sandbox.run(
        """
_, again = bootstrap.install_at_startup(["--no-sandbox", "-C", WS], config_dir=__import__("pathlib").Path(CONFIG))
check("still the same runtime", lambda: client.runtime() is RT)
check("state", lambda: again.label())
check("still confined", lambda: open(os.path.join(OTHER, "f.txt")).read())
"""
    )
    assert r["still the same runtime"]["value"] is True
    assert r["state"]["value"] == "active"
    assert not r["still confined"]["ok"]


def test_a_compromised_main_process_cannot_carry_the_floor_out(sandbox: Sandbox, tmp_path: Path) -> None:
    """Code running in iCode itself: not by rename, hard link, or moving a folder above the floor path."""
    home = sandbox.root / "fakehome"
    for name, body in ((".ssh/id_rsa", "KEY"), (".aws/creds", "CREDS"), (".config/gcloud/token", "TOKEN")):
        target = home / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    r = sandbox.run(
        """
HOME = os.path.expanduser("~")
def moved(fn, dest):
    fn(); return open(dest).read()
check("rename", lambda: moved(lambda: os.rename(HOME + "/.ssh/id_rsa", WS + "/a"), WS + "/a"))
check("rename folder", lambda: moved(lambda: os.rename(HOME + "/.ssh", WS + "/b"), WS + "/b/id_rsa"))
check("hard link", lambda: moved(lambda: os.link(HOME + "/.aws/creds", WS + "/c"), WS + "/c"))
check("rename the folder above", lambda: moved(lambda: os.rename(HOME + "/.config", WS + "/d"), WS + "/d/gcloud/token"))
""",
        env={"HOME": str(home)},
    )
    for name in ("rename", "rename folder", "hard link", "rename the folder above"):
        assert not r[name]["ok"], (name, r[name])
    assert (home / ".ssh" / "id_rsa").read_text(encoding="utf-8") == "KEY"
    assert (home / ".config" / "gcloud" / "token").read_text(encoding="utf-8") == "TOKEN"


@pytest.mark.skipif(sys.platform != "darwin", reason="LaunchServices and launchd are macOS")
def test_commands_cannot_have_the_system_start_a_program_outside_the_sandbox(sandbox: Sandbox) -> None:
    """``open`` on an app the command wrote itself, launchctl, Apple events: each would read outside the sandbox."""
    r = sandbox.run(
        """
import time
SECRET = os.path.join(OTHER, "f.txt")
app = os.path.join(WS, "h.app", "Contents")
os.makedirs(os.path.join(app, "MacOS"))
open(os.path.join(app, "Info.plist"), "w").write('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>h</string><key>CFBundleIdentifier</key><string>icode.sbtest.lsopen</string><key>LSBackgroundOnly</key><true/></dict></plist>')
script = os.path.join(app, "MacOS", "h")
open(script, "w").write(f"#!/bin/sh\\ncat {SECRET} > {WS}/via_open\\n")
os.chmod(script, 0o755)
sh = lambda c: subprocess.run(["sh", "-c", c], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
scope = policy.Scope(key="esc", roots=(WS,))
with client.scoped(scope):
    opened = sh(f"/usr/bin/open -g -j -n {WS}/h.app")
    label = "icode.sbtest.esc." + str(os.getpid())
    submitted = sh(f"launchctl submit -l {label} -- /bin/sh -c 'cat {SECRET} > {WS}/via_launchd'")
    events = sh("osascript -e 'tell application \\"Finder\\" to count windows'")
time.sleep(2)
subprocess.run(["launchctl", "remove", label], capture_output=True, stdin=subprocess.DEVNULL)
check("open refused", lambda: opened.returncode)
check("leak via open", lambda: os.path.exists(WS + "/via_open"))
check("leak via launchd", lambda: os.path.exists(WS + "/via_launchd"))
check("apple event refused", lambda: events.returncode)
"""
    )
    assert r["open refused"]["value"] != 0
    assert r["leak via open"]["value"] is False
    assert r["leak via launchd"]["value"] is False
    assert r["apple event refused"]["value"] != 0


def test_known_limits_are_what_the_docs_say(sandbox: Sandbox) -> None:
    """Pinned residual risks (EVALUATION.md): a change in either behaviour should be noticed.

    The sandbox governs file reads by this process tree. A daemon already running
    outside it can still be asked over a unix socket (docker, tmux, a D-Bus or
    systemd user session). The main process's own writes are not restricted.
    """
    import socket as sk
    import tempfile
    import threading

    socket_dir = tempfile.mkdtemp(dir="/tmp")
    path = os.path.join(socket_dir, "s")
    server = sk.socket(sk.AF_UNIX)
    server.bind(path)
    server.listen(1)

    def serve() -> None:
        connection, _ = server.accept()
        connection.sendall((sandbox.other / "f.txt").read_bytes())
        connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        r = sandbox.run(
            f"""
code = "import socket; s = socket.socket(socket.AF_UNIX); s.connect({path!r}); print(s.recv(100).decode())"
check("via a daemon", lambda: subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=20).stdout.strip())
def main_writes():
    with open(os.path.join(OTHER, "written"), "w") as stream:
        stream.write("w")
    return "done"
check("main process writes outside the workspace", main_writes)
"""
        )
    finally:
        thread.join(5)
        server.close()
    assert r["via a daemon"]["value"] == "OTHER"  # known limit: not stopped by this sandbox
    assert r["main process writes outside the workspace"]["value"] == "done"  # known limit: see WRITE_PLAN W3
    assert (sandbox.other / "written").exists()


def test_a_fresh_home_cache_works_for_commands(sandbox: Sandbox) -> None:
    """On a new machine ``~/.cache`` doesn't exist yet: a tool's first write and read there must work."""
    home = sandbox.root / "freshhome"
    home.mkdir()
    r = sandbox.run(
        """
script = 'mkdir -p ~/.cache/tool && echo c > ~/.cache/tool/t && mv ~/.cache/tool/t ~/.cache/tool/u && cat ~/.cache/tool/u'
check("first use", lambda: subprocess.run(["sh", "-c", script], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.strip())
""",
        env={"HOME": str(home)},
    )
    assert r["first use"]["value"] == "c"
