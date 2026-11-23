# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""With the sandbox on, a failure inside it refuses; it never runs the thing outside the sandbox.

Some sandboxes run a command on the host when their own machinery fails
(``fallback_on_failure``) or for listed commands; this one must not. A failing
broker request makes the start fail, and no error handler in the package
reaches for the original, unconfined ``open``/``Popen``/``os`` functions.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from tests.support.ci import CI_LINUX_ONLY

from .conftest import Sandbox, needs_kernel

PACKAGE = Path(__file__).resolve().parents[3] / "packages" / "icode-sandbox" / "src" / "icode_sandbox"

ACCOUNTED = {
    "patches.py _original_listdir": "lists the folder fd a confined helper opened and passed back: the kernel already decided",
}
"""Calls in error handlers that reach an original function without escaping the sandbox, and why."""


def _unconfined_calls_in_handlers(root: Path) -> list[str]:
    found = []
    for file in sorted(root.rglob("*.py")):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for handler in ast.walk(tree):
            if not isinstance(handler, ast.ExceptHandler):
                continue
            for node in ast.walk(handler):
                if isinstance(node, ast.Call):
                    name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                    if name.startswith("_original_") and f"{file.relative_to(root)} {name}" not in ACCOUNTED:
                        found.append(f"{file.relative_to(root)}:{node.lineno} {name}")
    return found


@CI_LINUX_ONLY
def test_no_error_handler_falls_back_to_the_unconfined_functions() -> None:
    assert len(list(PACKAGE.rglob("*.py"))) > 10, "scanned nothing"
    assert _unconfined_calls_in_handlers(PACKAGE) == []


def test_the_scan_notices_a_fallback(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text(
        "try:\n    pass\nexcept OSError:\n    _original_execute_child(1)\n", encoding="utf-8"
    )
    assert _unconfined_calls_in_handlers(tmp_path) == ["x.py:4 _original_execute_child"]


@needs_kernel
def test_a_failing_broker_request_fails_the_start_and_runs_nothing(sandbox: Sandbox) -> None:
    marker = sandbox.ws / "ran"
    r = sandbox.run(
        r"""
def broken(*args, **kwargs):
    raise OSError("broker gone")

RT.reserve_slot = broken
try:
    subprocess.run(["sh", "-c", "touch " + os.path.join(WS, "ran")], stdin=subprocess.DEVNULL, check=False)
    results["start"] = {"ok": True, "value": "started"}
except OSError as exc:
    results["start"] = {"ok": True, "value": f"refused: {exc}"}
"""
    )
    assert r["start"]["value"] == "refused: broker gone", r
    assert not marker.exists()


@needs_kernel
def test_a_failure_after_confining_stops_icode_even_with_warn(tmp_path: Path) -> None:
    """Confined for good but missing its hooks: carrying on would look unsandboxed while half being so."""
    import os
    import subprocess
    import sys

    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from icode_sandbox import bootstrap, patches\n"
        "def broken():\n"
        "    raise RuntimeError('hooks would not install')\n"
        "patches.install = broken\n"
        "bootstrap.install_at_startup(['--sandbox', '-C', sys.argv[1]], config_dir=Path(sys.argv[2]))\n"
        "print('CARRIED ON')\n"
    )
    (tmp_path / "ws").mkdir()
    (tmp_path / "config").mkdir()
    env = {**os.environ, "HOME": str(tmp_path), "CHRYS_FILE_SANDBOX_ON_UNAVAILABLE": "warn"}
    for name in ("CHRYS_TEST_SANDBOX", "CHRYS_FILE_SANDBOX", "CHRYS_FILE_SANDBOX_INHERITED"):
        env.pop(name, None)
    done = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path / "ws"), str(tmp_path / "config")],
        capture_output=True,
        text=True,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 78, done
    assert "CARRIED ON" not in done.stdout
    assert "failed after confining this process: hooks would not install" in done.stderr


@pytest.mark.skipif(
    os.environ.get("CHRYS_TEST_SANDBOX") == "1", reason="checks an unconfined process; this one is confined"
)
def test_the_inherited_marker_alone_is_not_believed(tmp_path: Path) -> None:
    """``CHRYS_FILE_SANDBOX_INHERITED=1`` in an unconfined process must not make it report a sandbox it hasn't."""
    import os
    import subprocess
    import sys

    code = (
        "import pathlib, sys\n"
        "from chrys.foundation import guard\n"
        "from icode_sandbox import bootstrap, client\n"
        "rest, decision = guard.decide(['run'], pathlib.Path(sys.argv[1]), env={'CHRYS_FILE_SANDBOX': '0'})\n"
        "st = bootstrap.start(rest, decision, pathlib.Path(sys.argv[1]))\n"
        "print(st.state, st.inherited)\n"
    )
    env = {**os.environ, "CHRYS_FILE_SANDBOX_INHERITED": "1"}
    env.pop("CHRYS_TEST_SANDBOX", None)
    done = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True, env=env, timeout=30, check=False
    )
    assert done.stdout.split() == ["inactive", "False"], done.stdout + done.stderr


@needs_kernel
def test_a_confined_process_knows_it_whichever_guard_is_current(sandbox: Sandbox) -> None:
    """Being confined is a fact about the process: a harness or a test swapping the current guard can't undo it,
    and the core's secure-file walk relies on it (Linux refuses even ``/`` to a confined process)."""
    r = sandbox.run(
        r"""
from chrys.foundation import guard
guard.set_current(guard._NoGuard())
results["confined"] = {"ok": True, "value": guard.confined()}
from chrys.foundation.platform import files
import tempfile
target = __import__("pathlib").Path(os.path.realpath(tempfile.mkdtemp())) / "made.txt"  # Linux: "/" itself is refused
handle = files.secure_open_owner_only_append(target)
os.close(handle.fd)
results["secure write"] = {"ok": True, "value": target.exists()}
"""
    )
    assert r["confined"]["value"] is True, r
    assert r["secure write"]["value"] is True, r
