# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Real-kernel sandbox tests: every scenario runs in a fresh confined subprocess.

The test process itself is never confined (a confined pytest worker could not
read the test tree or the temp dirs of other tests). Each scenario is a script
run under ``python -c``; it enables the sandbox exactly as ``icode`` does and
prints one JSON line of results.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from icode_sandbox.runtime import confine

SUPPORTED, MECHANISM = confine.available()
# Under CHRYS_TEST_SANDBOX the runner itself is confined, and a confined
# process can't confine children more loosely (macOS) — run these unconfined.
_CONFINED_RUNNER = os.environ.get("CHRYS_TEST_SANDBOX") == "1"
needs_kernel = pytest.mark.skipif(
    not SUPPORTED or _CONFINED_RUNNER,
    reason=f"no sandbox backend: {MECHANISM}" if not SUPPORTED else "the test runner itself is sandboxed",
)

PRELUDE = r"""
import json, os, subprocess, sys
ROOT = sys.argv[1]
WS, OTHER, GRANT, CONFIG = (os.path.join(ROOT, d) for d in ("ws", "other", "granted", "config"))
from icode_sandbox import bootstrap, client, policy
from icode_sandbox.runtime import confine
results = {}
def check(name, fn):
    try:
        value = fn()
        value = list(value) if isinstance(value, tuple) else value
        results[name] = {"ok": True, "value": value if isinstance(value, (str, int, list, bool, type(None))) else repr(value)[:80]}
    except BaseException as exc:
        results[name] = {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}
def cat(path, **kw):
    return subprocess.run(["cat", path], capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, **kw).stdout
_argv, STATUS = bootstrap.install_at_startup(["--sandbox", "-C", WS], config_dir=__import__("pathlib").Path(CONFIG))
RT = client.runtime()
"""

EPILOGUE = r"""
results["__status__"] = {"ok": True, "value": STATUS.label()}
print("@@RESULT@@" + json.dumps(results))
"""


@dataclass
class Sandbox:
    root: Path

    @property
    def ws(self) -> Path:
        return self.root / "ws"

    @property
    def other(self) -> Path:
        return self.root / "other"

    @property
    def granted(self) -> Path:
        return self.root / "granted"

    def run(self, body: str, *, env: dict[str, str] | None = None, timeout: float = 60) -> dict:
        script = PRELUDE + body + EPILOGUE
        full_env = {
            **os.environ,
            "CHRYS_FILE_SANDBOX_ON_UNAVAILABLE": "refuse",
            "CHRYS_FILE_SANDBOX_DEV_ALARM": "1",
            **(env or {}),
        }
        full_env.pop("CHRYS_FILE_SANDBOX_INHERITED", None)
        full_env.pop("CHRYS_FILE_SANDBOX", None)
        # Sessions live under the scenario's config dir, where the sandbox's session log is looked for.
        full_env.pop("CHRYS_SESSION_ROOT_DIR", None)
        proc = subprocess.run(
            [sys.executable, "-c", script, str(self.root)],
            capture_output=True,
            text=True,
            env=full_env,
            cwd=str(self.ws),
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("@@RESULT@@"):
                return json.loads(line.removeprefix("@@RESULT@@"))
        raise AssertionError(f"scenario failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")


@pytest.fixture
def sandbox() -> Iterator[Sandbox]:
    """A tree *inside the home directory* (a private root), so the sandbox applies."""
    home = Path(confine.real(os.path.expanduser("~")))
    base = Path(tempfile.mkdtemp(prefix=".icode-sbtest-", dir=home))
    for name, content in (("ws", "WS"), ("other", "OTHER"), ("granted", "GRANTED")):
        (base / name).mkdir()
        (base / name / "f.txt").write_text(content, encoding="utf-8")
    (base / "ws" / "sub").mkdir()
    (base / "ws" / "sub" / "g.txt").write_text("SUB", encoding="utf-8")
    (base / "config").mkdir()
    (base / "config" / "settings.yaml").write_text("{}\n", encoding="utf-8")
    try:
        yield Sandbox(base)
    finally:
        import shutil

        shutil.rmtree(base, ignore_errors=True)
