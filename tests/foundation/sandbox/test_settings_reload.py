# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Reloading settings mid-session (``/reload``, ACP ``settings/reload``) leaves the sandbox as it started.

The sandbox's settings are read once, by ``bootstrap.py`` straight from the
user's settings file, before iCode's settings loader runs. Nothing in the
sandbox asks the loader again, so a reload that turns the sandbox off or adds
a folder for commands only takes effect at the next start.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests.support.ci import CI_LINUX_ONLY

from .conftest import Sandbox, needs_kernel
from .test_tools_and_attacks import _run

SANDBOX = Path(__file__).resolve().parents[3] / "packages" / "icode-sandbox" / "src" / "icode_sandbox"
LOADER_MODULES = ("chrys.foundation.config.settings_store", "chrys.foundation.config.process_settings")


@CI_LINUX_ONLY
def test_the_sandbox_never_asks_the_settings_loader() -> None:
    found = []
    files = sorted(SANDBOX.rglob("*.py"))
    assert len(files) > 10, f"scanned nothing under {SANDBOX}"
    for file in files:
        for node in ast.walk(ast.parse(file.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(LOADER_MODULES):
                found.append(f"{file.relative_to(SANDBOX)}:{node.lineno}")
    assert not found, f"the sandbox reads reloadable settings: {found}"


@needs_kernel
def test_after_a_settings_reload_the_sandbox_is_still_on_and_as_narrow(sandbox: Sandbox) -> None:
    r = _run(
        sandbox,
        """
import yaml
from chrys.foundation.config.settings_store import load_settings
from icode_sandbox import client as sandbox_client

before = sandbox_client.status().state
with open(os.path.join(CONFIG, "settings.yaml"), "w", encoding="utf-8") as stream:
    yaml.safe_dump({"sandbox": {"enabled": False, "commands": {"allow_paths": [OTHER]}}}, stream)
load_settings(manual_reload=True)

async def scenario():
    mw = middleware(ApprovalMode.BYPASS)
    results["cat other"] = {"ok": True, "value": await call(mw, SHELL, command="cat " + os.path.join(OTHER, "f.txt"), reason="t")}
run(scenario)
results["state"] = {"ok": True, "value": [before, sandbox_client.status().state]}
""",
    )
    assert r["state"]["value"] == ["active", "active"], r["state"]
    assert "OTHER" not in r["cat other"]["value"], r["cat other"]
