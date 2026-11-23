# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The standalone sandbox processes trust only the standard library and each other.

``runtime/*.py`` run as ``python -I -S <script>``: the broker is the one
unconfined process, so everything it imports is trusted code. Importing chrys
(or a third-party package) there would widen that to the whole application.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from icode_sandbox.runtime import confine

RUNTIME = Path(confine.__file__).resolve().parent
SIBLINGS = {p.stem for p in RUNTIME.glob("*.py")}
# confine.py re-exports wire.py: by package name inside chrys, by file next door.
ALLOWED_PACKAGE_IMPORT = ("confine.py", "icode_sandbox.runtime.wire")


@pytest.mark.parametrize("script", sorted(p.name for p in RUNTIME.glob("*.py") if p.name != "__init__.py"))
def test_runtime_scripts_import_only_stdlib_and_siblings(script: str) -> None:
    tree = ast.parse((RUNTIME / script).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            top = name.split(".")[0]
            if (script, name) == ALLOWED_PACKAGE_IMPORT or top == "__future__":
                continue
            assert top in sys.stdlib_module_names or top in SIBLINGS, f"{script} imports {name}"


def test_the_guard_can_fail(tmp_path: Path) -> None:
    tree = ast.parse("import chrys.foundation\nfrom yaml import safe_load\n")
    tops = [
        (n.names[0].name if isinstance(n, ast.Import) else n.module or "").split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, ast.Import | ast.ImportFrom)
    ]
    assert [t for t in tops if t not in sys.stdlib_module_names and t not in SIBLINGS] == ["chrys", "yaml"]


def test_the_broker_refuses_to_import_after_startup() -> None:
    script = (
        "import runpy, sys\n"
        f"ns = runpy.run_path({str(RUNTIME / 'broker.py')!r}, run_name='loaded')\n"
        "sys.addaudithook(ns['_no_late_imports'])\n"
        "try:\n"
        "    import wave\n"
        "except ImportError as exc:\n"
        "    print('REFUSED', exc)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert "REFUSED" in proc.stdout, proc.stderr
