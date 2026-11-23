# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Starting a program under the sandbox fails the way ``subprocess.Popen`` fails without it.

The sandbox's ``Popen`` hook hands the command to the broker in a JSON spec. An
argument ``Popen`` itself refuses must still be refused up front: code such as
``interpolate_shell`` reports a start that can't happen as ``start_failed``.
"""

from __future__ import annotations

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel


def test_a_nul_in_an_argument_is_refused_before_anything_starts(sandbox: Sandbox) -> None:
    r = sandbox.run(
        r"""
for name, argv, shell in (("argv", ["echo", "a\x00b"], False), ("shell", "echo a\x00b", True)):
    try:
        subprocess.run(argv, shell=shell, stdin=subprocess.DEVNULL, capture_output=True, check=False)
        results[name] = {"ok": True, "value": "started"}
    except ValueError as exc:
        results[name] = {"ok": True, "value": f"ValueError: {exc}"}
"""
    )
    assert r["argv"]["value"] == "ValueError: embedded null byte", r
    assert r["shell"]["value"] == "ValueError: embedded null byte", r


def test_files_still_open_by_absolute_name_once_the_working_directory_is_gone(sandbox: Sandbox) -> None:
    """Deciding whether iCode writes its own state reads the name as given; a vanished cwd must not break that."""
    r = sandbox.run(
        r"""
gone = os.path.join(WS, "gone")
os.mkdir(gone)
os.chdir(gone)
os.rmdir(gone)
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    with open(os.path.join(WS, "made.txt"), "w", encoding="utf-8") as stream:
        stream.write("M")
    with open(os.path.join(WS, "made.txt"), encoding="utf-8") as stream:
        results["inside"] = {"ok": True, "value": stream.read()}
with open(os.path.join(CONFIG, "probe.txt"), "w", encoding="utf-8") as stream:
    stream.write("C")
results["config"] = {"ok": True, "value": "written"}
"""
    )
    assert r["inside"]["value"] == "M", r
    assert r["config"]["value"] == "written", r
