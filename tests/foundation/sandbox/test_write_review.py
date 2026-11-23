# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Write-control findings of an independent review, as experiments.

Each test asserts the safe outcome, in a fake home: a red test confirms the finding.
The first two were red on macOS before their fixes; the third was already refused
there (Seatbelt denies the link) and stays as a guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import Sandbox, needs_kernel
from .test_write_control import ROLLBACK, WRITE_FLOOR_SAMPLES, _run

pytestmark = needs_kernel


@pytest.fixture
def fake_home(sandbox: Sandbox) -> Path:
    path = sandbox.root / "fakehome"
    path.mkdir()
    for sample in WRITE_FLOOR_SAMPLES:
        (path / sample).parent.mkdir(parents=True, exist_ok=True)
    return path


def test_r1_a_rollback_cannot_write_git_config_through_a_swapped_folder(sandbox: Sandbox, fake_home: Path) -> None:
    """~/.gitconfig is one of iCode's own readable paths; a rollback must not write it directly."""
    (fake_home / ".gitconfig").write_text("[user]\n\tname = me\n", encoding="utf-8")
    (sandbox.ws / "a").mkdir()
    (sandbox.ws / "a" / ".gitconfig").write_text("EVIL", encoding="utf-8")
    r = _run(
        sandbox,
        fake_home,
        "import pathlib\n"
        + ROLLBACK
        + r"""
H = os.environ["HOME"]
path = os.path.join(WS, "a", ".gitconfig")
m = tracker.record(path, MutationOp.MODIFY, MutationSource.WRITE_FILE, "t")
with open(path, "w") as stream:
    stream.write("AFTER")
tracker.record_after(m)
os.rename(os.path.join(WS, "a"), os.path.join(WS, "a.old"))
os.symlink(H, os.path.join(WS, "a"))
with session_scope("sess-rb", [WS], WS):
    results["out"] = {"ok": True, "value": outcome(tracker.rollback_turns({1}))}
""",
    )
    assert (fake_home / ".gitconfig").read_text(encoding="utf-8") == "[user]\n\tname = me\n", r["out"]


def test_r2_a_command_cannot_turn_its_workspace_into_a_link_elsewhere(sandbox: Sandbox, fake_home: Path) -> None:
    """Replace the workspace with a link; the next call must not be able to write where it points."""
    target = fake_home / "Documents"
    target.mkdir()
    r = _run(
        sandbox,
        fake_home,
        r"""
import tempfile
H = os.environ["HOME"]
moved = tempfile.mkdtemp(prefix="icode-r2-")
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["swap"] = {"ok": True, "value": sh(f"mv {WS} {moved}/ws && ln -s {H}/Documents {WS} && echo swapped")}
with client.scoped(policy.Scope(key="s", roots=(WS,), workdir_root=WS)):
    results["plant"] = {"ok": True, "value": sh(f"echo PLANTED > {WS}/planted; cat {H}/Documents/planted")}
""",
    )
    assert not (target / "planted").exists(), r


def test_r3_a_command_cannot_write_git_config_through_a_hard_link(sandbox: Sandbox, fake_home: Path) -> None:
    """Commands may read ~/.gitconfig; a hard link to it must not make it writable."""
    (fake_home / ".gitconfig").write_text("[user]\n\tname = me\n", encoding="utf-8")
    r = _run(
        sandbox,
        fake_home,
        r"""
import tempfile
H = os.environ["HOME"]
link = os.path.join(tempfile.mkdtemp(prefix="icode-r3-"), "g")
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    results["link"] = {"ok": True, "value": sh(f"ln {H}/.gitconfig {link} && echo '[core]' >> {link}; echo rc=$?")}
""",
    )
    assert (fake_home / ".gitconfig").read_text(encoding="utf-8") == "[user]\n\tname = me\n", r
    # The link itself is refused: EPERM from Seatbelt, EXDEV from Landlock's refer rule.
    assert "Operation not permitted" in r["link"]["value"][1] or "cross-device" in r["link"]["value"][1], r
