# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Previewing an image the person referenced in the input reads it, wherever it is.

The TUI shows a preview when the person opens a referenced image's label. That
is their own action on a file they picked, as attaching it is, so the read is
marked as the person's (``user_reads``) and is not limited to the workspace.
The same read without the mark is refused.
"""

from __future__ import annotations

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel

SCENARIO = r"""
from pathlib import Path

image = os.path.join(OTHER, "picked.png")  # written by the test before the scenario starts
from chrys.app.tui.screens.dialogs.reference_preview import _read_preview
from chrys.foundation.text.images import read_image_source_bytes

try:
    preview = _read_preview(Path(image))
    results["preview"] = {"ok": True, "value": type(preview).__name__}
except Exception as exc:
    results["preview"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
try:
    read_image_source_bytes(Path(image))
    results["plain"] = {"ok": True, "value": "read"}
except OSError as exc:
    results["plain"] = {"ok": False, "error": type(exc).__name__}
"""


def test_a_referenced_image_outside_the_workspace_can_be_previewed(sandbox: Sandbox) -> None:
    from PIL import Image

    Image.new("RGB", (4, 4), "red").save(sandbox.other / "picked.png", format="PNG")
    r = sandbox.run(SCENARIO)
    assert r["preview"]["ok"], r["preview"]
    assert r["plain"] == {"ok": False, "error": "PermissionError"}, r["plain"]
