# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Every place iCode restores files from the mutation tracker runs in the session's sandbox scope.

The scope comes from ``chrys.foundation.guard`` (``guard.current().session_scope``).

A rollback writes paths that earlier tool calls recorded, through folders that
may have been swapped for links since. Inside ``session_scope`` those writes go
through the session's helper and the kernel decides where they land
(``test_write_control.py`` shows that with real processes). This finds the
calls by scanning the source, so a new rollback entry point that forgets the
scope fails here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from tests.support.ci import CI_LINUX_ONLY

SRC = Path(__file__).resolve().parents[3] / "src" / "chrys"
RESTORING = {"restore_files", "rollback", "rollback_turns"}
"""``MutationTracker`` methods that write files back."""
TRACKER = SRC / "service" / "mutations" / "tracker.py"


def _restore_calls(tree: ast.AST) -> list[tuple[ast.Call, list[ast.AST]]]:
    found: list[tuple[ast.Call, list[ast.AST]]] = []

    def walk(node: ast.AST, parents: list[ast.AST]) -> None:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in RESTORING:
            receiver = node.func.value
            name = receiver.id if isinstance(receiver, ast.Name) else getattr(receiver, "attr", "")
            if "tracker" in name.lower():
                found.append((node, parents))
        for child in ast.iter_child_nodes(node):
            walk(child, [*parents, node])

    walk(tree, [])
    return found


def _through_the_guard(call: ast.expr) -> bool:
    """``guard.current().session_scope(...)``: the guard of this process, not a stand-in."""
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "session_scope"):
        return False
    owner = call.func.value
    return (
        isinstance(owner, ast.Call)
        and isinstance(owner.func, ast.Attribute)
        and owner.func.attr == "current"
        and getattr(owner.func.value, "id", "") == "guard"
    )


def _in_session_scope(parents: list[ast.AST]) -> bool:
    return any(
        isinstance(node, ast.With) and any(_through_the_guard(item.context_expr) for item in node.items)
        for node in parents
    )


def _all_restore_calls() -> list[tuple[str, ast.Call, list[ast.AST]]]:
    calls = []
    for path in SRC.rglob("*.py"):
        if path == TRACKER:
            continue
        source = path.read_text(encoding="utf-8")
        if not any(name in source for name in RESTORING):
            continue
        for call, parents in _restore_calls(ast.parse(source)):
            calls.append((f"{path.relative_to(SRC)}:{call.lineno}", call, parents))
    return calls


@CI_LINUX_ONLY
def test_the_scan_finds_the_known_entry_points() -> None:
    """Guards the scan itself: an empty result would pass the next test for nothing."""
    where = {site.split(":")[0] for site, _, _ in _all_restore_calls()}
    assert {"orchestration/engine/rollback.py", "orchestration/workflows/rollback.py"} <= where, where


@CI_LINUX_ONLY
def test_every_restore_runs_in_the_session_scope() -> None:
    outside = [site for site, _, parents in _all_restore_calls() if not _in_session_scope(parents)]
    assert not outside, f"restores files outside session_scope: {outside}"
