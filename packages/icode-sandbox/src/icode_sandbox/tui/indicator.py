# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""SandboxIndicator — the file-access sandbox's state, in the footer row.

Always shown when the sandbox was requested, so "requested but not active" can
never go unnoticed; hidden when the sandbox is simply off. Clicking it opens
the sandbox panel (:class:`~icode_sandbox.tui.panel.SandboxDialog`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from textual.message import Message

from chrys.app.tui.i18n import render_str, widget_localizer
from chrys.app.tui.widgets.selection import NonSelectableStatic
from chrys.foundation.i18n import msg
from icode_sandbox import client as sandbox_client

if TYPE_CHECKING:
    from textual.events import Click

# Active is the steady state: one glyph, so the footer keys keep their room
# (details in the tooltip and on F7). Trouble states spell themselves out.
_ACTIVE = msg("tui.sandbox.indicator.active", fallback="🛡")
_DEGRADED = msg("tui.sandbox.indicator.degraded", fallback="🛡 Sandbox: degraded")
_OFF = msg("tui.sandbox.indicator.off", fallback="⚠ Sandbox NOT active")
_TOOLTIP_STATE = msg("tui.sandbox.indicator.tooltip_state", fallback="File-access sandbox: {state} ({mechanism})")
_TOOLTIP_HINT = msg("tui.sandbox.indicator.tooltip_hint", fallback="Click for details and grants.")
_LABELS = {
    "active": (_ACTIVE, "sandbox-indicator--active"),
    "degraded": (_DEGRADED, "sandbox-indicator--degraded"),
    "requested-not-active": (_OFF, "sandbox-indicator--off"),
}


class SandboxIndicator(NonSelectableStatic):
    """``🛡`` while confined; a spelled-out warning when requested but degraded or off."""

    COMPONENT_CLASSES: ClassVar[set[str]] = {
        "sandbox-indicator--active",
        "sandbox-indicator--degraded",
        "sandbox-indicator--off",
    }

    DEFAULT_CSS = """
    SandboxIndicator {
        width: auto;
        height: 1;
        padding: 0 1;
        background: $footer-item-background;
        text-wrap: nowrap;
    }
    SandboxIndicator > .sandbox-indicator--active {
        color: $success;
    }
    SandboxIndicator > .sandbox-indicator--degraded {
        color: $warning;
        text-style: bold;
    }
    SandboxIndicator > .sandbox-indicator--off {
        color: $error;
        text-style: bold;
    }
    SandboxIndicator:hover {
        background: $control-background;
    }
    """

    class Clicked(Message):
        """The user clicked the indicator."""

    def on_mount(self) -> None:
        self._shown: tuple[str, str, tuple[str, ...]] | None = None
        self.refresh_state()
        # The state changes rarely (a lost broker, a degraded start); the tick
        # repaints only when it did.
        self.set_interval(2.0, self.refresh_state)

    def refresh_state(self) -> None:
        status = sandbox_client.status()
        key = (status.label(), status.mechanism, tuple(status.reasons[-3:]))
        if key == self._shown:
            return
        self._shown = key
        entry = _LABELS.get(status.label())
        self.display = entry is not None
        if entry is None:
            return
        definition, component = entry
        localizer = widget_localizer(self)
        self.update(Text(render_str(localizer, definition.bind()), style=self.get_component_rich_style(component)))
        lines = [render_str(localizer, _TOOLTIP_STATE.bind(state=status.label(), mechanism=status.mechanism or "-"))]
        lines += [f"• {reason}" for reason in status.reasons[-3:]]
        lines.append(render_str(localizer, _TOOLTIP_HINT.bind()))
        self.tooltip = "\n".join(lines)

    def on_click(self, event: Click) -> None:
        event.stop()
        self.post_message(self.Clicked())
