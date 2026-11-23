# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""SandboxDialog — the file-access sandbox's state, read sets, grants and refusals.

Read-only except for revoking a grant, which narrows that session's read set at
once (its file helper is replaced before the dialog updates).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, ClassVar, cast

from rich.table import Table
from rich.text import Text
from textual import on
from textual.containers import ScrollableContainer, VerticalGroup
from textual.widgets import Button, Collapsible, Static

from chrys.app.tui.binding_display import CLOSE_BINDING, localized_binding
from chrys.app.tui.i18n import render_str, widget_localizer
from chrys.app.tui.screens.dialogs.base import BaseDialog
from chrys.foundation.branding import APP_DISPLAY_NAME
from chrys.foundation.i18n import MessageDef, msg
from icode_sandbox import client as sandbox_client

if TYPE_CHECKING:
    from textual.app import ComposeResult
from textual.compose import compose

_TITLE = msg("tui.sandbox.title", fallback="File-access sandbox")
_STATE = msg("tui.sandbox.state", fallback="State: {state} ({mechanism})")
_NO_BACKEND = msg("tui.sandbox.no_backend", fallback="no backend")
_NOT_CONFINED = msg(
    "tui.sandbox.not_confined",
    fallback="This process is not confined. Start {app} with --sandbox, or turn on the sandbox in Settings, to enable it.",
)
_PRIVATE = msg("tui.sandbox.private_roots", fallback="Private (unreadable except below)")
_MAIN_ALLOW = msg("tui.sandbox.main_allow", fallback="{app} itself may read")
_SERVED = msg("tui.sandbox.served", fallback="Workspaces served")
_FLOOR = msg("tui.sandbox.floor", fallback="Never granted")
_SESSION = msg("tui.sandbox.session", fallback="Session {session}")
_WORKSPACE = msg("tui.sandbox.workspace", fallback="Working folders")
_ADDITIONAL = msg("tui.sandbox.additional", fallback="Additional working folders")
_GRANTS = msg("tui.sandbox.grants", fallback="Grants")
_SELF_CHECK = msg("tui.sandbox.self_check", fallback="Self-check: {result}")
_REFUSALS_HINT = msg(
    "tui.sandbox.refusals_hint",
    fallback="Outcomes: refused (nobody could be asked), declined (you said no), granted, protected (never grantable).",
)
_GRANT_ROW = msg("tui.sandbox.grant_row", fallback="{kind} {path} (since {when})")
_GRANT_WRITE_ROW = msg("tui.sandbox.grant_write_row", fallback="{kind}, can write: {path} (since {when})")
_REVOKE = msg("tui.sandbox.revoke", fallback="Revoke")
_REFUSALS = msg("tui.sandbox.refusals", fallback="Recent refusals")
_NONE = msg("tui.sandbox.none", fallback="(none)")
_KIND_ONCE = msg("tui.sandbox.kind.once", fallback="Once")
_KIND_TURN = msg("tui.sandbox.kind.turn", fallback="This turn")
_KIND_SESSION = msg("tui.sandbox.kind.session", fallback="This session")
_KIND_WORKDIR = msg("tui.sandbox.kind.workdir", fallback="This working directory")
_KINDS: dict[str, MessageDef] = {
    "once": _KIND_ONCE,
    "turn": _KIND_TURN,
    "session": _KIND_SESSION,
    "workdir": _KIND_WORKDIR,
}


def _when(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


class SandboxDialog(BaseDialog[None]):
    """What the sandbox enforces right now, and the grants a person can take back."""

    BINDINGS: ClassVar[list] = [
        localized_binding("escape", "close", CLOSE_BINDING, show=False, priority=True),
        localized_binding("q", "close", CLOSE_BINDING, show=False),
    ]

    DEFAULT_CSS = """
    SandboxDialog {
        align: center middle;
        background: $background 40%;
    }
    #sandbox-container {
        width: 92%;
        max-width: 110;
        height: 85%;
        max-height: 44;
        border: round $tui-border-primary $border-opacity;
        border-title-color: $primary;
        border-title-style: bold;
        background: $surface;
    }
    #sandbox-scroll {
        height: 1fr;
        padding: 0 1;
    }
    .sandbox-section {
        height: auto;
        margin: 1 0 0 0;
    }
    .sandbox-grant {
        height: auto;
        layout: horizontal;
    }
    .sandbox-grant Static {
        width: 1fr;
    }
    .sandbox-grant Button {
        min-width: 10;
    }
    """

    def _t(self, definition: MessageDef, **values: str) -> str:
        # None of these messages is plural, so no value is a ``count``.
        return render_str(widget_localizer(self), definition.bind(**cast("dict[str, Any]", values)))

    def _paths(self, title: MessageDef, paths: list[str], **values: str) -> Table:
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold", no_wrap=True)
        table.add_column()
        table.add_row(
            Text(self._t(title, **values)), Text("\n".join(paths)) if paths else Text(self._t(_NONE), style="dim")
        )
        return table

    def compose(self) -> ComposeResult:
        with VerticalGroup(id="sandbox-container") as container:
            container.border_title = Text(self._t(_TITLE))
            with ScrollableContainer(id="sandbox-scroll"):
                yield from self._sections()

    def _sections(self) -> ComposeResult:
        rt = sandbox_client.runtime()
        st = sandbox_client.status()
        head = self._t(_STATE, state=st.label(), mechanism=st.mechanism or self._t(_NO_BACKEND))
        yield Static(Text(head, style="bold"), classes="sandbox-section")
        for reason in st.reasons:
            yield Static(Text(f"• {reason}", style="yellow"))
        if rt is None:
            yield Static(Text(self._t(_NOT_CONFINED, app=APP_DISPLAY_NAME), style="dim"), classes="sandbox-section")
            return
        snap: dict[str, Any] = rt.snapshot()
        if snap["self_check"]:
            yield Static(Text(self._t(_SELF_CHECK, result=snap["self_check"]), style="dim"))
        yield Static(self._paths(_PRIVATE, snap["private_roots"]), classes="sandbox-section")
        with Collapsible(title=self._t(_MAIN_ALLOW, app=APP_DISPLAY_NAME), collapsed=True, classes="sandbox-section"):
            yield Static(Text("\n".join(snap["main_allow"])))
        yield Static(self._paths(_SERVED, snap["service_paths"]), classes="sandbox-section")
        yield Static(self._paths(_FLOOR, snap["floor"]), classes="sandbox-section")
        for key, scope in snap["scopes"].items():
            yield Static(Text(self._t(_SESSION, session=key), style="bold underline"), classes="sandbox-section")
            additional = [root for root in scope["roots"] if root != scope["workdir_root"]]
            yield Static(self._paths(_WORKSPACE, [root for root in scope["roots"] if root not in additional]))
            if additional:
                yield Static(self._paths(_ADDITIONAL, additional))
            yield Static(Text(self._t(_GRANTS), style="bold"))
            if not scope["grants"]:
                yield Static(Text(self._t(_NONE), style="dim"))
            for grant in scope["grants"]:
                kind = _KINDS.get(grant["kind"])
                row = self._t(
                    _GRANT_WRITE_ROW if grant.get("access") == "write" else _GRANT_ROW,
                    kind=self._t(kind) if kind is not None else grant["kind"],
                    path=grant["path"],
                    when=_when(grant["created_at"]),
                )
                with VerticalGroup(classes="sandbox-grant"):
                    yield Static(Text(row))
                    yield Button(Text(self._t(_REVOKE)), id=f"revoke-{grant['id']}", variant="warning", compact=True)
        denials = snap["denials"]
        yield Static(Text(self._t(_REFUSALS), style="bold underline"), classes="sandbox-section")
        yield Static(Text(self._t(_REFUSALS_HINT), style="dim"))
        if not denials:
            yield Static(Text(self._t(_NONE), style="dim"))
        for denial in reversed(denials):
            line = f"{_when(denial['at'])}  {denial['outcome']:9} {denial['access']:5} {denial['tool'] or '-':12} {denial['path']}"
            yield Static(Text(line))

    @on(Button.Pressed)
    async def _revoke(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if not button_id.startswith("revoke-"):
            return
        rt = sandbox_client.runtime()
        if rt is not None:
            rt.revoke(button_id.removeprefix("revoke-"))
        scroll = self.query_one("#sandbox-scroll", ScrollableContainer)
        await scroll.remove_children()
        await scroll.mount_all(compose(scroll, self._sections()))

    def action_close(self) -> None:
        self.dismiss(None)
