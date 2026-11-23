# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Turn the sandbox on for one iCode process, at startup only.

:func:`install_at_startup` runs first thing in the command dispatcher, before
any thread exists (Landlock confines only the threads created after it). It

1. decides whether the sandbox is wanted: ``--sandbox``/``--no-sandbox`` on the
   command line, then ``CHRYS_FILE_SANDBOX``, then ``sandbox.files.enabled`` in the
   working directory's settings when the user enabled those (a working directory can only switch
   the sandbox on), then in the user's ``settings.yaml``;
2. starts the broker — the one unconfined process — while this process still
   can;
3. confines this process, proves it, and installs the read/command hooks.

The decision can't change later in the process: a confined process can never
be unconfined, and a setting edited mid-session (by anyone, the model included)
only applies at the next start.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from chrys.foundation import guard as core_guard
from icode_sandbox import client as sandbox_client
from icode_sandbox.runtime import confine

ENV_ENABLED = core_guard.ENV_ENABLED
ENV_ON_UNAVAILABLE = core_guard.ENV_ON_UNAVAILABLE
ENV_INHERITED = core_guard.ENV_INHERITED
EXIT_UNAVAILABLE = core_guard.EXIT_UNAVAILABLE


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        # The settings panel stores text: one path per line, or separated by the platform path separator.
        parts = value.replace(os.pathsep, "\n").replace(",", "\n").splitlines()
        return [p.strip() for p in parts if p.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if isinstance(v, (str, os.PathLike))]
    return []


def resolve_settings(
    argv: list[str], config_dir: Path, env: Mapping[str, str] | None = None
) -> tuple[list[str], sandbox_client.SandboxSettings]:
    """Strip the sandbox flags from *argv*; iCode's decision plus the sandbox's own settings."""
    rest, decision = core_guard.decide(argv, config_dir, env)
    return rest, settings_for(decision, config_dir)


def settings_for(decision: core_guard.Decision, config_dir: Path) -> sandbox_client.SandboxSettings:
    """The sandbox's settings for a start iCode decided on."""
    doc = core_guard.settings_doc(config_dir / "settings.yaml")
    return sandbox_client.SandboxSettings(
        enabled=decision.enabled,
        source=decision.source,
        on_unavailable=decision.on_unavailable,
        workdir_off_ignored=decision.workdir_off_ignored,
        main_allow=_as_list(doc.get("sandbox.files.main.allow_paths")),
        shell_allow=_as_list(doc.get("sandbox.files.commands.allow_paths")),
        shell_write=_as_list(doc.get("sandbox.files.commands.write_paths")),
        floor_extra=_as_list(doc.get("sandbox.files.floor.extra")),
        audit_redact_paths=core_guard.as_bool(doc.get("sandbox.files.audit.redact_paths")) is True,
    )


launch_dirs = core_guard.launch_dirs


def _fail(settings: sandbox_client.SandboxSettings, reason: str) -> sandbox_client.Status:
    status = sandbox_client.Status(state="inactive", requested=True, reasons=[reason])
    sandbox_client._set_runtime(None, status)
    decision = core_guard.Decision(enabled=True, source=settings.source, on_unavailable=settings.on_unavailable)
    core_guard.unavailable(decision, reason)  # exits unless on_unavailable is warn
    return status


def install_at_startup(argv: list[str], *, config_dir: Path | None = None) -> tuple[list[str], sandbox_client.Status]:
    """Decide and, when wanted, enable the sandbox in this process (tests and tools; iCode goes through its guard)."""
    if config_dir is None:
        from chrys.foundation.platform import conventional_config_dir

        config_dir = conventional_config_dir()
    rest, decision = core_guard.decide(argv, config_dir)
    st = start(rest, decision, config_dir)
    if decision.enabled:
        from icode_sandbox.guard import GUARD

        core_guard.set_current(GUARD)
    return rest, st


def start(rest: list[str], decision: core_guard.Decision, config_dir: Path) -> sandbox_client.Status:
    """Enable the sandbox iCode decided on; the status it ends up in."""
    settings = settings_for(decision, config_dir)
    if (live := sandbox_client.runtime()) is not None:
        # Already confined (a second entry into ``main`` in the same process):
        # the decision was made once and can't be undone — keep it.
        return live.status
    if os.environ.get(ENV_INHERITED) == "1" and confine.looks_confined():
        # Started by the broker inside a parent's sandbox. The variable alone is no proof:
        # without the kernel's own sign the process starts its own sandbox below.
        status = sandbox_client.Status(
            state="active" if settings.enabled else "inactive",
            requested=settings.enabled,
            mechanism="inherited",
            inherited=True,
            reasons=["confined by the parent iCode process"],
        )
        sandbox_client._set_runtime(None, status)
        return status
    if not settings.enabled:
        sandbox_client._set_runtime(None, sandbox_client.Status(state="inactive", requested=False))
        return sandbox_client.status()

    if settings.workdir_off_ignored:
        sys.stderr.write(
            "iCode: this working directory's settings ask to turn the sandbox off; they cannot, so it stays on.\n"
        )
        sys.stderr.flush()
    ok, mechanism = confine.available()
    if not ok:
        return _fail(settings, mechanism)
    if confine.PLATFORM == "linux" and confine.thread_count() > 1:
        return _fail(settings, f"{confine.thread_count()} threads were already running before the sandbox could start")

    from icode_sandbox import patches

    patches.remember_cwd()
    rt = sandbox_client.Runtime(config_dir=config_dir, settings=settings)
    try:
        rt.start_broker()
        rt.register_roots("launch", launch_dirs(rest))
        rt.confine_main()
    except (OSError, confine.ConfineError) as exc:
        _kill_broker(rt)
        if rt.main_confined:
            # Confined, but the check after it failed and no hook is in place: neither
            # sandboxed nor free. Whatever ``on_unavailable`` says, stop.
            sys.stderr.write(f"iCode: the sandbox failed after confining this process: {exc}\n")
            sys.stderr.flush()
            raise SystemExit(EXIT_UNAVAILABLE) from exc
        return _fail(settings, str(exc))

    rt.status.state = "degraded" if rt.status.reasons else "active"
    rt.status.mechanism = mechanism
    try:
        sandbox_client._set_runtime(rt)
        patches.install()
        rt.audit(
            "started",
            mechanism=mechanism,
            source=settings.source,
            main_allow=rt.main_allow,
            private_roots=rt.private_roots,
        )
    except Exception as exc:
        # This process is confined for good, but its hooks aren't all in place:
        # running on would look unsandboxed while being half so. Whatever
        # ``on_unavailable`` says, stop.
        _kill_broker(rt)
        sys.stderr.write(f"iCode: the sandbox failed after confining this process: {exc}\n")
        sys.stderr.flush()
        raise SystemExit(EXIT_UNAVAILABLE) from exc
    return rt.status


def _kill_broker(rt: sandbox_client.Runtime) -> None:
    import signal

    if rt.broker_pid():
        with contextlib.suppress(OSError):
            os.kill(rt.broker_pid(), cast(Any, signal).SIGKILL)
