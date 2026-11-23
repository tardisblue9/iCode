# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Run the whole test suite inside the file-access sandbox (``CHRYS_TEST_SANDBOX=1``).

Acceptance for the sandbox includes the full suite passing *with* it on: every
pytest process (each xdist worker) confines itself at configure time exactly as
``icode`` does at start — broker first, then the process, then the hooks — with
the repository as its workspace. Tests then run with the kernel refusing reads
of the home directory outside the repository, iCode's install and its config,
and every subprocess they start goes through the broker.

Two differences from ``icode``, both specific to a test runner:

- the Linux thread check is skipped: execnet starts I/O threads before any test
  code runs; the tests themselves run on the confining thread or threads it
  starts, which Landlock covers;
- the real-kernel sandbox tests skip themselves (``needs_kernel``): they confine
  fresh processes, which a confined parent cannot do on macOS.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ENV = "CHRYS_TEST_SANDBOX"
REPO_ROOT = Path(__file__).resolve().parents[2]


def wanted(config: object) -> bool:
    """True in the processes that run tests: each xdist worker, or the only process under ``-n0``.

    Never the xdist controller: it starts the workers, and a confined parent
    can't give them a sandbox of their own.
    """
    if os.environ.get(ENV) != "1":
        return False
    if hasattr(config, "workerinput"):
        return True
    option = getattr(config, "option", None)
    return not getattr(option, "numprocesses", 0)


def confine_this_process() -> None:
    """Confine the calling pytest process; exit loudly if that fails."""
    from chrys.foundation.platform import conventional_config_dir
    from icode_sandbox import client as sandbox_client
    from icode_sandbox import patches
    from icode_sandbox.runtime import confine

    ok, mechanism = confine.available()
    if not ok:
        sys.exit(f"{ENV}=1 but the sandbox is unavailable here: {mechanism}")
    settings = sandbox_client.SandboxSettings(enabled=True, source="test-harness")
    patches.remember_cwd()
    runtime = sandbox_client.Runtime(config_dir=conventional_config_dir(), settings=settings)
    runtime.start_broker()
    runtime.register_roots("launch", [str(REPO_ROOT)])
    runtime.confine_main()
    runtime.status.state, runtime.status.mechanism = "active", mechanism
    # The harness imposed it; the commands under test did not ask for it, so
    # they print no sandbox status line (``status_line`` reports requests).
    runtime.status.requested = False
    sandbox_client._set_runtime(runtime)
    patches.install()
    runtime.audit("started", mechanism=mechanism, source="test-harness", pid=os.getpid())
