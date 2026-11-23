# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""File-access sandbox: kernel-confined reads for iCode and everything it runs.

Overview (the user guide, ``docs/en/guides/configuration/file-sandbox.md``, says what it does for the person):

- :mod:`.bootstrap` enables it at process start (never later);
- :mod:`.client` holds the runtime: broker connection, file helpers, scopes,
  grants, status;
- :mod:`.patches` keeps iCode's own code and its subprocesses working inside
  the sandbox;
- :mod:`.policy` computes every read set;
- ``runtime/`` holds the standalone processes (broker, helper, stub,
  trampoline) and the kernel primitives they share.
"""

from icode_sandbox.client import (
    SandboxDenied,
    Status,
    current_scope,
    runtime,
    scoped,
    status,
)
from icode_sandbox.policy import Scope

__all__ = ["SandboxDenied", "Scope", "Status", "current_scope", "runtime", "scoped", "status"]
