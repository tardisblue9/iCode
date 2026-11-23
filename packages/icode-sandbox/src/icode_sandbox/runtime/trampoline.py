# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Exec trampoline: place inherited fds, take a terminal, then exec a command.

The broker starts it as ``python -I -S trampoline.py <spec-json>`` already
confined: this file and the interpreter can be overwritten by the main process,
so nothing here may run with more rights than the command will have. The spec
holds the argv to exec and an fd map (``[[received_fd, target_fd], ...]``) that
puts the caller's extra fds back on the numbers the caller expects. Stdio (0-2)
is already in place.
"""

import fcntl
import json
import os
import sys
from typing import Any, cast

_EXEC_FAILED = 127


def _place_fds(fd_map: list[list[int]]) -> None:
    staged = []
    for source, target in fd_map:
        posix_fcntl = cast(Any, fcntl)
        staged.append((posix_fcntl.fcntl(source, posix_fcntl.F_DUPFD_CLOEXEC, 100), target))
        os.close(source)
    for temp, target in staged:
        os.dup2(temp, target, inheritable=True)
        os.close(temp)


def main() -> int:
    spec = json.loads(sys.argv[1])
    argv = [str(a) for a in spec["argv"]]
    program = str(spec.get("program") or argv[0])
    try:
        _place_fds(spec.get("fd_map", []))
        if spec.get("ctty"):
            # A terminal program: this process leads its own session (the broker
            # started it so), and takes the terminal on its stdin as that
            # session's controlling terminal, as it would outside the sandbox.
            import termios

            cast(Any, fcntl).ioctl(0, cast(Any, termios).TIOCSCTTY, 0)
    except OSError as exc:
        os.write(2, f"sandbox: could not start command: {exc}\n".encode(errors="replace"))
        return _EXEC_FAILED
    os.environ["CHRYS_FILE_SANDBOX_INHERITED"] = "1"
    try:
        if "/" in program:
            os.execve(program, argv, os.environ)
        os.execvpe(program, argv, os.environ)
    except OSError as exc:
        os.write(2, f"sandbox: {program}: {exc.strerror or exc}\n".encode(errors="replace"))
    return _EXEC_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
