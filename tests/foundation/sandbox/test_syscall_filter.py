# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Linux: the syscalls no command needs are refused to commands and helpers (``confine.linux_syscall_filter``).

The whole list is checked by running the built filter on each machine's
numbers; a safe part of it (nothing that would act if it ran) is called for
real in a sandboxed command, against the same calls made by this test's own
unsandboxed process.
"""

from __future__ import annotations

import errno
import json
import platform
import struct
import subprocess
import sys

import pytest

from icode_sandbox.runtime import confine

from .conftest import Sandbox, needs_kernel


def _run_filter(program: bytes, arch: int, nr: int) -> int:
    """The action the filter returns for syscall *nr* on *arch* (a tiny interpreter for the ops it uses)."""
    code = [struct.unpack("HBBI", program[i : i + 8]) for i in range(0, len(program), 8)]
    data = {0: nr, 4: arch}
    acc, pc = 0, 0
    while True:
        op, jt, jf, k = code[pc]
        if op == 0x20:
            acc = data[k]
            pc += 1
        elif op == 0x15:
            pc += 1 + (jt if acc == k else jf)
        elif op == 0x45:
            pc += 1 + (jt if acc & k else jf)
        elif op == 0x06:
            return k
        else:
            raise AssertionError(f"unexpected op {op:#x}")


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_every_listed_syscall_is_refused_and_others_pass(machine: str) -> None:
    built = confine.linux_syscall_filter(machine)
    assert built is not None
    program = bytes(built.buffer)
    arch, numbers = confine._SYSCALL_TABLES[machine]
    eperm = 0x00050000 | errno.EPERM
    for name in confine.BLOCKED_SYSCALLS:
        assert _run_filter(program, arch, numbers[name]) == eperm, name
    ordinary = {"x86_64": (0, 1, 2, 3, 59, 57, 56, 435), "aarch64": (63, 64, 56, 57, 221, 220, 435)}[machine]
    for nr in ordinary:  # read, write, open(at), close, execve, fork/clone, clone3
        assert _run_filter(program, arch, nr) == 0x7FFF0000, nr
    # Another architecture's numbers mean other calls: refused outright.
    assert _run_filter(program, 0x40000003, 1) == eperm  # i386
    if machine == "x86_64":
        assert _run_filter(program, arch, 0x40000000 | 165) == eperm  # x32 mount


def test_a_machine_without_a_table_gets_no_filter() -> None:
    assert confine.linux_syscall_filter("riscv64") is None


# Calls that do nothing harmful when they do reach the kernel (bad pointers, bad descriptors, flags 0).
PROBE = r"""
import ctypes, json, platform, sys
libc = ctypes.CDLL(None, use_errno=True)
numbers = json.loads(sys.argv[1])
calls = {
    "mount": (0, 0, 0, 0, 0), "umount2": (0, 0), "pivot_root": (0, 0), "fsopen": (0, 0), "open_tree": (-1, 0, 0),
    "unshare": (0,), "setns": (-1, 0), "ptrace": (2, 1, 0, 0), "keyctl": (0, 0), "add_key": (0, 0, 0, 0, 0),
    "request_key": (0, 0, 0, 0), "bpf": (0, 0, 0), "perf_event_open": (0, 0, -1, -1, 0), "userfaultfd": (0,),
    "io_uring_setup": (0, 0), "io_uring_enter": (-1, 0, 0, 0, 0, 0), "io_uring_register": (-1, 0, 0, 0),
    "open_by_handle_at": (-1, 0, 0), "name_to_handle_at": (-1, 0, 0, 0, 0),
}
out = {}
for name, args in calls.items():
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(numbers[name]), *[ctypes.c_long(a) for a in args])
    out[name] = 0 if rc >= 0 else ctypes.get_errno()
print(json.dumps(out))
"""

_LINUX = pytest.mark.skipif(
    not sys.platform.startswith("linux") or platform.machine() not in ("x86_64", "aarch64"), reason="Linux seccomp"
)


@needs_kernel
@_LINUX
def test_a_command_is_refused_the_dangerous_syscalls(sandbox: Sandbox) -> None:
    numbers = json.dumps(confine._SYSCALL_TABLES[platform.machine()][1])
    outside = json.loads(
        subprocess.run([sys.executable, "-c", PROBE, numbers], capture_output=True, text=True, check=True).stdout
    )
    r = sandbox.run(
        f"""
scope = policy.Scope(key="s", roots=(WS,), workdir_root=WS)
with client.scoped(scope):
    done = subprocess.run([sys.executable, "-c", {PROBE!r}, {numbers!r}], capture_output=True, text=True)
    results["inside"] = {{"ok": True, "value": json.loads(done.stdout) if done.stdout else done.stderr[-500:]}}
"""
    )
    inside = r["inside"]["value"]
    assert isinstance(inside, dict), r
    assert {name: e for name, e in inside.items() if e != errno.EPERM} == {}, inside
    # Control: without the sandbox some of them reach the kernel and fail (or work) otherwise.
    assert [name for name, e in outside.items() if e != errno.EPERM], outside
