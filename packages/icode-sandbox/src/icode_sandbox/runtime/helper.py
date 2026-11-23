# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""File helper: opens files for iCode inside a kernel sandbox and hands back fds.

Started by the broker as ``python -I -S helper.py <sock-fd> <profile-json>``.
It starts already confined to that profile plus what an interpreter needs to
start: this file and the interpreter can be overwritten by the main process, so
they never run with more. On Linux it then narrows itself to the profile alone;
macOS can't confine twice, so there it refuses other paths itself, and the
kernel still holds the outer line. It proves the confinement took effect, then
serves requests on its socket until the socket closes:

- ``{"op": "open", "path": p, "flags": f}`` → an fd for *p* opened with *f*
- ``{"op": "list", "path": p}`` → an fd for directory *p* (``os.scandir(fd)``)
- ``{"op": "mkdir", "path": p, "mode": m}``, ``{"op": "unlink", "path": p}``,
  ``{"op": "rmdir", "path": p}``, ``{"op": "rename", "path": p, "dest": q}``,
  ``{"op": "symlink", "path": p, "target": t}`` (a link at *p* reading *t*):
  done here so the kernel decides where they land, for a file tool whose checked
  path may have become something else since

The kernel checks every open; this process trusts nothing it receives.
"""

import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import confine

_CHANGES = frozenset({"mkdir", "unlink", "rmdir", "rename", "symlink"})
_WRITE_BITS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
_ALLOWED_FLAG_BITS = (
    os.O_RDONLY
    | os.O_WRONLY
    | os.O_RDWR
    | os.O_APPEND
    | os.O_CREAT
    | os.O_TRUNC
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_DIRECTORY", 0)
)


def _change(sock: socket.socket, op: str, path: str, request: dict, profile: confine.Profile) -> None:
    dest = request.get("dest")
    targets = [path] if dest is None else [path, dest]
    if not all(isinstance(t, str) and t.startswith("/") and "\x00" not in t for t in targets):
        confine.send(sock, {"ok": False, "errno": 22, "error": "invalid path"})
        return
    # The folder a name would be changed in: the name itself may be a link, which isn't followed.
    held = [os.path.join(confine.real(os.path.dirname(t)), os.path.basename(t)) for t in targets]
    if not all(any(confine.is_within(t, r) for r in profile.write) for t in held):
        confine.send(sock, {"ok": False, "errno": 13, "error": "not writable by this helper"})
        return
    try:
        if op == "mkdir":
            os.mkdir(path, int(request.get("mode", 0o777)) & 0o7777)
        elif op == "unlink":
            os.unlink(path)
        elif op == "rmdir":
            os.rmdir(path)
        elif op == "symlink":
            os.symlink(str(request.get("target", "")), path)
        else:
            os.replace(path, str(dest))
    except OSError as exc:
        confine.send(sock, {"ok": False, "errno": exc.errno or 13, "error": exc.strerror or str(exc)})
        return
    confine.send(sock, {"ok": True})


def _serve(sock: socket.socket, profile: confine.Profile) -> None:
    while True:
        try:
            request, _fds = confine.recv(sock)
        except ConnectionError, OSError:
            return
        if request is None:
            return
        op = request.get("op")
        path = request.get("path")
        if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            confine.send(sock, {"ok": False, "errno": 22, "error": "invalid path"})
            continue
        if op in _CHANGES:
            _change(sock, op, path, request, profile)
            continue
        if op != "ping" and not any(confine.is_within(confine.real(path), root) for root in profile.allow):
            confine.send(sock, {"ok": False, "errno": 13, "error": "outside this helper's profile"})
            continue
        try:
            if op == "open":
                flags = int(request.get("flags", os.O_RDONLY)) & _ALLOWED_FLAG_BITS
                if flags & _WRITE_BITS and not any(confine.is_within(confine.real(path), r) for r in profile.write):
                    # macOS: the kernel's line here is the outer one (see above).
                    confine.send(sock, {"ok": False, "errno": 13, "error": "not writable by this helper"})
                    continue
                mode = int(request.get("mode", 0o666)) & 0o7777
                fd = os.open(path, flags | getattr(os, "O_CLOEXEC", 0), mode)
            elif op == "list":
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
            elif op == "ping":
                confine.send(sock, {"ok": True})
                continue
            else:
                confine.send(sock, {"ok": False, "errno": 22, "error": f"unknown op {op!r}"})
                continue
        except OSError as exc:
            confine.send(sock, {"ok": False, "errno": exc.errno or 13, "error": exc.strerror or str(exc)})
            continue
        try:
            confine.send(sock, {"ok": True}, [fd])
        finally:
            os.close(fd)


def main() -> int:
    sock = socket.socket(fileno=int(sys.argv[1]))
    profile = confine.Profile.from_json(sys.argv[2])
    probe = sys.argv[3]
    try:
        if confine.PLATFORM == "linux":
            confine.apply(profile)
        confine.self_check(probe)
    except confine.ConfineError as exc:
        confine.send(sock, {"ok": False, "fatal": True, "error": str(exc)})
        return 70
    confine.send(sock, {"ok": True, "ready": True, "pid": os.getpid()})
    _serve(sock, profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
