# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Stub: the child iCode waits on while the broker runs the real command.

iCode's own process is confined, so a command that needs the workspace (or a
granted directory) cannot be its child. Instead iCode starts this stub as the
child — so ``asyncio`` and ``subprocess`` keep a real process to wait on,
signal and read from — and gives it one end of a socket whose other end the
broker already holds. The stub sends its argv, cwd, environment and stdio fds;
the broker runs the command under the requested profile with exactly those
fds, and reports the exit status, which the stub then exits with.

Catchable signals are forwarded to the command's process group; if the stub is
killed outright, the broker sees its socket close and kills the command.
Started as ``python -I -S stub.py <sock-fd> <spec-json>``.
"""

# Every import here costs every command iCode runs under the sandbox, so the
# stub uses the C modules directly: ``json`` pulls in ``re``, ``socket`` and
# ``signal`` pull in ``enum``, ``typing`` pulls in much more. It speaks the same
# frames as ``wire.py``.
import _json
import _signal
import _socket
import array
import os
import struct
import sys

_HEADER = struct.Struct("!I")
_MAX_MESSAGE = 8 * 1024 * 1024
_FORWARDED = ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2", "SIGWINCH", "SIGALRM", "SIGCONT")
_target = {"pgid": 0}
_early: list[int] = []
"""Signals that arrived before the command had a pid: they are for it all the same."""


class _Decoder:
    """What ``_json.make_scanner`` reads off its context, with ``json.loads``'s defaults."""

    strict = True
    object_hook = None
    object_pairs_hook = None
    parse_float = float
    parse_int = int
    parse_constant = float
    memo = {}  # noqa: RUF012 — read by the C scanner, which clears it per call


_scan = getattr(_json, "make_scanner")(_Decoder())  # noqa: B009 — typeshed wants a JSONDecoder


def _loads(text: str):
    return _scan(text, 0)[0]


def _dumps(value) -> str:
    """JSON of the plain values this stub sends (``json.dumps`` output for them)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _json.encode_basestring_ascii(value)
    if isinstance(value, list):
        return "[" + ",".join(_dumps(item) for item in value) + "]"
    return "{" + ",".join(f"{_json.encode_basestring_ascii(k)}:{_dumps(v)}" for k, v in value.items()) + "}"


def _send(sock, message: dict, fds: list[int]) -> None:
    payload = _dumps(message).encode()
    data = _HEADER.pack(len(payload)) + payload
    if fds:
        rights = array.array("i", fds)
        level = getattr(_socket, "SCM_RIGHTS")  # noqa: B009 — POSIX-only
        sent = sock.sendmsg([data], [(_socket.SOL_SOCKET, level, rights)])
    else:
        sent = sock.send(data)
    if sent < len(data):
        sock.sendall(data[sent:])


def _read_exactly(sock, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            if data:
                raise ConnectionError("truncated frame")
            return None
        data += chunk
    return bytes(data)


def _recv(sock) -> dict | None:
    head = _read_exactly(sock, _HEADER.size)
    if head is None:
        return None
    (length,) = _HEADER.unpack(head)
    if length > _MAX_MESSAGE:
        raise ConnectionError("frame too large")
    body = _read_exactly(sock, length)
    if body is None:
        raise ConnectionError("truncated frame")
    return _loads(body.decode())


def _forward(signum, _frame) -> None:
    if not _target["pgid"]:
        _early.append(signum)
        return
    try:  # noqa: SIM105 — contextlib costs every command an import
        getattr(os, "killpg")(_target["pgid"], signum)  # noqa: B009 — POSIX-only
    except OSError:
        pass


def _open_fds(candidates: list[int]) -> list[int]:
    import fcntl

    alive = []
    for fd in candidates:
        try:
            getattr(fcntl, "fcntl")(fd, getattr(fcntl, "F_GETFD"))  # noqa: B009 — POSIX-only
        except OSError:
            continue
        alive.append(fd)
    return alive


def main() -> int:
    sock = _socket.socket(fileno=int(sys.argv[1]))
    spec = _loads(sys.argv[2])
    for name in _FORWARDED:
        _signal.signal(getattr(_signal, name), _forward)
    targets = _open_fds([0, 1, 2, *[int(fd) for fd in spec.get("pass_fds", [])]])
    _send(
        sock,
        {
            "op": "run",
            "argv": spec["argv"],
            "program": spec.get("program"),
            "ctty": bool(spec.get("ctty")),
            "cwd": spec.get("cwd"),
            "env": dict(os.environ),
            "fd_targets": targets,
        },
        targets,
    )
    code = 127
    while True:
        try:
            message = _recv(sock)
        except InterruptedError:
            continue
        except OSError, ConnectionError:
            break
        if message is None:
            break
        if "pid" in message:
            _target["pgid"] = int(message["pid"])
            while _early:
                _forward(_early.pop(0), None)
        if "exit" in message:
            code = int(message["exit"])
            if message.get("error"):
                os.write(2, f"sandbox: {message['error']}\n".encode(errors="replace"))
            break
    if code < 0:
        _signal.signal(-code, _signal.SIG_DFL)
        os.kill(os.getpid(), -code)
        return 128 - code
    return code


if __name__ == "__main__":
    raise SystemExit(main())
