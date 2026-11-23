# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Framed JSON messages with attached fds, shared by iCode and the sandbox processes.

Standard library only, and as little of it as possible: the stub imports just
this module, and it starts for every command iCode runs under the sandbox.
"""

# ``socket.send_fds``/``recv_fds`` import ``array`` on first use. A file helper
# can read nothing outside its allow list once confined (Landlock), so it is
# loaded here, before any process confines itself.
import array  # noqa: F401
import json
import socket
import struct

HEADER = struct.Struct("!I")
MAX_FDS = 16
MAX_MESSAGE = 8 * 1024 * 1024


def send(sock: socket.socket, message: dict, fds: list[int] | tuple[int, ...] = ()) -> None:
    """Send one framed JSON message, with *fds* attached to its first byte."""
    payload = json.dumps(message, separators=(",", ":")).encode()
    data = HEADER.pack(len(payload)) + payload
    sent = getattr(socket, "send_fds")(sock, [data], list(fds)) if fds else sock.send(data)  # noqa: B009 — POSIX-only
    if sent < len(data):
        sock.sendall(data[sent:])


def recv(sock: socket.socket) -> tuple[dict | None, list[int]]:
    """Receive one framed message; ``(None, [])`` on a clean EOF."""
    head, fds, _flags, _addr = getattr(socket, "recv_fds")(sock, HEADER.size, MAX_FDS)  # noqa: B009 — POSIX-only
    if not head:
        return None, []
    while len(head) < HEADER.size:
        more = sock.recv(HEADER.size - len(head))
        if not more:
            raise ConnectionError("truncated frame header")
        head += more
    (length,) = HEADER.unpack(head)
    if length > MAX_MESSAGE:
        raise ConnectionError("frame too large")
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(min(65536, length - len(body)))
        if not chunk:
            raise ConnectionError("truncated frame body")
        body += chunk
    return json.loads(body), list(fds)
