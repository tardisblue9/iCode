# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The platform backends of the sandbox, and what each one can do.

The kernel work lives in ``runtime/confine.py`` (standard library only, so the
standalone broker and helpers can load it); this table names the backend for
each platform and declares its capabilities, which ``icode sandbox status`` and
the panel show as they are. A capability that is ``False`` is one the backend
does not provide on that platform, not one it might.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

CAPABILITIES = (
    "read_control",  # commands and helpers read only the workspace and grants
    "write_control",  # they change only the workspace, scratch space, caches and write grants
    "metadata_control",  # mode, times and extended attributes outside those, too
    "main_process",  # iCode's own process reads only its minimal set
    "live_grants",  # grants change mid-session without a restart
    "network_control",  # commands can't reach the network
    "socket_control",  # commands can't talk to local services over unix sockets
)


@dataclass(frozen=True)
class Backend:
    name: str
    platform: str
    mechanism: str
    supported: bool
    capabilities: dict[str, bool] = field(default_factory=dict)


def _caps(**on: bool) -> dict[str, bool]:
    return {name: on.get(name, False) for name in CAPABILITIES}


BACKENDS: dict[str, Backend] = {
    "darwin": Backend(
        name="seatbelt",
        platform="macOS",
        mechanism="Seatbelt",
        supported=True,
        capabilities=_caps(
            read_control=True, write_control=True, metadata_control=True, main_process=True, live_grants=True
        ),
    ),
    "linux": Backend(
        name="landlock",
        platform="Linux",
        mechanism="Landlock",
        supported=True,
        # Landlock has no rights for chmod, utime or extended attributes.
        capabilities=_caps(read_control=True, write_control=True, main_process=True, live_grants=True),
    ),
    "win32": Backend(name="windows", platform="Windows", mechanism="", supported=False, capabilities=_caps()),
}

_UNSUPPORTED = Backend(name="none", platform=sys.platform, mechanism="", supported=False, capabilities=_caps())


def current_backend() -> Backend:
    """The backend for this platform (an unsupported one when there is none)."""
    key = "linux" if sys.platform.startswith("linux") else sys.platform
    return BACKENDS.get(key, _UNSUPPORTED)
