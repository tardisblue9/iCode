# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""``{{!command}}`` credential commands under the sandbox.

iCode runs them itself, outside any tool call, so they get the commands'
base scope: a command that only prints a token works; one that reads a file
outside that scope fails, and the error says the sandbox is why.
"""

from __future__ import annotations

from .conftest import Sandbox, needs_kernel

pytestmark = needs_kernel

SCENARIO = r"""
import asyncio
import chrys.service.command_credentials as cc
from chrys.foundation.util.env_templates import command_handles_in, resolve_env_templates

async def token(command):
    (handle,) = command_handles_in([resolve_env_templates("{{!" + command + "}}", location="test field")])
    try:
        await cc._fetch(handle)
        return {"ok": True, "value": cc._credentials[handle].token}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

results["plain"] = asyncio.run(token("echo tok-123"))
results["outside"] = asyncio.run(token("cat " + os.path.join(OTHER, "f.txt")))
"""


def test_a_credential_command_runs_confined_and_a_refusal_names_the_sandbox(sandbox: Sandbox) -> None:
    r = sandbox.run(SCENARIO)
    assert r["plain"] == {"ok": True, "value": "tok-123"}, r["plain"]
    assert not r["outside"]["ok"], r["outside"]
    assert "OTHER" not in r["outside"]["error"]
    assert "exited with code" in r["outside"]["error"]
    assert "sandbox is on" in r["outside"]["error"]
