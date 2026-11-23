# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Under ``CHRYS_TEST_SANDBOX=1`` the runner really is confined (else the full-suite run proves nothing)."""

from __future__ import annotations

import os
import subprocess

import pytest

from icode_sandbox import client as sandbox_client
from icode_sandbox import policy
from tests.support import sandbox_harness

pytestmark = pytest.mark.skipif(
    os.environ.get(sandbox_harness.ENV) != "1", reason="only under the sandboxed full-suite run"
)


def test_the_runner_is_confined() -> None:
    assert sandbox_client.runtime() is not None
    assert sandbox_client.status().label() == "active"
    assert sandbox_client.status_line() is None  # imposed by the harness, not requested by a command
    with pytest.raises(PermissionError):
        os.listdir(policy.home())
    result = subprocess.run(["ls", policy.home()], capture_output=True, stdin=subprocess.DEVNULL, check=False)
    assert result.returncode != 0
    assert os.listdir(sandbox_harness.REPO_ROOT)  # the workspace stays readable
