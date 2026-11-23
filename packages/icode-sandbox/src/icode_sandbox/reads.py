# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Read and write access of model-directed file tools under the file-access sandbox.

Every tool call runs in its session's *scope* (see ``icode_sandbox.policy``):
the kernel lets it read the workspace and the session's grants, nothing else in
the private roots. This module adds the user-facing half, before the tool
runs:

- a path the tool names that lies outside the scope is either *protected*
  (never grantable: a clear error), or the user is asked, in an interactive
  (manual-approval) session, whether to grant it;
- otherwise the call is refused with a message the model can act on.

What the person decides becomes a grant:

==========================  =====================================
dialog answer               grant
==========================  =====================================
Approve                     this tool call only, the exact path
Remember → This turn        the rest of the turn, the path's folder
Remember → This session     the session, the folder
Remember → This working directory  every session in this working directory, folder
Decline                     none
==========================  =====================================

The same goes for writes, with their own grants: a folder granted for reading
stays read-only, a folder granted for writing can also be read, and write
grants never outlive the session. The kernel remains the enforcement: a path
this check misses (a shell command's argument, say) is still refused by the
sandbox itself.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Generator
from dataclasses import dataclass
from typing import Any

from chrys.foundation.models.approval_reuse import ApprovalReuseOffer
from chrys.foundation.platform.paths import resolve_workspace_path
from chrys.foundation.tool_kinds import (
    KIND_DOC_CONVERTER,
    KIND_FILESYSTEM_READ,
    KIND_FILESYSTEM_WRITE,
    KIND_SEARCH,
)
from icode_sandbox import client as sandbox_client
from icode_sandbox import policy
from icode_sandbox.grants import GrantAccess
from icode_sandbox.runtime import confine

TOOL_KIND = "sandbox.read"
"""``ApprovalRequest.tool_kind`` of a read-grant request (no policy rule can match it)."""
WRITE_TOOL_KIND = "sandbox.write"
"""The same, for a write grant."""

_PATH_KINDS = frozenset({KIND_FILESYSTEM_READ, KIND_SEARCH, KIND_DOC_CONVERTER})
_PATH_KEYS = ("path", "file_path", "paths")


@dataclass(frozen=True)
class Blocked:
    """A path the call may not read, and whether a person could grant it."""

    path: str
    protected: bool


def scope_for(session_id: str | None, roots: list[str], workspace_cwd: str | None) -> policy.Scope:
    workdir = confine.real(workspace_cwd) if workspace_cwd else (roots[0] if roots else "")
    return policy.Scope(key=session_id or "default", roots=tuple(roots), workdir_root=workdir)


def candidate_paths(tool_kind: str, arguments: Any, workspace_cwd: str | None) -> list[str]:
    """Resolved, existing paths a file tool call names."""
    if tool_kind not in _PATH_KINDS or not isinstance(arguments, dict):
        return []
    raw: list[str] = []
    for key in _PATH_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            raw.append(value)
        elif isinstance(value, list):
            raw.extend(v for v in value if isinstance(v, str) and v)
    if tool_kind == KIND_SEARCH and not raw:
        raw.append(".")
    found = []
    for item in raw:
        try:
            resolved = confine.real(resolve_workspace_path(item, base_cwd=workspace_cwd))
        except OSError, ValueError:
            continue
        if os.path.lexists(resolved):
            found.append(resolved)
    return found


@contextlib.contextmanager
def session_scope(session_id: str | None, roots: list[str], workspace_cwd: str | None) -> Generator[None]:
    """Run iCode's own work for a session (a rollback) inside its scope, as a tool call would be.

    Its writes then go through the session's helper, so the kernel decides
    where they land: the paths it works on were recorded from earlier tool
    calls, and the folders on the way may have been swapped for links since.
    """
    if sandbox_client.runtime() is None:
        yield
        return
    with sandbox_client.scoped(scope_for(session_id, roots, workspace_cwd)):
        yield


def write_targets(tool_kind: str, arguments: Any, workspace_cwd: str | None) -> list[str]:
    """Resolved paths a file tool call would change, whether they exist yet or not."""
    if tool_kind != KIND_FILESYSTEM_WRITE or not isinstance(arguments, dict):
        return []
    found = []
    for key in _PATH_KEYS:
        value = arguments.get(key)
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item:
                with contextlib.suppress(OSError, ValueError):
                    found.append(confine.real(resolve_workspace_path(item, base_cwd=workspace_cwd)))
    return found


def blocked_writes(scope: policy.Scope, paths: list[str]) -> list[Blocked]:
    """The paths in *paths* outside what the scope may change, and whether a person could grant each."""
    rt = sandbox_client.runtime()
    if rt is None:
        return []
    allowed = rt.write_set(scope)
    blocked = []
    for path in paths:
        if any(confine.is_within(path, root) for root in allowed):
            continue
        target = grant_target(path)
        protected = (
            policy.is_write_protected(path, rt.config_dir, rt.settings.floor_extra)
            or policy.is_write_protected(target, rt.config_dir, rt.settings.floor_extra)
            or policy.is_home(target)
            or target in rt.private_roots
        )
        blocked.append(Blocked(path, protected))
    return blocked


def blocked_paths(scope: policy.Scope, paths: list[str]) -> list[Blocked]:
    rt = sandbox_client.runtime()
    if rt is None:
        return []
    blocked = []
    access = rt.access_set(scope)
    for path in paths:
        if not policy.is_private(path) or access.covers(path):
            continue
        if any(confine.is_within(path, p) for p in _session_internal(rt)):
            continue
        blocked.append(Blocked(path, policy.is_protected(path, rt.settings.floor_extra) or policy.is_home(path)))
    return blocked


def _session_internal(rt: sandbox_client.Runtime) -> list[str]:
    # Session artifacts (document handles, spilled output) live in the config dir.
    return [os.path.join(str(rt.config_dir), "sessions")]


def mentioned_paths(user_messages: list[str], cwd: str | None) -> list[str]:
    """Resolved paths the person ``@``-mentioned in this turn's messages."""
    from chrys.foundation.text.mentions import iter_mention_tokens

    found = []
    for message in user_messages:
        for token in iter_mention_tokens(message):
            try:
                resolved = confine.real(resolve_workspace_path(token.value, base_cwd=cwd))
            except OSError, ValueError, RuntimeError:
                continue
            # Naming a whole private root (``@~``) doesn't open everything under it.
            if resolved != "/" and not policy.is_home(resolved) and resolved not in policy.private_roots():
                found.append(resolved)
    return found


def mentioned_by_user(path: str, mentioned: list[str]) -> bool:
    """True when the person named *path* (or a folder holding it) this turn."""
    return any(confine.is_within(path, m) for m in mentioned)


def grant_target(path: str) -> str:
    """The nearest existing folder a remembered grant covers for *path*."""
    if os.path.isdir(path):
        return path
    parent = os.path.dirname(path)
    while parent != "/" and not os.path.isdir(parent):
        parent = os.path.dirname(parent)
    return parent


def offer_for(path: str, access: GrantAccess = "read") -> ApprovalReuseOffer:
    return ApprovalReuseOffer(
        kind="write_folder" if access == "write" else "read_folder", targets=(grant_target(path),)
    )


def apply_answer(scope: policy.Scope, path: str, remember_choice: str, access: GrantAccess = "read") -> str | None:
    """Turn the person's answer into a grant; returns the id of a call-long grant to revoke afterwards."""
    rt = sandbox_client.runtime()
    if rt is None:
        return None
    if remember_choice.endswith("_WORKDIR"):
        rt.grant(scope, "workdir", grant_target(path), access=access)
    elif remember_choice.endswith("_SESSION"):
        rt.grant(scope, "session", grant_target(path), access=access)
    elif remember_choice.endswith("_TURN"):
        rt.grant(scope, "turn", grant_target(path), access=access)
    elif access == "write":
        # A tool writes through a temporary file beside its target: the folder, for this one call.
        return rt.grant(scope, "call", grant_target(path), access=access).id
    else:
        return rt.grant(scope, "call", path).id
    return None


def refusal(
    blocked: Blocked, tool_name: str, *, can_ask: bool, rejected: bool = False, access: GrantAccess = "read"
) -> str:
    """The tool result the model sees for a refused read or write."""
    if access == "write":
        if blocked.protected:
            return (
                f"Error: sandbox: {blocked.path} can't be written in this session: changing it could run code outside "
                "the sandbox, or it is in a folder too broad to grant. Write inside the workspace, or tell the user "
                "what to change so they can do it themselves."
            )
        if rejected:
            return f"Error: sandbox: the user declined write access to {blocked.path}."
        if can_ask:
            return f"Error: sandbox: write access to {blocked.path} was not granted."
        return (
            f"Error: sandbox: {blocked.path} is outside the workspace and this session's write grants, and this "
            "session cannot ask the user for access (non-interactive or automatic approval). Write inside the "
            "workspace, or tell the user which path you need so they can add it as a working directory."
        )
    if blocked.protected:
        return (
            f"Error: sandbox: {blocked.path} is in a protected location (credentials, keys, browser data) "
            "and cannot be read in this session. Do not try other ways to read it."
        )
    if rejected:
        return f"Error: sandbox: the user declined read access to {blocked.path}."
    if can_ask:
        return f"Error: sandbox: read access to {blocked.path} was not granted."
    return (
        f"Error: sandbox: {blocked.path} is outside the workspace and this session's read grants, and this session "
        "cannot ask the user for access (non-interactive or automatic approval). Work inside the workspace, or tell "
        "the user which path you need so they can add it as a working directory."
    )
