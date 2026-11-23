# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""The sandbox's part in one agent's tool calls (``chrys.foundation.guard.ToolCalls``).

Each call runs in its session's scope: files it opens and programs it starts
are confined to the workspace and the session's grants. A path the call names
outside them is either readable for this turn (the person named it in their
own message), granted after asking (manual approval, not for sub-agents), or
refused before the tool runs. Refusals the kernel made while the tool ran are
reported afterwards, to the session's trajectory and to the frontends.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

from chrys.foundation.events.types import SandboxAccessDenied
from chrys.foundation.trajectory.context import current_tool_operation_id, current_trajectory
from chrys.foundation.trajectory.event_types import EventType
from icode_sandbox import client as sandbox_client
from icode_sandbox import reads as sandbox_reads

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from chrys.foundation.guard import ToolCallHost
    from icode_sandbox.grants import GrantAccess
    from icode_sandbox.policy import Scope


class SandboxToolCalls:
    def __init__(self, rt: sandbox_client.Runtime, host: ToolCallHost) -> None:
        self._rt = rt
        self._host = host
        self._key = host.session_id or "default"
        rt.hold_scope(self._key)
        self._closed = False

    async def run(self, context: Any, proceed: Callable[[], Awaitable[None]]) -> None:
        rt, host = self._rt, self._host
        roots = host.workspace_roots or ([host.workspace_cwd] if host.workspace_cwd else [])
        scope = sandbox_reads.scope_for(host.session_id, roots, host.workspace_cwd)
        with sandbox_client.scoped(scope):
            tool_name = context.function.name
            tool_kind = host.tool_kind(context)
            paths = await asyncio.to_thread(
                sandbox_reads.candidate_paths, tool_kind, context.arguments, host.workspace_cwd
            )
            targets = await asyncio.to_thread(
                sandbox_reads.write_targets, tool_kind, context.arguments, host.workspace_cwd
            )
            call_grants: list[str] = []
            try:
                admitted = True
                for blocked in sandbox_reads.blocked_paths(scope, paths):
                    admitted = await self._admit(context, scope, blocked, tool_name, call_grants)
                    if not admitted:
                        break
                if admitted:
                    for blocked in sandbox_reads.blocked_writes(scope, targets):
                        admitted = await self._admit(context, scope, blocked, tool_name, call_grants, access="write")
                        if not admitted:
                            break
                if admitted:
                    await proceed()
            finally:
                for grant_id in call_grants:
                    rt.revoke(grant_id)
            # After a failed or cancelled call they stay queued for the session's next one.
            await self._report(scope.key, tool_name)

    def end_turn(self) -> None:
        if self._host.can_request:
            self._rt.end_turn(self._key)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._rt.release_scope(self._key)

    async def _report(self, scope_key: str, tool_name: str) -> None:
        """Pass this call's refusals on to the session's trajectory and frontends."""
        rt = self._rt
        for denial in rt.take_unreported(scope_key):
            if denial.outcome == "granted":
                continue
            tool = denial.tool or tool_name
            trajectory = current_trajectory()
            if trajectory is not None:
                draft = trajectory.draft(
                    EventType.SANDBOX_ACCESS_DENIED,
                    payload={
                        "path": rt.logged_path(denial.path),
                        "tool": tool,
                        "outcome": denial.outcome,
                        "access": denial.access,
                    },
                    parent_operation_id=current_tool_operation_id(),
                )
                # Recording never stands in the way of the refusal it describes.
                with contextlib.suppress(Exception):
                    trajectory.sink.emit_soon(draft)
            await self._host.publish(
                SandboxAccessDenied(
                    session_id=self._host.session_id,
                    path=denial.path,
                    tool=tool,
                    outcome=denial.outcome,
                    access=denial.access,
                )
            )

    async def _admit(
        self,
        context: Any,
        scope: Scope,
        blocked: sandbox_reads.Blocked,
        tool_name: str,
        call_grants: list[str],
        *,
        access: GrantAccess = "read",
    ) -> bool:
        """Ask the person to grant a read or write the sandbox would refuse; ``False`` sets the refusal."""
        rt, host = self._rt, self._host
        if (
            access == "read"
            and not blocked.protected
            and sandbox_reads.mentioned_by_user(
                blocked.path, sandbox_reads.mentioned_paths(host.user_messages(), host.workspace_cwd)
            )
        ):
            # The person named this path in their own message this turn: their
            # request, not the model's — readable for the turn, without asking.
            rt.grant(scope, "turn", blocked.path, source="mention")
            rt.record_denial(blocked.path, scope.key, tool_name, "granted")
            return True
        can_ask = host.may_ask() and host.can_request and not blocked.protected
        rejected = False
        if can_ask:
            kind, verb = (
                (sandbox_reads.WRITE_TOOL_KIND, "writing")
                if access == "write"
                else (sandbox_reads.TOOL_KIND, "reading")
            )
            response = await host.ask(
                context,
                path=blocked.path,
                tool_name=tool_name,
                kind=kind,
                intent=f"Allow {verb} {blocked.path} (outside the workspace)",
                offer=sandbox_reads.offer_for(blocked.path, access),
            )
            if response is not None and response.approved:
                try:
                    call_grant = sandbox_reads.apply_answer(scope, blocked.path, response.remember_choice, access)
                except sandbox_client.SandboxDenied:
                    blocked = sandbox_reads.Blocked(blocked.path, protected=True)
                else:
                    if call_grant is not None:
                        call_grants.append(call_grant)
                    rt.record_denial(blocked.path, scope.key, tool_name, "granted", access)
                    return True
            rejected = response is not None
        outcome = "protected" if blocked.protected else "declined" if rejected else "refused"
        rt.record_denial(blocked.path, scope.key, tool_name, outcome, access)
        host.refuse(
            context, sandbox_reads.refusal(blocked, tool_name, can_ask=can_ask, rejected=rejected, access=access)
        )
        return False
