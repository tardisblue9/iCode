# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Grants: which extra paths a scope may read or also write, and for how long.

The lifetimes, matching the events that change a scope's read set:

- ``call``: one exact path for the duration of one tool call ("only this
  time" in the dialog), revoked when the call ends;
- ``once``: one open of one exact file, then gone;
- ``turn``: until the scope's current turn ends;
- ``session``: until the session ends (persisted, so a restore keeps it);
- ``workdir``: every session in the same working directory (persisted).

A grant is for reading unless it says ``access="write"``, which also covers
reading; grants stored before writes were controlled carry no ``access`` and are
for reading. Grants are keyed by the scope key (the session id) and only ever
*add* paths; the floor is checked by the broker no matter what is stored here.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from icode_sandbox.runtime import confine

GrantKind = Literal["once", "call", "turn", "session", "workdir"]
GrantAccess = Literal["read", "write"]
_PERSISTED: tuple[GrantKind, ...] = ("session", "workdir")


@dataclass(frozen=True)
class Grant:
    id: str
    kind: GrantKind
    path: str
    scope_key: str
    workdir_root: str
    created_at: float
    source: str = "user"
    access: GrantAccess = "read"


class GrantStore:
    """Thread-safe grant registry with JSON persistence for durable kinds."""

    def __init__(self, state_dir: Path | None) -> None:
        # Reentrant: persisting a grant opens files, and open hooks may ask back.
        self._lock = threading.RLock()
        self._grants: dict[str, Grant] = {}
        self._dir = state_dir
        self._loaded_scopes: set[str] = set()
        self._workdirs_loaded = False

    # ------------------------------------------------------------ persistence

    def _session_file(self, scope_key: str) -> Path | None:
        if self._dir is None:
            return None
        safe = "".join(c for c in scope_key if c.isalnum() or c in "-_.") or "default"
        return self._dir / "sessions" / f"{safe}.json"

    def _workdir_file(self) -> Path | None:
        return None if self._dir is None else self._dir / "workdirs.json"

    def _read(self, path: Path | None) -> list[Grant]:
        if path is None:
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError, ValueError:
            return []
        grants = []
        for item in raw.get("grants", []) if isinstance(raw, dict) else []:
            with contextlib.suppress(KeyError, TypeError, ValueError):
                grants.append(Grant(**item))
        return grants

    def _write(self, path: Path | None, grants: list[Grant]) -> None:
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"grants": [asdict(g) for g in grants]}, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _ensure_loaded(self, scope_key: str) -> None:
        if scope_key not in self._loaded_scopes:
            self._loaded_scopes.add(scope_key)
            for grant in self._read(self._session_file(scope_key)):
                self._grants.setdefault(grant.id, grant)
        if not self._workdirs_loaded:
            self._workdirs_loaded = True
            for grant in self._read(self._workdir_file()):
                self._grants.setdefault(grant.id, grant)

    def _flush(self, scope_key: str) -> None:
        self._write(
            self._session_file(scope_key),
            [g for g in self._grants.values() if g.kind == "session" and g.scope_key == scope_key],
        )
        self._write(self._workdir_file(), [g for g in self._grants.values() if g.kind == "workdir"])

    # ---------------------------------------------------------------- queries

    def add(
        self,
        scope_key: str,
        kind: GrantKind,
        path: str,
        workdir_root: str = "",
        source: str = "user",
        access: GrantAccess = "read",
    ) -> Grant:
        grant = Grant(
            id=uuid.uuid4().hex[:12],
            kind=kind,
            path=confine.real(path),
            scope_key=scope_key,
            workdir_root=confine.real(workdir_root) if workdir_root else "",
            created_at=time.time(),
            source=source,
            access=access,
        )
        with self._lock:
            self._ensure_loaded(scope_key)
            self._grants[grant.id] = grant
            if kind in _PERSISTED:
                self._flush(scope_key)
        return grant

    def paths(self, scope_key: str, workdir_root: str = "", access: GrantAccess | None = None) -> list[str]:
        """Directory/file grants (``turn``, ``session``, ``workdir``) of a scope, optionally of one access."""
        workdir = confine.real(workdir_root) if workdir_root else ""
        with self._lock:
            self._ensure_loaded(scope_key)
            return sorted(
                {
                    g.path
                    for g in self._grants.values()
                    if (access is None or g.access == access)
                    and (
                        (g.kind in ("call", "turn", "session") and g.scope_key == scope_key)
                        # Never a write grant, whatever a stored file says.
                        or (g.kind == "workdir" and workdir and g.workdir_root == workdir and g.access == "read")
                    )
                }
            )

    def take_once(self, scope_key: str, path: str) -> Grant | None:
        """Consume a ``once`` grant for exactly *path*, if one is pending."""
        resolved = confine.real(path)
        with self._lock:
            for grant in list(self._grants.values()):
                if grant.kind == "once" and grant.scope_key == scope_key and grant.path == resolved:
                    del self._grants[grant.id]
                    return grant
        return None

    def end_turn(self, scope_key: str) -> list[Grant]:
        with self._lock:
            ended = [
                g for g in self._grants.values() if g.scope_key == scope_key and g.kind in ("call", "turn", "once")
            ]
            for grant in ended:
                del self._grants[grant.id]
        return ended

    def revoke(self, grant_id: str) -> Grant | None:
        with self._lock:
            grant = self._grants.pop(grant_id, None)
            if grant is not None and grant.kind in _PERSISTED:
                self._flush(grant.scope_key)
        return grant

    def entries(self, scope_key: str | None = None) -> list[Grant]:
        with self._lock:
            if scope_key is not None:
                self._ensure_loaded(scope_key)
            return sorted(
                (
                    g
                    for g in self._grants.values()
                    if scope_key is None or g.scope_key == scope_key or g.kind == "workdir"
                ),
                key=lambda g: g.created_at,
            )

    def list_persisted(self) -> list[Grant]:
        """Every durable grant on disk, for the CLI (no session needs to be live)."""
        found: list[Grant] = []
        if self._dir is not None:
            for path in sorted((self._dir / "sessions").glob("*.json")):
                found.extend(self._read(path))
        found.extend(self._read(self._workdir_file()))
        return found

    def revoke_persisted(self, grant_id: str) -> Grant | None:
        """Remove a durable grant from disk by id (CLI use)."""
        if self._dir is None:
            return None
        files = [*sorted((self._dir / "sessions").glob("*.json")), self._workdir_file()]
        for path in files:
            grants = self._read(path)
            kept = [g for g in grants if g.id != grant_id]
            if len(kept) != len(grants):
                self._write(path, kept)
                with self._lock:
                    self._grants.pop(grant_id, None)
                return next(g for g in grants if g.id == grant_id)
        return None
