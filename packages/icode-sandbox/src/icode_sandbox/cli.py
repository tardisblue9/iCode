# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""``icode sandbox``: inspect the file-access sandbox from outside a session.

- ``status``: whether this machine can confine iCode and whether it would
  (settings, environment); ``--session ID`` adds that session's grants and its
  recent sandbox events from the audit log.
- ``grants``: durable grants (session and working directory); ``--revoke ID`` removes one.
- ``probe``: start a confined process and check every boundary for real.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from chrys.foundation.branding import APP_COMMAND
from chrys.foundation.platform import conventional_config_dir
from icode_sandbox import policy
from icode_sandbox.bootstrap import resolve_settings
from icode_sandbox.grants import GrantStore
from icode_sandbox.runtime import confine


def _config_dir() -> Path:
    return Path(confine.real(str(conventional_config_dir())))


_LIVE_CHECK = (
    "import sys; sys.path.insert(0, sys.argv[1]); import confine; "
    "confine.apply(confine.Profile(mode='except', deny_roots=[sys.argv[2]])); confine.self_check(sys.argv[2])"
)


def _live_check() -> tuple[bool, str]:
    """Confine a throwaway process the way iCode would and check it took effect."""
    runtime_dir = str(Path(confine.__file__).resolve().parent)
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", _LIVE_CHECK, runtime_dir, policy.home()],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    if result.returncode == 0:
        return True, "confinement works"
    return False, (result.stderr.strip().splitlines() or ["unknown failure"])[-1]


def _status(args: argparse.Namespace) -> int:
    config_dir = _config_dir()
    _rest, settings = resolve_settings([], config_dir)
    ok, mechanism = confine.available()
    live_ok, live = _live_check() if ok else (False, mechanism)
    report: dict[str, Any] = {
        "platform": confine.PLATFORM,
        "supported": ok,
        "mechanism": mechanism,
        "works": live_ok,
        "live_check": live,
        "enabled_at_next_start": settings.enabled,
        "decided_by": settings.source,
        "on_unavailable": settings.on_unavailable,
        "private_roots": policy.private_roots(),
        "floor": policy.floor(settings.floor_extra),
        "main_allow_extra": settings.main_allow,
        "commands_allow_extra": settings.shell_allow,
        "commands_write_extra": settings.shell_write,
        "write_floor": policy.write_floor(config_dir),
    }
    if args.session:
        store = GrantStore(config_dir / "sandbox")
        report["session"] = args.session
        report["grants"] = [
            g.__dict__ for g in store.list_persisted() if g.scope_key == args.session or g.kind == "workdir"
        ]
        report["events"] = _session_events(config_dir, args.session, limit=args.limit)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    print(
        f"Platform:       {report['platform']} ({'supported: ' + mechanism if ok else 'NOT supported: ' + mechanism})"
    )
    print(f"Live check:     {'OK' if live_ok else 'FAILED'} ({live})")
    print(f"Next start:     {'sandbox ON' if settings.enabled else 'sandbox off'} (decided by {settings.source})")
    print(f"If unavailable: {settings.on_unavailable}")
    print("Private roots:  " + ", ".join(report["private_roots"]))
    print("Never granted:  " + ", ".join(report["floor"]))
    print("Never writable: " + ", ".join(report["write_floor"]))
    if args.session:
        print(f"\nSession {args.session}")
        for grant in report["grants"]:
            print(f"  grant {grant['id']}  {grant['kind']:8} {grant.get('access', 'read'):5} {grant['path']}")
        if not report["grants"]:
            print("  (no durable grants)")
        for event in report["events"]:
            print(f"  {event.get('t')}  {event.get('event'):14} {event.get('path', '')} {event.get('outcome', '')}")
    return 0


def _session_events(config_dir: Path, session: str, *, limit: int) -> list[dict[str, Any]]:
    """The session's own sandbox log when it has one, else its lines of the process-wide log."""
    from chrys.foundation.config.settings import resolve_sessions_dir
    from chrys.foundation.util.session_ids import session_short_id
    from icode_sandbox.client import SESSION_EVENTS_FILE

    path = config_dir / "sandbox" / "audit.jsonl"
    try:
        own = resolve_sessions_dir(config_dir, create=False) / session_short_id(session) / SESSION_EVENTS_FILE
    except OSError:
        own = None
    if own is not None and own.is_file():
        path = own
    events: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("scope") == session:
                    events.append(record)
    except OSError:
        return []
    return events[-limit:]


def _grants(args: argparse.Namespace) -> int:
    store = GrantStore(_config_dir() / "sandbox")
    if args.revoke:
        grant = store.revoke_persisted(args.revoke)
        if grant is None:
            print(f"No durable grant with id {args.revoke}", file=sys.stderr)
            return 1
        print(f"Revoked {grant.kind} grant {grant.id}: {grant.path}")
        return 0
    grants = store.list_persisted()
    if args.json:
        print(json.dumps([g.__dict__ for g in grants], indent=2, ensure_ascii=False))
        return 0
    if not grants:
        print("No durable sandbox grants.")
    for grant in grants:
        where = grant.workdir_root if grant.kind == "workdir" else grant.scope_key
        print(f"{grant.id}  {grant.kind:8} {grant.access:5} {grant.path}  ({where})")
    return 0


_PROBE = r"""
import json, os, subprocess, sys
ws, secret, floor_dir = sys.argv[1], sys.argv[2], sys.argv[3]
from icode_sandbox import bootstrap, client, policy
_argv, status = bootstrap.install_at_startup(["--sandbox", "-C", ws])
results = {"status": status.label(), "mechanism": status.mechanism, "checks": []}
def check(name, expect_ok, fn):
    try:
        fn(); ok = True; detail = ""
    except Exception as exc:
        ok = False; detail = type(exc).__name__
    results["checks"].append({"name": name, "expected": "allow" if expect_ok else "deny", "got": "allow" if ok else "deny", "pass": ok == expect_ok, "detail": detail})
def run(cmd):
    subprocess.run(cmd, capture_output=True, check=True)
check("main: read workspace file", True, lambda: open(os.path.join(ws, "f.txt")).read())
check("main: read private file outside workspace", False, lambda: open(os.path.join(secret, "f.txt")).read())
check("main: list home directory", False, lambda: os.listdir(os.path.expanduser("~")))
check("command: cat workspace file", True, lambda: run(["cat", os.path.join(ws, "f.txt")]))
check("command: cat private file", False, lambda: run(["cat", os.path.join(secret, "f.txt")]))
scope = policy.Scope(key="probe", roots=(ws,))
with client.scoped(scope):
    check("scope: read workspace file", True, lambda: open(os.path.join(ws, "f.txt")).read())
    check("scope: read outside workspace", False, lambda: open(os.path.join(secret, "f.txt")).read())
    check("scope: read iCode config dir", False, lambda: os.listdir(str(client.runtime().config_dir)))
    rt = client.runtime()
    rt.grant(scope, "turn", secret)
    check("scope: read after turn grant", True, lambda: open(os.path.join(secret, "f.txt")).read())
    check("scope: command after turn grant", True, lambda: run(["cat", os.path.join(secret, "f.txt")]))
    rt.end_turn("probe")
    check("scope: read after turn end", False, lambda: open(os.path.join(secret, "f.txt")).read())
    check("scope: grant a protected path", False, lambda: rt.grant(scope, "session", floor_dir))
    write = lambda path: run(["sh", "-c", f"echo x > {path!r}"])
    check("command: write workspace", True, lambda: write(os.path.join(ws, "w.txt")))
    check("command: write outside workspace", False, lambda: write(os.path.join(secret, "w.txt")))
    read_grant = rt.grant(scope, "session", secret)
    check("command: write after a read grant", False, lambda: write(os.path.join(secret, "w.txt")))
    rt.revoke(read_grant.id)
    write_grant = rt.grant(scope, "turn", secret, access="write")
    check("command: write after a write grant", True, lambda: write(os.path.join(secret, "w.txt")))
    rt.end_turn("probe")
    check("command: write after the turn ends", False, lambda: write(os.path.join(secret, "w2.txt")))
    check("scope: write grant on a startup file", False, lambda: rt.grant(scope, "turn", os.path.expanduser("~/.zshrc"), access="write"))
print(json.dumps(results))
"""


def _probe(args: argparse.Namespace) -> int:
    ok, mechanism = confine.available()
    if not ok:
        print(f"Sandbox not supported here: {mechanism}")
        return 2
    home = policy.home()
    base = tempfile.mkdtemp(prefix=".icode-sandbox-probe-", dir=home)
    try:
        ws, secret = os.path.join(base, "ws"), os.path.join(base, "secret")
        for directory in (ws, secret):
            os.makedirs(directory)
            Path(directory, "f.txt").write_text("probe\n", encoding="utf-8")
        floor_dir = os.path.join(home, ".ssh")
        env = {**os.environ, "CHRYS_FILE_SANDBOX_ON_UNAVAILABLE": "refuse"}
        env.pop("CHRYS_FILE_SANDBOX_INHERITED", None)
        proc = subprocess.run(
            [sys.executable, "-c", _PROBE, ws, secret, floor_dir],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
            cwd=ws,
            timeout=120,
            check=False,
        )
    finally:
        shutil.rmtree(base, ignore_errors=True)
    lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    if proc.returncode != 0 or not lines:
        print(f"Probe failed to run (exit {proc.returncode}):\n{proc.stderr.strip()}")
        return 1
    results = json.loads(lines[-1])
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"Sandbox state: {results['status']} ({results['mechanism']})")
        for item in results["checks"]:
            mark = "PASS" if item["pass"] else "FAIL"
            print(f"  [{mark}] {item['name']:42} expected {item['expected']:5} got {item['got']}")
    return 0 if all(item["pass"] for item in results["checks"]) else 1


def main(argv: list[str] | None = None) -> int:
    from chrys.orchestration.startup import bootstrap_runtime

    bootstrap_runtime(configure_stdio=True, setup_telemetry=False)
    parser = argparse.ArgumentParser(prog=f"{APP_COMMAND} sandbox", description="Inspect the file-access sandbox.")
    sub = parser.add_subparsers(dest="action")
    status = sub.add_parser("status", help="Platform support, settings and (with --session) a session's grants")
    status.add_argument("--session", help="Show this session's grants and recent sandbox events")
    status.add_argument("--limit", type=int, default=20, help="Events to show with --session (default: 20)")
    status.add_argument("--json", action="store_true")
    grants = sub.add_parser("grants", help="List durable grants, or revoke one")
    grants.add_argument("--revoke", metavar="ID")
    grants.add_argument("--json", action="store_true")
    probe = sub.add_parser("probe", help="Start a confined process and check every boundary")
    probe.add_argument("--json", action="store_true")
    args = parser.parse_args(argv or ["status"])
    if args.action in (None, "status"):
        if args.action is None:
            args = parser.parse_args(["status"])
        return _status(args)
    if args.action == "grants":
        return _grants(args)
    return _probe(args)
