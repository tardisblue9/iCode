# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Which paths each confined process may read.

Everything here is computed once, in the main process, before it confines
itself. The broker re-checks the parts it is responsible for (the floor and the
private roots) on every request, so nothing below is trusted on its own.

Three kinds of process, three read sets:

- **main**: every path except the private roots (the user's home directory and
  external volumes); inside those, only what iCode itself needs — its config
  directory, its interpreter and packages, git's user config.
- **children** (commands run for iCode: shell, git, rg, MCP servers, hooks):
  the same "everything except" shape, with the private roots opened up for the
  owning scope's workspace and grants, common toolchain caches, and the config
  subdirectories that hold user scripts — never the config directory itself
  (it holds API keys and every session's transcript).
- **file helpers**: only the scope's workspace and grants.
"""

from __future__ import annotations

import contextlib
import functools
import os
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from icode_sandbox.runtime import confine

# What runs with the person's full rights later: a command changing it escapes the
# sandbox. Kept in sync with ``runtime/broker.py::_BUILTIN_WRITE_FLOOR``.
BUILTIN_WRITE_FLOOR = (
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".config/fish",
    "Library/LaunchAgents",
    ".config/systemd",
    ".config/autostart",
    ".config/environment.d",
    ".gitconfig",
    ".config/git",
    ".cargo/config",
    ".cargo/config.toml",
    ".vimrc",
    ".config/nvim",
    ".local/bin",
    ".cargo/bin",
    "bin",
    ".claude",
    ".codex",
    ".bash_aliases",
    ".config/zsh",
    ".oh-my-zsh",
    ".tmux.conf",
    ".vim",
    ".emacs.d",
    ".local/lib",
    ".agents",
    ".pyenv",
    ".nvm",
    "go/bin",
    ".bun/bin",
    ".config/pip",
    ".config/uv",
    ".ipython",
    ".gradle/init.d",
    ".m2/settings.xml",
    "Library/Application Support/Code/User",
    ".config/Code/User",
    ".cursor",
    ".gemini",
    ".hgrc",
    ".config/direnv",
    ".hammerspoon",
    "Library/Application Support/iTerm2/Scripts",
    "Library/Application Support/Cursor/User",
    ".config/Cursor/User",
)

# Caches a build writes as it runs. Only caches: never a bin folder or a tool's
# install, whose contents run outside the sandbox later.
WRITABLE_CACHES = (
    ".cache",
    "Library/Caches",
    ".npm",
    ".pnpm-store",
    ".cargo/registry",
    ".cargo/git",
    ".cargo/.package-cache",
    ".cargo/.package-cache-mutate",
    ".gradle/caches",
    ".m2/repository",
    "go/pkg",
)

# Kept in sync with ``runtime/broker.py::_BUILTIN_FLOOR``; the broker enforces
# its own copy, this one only lets the main process explain a refusal early.
BUILTIN_FLOOR = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
    ".netrc",
    ".git-credentials",
    ".password-store",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Safari",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/com.operasoftware.Opera",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/microsoft-edge",
    ".config/vivaldi",
    ".config/opera",
    ".local/share/keyrings",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".gem/credentials",
    ".pypirc",
    ".npmrc",
)

# Toolchain homes a command commonly reads: package caches, language
# installs, version managers. None holds credentials by convention.
TOOLCHAIN_HOME_PATHS = (
    ".local/bin",
    ".local/lib",
    ".local/share/uv",
    ".local/share/pipx",
    ".local/share/pnpm",
    ".local/share/mise",
    ".local/share/virtualenv",
    ".cache",
    ".cargo/bin",
    ".cargo/env",
    ".cargo/registry",
    ".cargo/git",
    ".rustup",
    ".npm",
    ".nvm",
    ".pnpm-store",
    ".yarn",
    ".bun",
    ".deno",
    ".pyenv",
    ".rbenv",
    ".gem/ruby",
    ".gem/specs",
    ".gradle/caches",
    ".gradle/wrapper",
    ".m2/repository",
    "go/pkg",
    "go/bin",
    ".conda",
    "miniconda3",
    "anaconda3",
    "miniforge3",
    ".volta",
    ".sdkman",
    ".asdf",
    ".gitconfig",
    ".config/git",
    "Library/Caches",
    "Library/pnpm",
)

GIT_CONFIG_PATHS = (".gitconfig", ".config/git")

# Project configuration that tools look for in every directory above the one
# they run in (pytest, ruff, eslint, tsc, cargo, …): readable in the ancestors
# of a workspace, so such a search still works. A tool that finds one of these
# and can't read it fails; a missing one reads as "not found" either way.
# Nothing here holds credentials (``.npmrc``, ``.pypirc``, ``.netrc`` do and are
# not listed).
ANCESTOR_CONFIG_NAMES = (
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "pytest.ini",
    ".pytest.ini",
    "ruff.toml",
    ".ruff.toml",
    "mypy.ini",
    ".mypy.ini",
    ".flake8",
    ".pylintrc",
    ".coveragerc",
    ".python-version",
    "package.json",
    "tsconfig.json",
    "jsconfig.json",
    "pnpm-workspace.yaml",
    "lerna.json",
    "nx.json",
    "turbo.json",
    "deno.json",
    "biome.json",
    ".editorconfig",
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.yaml",
    ".eslintrc",
    ".eslintrc.json",
    ".eslintrc.js",
    "eslint.config.js",
    "eslint.config.mjs",
    ".nvmrc",
    ".node-version",
    ".tool-versions",
    "Cargo.toml",
    "rust-toolchain.toml",
    "go.mod",
    "go.work",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "CMakeLists.txt",
    "Makefile",
    "WORKSPACE",
    "MODULE.bazel",
    ".gitignore",
    ".gitattributes",
    "AGENTS.md",
)


def ancestor_configs(roots: list[str] | tuple[str, ...]) -> list[str]:
    """Existing :data:`ANCESTOR_CONFIG_NAMES` files above each root, inside a private root."""
    found: set[str] = set()
    for root in roots:
        resolved = confine.real(root)
        parent = os.path.dirname(resolved)
        while parent and parent != resolved and is_private(parent):
            for name in ANCESTOR_CONFIG_NAMES:
                candidate = os.path.join(parent, name)
                if os.path.isfile(candidate) and not is_protected(candidate):
                    found.add(candidate)
            resolved, parent = parent, os.path.dirname(parent)
    return sorted(found)


_frozen_home: list[str] = []


def freeze_home() -> None:
    """Pin :func:`home` to its value now — the kernel profile was built from it.

    A later ``HOME`` change (a test, a library) must not move what this process
    treats as private while the kernel keeps enforcing the old boundary.
    """
    _frozen_home[:] = [confine.real(os.path.expanduser("~"))]


def home() -> str:
    if _frozen_home:
        return _frozen_home[0]
    return confine.real(os.path.expanduser("~"))


def account_home() -> str:
    """The account's home from the user database, which ``$HOME`` can't move."""
    try:
        import pwd

        return confine.real(cast(Any, pwd).getpwuid(cast(Any, os).getuid()).pw_dir)
    except ImportError, KeyError, OSError:
        return home()


def private_roots() -> list[str]:
    """Roots the main process and every child can't read beyond their allow lists.

    Both ``$HOME`` and the account's real home: a process started with another
    ``HOME`` must not thereby make the real one readable.
    """
    platform_roots = confine.LINUX_PRIVATE_ROOTS if confine.PLATFORM == "linux" else confine.MACOS_PRIVATE_ROOTS
    return sorted({home(), account_home(), *(confine.real(p) for p in platform_roots)})


def is_home(path: str) -> bool:
    return path in {home(), account_home()}


def is_private(path: str) -> bool:
    return any(confine.is_within(path, root) for root in private_roots())


def floor(extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    bases = {home(), account_home()}
    builtin = {confine.real(os.path.join(base, p)) for base in bases for p in BUILTIN_FLOOR}
    return sorted(builtin | {confine.real(p) for p in extra})


def floor_ancestors(extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    """Every directory above a floor path: renaming one would carry the floor path along."""
    found: set[str] = set()
    for path in floor(extra):
        parent = os.path.dirname(path)
        while parent and parent != "/":
            found.add(parent)
            parent = os.path.dirname(parent)
    return sorted(found)


def is_protected(path: str, extra: list[str] | tuple[str, ...] = ()) -> bool:
    """True when *path* overlaps a floor path (so it can never be granted)."""
    return any(confine.same_or_nested(path, f) for f in floor(extra))


def _existing(paths: list[str]) -> list[str]:
    return [p for p in paths if os.path.exists(p)]


def installed_packages() -> list[str]:
    """The folders of iCode's code and of this package: ``.../chrys`` and ``.../icode_sandbox``.

    Found from the modules themselves, not from this file's depth: in a wheel
    install both sit in site-packages, in the source checkout under ``src/`` and
    ``packages/icode-sandbox/src/``.
    """
    from chrys import foundation

    chrys_dir = os.path.dirname(os.path.dirname(os.path.abspath(foundation.__file__)))
    return [chrys_dir, os.path.dirname(os.path.abspath(__file__))]


def package_roots() -> list[str]:
    """The folders holding those packages (site-packages, or the checkout's source roots)."""
    return sorted({os.path.dirname(p) for p in installed_packages()})


def main_allow(config_dir: Path, extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    """What the main process may read inside the private roots."""
    base = home()
    candidates = {
        confine.real(str(config_dir)),
        confine.real(sys.prefix),
        confine.real(sys.base_prefix),
        confine.real(sys.exec_prefix),
        *(confine.real(root) for root in package_roots()),
        *(confine.real(os.path.join(base, p)) for p in GIT_CONFIG_PATHS),
        *(confine.real(p) for p in extra),
    }
    executable = confine.real(sys.executable)
    candidates.add(os.path.dirname(executable))
    for entry in sys.path:
        if entry and os.path.isabs(entry):
            candidates.add(confine.real(entry))
    # Only what lies inside a private root needs listing; the rest is readable anyway.
    return sorted(p for p in candidates if is_private(p) and not is_protected(p) and p not in {base, account_home()})


def ensure_user_cache_dirs() -> None:
    """Create the folders commands need before confining: cargo's, and (Linux) the XDG cache and data folders.

    A Landlock rule needs an existing path to attach to, so a tool's first write
    to a missing ``~/.cache`` would be refused for good. Other toolchain folders
    (``~/.cargo``, ``~/.npm``) stay uncreated, since their presence can change how
    their tools behave: until one exists, commands can't read it.
    """
    ensure_cargo_paths()
    if confine.PLATFORM != "linux":
        return
    for name in (".cache", ".local/share/uv", ".npm"):
        with contextlib.suppress(OSError):
            os.makedirs(os.path.join(home(), name), mode=0o700, exist_ok=True)


def ensure_cargo_paths() -> None:
    """Where cargo keeps downloads and its locks, if cargo is here at all.

    Its home also holds its config and installed programs, which a command must
    not change, so it can't create these itself once confined.
    """
    if not (shutil.which("cargo") or os.path.isdir(os.path.join(home(), ".cargo"))):
        return
    with contextlib.suppress(OSError):
        for name in (".cargo/registry", ".cargo/git"):
            os.makedirs(os.path.join(home(), name), exist_ok=True)
        for name in (".cargo/.package-cache", ".cargo/.package-cache-mutate"):
            os.close(os.open(os.path.join(home(), name), os.O_WRONLY | os.O_CREAT, 0o644))


def write_floor(config_dir: Path | str | None = None, extra: list[str] | tuple[str, ...] = ()) -> list[str]:
    """What can never be made writable: the read floor's reasons, plus what runs later with full rights."""
    bases = {home(), account_home()}
    found = {confine.real(os.path.join(base, p)) for base in bases for p in BUILTIN_WRITE_FLOOR}
    if config_dir is not None:
        found.add(confine.real(str(config_dir)))
    return sorted(found | {confine.real(p) for p in extra})


def install_paths() -> list[str]:
    """iCode's own code and interpreter: the broker refuses a writable path under them."""
    return sorted({confine.real(p) for p in (*installed_packages(), sys.prefix, sys.base_prefix, sys.exec_prefix)})


def is_write_protected(
    path: str,
    config_dir: Path | str | None = None,
    extra: list[str] | tuple[str, ...] = (),
    *,
    holding_install: bool = False,
) -> bool:
    """True when *path* overlaps the write floor or lies in iCode's install (so it can never be made writable).

    With *holding_install*, a folder holding the install counts as well. Only a
    working folder may hold it (a checkout of iCode being worked on), so that
    answer is for what a grant or a setting asks for.
    """
    if is_protected(path, extra) or any(confine.same_or_nested(path, f) for f in write_floor(config_dir)):
        return True
    roots = install_paths()
    if holding_install and any(confine.is_within(root, path) for root in roots):
        return True
    return any(confine.is_within(path, root) for root in roots)


@functools.cache
def temp_write_paths() -> list[str]:
    """Scratch space, as tools find it on this platform (found once, before the process confines itself)."""
    import tempfile

    temp = confine.real(tempfile.gettempdir())
    found = {temp, confine.real("/tmp"), confine.real("/var/tmp"), "/dev"}
    if confine.PLATFORM == "macos" and temp.startswith("/private/var/folders/"):
        # The per-user folder holds ``T`` and also ``C``, the system's own user cache.
        found.add(os.path.dirname(temp))
    return sorted(found)


def git_write_paths(root: str, read: Callable[[str], str] | None = None) -> list[str]:
    """The git folders of a workspace that aren't under it: a subfolder of a repository, a worktree, a submodule.

    A ``.git`` *file* is workspace content: anyone who can write the workspace can
    make it name any folder. So a named folder only counts if it names this
    workspace back, in a file the workspace's writers can't reach. The caller
    asks once per root, before the model has run in this session; *read* gets a
    file's text from a process that may read it (this one may not).
    """
    start = confine.real(root)
    current = start
    base = {home(), account_home()}
    while current not in base and current != "/":
        marker = os.path.join(current, ".git")
        if os.path.isdir(marker) and not os.path.islink(marker):
            return [] if current == start or not _looks_like_git_dir(marker) else [marker]
        if os.path.isfile(marker) and not os.path.islink(marker):
            return _linked_git_dirs(marker, read or _read_small)
        current = os.path.dirname(current)
    return []


def _looks_like_git_dir(path: str) -> bool:
    return all(os.path.exists(os.path.join(path, name)) for name in ("HEAD", "objects", "refs"))


def _read_small(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read(65536)
    except OSError, ValueError:
        return ""


def _worktree_names_back(linked: str, marker: str, read: Callable[[str], str]) -> bool:
    return confine.real(read(os.path.join(linked, "gitdir")).strip()) == confine.real(marker)


def _module_names_back(linked: str, marker: str, read: Callable[[str], str]) -> bool:
    for line in read(os.path.join(linked, "config")).splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "worktree" and value.strip():
            return confine.real(os.path.join(linked, value.strip())) == confine.real(os.path.dirname(marker))
    return False


def _linked_git_dirs(marker: str, read: Callable[[str], str]) -> list[str]:
    text = read(marker).strip()
    if not text.startswith("gitdir:"):
        return []
    named = text.removeprefix("gitdir:").strip()
    linked = confine.real(os.path.join(os.path.dirname(marker), named))
    parts = linked.split("/")
    # ``<repo>/.git/worktrees/<name>`` or ``<repo>/.git/modules/<name>...``; nothing else is git's own.
    try:
        index = len(parts) - 1 - parts[::-1].index(".git")
    except ValueError:
        return []
    kind = parts[index + 1] if index + 1 < len(parts) else ""
    if (
        kind not in ("worktrees", "modules")
        or len(parts) <= index + 2
        or not os.path.exists(os.path.join(linked, "HEAD"))
    ):
        return []
    common = "/".join(parts[: index + 1])
    if not _looks_like_git_dir(common):
        return []
    if kind == "worktrees":
        return [common] if _worktree_names_back(linked, marker, read) else []
    return [linked] if _module_names_back(linked, marker, read) else []


def child_write(
    config_dir: Path,
    roots: list[str] | tuple[str, ...],
    extra: list[str] | tuple[str, ...] = (),
    floor_extra: list[str] | tuple[str, ...] = (),
) -> list[str]:
    """What a command run for a scope may change: *roots*, scratch space, caches, and what the person added."""
    base = home()
    config = confine.real(str(config_dir))
    # A workflow worker's bytecode cache, asked for only when starting that worker.
    worker_cache = confine.real(os.path.join(config, "workflows", ".pycache"))
    # ``TMPDIR`` may name anything; a home or a whole private root is never scratch space.
    broad = {*private_roots(), "/"}
    fixed = {*temp_write_paths(), *(confine.real(os.path.join(base, p)) for p in WRITABLE_CACHES)}
    kept = {p for p in {*fixed, *(confine.real(p) for p in roots)} if not is_write_protected(p, config, floor_extra)}
    added = {confine.real(p) for p in extra}
    kept |= {
        p for p in added if p == worker_cache or not is_write_protected(p, config, floor_extra, holding_install=True)
    }
    if "/dev" in fixed:
        kept.add("/dev")
    return sorted(kept - broad)


def child_allow(
    config_dir: Path,
    roots: list[str] | tuple[str, ...],
    extra: list[str] | tuple[str, ...] = (),
) -> list[str]:
    """What a command run for a scope may read inside the private roots."""
    base = home()
    config = confine.real(str(config_dir))
    # Toolchain folders count even before they exist: a tool creates its cache
    # on first use, and moves files inside it at once (atomic writes).
    # Under the account's home too, when $HOME points elsewhere: the tools a hook or a script runner finds
    # on PATH (uv, pipx, cargo) stay where they were installed.
    toolchain = {confine.real(os.path.join(b, p)) for b in {base, account_home()} for p in TOOLCHAIN_HOME_PATHS}
    # iCode's own install: its vendored tools (ripgrep) run as commands.
    candidates = {
        *(confine.real(root) for root in package_roots()),
        confine.real(os.path.join(config, "skills")),
        confine.real(os.path.join(config, "hooks")),
        # A workflow worker runs from here: the person's workflows, the injected SDK, its bytecode cache.
        confine.real(os.path.join(config, "workflows")),
        confine.real(sys.base_prefix),
        # iCode's own environment: a command started from iCode often finds its
        # interpreter first on PATH (uv tool, pipx, a dev venv).
        confine.real(sys.prefix),
        *(confine.real(p) for p in roots),
        *ancestor_configs(roots),
        *(confine.real(p) for p in extra),
        # A cache a command may change, it may also read.
        *(confine.real(os.path.join(base, p)) for p in WRITABLE_CACHES),
    }
    homes = {base, account_home()}
    kept = [*_existing(list(candidates)), *toolchain]
    return sorted({p for p in kept if is_private(p) and not is_protected(p) and p not in homes})


@dataclass(frozen=True)
class Scope:
    """A unit of access: one session's workspace roots (and the grants keyed by its id)."""

    key: str
    roots: tuple[str, ...]
    workdir_root: str = ""
    caller: str = ""


@dataclass
class AccessSet:
    """The resolved read set of a scope at one point in time."""

    roots: list[str] = field(default_factory=list)
    grants: list[str] = field(default_factory=list)

    write_grants: list[str] = field(default_factory=list)

    def paths(self) -> list[str]:
        """Everything readable: a folder that may be written may also be read."""
        return sorted({*self.roots, *self.grants, *self.write_grants})

    def writable(self) -> list[str]:
        return sorted({*self.roots, *self.write_grants})

    def covers_write(self, path: str) -> bool:
        return any(confine.is_within(path, p) for p in self.writable())

    def covers(self, path: str) -> bool:
        return any(confine.is_within(path, p) for p in self.paths())
