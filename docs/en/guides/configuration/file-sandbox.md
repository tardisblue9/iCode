# File-Access Sandbox

The file-access sandbox keeps iCode, and everything it runs for you, from reading files outside the folders you work in. If a web page, file or tool output tricks the model into reading something unrelated, such as your documents, another project or your SSH keys, the operating system refuses the read.

The sandbox is off by default. It works on macOS and Linux (kernel 5.19 or later, which Ubuntu 22.04's newer kernels and Ubuntu 24.04 have). It is not available on Windows.

## Turn it on

The sandbox is decided when iCode starts and stays that way until iCode exits. Changing the setting in a running session takes effect at the next start.

- For one start: `icode --sandbox` (also `icode run --sandbox …` and `icode acp --sandbox`). `--no-sandbox` turns it off for one start.
- For one start, from the environment: `CHRYS_FILE_SANDBOX=1`.
- Every time: in **Settings → Safety**, turn on **File-access sandbox (next start)**, or add `sandbox: {enabled: true}` to `~/.chrys/settings.yaml`.

A working directory's own settings (used only if you turned on working directory settings) can switch the sandbox on, but not off. If they try to switch it off, iCode says so at startup and the sandbox stays on.

If the sandbox is requested but this computer can't provide it, iCode does not start and tells you why. To start without it instead, set **If the sandbox is unavailable** to `warn` (or `CHRYS_FILE_SANDBOX_ON_UNAVAILABLE=warn`); iCode then shows **⚠ Sandbox NOT active** in the footer for the whole session.

The sandbox is a package of its own, `icode-sandbox`. The offline installers include it; an install from PyPI (`pip install icode-tui`, `uv tool install icode-tui`) does not. iCode loads it only when the sandbox is on, and offers the switch in **Settings** and `icode --help` only when it is installed. If it is missing, `icode sandbox status` says so, and a start that asks for the sandbox is handled as above: iCode does not start, or with `warn` starts without it. A working directory's settings that ask for the sandbox only warn when it can't be had: a repository can't stop iCode starting.

## What can be read

| Location | iCode's tools and commands |
|---|---|
| The working folders of the session | Readable |
| System folders, installed programs, `/tmp` | Readable |
| Your home folder and external volumes, everywhere else | Not readable, unless you grant it |
| Credentials and browser data (`~/.ssh`, `~/.aws`, `~/.gnupg`, keychains, cookies and similar) | Never readable; cannot be granted |

Commands (the shell, `grep`, `glob`, scripts) also see common toolchain folders in your home, such as `~/.cache`, `~/.cargo/registry` or `~/.npm`, and project files such as `pyproject.toml` or `package.json` in the folders above your workspace, so builds and test runners keep working. On Linux, a toolchain folder that doesn't exist yet when iCode starts stays unreadable to commands until the next start (`~/.cache` and `~/.local/share/uv` are created for you). Files that hold credentials, such as `~/.npmrc`, `~/.pypirc` and `~/.cargo/credentials.toml`, stay unreadable; a tool that reads its settings from another file in those folders may need that file added under `sandbox.files.commands.allow_paths`.

Commands also can't move or hard-link a file out of an unreadable folder (for example `mv ~/Documents/report.pdf .`), since that would make it readable in the workspace. Deleting or renaming files inside those folders is refused for the same reason; inside the workspace, and in granted and toolchain folders, nothing changes.

## What can be changed

The sandbox also limits what commands and file tools can change, so that nothing can be left behind to run later, outside the sandbox.

| Location | Commands and file tools |
|---|---|
| The session's working folders | Can change |
| The system temporary folders | Can change |
| Build caches such as `~/.cache`, `~/.npm`, `~/.cargo/registry` | Can change |
| Other locations | Can't change, unless you grant it |
| Shell startup files (`~/.zshrc`, `~/.bashrc` and similar), autostart (`~/Library/LaunchAgents`, `~/.config/systemd`), `~/.gitconfig`, `~/.config/git`, program folders (`~/.local/bin`, `~/.cargo/bin`, `~/bin`), other agents' settings, and iCode's own settings and install | Never; can't be granted |

So some commands stop working under the sandbox, and tell you so with "Operation not permitted": `git config --global` and `cargo install`, for example. Run those yourself, outside iCode. If a build tool needs another folder, add it under **`sandbox.files.commands.write_paths`** in `~/.chrys/settings.yaml`; what's listed above as never changeable stays that way. An MCP server you configured can be given its own folders with `write_paths`, as with `read_paths` below.

Rolling back a turn follows the same rules: a file is put back only where the agent may change files now. If a folder on its path has since been turned into a link to somewhere outside, that file isn't restored, and the rollback says why.

Hooks, skill scripts and MCP servers run under the same limits: a hook that writes to a file in your home outside these folders gets "Operation not permitted". Have it write in the working folder or a temporary folder, or add its folder under `sandbox.files.commands.write_paths`.

Git works in a repository's root, a linked worktree and a submodule. If your working folder is a subfolder of a repository, git also has to read the rest of the repository. That isn't open by default; add the repository's root under `sandbox.files.commands.allow_paths` if you want git to work there.

## When the model needs another folder

In a session where iCode asks you before running tools (manual approval), a read outside the working folders opens an approval dialog naming the file:

- **Approve**: the model may read that one path, for this request only.
- **Don't ask again to read in this folder → This turn**: the folder stays readable until the agent finishes answering your message.
- **→ This session**: the folder stays readable for the rest of the session, also after you restore it.
- **→ This working directory**: the folder is readable in every session in this working directory.

When a file tool wants to change something outside what's listed above, the dialog asks for that instead. Reading a folder never allows changing it. Approve covers that folder for this one request, and you can also keep it for the turn or the session; a write grant never lasts longer than the session. Commands can't open the dialog: they just get "Operation not permitted", and can write there once a grant is in place. A grant to read or write is refused outright for the locations above that are never changeable, and for a folder that holds one of them, such as your home or `~/.config`.
- **Decline**: the model is told you declined.

In an editor connected over ACP, the same request offers **Allow once**, **Allow this folder for the session** and **Reject once**.

Files and folders you name yourself with `@` in your message are readable for that turn without asking, and images you attach that way are attached even when they are outside the working folders. Naming a whole home folder (`@~`) doesn't open everything in it, and credentials stay unreadable.

With automatic approval, and in `icode run`, nobody is there to ask, so such reads are refused; the model is told to work inside the workspace or to ask you to add the folder as a working directory. Sub-agents use the grants of the session that started them but can't ask for new ones.

## MCP servers that need other folders

An MCP server you configured can read its own program's folder and the workspace. To let one server read more, add `read_paths` to it in the agent profile; other servers don't get them, and credential folders stay unreadable:

```yaml
tools:
  mcp:
    - name: notes
      transport: stdio
      command: notes-server
      read_paths:
        - ~/Documents/notes
```

## API keys from a command

A `{{!command}}` that gets an API key (see [Get an API key from a command](./models.md#get-an-api-key-from-a-command)) runs like any other command: it can read only what commands may read. A command that just prints a key, or asks a tool that keeps its own login, works. One that reads a password store in your home folder fails, and the error says the sandbox is on; add that folder under `sandbox.files.commands.allow_paths` to let it in. The keychain and other credential folders can't be opened this way: with the sandbox on, get the key some other way, such as an environment variable set before you start iCode.

## See what the sandbox is doing

- The footer shows **🛡** while the sandbox is active (and a spelled-out warning when it is degraded or not active). Click it, or press **F7**, to open the sandbox panel: what is readable, the grants of each session (with **Revoke**), and the most recent refusals.
- `icode sandbox status` shows whether this computer supports the sandbox (and checks that it works), and whether the next start will use it. Add `--session ID` to see a session's grants and its sandbox events, which are also kept in the session's folder.
- `icode run` and `icode workflow run` print one line saying whether the sandbox is active when it was asked for; an editor connected over ACP gets the same in the server's capabilities.
- `icode sandbox grants` lists remembered grants; `icode sandbox grants --revoke ID` removes one.
- `icode sandbox probe` starts a sandboxed process and checks every boundary for real.
- `icode run`, `icode workflow run` and each session's trajectory record a read iCode refused for a tool (`sandbox.access.denied`). An editor connected over ACP also receives `chrys/sandbox_denied`. When a command's own read is refused, the operating system answers the command directly, so only the command's error output shows it.
- **Keep paths out of the sandbox's logs:** turn on **Sandbox: hide paths in its logs and trajectories** in **Settings → Safety** (`sandbox.files.audit.redact_paths`). The logs then hold a keyed digest instead of each path: the same path keeps the same digest, so you can still follow one through a log.

## Limits

- iCode's own file tools are limited through the functions Python code uses to open, create, link and change files, and a tool can't start a program except through iCode's confined path. Python code that opens files some other way (for example `io.FileIO` directly) is not checked in iCode's own process; iCode's code doesn't do that, and its tests check it stays so. The commands the agent runs are always limited by the kernel.
- The sandbox controls **reading files**. It does not stop a command from sending data over the network; use approval for that.
- The limits on changing files apply to commands and file tools. Everything in your working folders can still change, and anything there that runs later (source code, `Makefile`, `.git/hooks`) runs as you. Build caches can change too, and a tool may later run what's in them.
- Services already running outside the sandbox can change files for a command as well as read them, including macOS's settings service through `defaults write`.
- A service **already running outside the sandbox** can still be asked over its local socket to read for a command, for example Docker, a tmux server, or (on Linux) a desktop or systemd user session. Don't start iCode with such services exposed to untrusted work.
- On macOS, while the sandbox is on, iCode can't open other applications: opening a new iCode window or showing a folder in Finder doesn't work. Start another `icode` yourself instead. Leaving this open would let a command start a program outside the sandbox.
- What the model has already read is part of the conversation and is sent to your model provider.
- If code running inside iCode itself were taken over (for example through a malicious document that exploits a parser), it could ask for folders you could grant. It can't read credentials and browser data while it runs, but iCode's own process isn't limited in what it changes: it could change iCode's own files or a shell startup file, and what it changed would run with your full rights the next time they start.
- A command run by the agent that itself starts iCode (`icode run` inside the shell) runs inside the agent's sandbox and can't read iCode's settings.
