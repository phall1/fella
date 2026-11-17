# fella

**A small Linux tool for keeping workspaces and identities separate.**

Enter a project with its own home, configuration, credentials, and shell history.
Leave it by exiting the shell. Come back tomorrow and everything you chose to
keep is still there.

No daemon. No sudo. No Tor. No host identity changes or firewall rewrites.

## Use it

Use Linux 5.11+ with user namespaces enabled. Install `bubblewrap` and `bash`
using your Linux distribution's package manager.
Install the fella binary, or [build it](#build). Then, as your normal user:

```sh
fella doctor
fella identity create work
fella workspace add app --identity work --path ~/code/app
fella enter app
```

Inside, `/workspace` is your project and `/home/fella` is the identity's persistent
home. The prompt shows `[fella:work/app]`. Set up Git and log into tools **inside
that identity**, once:

```sh
git config --global user.name "Work Name"
git config --global user.email "work@example.com"
exit
```

Run a command without opening a shell:

```sh
fella enter app -- git status
fella enter app --offline -- make test
```

Create another identity for unrelated work. Workspaces using the same identity
intentionally share its home and credentials; different identities do not.
Opening a second terminal gives you a second session, with no global "active
identity" to accidentally switch underneath an existing command.

## The small model

| Concept | What persists |
|---|---|
| **Identity** | A named home: application configuration, credentials, history, caches, user-installed tools |
| **Workspace** | A name associating an existing project directory with an identity |
| **Session** | A foreground shell or command; its temporary files and process namespace disappear on exit |

Project files remain in the directory you selected. Identity homes and workspace
registrations live in `${XDG_DATA_HOME:-$HOME/.local/share}/fella`, privately
created with mode 0700; registration files are 0600.

```sh
fella identity list
fella identity path work       # locate the home for setup and backups
fella workspace list
fella show app
fella workspace remove app     # forget the association; NEVER delete project/home
```

There is deliberately no `wipe`, destructive identity removal, or automatic
credential import. Back up identity homes as you would your normal home.
To change an association, remove and re-add its registration. A deleted or
retargeted project fails to launch rather than opening an unrelated directory.

## What containment means here

Fella uses **bubblewrap**, rather than implementing Linux isolation itself:

- Only the selected home and project are writable host filesystem mounts.
- Installed system programs/libraries and a small allowlist of system
  configuration (DNS, certificates, timezone, loader configuration) are read-only.
- Other homes, the host's `/tmp`, host processes, display sockets, desktop bus,
  and SSH-agent paths are not mounted.
- The environment starts empty. Only standard session variables and `TERM`
  are provided; host tokens and configuration overrides are not forwarded.
- Inherited non-stdio file descriptors are closed at exec, so an already-open
  host file or agent socket cannot silently cross the filesystem policy.
- `/tmp` and `/run` are private and temporary. Background descendants are
  terminated when the session ends, including if its launcher is killed.
- Normal networking is **the host's networking**, including its IP address,
  DNS, and reachable local services. `--offline` creates a disconnected network
  namespace. Fella does not configure a VPN or claim anonymity.
- Missing bubblewrap or denied namespace support is an error. There is
  **no unsandboxed fallback**. `doctor` actually tests namespace creation.

**This is compartmentalization for your own work, not a promise that arbitrary
malware is safe to run.** Sessions share the Linux kernel, host user account,
installed system tools, and terminal. Host networking permits access to local
services and abstract Unix sockets. A selected project may itself contain
credentials, executable hooks, or hardlinks. Sharing a project between identities
shares that content. Root or another process acting as your host user can still
read identity data. No resource quotas, encrypted storage, secure deletion,
browser-fingerprint spoofing, or forensic deniability are claimed.

The interactive shell intentionally retains normal terminal job control.
It shares the terminal with the host; it is not a terminal-injection defense.
Use a VM or a dedicated hardened sandbox for hostile code.

Exit normally to let applications save their data. **Inside the interactive
shell**, Ctrl-C reaches its foreground job and leaves the session usable.
Ctrl-C in direct-command mode (`enter … -- command`) can instead hard-cancel
the session; graceful application cleanup is not guaranteed. Signals sent
directly to the launcher's PID, **including SIGTERM**, are hard cancellation:
bubblewrap tears down the session, without forwarding application shutdown
handlers. For graceful automated shutdown, signal the application from inside
the session before ending it. Killing a session can lose unsaved application
state, just as killing the application can.

GUI applications, desktop/workspace switching, host agent forwarding, custom
environment passthrough, and transports are deferred. The initial product is
terminal-first. They can extend the resolved session plan later without
reintroducing host-wide state management.

## Build

Zig **0.17.1** (latest stable at this rebuild), no third-party Zig dependencies:

```sh
mise install                  # optional: toolchain pin in .mise.toml
zig build -Doptimize=ReleaseSafe
install -Dm755 zig-out/bin/fella ~/.local/bin/fella
```

Alternatively `bash scripts/zig.sh build -Doptimize=ReleaseSafe` downloads the
pinned compiler from ziglang.org, verifies its SHA-256, and caches it privately.
It does not change your system Zig. Runtime needs only fella, bubblewrap, bash,
and whatever programs you want to run. Tools installed inside an identity's
`~/.local/bin` are on its PATH; programs installed only in your **host** home
are intentionally not available.

## Verification

```sh
zig build test
zig build
python3 tests/integration.py zig-out/bin/fella   # Linux, normal user, bubblewrap
```

The integration suite uses temporary directories and a local test socket, not
Tor, a VPN server, root, or a privileged container. It exercises persistence,
separate homes, environment/credential exclusion, literal argv, exit codes,
offline networking, read-only system mounts, concurrent registration, corrupt
metadata, crash cleanup, and an actual interactive PTY.

From macOS, with an existing OrbStack Linux machine:

```sh
bash scripts/orb-test.sh fella-test
```

Install `bubblewrap`, `bash`, and `python3` in that VM first. The harness streams
the source into a fresh temporary directory and builds/tests on the VM's native
filesystem. It never clears an existing checkout or installs packages itself.
See [DEVELOPMENT.md](DEVELOPMENT.md) for architecture and validation.

### Ubuntu user-namespace policy

Ubuntu can require an AppArmor permission for bubblewrap to create user
namespaces, even when the kernel supports them. If `doctor` reports permission
errors during namespace setup, have the machine's administrator check its
policy. Fella never changes that policy itself.

An optional [bubblewrap-only profile](contrib/apparmor/fella-bwrap) follows
[Ubuntu's per-application approach](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces).
On a machine without an existing bubblewrap profile, an administrator can review
and install it once:

```sh
sudo install -m644 contrib/apparmor/fella-bwrap /etc/apparmor.d/fella-bwrap
sudo apparmor_parser -r /etc/apparmor.d/fella-bwrap
fella doctor
```

This grants namespace creation to **all `/usr/bin/bwrap` invocations**, not just
Fella. If your administrator already manages a bubblewrap profile, add the
`userns,` rule there instead of loading a competing attachment.
Do not disable AppArmor or global namespace restrictions to make Fella work.
CI uses this scoped helper permission; the actual tests still run without sudo.

## Coming from the old privacy prototype

This is an intentional replacement, not a compatible upgrade of the old
root-operated CLI. If the old version is active, use **that version's `stop`**
to restore the host before switching binaries. Do not wipe its restoration
backups first.

This version neither reads nor removes `/var/lib/fella`, old personas, Tor
configuration, namespaces, or firewall state. There is no automatic migration
of simulated identities into real application credentials. The old prototype
remains in Git history.

MIT.
