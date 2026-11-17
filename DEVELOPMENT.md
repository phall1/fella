# Development

## Contract

Build a dependable, terminal-first Linux workspace launcher. Separate application
state without mutating the host or requiring a long-lived service.
The vocabulary is in [CONTEXT.md](CONTEXT.md).

## Four modules, no framework

- `src/Cli.zig`: pure argument parsing and name validation.
- `src/Store.zig`: identity initialization, workspace registration, path grants.
- `src/Session.zig`: one launch seam. A resolved `Plan` becomes a bubblewrap argv.
- `src/main.zig`: output, diagnostics, and replacing the CLI process with bubblewrap.

Use the standard library for files, JSON, and process execution. A single
Linux `close_range(CLOEXEC)` primitive makes non-stdio descriptors exec-private;
failure aborts rather than carrying ambient file/socket access into a session.
This requires Linux 5.11+. No manual
fork/exec wrappers, global firewall, PID registry, signal supervisor, or daemon.
No shell interpolation: arguments after `--` remain individual arguments.
The launch plan is the point for a future concrete policy to vary; do not add a
plugin registry for hypothetical browsers or transports.

### Ownership and lifetime

The selected project and identity home are explicit persistent writable grants.
The store itself is never mounted into the session. Registrations are
versioned JSON, atomically published without replacing existing names.
Identities are initialized in private hidden staging directories, then published
with an atomic no-replace rename. A killed initialization does not reserve the
requested name; retrying needs no repair. Hidden orphan staging directories are
ignored rather than opportunistically deleted. Names cannot contain path
separators. Atomic publication protects against partial process execution, not
power-loss durability of application data. Broad grants of the whole host
home, store, or system directories are rejected, including symlink targets.
Paths are resolved and checked again at launch.

Each `enter` replaces the CLI with bubblewrap. Bubblewrap and the kernel own
the process/mount lifetime and propagate the command's exit status.
There is no stored "active" state to repair after a crash. Failures to create
isolation fail the launch; never substitute an ordinary shell.
Terminal signals inside the interactive shell retain foreground-job behavior.
Direct-command Ctrl-C and PID-targeted launcher signals can hard-cancel the
session, not gracefully forward application signals; see
the explicit user-facing warning in README. This intentionally follows
bubblewrap rather than adding a custom signal supervisor.

Runtime allocations use the process arena; they disappear on exit/exec. No
secrets are imported from the host environment. Identity homes store ordinary
application data, not specially encrypted or magically erasable state.

### Explicit trade-offs

Identity is not an OS account, forged device, browser fingerprint, or network
identity. The namespace-local UID/GID are always 1000; the host user is unchanged.
Concurrent sessions can intentionally share an identity home, just as two
terminals share a normal home. Applications own their usual file locking.
Workspaces can intentionally share a project, and therefore its contents.
Host networking is not isolation from host services. Terminal sharing retains
job control, not protection against hostile terminal applications.

The system mount allowlist targets conventional FHS Linux distributions.
NixOS, custom `/opt` toolchains, remote filesystems, graphical applications,
resource quotas, and untrusted-code hardening are not verified targets.
Debian/Ubuntu are the current tested baseline. Missing system programs fail
normally; fella never installs or updates application dependencies at runtime.

## Toolchain and checks

Zig is pinned in `.mise.toml`. When upgrading it, update `minimum_zig_version`
and the verified archive hashes in `scripts/zig.sh` together.

```sh
bash scripts/zig.sh fmt --check build.zig build.zig.zon src
bash scripts/zig.sh build test --summary all
bash scripts/zig.sh build -Doptimize=ReleaseSafe
python3 tests/integration.py zig-out/bin/fella
lizard -l zig -C 10 src/*.zig
```

Unit tests are portable. Actual session tests require Linux and must run as a
normal user. CI runs both on Linux amd64 and arm64 on every PR.
`bash scripts/orb-test.sh <existing-machine>` performs a native Linux build and
the full suite without modifying existing VM checkouts.

Add failure tests alongside behavior changes. Exercise signals and descendants
in subprocesses, not by killing processes by name. Changes to the mount policy
need actual inside-session tests, not just checks for strings in an argv.

## Deliberately removed

Tor/WireGuard/Chain, host identifier and MAC mutation, firewall management,
custom browser fingerprints, process masquerade, padding, hardware spoofing,
state encryption wrappers, and secure-wipe claims are not maintained here.
Their previous implementations and speculative roadmaps remain in Git history,
not as dormant code that appears supported.
