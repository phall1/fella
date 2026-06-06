# Module Spec: Identity Rotation

## 1. What It Does

Rotates host identity artifacts to break correlation between sessions. Restores original identity on stop.

## 2. Inputs

- Active persona configuration (or random defaults)
- Original system state (saved at first init)

## 3. Outputs

- New hostname in `/etc/hostname` and `/etc/hosts`
- New machine-id in `/etc/machine-id`
- New timezone (symlink or timedatectl)
- New locale in `/etc/default/locale`
- New keyboard layout (if supported)
- Cleared shell history

## 4. Identity Artifacts

| Artifact | Source | Rotation Method | Restore Method |
|----------|--------|-----------------|----------------|
| hostname | `/etc/hostname`, `uname` | `sethostname()` syscall or `hostnamectl` | Save original, restore |
| machine-id | `/etc/machine-id` | Regenerate via `systemd-machine-id-setup` or random | Save original bytes |
| timezone | `/etc/localtime` symlink | `timedatectl set-timezone` or symlink | Save original path |
| locale | `/etc/default/locale` | Write new LANG/LC_ALL | Save original values |
| keyboard | `localectl` | `localectl set-keymap` | Save original layout |
| shell history | `~/.bash_history` | Truncate file | N/A (don't restore) |

## 5. Failure Modes

| Failure | Handling |
|---------|----------|
| `sethostname()` fails (no CAP_SYS_ADMIN) | Log warning, continue without hostname change |
| `machine-id` read-only | Log warning, skip |
| `timedatectl` not available | Fallback to `/etc/localtime` symlink |
| Original state missing | Cannot restore; warn user |

## 6. Verification

```bash
# Unit
zig test tests/unit/identity.zig

# Integration
fella init
ORIG_HOST=$(hostname)
fella start
NEW_HOST=$(hostname)
[[ "$ORIG_HOST" != "$NEW_HOST" ]] || exit 1
NEW_MID=$(cat /etc/machine-id)
[[ -n "$NEW_MID" ]] || exit 1
fella stop
[[ "$(hostname)" == "$ORIG_HOST" ]] || exit 1
```

## 7. Platform Constraints

- Linux only for v0.1
- Requires root for hostname, machine-id
- Container: `hostnamectl` may fail inside LXC (use `hostname` syscall)

## 8. Security Properties

- Original identity stored in `/var/lib/fella/original/` with 600 permissions
- Never log the original hostname in audit logs (log hashes only)
- Persona files encrypted at rest in v0.3
