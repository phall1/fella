# Module Spec: Container Hardening

## 1. What It Does

Patches container fingerprint leaks that expose the host kernel, CPU, and boot time.

## 2. Patches

| Patch | Target | Method | Requires |
|-------|--------|--------|----------|
| `uname()` spoof | Kernel version, machine arch | `LD_PRELOAD` shared object | `gcc` or `zig cc` |
| `sysinfo()` spoof | System uptime | `LD_PRELOAD` shared object | `gcc` or `zig cc` |
| Fake `/proc/cpuinfo` | CPU model, vendor | Bind mount over `/proc/cpuinfo` | `CAP_SYS_ADMIN` |
| Fake `/proc/version` | Kernel version string | Bind mount over `/proc/version` | `CAP_SYS_ADMIN` |
| Fake `/proc/uptime` | System uptime | Bind mount over `/proc/uptime` | `CAP_SYS_ADMIN` |
| Fake `/proc/stat` | Boot time (`btime`) | Bind mount over `/proc/stat` | `CAP_SYS_ADMIN` |

## 3. LD_PRELOAD Library

Compiled from `src/opsec_spoof.c` (or native Zig rewrite in v0.2):
- Intercepts `uname()` syscall
- Intercepts `sysinfo()` syscall
- Reads fake values from environment variables:
  - `FELLA_FAKE_RELEASE`
  - `FELLA_FAKE_VERSION`
  - `FELLA_FAKE_MACHINE`
  - `FELLA_FAKE_UPTIME`

## 4. Failure Modes

| Failure | Handling |
|---------|----------|
| Cannot compile C | Skip LD_PRELOAD, log warning |
| No `CAP_SYS_ADMIN` | Skip bind mounts, log warning |
| `LD_PRELOAD` fails to load | Log warning, continue without spoof |
| Cannot unmount on stop | Log warning, may leave fake proc behind |

## 5. Verification

```bash
# Before hardening
uname -a  # shows real kernel

fella harden

# After hardening
uname -a  # shows fake kernel
uname -m  # shows x86_64 (or configured arch)
cat /proc/cpuinfo | grep "model name"  # shows fake CPU
awk '/btime/{print $2}' /proc/stat  # shows fake boot time

# Inside fella shell
fella shell
uname -a  # also shows fake kernel
exit

fella stop  # removes hardening
uname -a  # shows real kernel again
```

## 6. Platform Constraints

- Linux only
- Best effort: some patches may fail in unprivileged containers
- Privileged containers/VMs: all patches work

## 7. Security Properties

- LD_PRELOAD only affects current process tree
- Fake proc files are read-only (no host filesystem modification)
- No persistence across reboots (unless `.bashrc` modified)
