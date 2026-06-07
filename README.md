# fella

[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange.svg)](https://ziglang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20x86__64%20%7C%20aarch64-blue.svg)](https://kernel.org/)
[![Tests](https://img.shields.io/badge/tests-5%2F5%20passing-brightgreen.svg)](#testing)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **A nation-state tier network identity and traffic containment framework.**  
> Written in Zig. Zero shell dependency. Real integration tests. No bullshit.

```
   _____     __
  / __(_)__ / /  ___ ___
 / _// (_-< / _ \/ -_) _ \
/_/ /_/___/_//_/\__/_//_/
```

**fella** rotates your system's identity artifacts, isolates traffic inside a dedicated network namespace, and routes it through privacy-preserving backends (Tor, WireGuard) with a fail-closed killswitch. It was built to survive hostile network environments, container fingerprinting, and forensic analysis.

## Why fella?

Most "privacy tools" are shell scripts wrapped in sudo. **fella** is different:

- **Compiled language** (Zig 0.16) — testable, auditable, cross-compiles to bare metal
- **Real containment** — dedicated `fella` netns with veth pair, not just `proxychains`
- **Fail-closed by design** — if the backend drops, your traffic drops, not leaks
- **Forensic resistance** — encrypted state, secure memory (`mlock` + `MADV_DONTDUMP`), 3-pass anti-forensic wipe
- **Runtime self-protection** — seccomp-bpf sandbox blocks `ptrace`, `userfaultfd`, kernel module loading, and other high-leverage attack primitives
- **Backend plugin architecture** — Tor, WireGuard, or chained VPN→Tor

## What It Does

| Layer | Feature |
|-------|---------|
| 🎭 **Identity** | Rotates hostname, machine-id, timezone, locale, MAC addresses, bash history per session |
| 🔒 **Containment** | Dedicated `fella` network namespace with veth pair to host |
| 🎭 **Masquerade** | Renames fella process to common systemd service names in `ps`/`top` |
| 💾 **Ephemeral** | `--ephemeral` mounts `/var/lib/fella` as tmpfs; pull the plug, evidence vanishes |
| 🌐 **Routing** | Tor (SOCKS5 + DNS + ControlPort), WireGuard, or chained backends |
| ⛔ **Killswitch** | `iptables-restore` / `ip6tables-restore` atomic ruleset; basic or strict mode |
| 🛡️ **Sandbox** | seccomp-bpf deny-list blocks 15+ dangerous syscalls |
| 🧬 **Hardening** | Container fingerprint spoofing via `/proc` bind-mounts + LD_PRELOAD `libfella.so` |
| 🧹 **Wipe** | 3-pass overwrite (random → complement → random) + `fsync` for session artifacts |
| 🔗 **Chain** | VPN → Tor chaining (`--backend chain`) for nested tunneling |
| 🎲 **Padding** | Constant-rate traffic padding (fixed-size packets every 100ms) through the tunnel |
| 🌉 **Bridges** | Auto-detects obfs4 / snowflake transports for censored networks |
| 🎭 **Masquerade** | Renames fella to common systemd processes in `ps` / `top` |
| 💾 **Ephemeral** | `--ephemeral` mounts `/var/lib/fella` as tmpfs; evidence evaporates on power loss |
| 🔐 **Crypto** | XChaCha20-Poly1305 encrypted state via `init --encrypt` |
| ✅ **Verify** | Tor confirmation, IP exposure, direct bypass leak tests |

## Quick Start

```bash
# Clone and build
git clone https://github.com/phall1/fella.git
cd fella
zig build

# Initialize (pick your backend)
sudo ./zig-out/bin/fella init
sudo ./zig-out/bin/fella init --backend wireguard   # requires /var/lib/fella/wireguard.conf
sudo ./zig-out/bin/fella init --backend chain       # VPN -> Tor, requires wireguard.conf

# Activate
sudo ./zig-out/bin/fella start                      # identity + backend + netns + killswitch + seccomp
sudo ./zig-out/bin/fella start --cover              # ...plus decoy traffic padding

# Use
sudo ./zig-out/bin/fella shell          # drop into routed subshell
sudo ./zig-out/bin/fella exec curl -s https://check.torproject.org/api/ip
sudo ./zig-out/bin/fella verify         # run leak tests
sudo ./zig-out/bin/fella status         # full posture report

# Panic button
sudo ./zig-out/bin/fella wipe           # secure-delete session artifacts
sudo ./zig-out/bin/fella stop           # restore identity + teardown netns
```

### Encrypted State

```bash
export FELLA_PASSPHRASE="correct horse battery staple"
sudo ./zig-out/bin/fella init --encrypt
sudo ./zig-out/bin/fella start
```

## Requirements

- **Zig 0.16.0** — [download](https://ziglang.org/download/)
- **Linux** (x86_64 or aarch64) with `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`
- **root** — required for netns, iptables, hostname, etc.

Optional packages:
- `tor` + `torsocks` — Tor backend
- `wireguard-tools` (`wg`, `wireguard` kernel module) — WireGuard backend
- `iptables` / `ip6tables` — killswitch
- `iproute2` (`ip`) — netns management

## Install

### Method 1: Prebuilt Binary (fastest)

We publish binaries for every release via [GitHub Releases](https://github.com/phall1/fella/releases).

```bash
# Pick your architecture: x86_64 or aarch64
ARCH=$(uname -m)
VERSION=$(curl -s https://api.github.com/repos/phall1/fella/releases/latest | grep tag_name | cut -d '"' -f 4)

sudo curl -fsSL -o /usr/local/bin/fella \
  "https://github.com/phall1/fella/releases/download/${VERSION}/fella-${VERSION}-${ARCH}-linux"
sudo chmod +x /usr/local/bin/fella
sudo mkdir -p /var/lib/fella /var/lib/fella/original /var/lib/fella/tor
```

You still need runtime dependencies. The install script below can set those up.

### Method 2: One-Line Curl Install (builds from source)

The install script detects your package manager, installs missing dependencies, downloads Zig if needed, clones the repo, builds fella, and installs it.

```bash
# Interactive — tells you what's missing and how to install it
curl -sL https://raw.githubusercontent.com/phall1/fella/main/scripts/install.sh | sudo bash

# Fully automatic — installs deps, downloads Zig, builds, and installs
curl -sL https://raw.githubusercontent.com/phall1/fella/main/scripts/install.sh | sudo bash -s -- --auto
```

Supported platforms: Ubuntu/Debian (`apt`), Fedora/RHEL (`dnf`), Arch (`pacman`), Alpine (`apk`).

What `--auto` installs:
- `iptables`, `iproute2`, `tor`, `torsocks`, `wireguard-tools`
- `curl`, `git`, `gcc` (for `fella harden`)
- Zig 0.16.0 into `/opt/zig-0.16.0` with a symlink at `/usr/local/bin/zig`

### Method 3: Clone and Build Manually

```bash
git clone https://github.com/phall1/fella.git
cd fella
make              # or: zig build
sudo make install
```

## Commands

```
fella init                  Probe environment, first-time setup
fella init --encrypt        Enable encrypted state storage
fella init --backend <k>    Select backend: tor | wireguard | chain
fella start                 Activate identity + backend + containment
fella start --cover         Enable cover traffic padding
fella start --ephemeral     RAM-only session data (tmpfs)
fella lockdown              Strict killswitch (backend-only traffic)
fella lockdown --cover      Strict mode with cover traffic
fella lockdown --ephemeral  Strict mode with RAM-only data
fella cover start           Start cover traffic daemon
fella cover stop            Stop cover traffic daemon
fella macrotate start       Start periodic MAC rotation subagent
fella macrotate stop        Stop MAC rotation subagent
fella stop                  Deactivate everything, restore system
fella rotate                New identity + rotate MACs + rotate backend circuit
fella status                Show current posture
fella verify                Run leak/health tests
fella shell                 Drop into routed subshell (isolated netns)
fella exec <cmd>            Run a single command in the routed namespace
fella wipe                  Secure-delete session artifacts
fella harden                Apply container fingerprint patches
fella doctor                Diagnose environment
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Userland                                │
│  ┌─────────┐    ┌──────────┐    ┌─────────────┐   ┌─────────┐  │
│  │   CLI   │───▶│  Engine  │───▶│   Backend   │   │ Sandbox │  │
│  └─────────┘    └──────────┘    │  (Tor/WG)   │   │seccomp  │  │
│         │              │         └─────────────┘   └─────────┘  │
│         │              ▼              │                          │
│         │      ┌──────────────┐       │                          │
│         │      │   Identity   │       │                          │
│         │      │  Rotation    │◀──────┘                          │
│         │      └──────────────┘                                  │
│         ▼              │                                         │
│  ┌─────────────┐       ▼                                         │
│  │   Netns     │◀── veth pair ──▶ Host NAT                       │
│  │  (fella)    │                                                 │
│  │  torsocks   │                                                 │
│  │  fail-closed│                                                 │
│  │  iptables   │                                                 │
│  └─────────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Backend Plugin System

Backends are swappable unions implementing `start`, `stop`, `rotate`, and `isRunning`.

```zig
const Backend = @import("backends/Backend.zig");
const Kind = Backend.Kind;  // .tor | .wireguard | .chain

var b = Backend.create(Kind.tor);
try b.start(io, alloc);
```

### Tor Backend (default)

- Fork/exec `tor` with generated `torrc`
- SOCKS5 on `127.0.0.1:9050` + `10.200.200.1:9050`
- DNS on `127.0.0.1:5353` + `10.200.200.1:5353`
- ControlPort on `127.0.0.1:9051` for circuit rotation

### WireGuard Backend

Requires `/var/lib/fella/wireguard.conf`:

```ini
[Interface]
PrivateKey = <your private key>
Address = 10.0.0.2/24
ListenPort = 51820
DNS = 1.1.1.1

[Peer]
PublicKey = <peer public key>
Endpoint = your-server:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Activate with:

```bash
sudo ./zig-out/bin/fella init --backend wireguard
sudo ./zig-out/bin/fella start
```

### Chained Backend (VPN → Tor)

Layer Tor on top of WireGuard. Your exit IP is a Tor exit node, but Tor's own traffic flows through the WireGuard tunnel first.

```bash
sudo cp your-wireguard.conf /var/lib/fella/wireguard.conf
sudo ./zig-out/bin/fella init --backend chain
sudo ./zig-out/bin/fella start
```

The chain path is:

```
netns app → torsocks → Tor SOCKS (host) → Tor outbound bound to WG IP → WireGuard tunnel
```

### Constant-Rate Traffic Padding

Tor alone does not hide *when* you send traffic or *how much*. A nation-state passive adversary can correlate bursts entering and exiting the Tor network. fella runs a background subagent that emits fixed-size HTTP POSTs through the tunnel at a fixed 100ms interval. This pads the tunnel with constant-rate noise, making size/timing correlation significantly harder.

```bash
sudo ./zig-out/bin/fella start --cover
# or manually
sudo ./zig-out/bin/fella cover start
sudo ./zig-out/bin/fella cover stop
```

### Censorship-Resistant Bridges

If you are behind a firewall that blocks Tor (e.g., China, Iran, Russia), install `obfs4proxy` or `snowflake-client` and fella will auto-inject bridge lines into `torrc`:

```bash
# Debian/Ubuntu
sudo apt install obfs4proxy

# Then start normally
sudo fella init
sudo fella start
```

You can also supply your own bridges:

```bash
sudo cp my-bridges.conf /var/lib/fella/bridges.conf
sudo fella start
```

## Security Model

1. **Assume the host network is hostile** — all application traffic is forced through the backend namespace.
2. **Assume the process may be compromised** — seccomp-bpf blocks `ptrace`, `userfaultfd`, module loading, `bpf`, keyctl, etc.
3. **Assume disk may be inspected** — state file can be encrypted; session artifacts can be 3-pass wiped.
4. **Assume containers leak fingerprints** — `/proc/cpuinfo`, `/proc/version`, `/proc/uptime`, kernel params are spoofed via bind-mounts + LD_PRELOAD.

## Testing

We don't do "tests for coverage." We do **real integration tests** that modify actual system state inside containers.

```bash
# Unit tests
zig build test

# Integration (needs root)
sudo ./scripts/validate.sh --integration

# Everything
sudo ./scripts/validate.sh --all
```

| Suite | Tests | Status |
|-------|-------|--------|
| Unit | — | ✅ PASS |
| Identity Rotation | hostname rotate + restore | ✅ PASS |
| Tor Backend | daemon lifecycle, SOCKS, status | ✅ PASS |
| Netns Shell | traffic routes through Tor | ✅ PASS |
| Platform Probe | SYS_ADMIN / NET_ADMIN detection | ✅ PASS |
| E2E Full Session | init → start → verify → rotate → stop | ✅ PASS |

## Roadmap

### v0.3.0 "Ghost" ✅
- [x] Encrypted state (XChaCha20-Poly1305)
- [x] Secure memory (`mlock`, `MADV_DONTDUMP`, explicit zeroing)
- [x] 3-pass anti-forensic wipe
- [x] Atomic `iptables-restore` killswitch
- [x] Silent cleanup / no stderr noise

### v0.4.0 "Chain" ✅
- [x] seccomp-bpf sandbox
- [x] Backend plugin architecture (Tor, WireGuard, Chain)
- [x] Backend chaining: VPN → Tor (`--backend chain`)
- [x] Cover traffic padding (`start --cover`, `fella cover start|stop`)
- [ ] Browser fingerprint isolation (ephemeral Firefox profiles)

See [docs/tracking/status.md](docs/tracking/status.md) and [docs/tracking/nation-state-roadmap.md](docs/tracking/nation-state-roadmap.md) for the full gap analysis.

## Threat Model

fella is built for a specific set of adversaries and makes explicit trade-offs. It does **not** claim to defeat a global passive adversary with infinite resources.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for:
- Asset inventory
- Adversary capabilities (ISP, nation-state firewall, endpoint forensics, global passive)
- Mitigations and gaps matrix
- Operational security recommendations
- Trust assumptions

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for module lifecycle, acceptance criteria, and testing philosophy.

## License

MIT. See [LICENSE](LICENSE).

## Warning

### Ephemeral Mode

```bash
sudo fella start --ephemeral
```

This mounts `/var/lib/fella` as a **tmpfs**. Every byte of session state — identity backups, Tor data, configs, keys, state file — lives in RAM only. Pull the plug or unmount, and it evaporates. This is the mode you want if physical seizure is in your threat model.

### Process Masquerade

On every `start`/`lockdown`, fella renames its own process to something boring like `systemd-resolve`, `systemd-network`, or `dbus-daemon`. `ps`, `top`, and `/proc/<pid>/comm` show the fake name. Cheap obfuscation against process-targeted attacks.

### MAC Address Rotation

fella randomizes the MAC address of both the primary host interface and the `veth-fella-host` pair on every start/rotate. This breaks L2 tracking, DHCP fingerprinting, and router logging correlation.

## Warning

This tool is for **authorized security research, CTFs, journalism, and privacy-conscious browsing only**. The authors assume no liability for misuse.
