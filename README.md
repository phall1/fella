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
- **Backend plugin architecture** — Tor today, WireGuard tomorrow, chained VPN→Tor after that

## What It Does

| Layer | Feature |
|-------|---------|
| 🎭 **Identity** | Rotates hostname, machine-id, timezone, locale, bash history per session |
| 🔒 **Containment** | Dedicated `fella` network namespace with veth pair to host |
| 🌐 **Routing** | Tor (SOCKS5 + DNS + ControlPort), WireGuard, or chained backends |
| ⛔ **Killswitch** | `iptables-restore` / `ip6tables-restore` atomic ruleset; basic or strict mode |
| 🛡️ **Sandbox** | seccomp-bpf deny-list blocks 15+ dangerous syscalls |
| 🧬 **Hardening** | Container fingerprint spoofing via `/proc` bind-mounts + LD_PRELOAD `libfella.so` |
| 🧹 **Wipe** | 3-pass overwrite (random → complement → random) + `fsync` for session artifacts |
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

# Activate
sudo ./zig-out/bin/fella start          # identity + backend + netns + killswitch + seccomp

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

```bash
# Method 1: clone and build
git clone https://github.com/phall1/fella.git
cd fella
make              # or: zig build
sudo make install

# Method 2: curl pipe
curl -sL https://raw.githubusercontent.com/phall1/fella/main/scripts/install.sh | sudo bash
```

## Commands

```
fella init                  Probe environment, first-time setup
fella init --encrypt        Enable encrypted state storage
fella init --backend <k>    Select backend: tor | wireguard
fella start                 Activate identity + backend + containment
fella lockdown              Strict killswitch (backend-only traffic)
fella stop                  Deactivate everything, restore system
fella rotate                New identity + rotate backend circuits
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
const Kind = Backend.Kind;  // .tor | .wireguard

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

### v0.4.0 "Chain" 🚧
- [x] seccomp-bpf sandbox
- [x] Backend plugin architecture (Tor, WireGuard)
- [ ] Backend chaining: VPN → Tor
- [ ] Browser fingerprint isolation (ephemeral Firefox profiles)

See [docs/tracking/status.md](docs/tracking/status.md) and [docs/tracking/nation-state-roadmap.md](docs/tracking/nation-state-roadmap.md) for the full gap analysis.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for module lifecycle, acceptance criteria, and testing philosophy.

## License

MIT. See [LICENSE](LICENSE).

## Warning

This tool is for **authorized security research, CTFs, journalism, and privacy-conscious browsing only**. The authors assume no liability for misuse.
