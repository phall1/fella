# fella

> A dumb name for a serious tool.

**fella** is a network identity and traffic containment framework. It rotates your system's identity artifacts, routes traffic through privacy-preserving backends, and enforces traffic containment with a configurable killswitch.

```
   _____     __
  / __(_)__ / /  ___ ___
 / _// (_-< / _ \/ -_) _ \
/_/ /_/___/_//_/\__/_//_/
```

## What It Does

- **Identity Rotation:** Changes hostname, machine-id, timezone, locale, and keyboard layout per-session
- **Traffic Routing:** Supports Tor, WireGuard, OpenVPN, and chained combinations
- **Killswitch:** Blocks all non-backend traffic at the iptables level
- **Container Hardening:** Patches kernel/CPU fingerprints in container environments
- **Verification:** Tests for DNS leaks, IP exposure, and Tor confirmation

## Quick Start

```bash
# Clone
git clone https://github.com/yourname/fella.git
cd fella

# Build
zig build

# Run
sudo ./zig-out/bin/fella init
sudo ./zig-out/bin/fella start    # Identity + Tor + basic killswitch
sudo ./zig-out/bin/fella verify   # Run leak tests
sudo ./zig-out/bin/fella stop     # Restore everything
```

## Requirements

- Zig 0.16.0+
- Linux (x86_64 or aarch64)
- root privileges (for iptables, hostname, etc.)

Optional:
- `tor` — for Tor backend
- `wireguard-tools` — for WireGuard backend
- `proxychains4` — for application-level proxying

## Install

```bash
# Method 1: git clone + build
git clone https://github.com/yourname/fella.git
cd fella
zig build
sudo ./scripts/install.sh

# Method 2: curl pipe
curl -sL https://raw.githubusercontent.com/yourname/fella/main/scripts/install.sh | sudo bash
```

## Commands

```
fella init        Probe environment, first-time setup
fella start       Activate identity + backends + containment
fella lockdown    Strict killswitch (Tor-only traffic)
fella stop        Deactivate everything, restore system
fella rotate      New identity + rotate circuits
fella status      Show current posture
fella verify      Run leak/health tests
fella shell       Drop into backend-routed subshell
fella wipe        Clear session artifacts
fella harden      Apply container fingerprint patches
fella doctor      Diagnose environment
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the full methodology, module lifecycle, and testing philosophy.

```bash
# Run tests
zig build test                           # Unit tests
sudo ./scripts/validate.sh --integration # Integration tests
sudo ./scripts/validate.sh --all         # Everything
```

## Architecture

```
CLI → Engine → Identity → Backends → Killswitch → Verification
                ↓           ↓
         Container      Platform
         Hardening      Abstraction
```

## Status

Currently v0.1.0-dev. See [docs/tracking/status.md](docs/tracking/status.md) for live development status.

| Feature | Status |
|---------|--------|
| Core Engine | 🚧 In Progress |
| Platform Probe | ✅ Working |
| Identity Rotation | 📝 Planned |
| Tor Backend | 📝 Planned |
| Killswitch | 📝 Planned |
| Container Hardening | 📝 Planned |

## License

MIT. See [LICENSE](LICENSE).

## Warning

This tool is for **authorized security research, CTFs, and privacy-conscious browsing only**. The authors assume no liability for misuse.
