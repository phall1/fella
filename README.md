# fella

**fella** is a network identity and traffic containment framework. It rotates your system's identity artifacts, routes traffic through privacy-preserving backends, and enforces traffic containment with a configurable killswitch.

```
   _____     __
  / __(_)__ / /  ___ ___
 / _// (_-< / _ \/ -_) _ \
/_/ /_/___/_//_/\__/_//_/
```

## What It Does

- **Identity Rotation:** Changes hostname, machine-id, timezone, locale, and keyboard layout per-session
- **Network Namespace Isolation:** Dedicated `fella` netns with veth pair — apps inside are transparently routed through Tor, apps outside are unaffected
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
sudo ./zig-out/bin/fella start              # Identity + Tor + netns + basic killswitch
sudo ./zig-out/bin/fella shell              # Drop into Tor-routed subshell
sudo ./zig-out/bin/fella exec curl https://check.torproject.org/api/ip
sudo ./zig-out/bin/fella verify             # Run leak tests
sudo ./zig-out/bin/fella stop               # Restore everything
```

## Requirements

- Zig 0.16.0+
- Linux (x86_64 or aarch64)
- root privileges (for iptables, hostname, etc.)

Optional:
- `tor` — for Tor backend
- `torsocks` — for transparent SOCKS proxying inside the netns
- `wireguard-tools` — for WireGuard backend

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
fella shell       Drop into Tor-routed subshell (isolated netns)
fella exec <cmd>  Run a single command in the Tor-routed namespace
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

**v0.1.0 is complete.** All MVP modules are implemented, tested, and passing.

See [docs/tracking/status.md](docs/tracking/status.md) for module-by-module status.

| Feature | Status |
|---------|--------|
| Core Engine | ✅ Complete |
| Platform Probe | ✅ Complete |
| Identity Rotation | ✅ Complete |
| Tor Backend | ✅ Complete |
| Killswitch | ✅ Complete |
| Container Hardening | ✅ Complete |
| Verification Suite | ✅ Complete |
| Network Namespace Isolation | ✅ Complete |
| Transparent Proxy (torsocks) | ✅ Complete |

For the gap analysis between v0.1.0 and nation-state tier, see [docs/tracking/nation-state-roadmap.md](docs/tracking/nation-state-roadmap.md).

## License

MIT. See [LICENSE](LICENSE).

## Warning

This tool is for **authorized security research, CTFs, and privacy-conscious browsing only**. The authors assume no liability for misuse.
