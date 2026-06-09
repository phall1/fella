# fella Development Status

> Last updated: 2026-06-08
> Current version: 0.5.0

## Architecture

fella is organized around three layers. Every feature maps to exactly one.

| Layer | Purpose | Modules |
|-------|---------|---------|
| **L1 — Containment** | If it leaves the NIC, it goes through Tor. Fail-closed. | Netns, Killswitch, Backend, Verify |
| **L2 — Identity** | Each session the machine looks like a different person. | Identity, Mac, Browser |
| **L3 — Forensics** | After `stop`, an examiner finds nothing. | Crypto, Wipe, Ephemeral, Secure |

Defense-in-depth (not core): seccomp-bpf, Chain backend, Subagent system.

---

## Module Status

| Module | Layer | Gate 1 Spec | Gate 2 Impl | Gate 3 Unit | Gate 4 Integ | Gate 5 E2E | Overall |
|--------|-------|:-----------:|:-----------:|:-----------:|:------------:|:----------:|:-------:|
| **Core Engine** | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Platform Probe** | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Identity Rotation** | L2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Tor Backend** | L1 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **WireGuard Backend** | L1 | ✅ | ✅ | ✅ | ✅ | 🚧 | 🚧 |
| **Chain Backend (VPN→Tor)** | L1 | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Killswitch** | L1 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Netns Isolation** | L1 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DNS Enforcement** | L1 | ✅ | ✅ | ⬜ | ⬜ | ⬜ | 🚧 |
| **IPv6 Disable** | L1 | ✅ | ✅ | ⬜ | ⬜ | ⬜ | 🚧 |
| **Fail-Closed Verify** | L1 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Browser Isolation** | L2 | ✅ | ✅ | ✅ | ✅ | 🚧 | 🚧 |
| **MAC Rotation** | L2 | ✅ | ✅ | ✅ | ✅ | 🚧 | 🚧 |
| **Ephemeral Mode** | L3 | ✅ | ✅ | ✅ | ✅ | 🚧 | 🚧 |
| **Anti-Forensic Wipe** | L3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Encrypted State** | L3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Secure Memory** | L3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Verification** | L1 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Censorship Bridges** | L1 | ✅ | ✅ | ✅ | ✅ | 🚧 | 🚧 |
| **Seccomp-bpf Sandbox** | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Install/Build** | — | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Legend:**
- ✅ Complete
- 🚧 In Progress
- 📝 Planned
- ⬜ Not Started

---

## Release History

### v0.5.0 — "Browser" ✅
Focused 3-layer architecture. DNS enforcement, IPv6 disable, fail-closed auto-verify, vendor-OUI MACs, browser fingerprint isolation, honest theater documentation.

- [x] DNS enforcement: bind-mount custom `resolv.conf` inside `fella exec` / `fella shell`
- [x] IPv6 disable in netns (`sysctl net.ipv6.conf.all.disable_ipv6=1`)
- [x] Fail-closed auto-verify: abort and stop if Tor bootstrap fails
- [x] Vendor-OUI MAC rotation (Intel, Realtek, Broadcom, Apple, Dell, HP, Samsung)
- [x] Browser fingerprint isolation: ephemeral Firefox profile with RFP, WebRTC off, no history
- [x] Policy routing for Chain backend (no host default-route hijack)
- [x] Runtime capability probe via `capget` instead of hardcoded assumptions
- [x] Real primary interface detection via `/proc/net/route`
- [x] MAC restore on `stop`
- [x] Killswitch auto-detects Tor user (`debian-tor`, `tor`, `_tor`)
- [x] WireGuard key rotation: `wg genkey`/`wg pubkey` + config update
- [x] Traffic padding rewritten: 30–120s jitter, lightweight GET, 4 decoy URLs
- [x] Static-binary warning in `fella exec`
- [x] Rewritten threat model with honest "theater" classification

### v0.4.0 — "Chain"
Backend plugin architecture + seccomp-bpf + traffic padding + install + obfuscation.

- [x] seccomp-bpf sandbox (arch-aware x86_64 + aarch64)
- [x] Backend plugin architecture with union-based `Backend.Instance`
- [x] WireGuard backend skeleton (`wg` + `ip` integration)
- [x] Chain backend: VPN → Tor nested tunneling
- [x] Traffic padding subagent
- [x] Auto-detect obfs4 / snowflake bridges for censored networks
- [x] Subagent system for netns-side background tasks
- [x] MAC address randomization on host interface + veth pair with original save/restore
- [x] Process masquerade (`prctl(PR_SET_NAME)`) to common systemd names
- [x] Ephemeral mode: tmpfs-backed `/var/lib/fella` for RAM-only sessions
- [x] `Makefile` with `install` / `uninstall` / `test` / `validate`
- [x] `scripts/install.sh` with `--auto` dependency + Zig installation
- [x] Formal threat model document (`docs/THREAT_MODEL.md`)

### v0.3.0 — "Ghost"
Encrypted state, secure memory, anti-forensic wipe.

- [x] Secure memory (`mlock`, `MADV_DONTDUMP`, explicit zeroing)
- [x] Anti-forensic 3-pass wipe
- [x] Encrypted state storage (XChaCha20-Poly1305)
- [x] Atomic `iptables-restore` / `ip6tables-restore` killswitch
- [x] Silent cleanup

### v0.2.0 — "Fortress"
Network containment.

- [x] Network namespace isolation (`fella` netns with veth pair)
- [x] Transparent proxy via torsocks
- [x] `fella shell` / `fella exec`
- [x] Fail-closed firewall inside netns
- [x] Host NAT for netns traffic

### v0.1.0 — "Foundation"
MVP.

- [x] Core Engine state persistence
- [x] Identity module implementation (hostname, machine-id, timezone, locale)
- [x] Tor backend (process management, config generation, bootstrap, circuit rotation)
- [x] Killswitch (iptables save/restore/basic/strict)
- [x] Verification suite (IP exposure, Tor check, direct bypass)
- [x] Integration + E2E tests

---

## Backlog

| Feature | Layer | Status |
|---------|-------|--------|
| Persona system (save/load named identity bundles) | L2 | 📝 Planned |
| ICMP block in netns | L1 | 📝 Planned |
| NTP intercept/block | L1 | 📝 Planned |
| Tor→VPN backend mode | L1 | 📝 Planned |
| Scheduled circuit rotation subagent | L1 | 📝 Planned |
| macOS platform support | — | 📝 Planned |
| WireGuard real-endpoint integration test | L1 | 🚧 |
| Chain backend real-endpoint integration test | L1 | 🚧 |

---

## Test Results

### Unit Tests
```
Last run: 2026-06-08
Status: PASS
Modules: Crypto, State, Transport, MAC, Passphrase, Killswitch
```

### Integration Tests
```
Last run: 2026-06-08
Status: PASS
```

### E2E Tests
```
Last run: 2026-06-08
Status: PASS
```

---

## Honest Assessment

**What works:** The Tor path is real and functional. Identity rotation works. Netns isolation works. The wipe and crypto work. Browser isolation works. The tool is safe to use on x86_64 and aarch64, on Debian/Fedora/Arch/Alpine.

**What is theater:** Process masquerade, container hardening, and traffic padding are documented as limited. They exist in the codebase but are not promoted as primary defenses.

**What is missing:** ICMP and NTP leak vectors inside the netns. No persona system. No Tor→VPN mode.
