# fella Development Status

> Last updated: 2026-06-07
> Current version: 0.4.0 "Chain"

## Module Status

| Module | Gate 1 Spec | Gate 2 Impl | Gate 3 Unit | Gate 4 Integ | Gate 5 E2E | Overall |
|--------|:-----------:|:-----------:|:-----------:|:------------:|:----------:|:-------:|
| **Core Engine** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Platform Probe** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Identity Rotation** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Tor Backend** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **WireGuard Backend** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Chain Backend (VPN→Tor)** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Constant-Rate Padding** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Censorship Bridges (obfs4/snowflake)** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **MAC Rotation** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Process Masquerade** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Ephemeral Mode** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Subagent System** | ✅ | ✅ | ✅ | 🚧 | 🚧 | 🚧 |
| **Killswitch** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Container Hardening** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Verification** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Netns Isolation** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Transparent Proxy** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Install/Build** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Secure Memory** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Anti-Forensic Wipe** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Encrypted State** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Seccomp-bpf Sandbox** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Backend Plugin Architecture** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Legend:**
- ✅ Complete
- 🚧 In Progress
- 📝 Planned
- ⬜ Not Started

## Active Work

### v0.1.0 "Foundation" Completed
- [x] Core Engine state persistence
- [x] Identity module implementation (hostname, machine-id, timezone, locale)
- [x] Tor backend (process management, config generation, bootstrap, circuit rotation)
- [x] Killswitch (iptables save/restore/basic/strict)
- [x] Verification suite (IP exposure, Tor check, direct bypass)
- [x] Integration + E2E tests

### v0.2.0 "Fortress" Completed
- [x] Network namespace isolation (`fella` netns with veth pair)
- [x] Transparent proxy via torsocks
- [x] `fella shell` / `fella exec`
- [x] Fail-closed firewall inside netns
- [x] Host NAT for netns traffic

### v0.3.0 "Ghost" Completed
- [x] Secure memory (`mlock`, `MADV_DONTDUMP`, explicit zeroing)
- [x] Anti-forensic 3-pass wipe
- [x] Encrypted state storage (XChaCha20-Poly1305)
- [x] Atomic `iptables-restore` / `ip6tables-restore` killswitch
- [x] Silent cleanup

### v0.4.0 "Chain" Completed
- [x] seccomp-bpf sandbox (15 high-leverage syscalls blocked)
- [x] Backend plugin architecture with union-based `Backend.Instance`
- [x] WireGuard backend skeleton (`wg` + `ip` integration)
- [x] Chain backend: VPN → Tor nested tunneling
- [x] Constant-rate traffic padding daemon (fixed-size packets every 100ms)
- [x] Auto-detect obfs4 / snowflake bridges for censored networks
- [x] Subagent system for netns-side background tasks
- [x] MAC address rotation for host interface and veth pair
- [x] Process masquerade (`prctl(PR_SET_NAME)`) to common systemd names
- [x] Ephemeral mode: tmpfs-backed `/var/lib/fella` for RAM-only sessions
- [x] `Makefile` with `install` / `uninstall` / `test` / `validate`
- [x] `scripts/install.sh` with `--auto` dependency + Zig installation

### Next Sprint (v0.5 — "Browser")
- [ ] Browser fingerprint isolation (ephemeral Firefox profiles)
- [ ] WireGuard real-endpoint integration test
- [ ] Chain backend real-endpoint integration test
- [ ] Threat model validation checklist

### Backlog
- [ ] macOS platform support
- [ ] Traffic shaping / QoS controls
- [ ] Interactive passphrase prompt (when Zig supports it)

## Blockers

| Issue | Blocking | Status |
|-------|----------|--------|
| None currently | — | — |

## Test Results

### Unit Tests
```
Last run: 2026-06-07
Status: PASS
```

### Integration Tests
```
Last run: 2026-06-07
Status: 4/4 PASS
```

### E2E Tests
```
Last run: 2026-06-07
Status: 1/1 PASS
```

## Release Target

**v0.4.0 "Chain"** — Backend plugin architecture + seccomp-bpf + cover traffic + install + obfuscation
- Swappable backends: Tor, WireGuard, Chain (VPN→Tor)
- seccomp-bpf deny-list: ptrace, userfaultfd, kexec, module loading, bpf, keyctl, etc.
- `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation in child processes
- Cover traffic daemon with decoy URL fetches through the tunnel
- Subagent framework for netns-side background tasks (cover, MAC rotate)
- MAC address randomization on host interface + veth pair per session/rotation
- Process masquerade to common systemd service names
- Ephemeral mode: tmpfs mount for `/var/lib/fella` makes all session data RAM-only
- `make` / `make install` / `make uninstall` / `make validate-all`
- `scripts/install.sh --auto` installs system deps and Zig automatically
- Real integration (4 tests) + E2E (1 test) passing on Tor backend
