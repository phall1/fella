# fella Threat Model

> **Last updated:** 2026-06-08
> **Version:** 0.5.0
> **Status:** Living document

---

## What fella promises

**In one sentence:** On a hostile network, fella makes your traffic indistinguishable from any other Tor user, and after you stop, your machine looks like it was never there.

That promise is delivered through three layers. Every feature in fella maps to exactly one layer. If a feature does not serve one of these layers, it is either defense-in-depth or theater, and we document which.

---

## The Three Layers

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 3 — FORENSICS                                        │
│  After stop(), an examiner finds nothing.                   │
│  • Ephemeral tmpfs mount                                    │
│  • 3-pass anti-forensic wipe                                │
│  • Encrypted state (XChaCha20-Poly1305)                     │
│  • Secure memory (mlock + MADV_DONTDUMP)                    │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│  LAYER 2 — IDENTITY                                         │
│  Each session the machine looks like a different person.    │
│  • Hostname / machine-id / timezone / locale rotation       │
│  • Vendor-OUI MAC rotation (looks like real hardware)       │
│  • Ephemeral Firefox profile with RFP + WebRTC off          │
│  • [Future] Persona system: save named identity bundles     │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1 — CONTAINMENT (The Pipe)                           │
│  If it leaves the NIC, it goes through Tor. Fail-closed.    │
│  • Dedicated netns with veth pair to host                   │
│  • iptables OUTPUT DROP by default; only Tor/DNS allowed    │
│  • DNS forced through Tor DNSPort (bind-mount resolv.conf)  │
│  • IPv6 disabled in netns (no AAAA leaks)                   │
│  • torsocks for app proxying                                │
│  • Auto-verify: if Tor bootstrap fails, abort and stop()    │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Containment

### Adversary: Local Network / ISP (Passive Observer)
**Capabilities:** Sees all cleartext metadata leaving the machine: packet sizes, timing, destination IPs, DNS queries, SNI.

**Assumption:** The adversary cannot break Tor cryptography or control a significant portion of Tor relays.

**How fella counters:**

1. **Network namespace isolation.** All application traffic runs inside a dedicated `fella` netns. The netns firewall defaults to `OUTPUT DROP`. Only TCP to the host-side Tor SOCKS port (9050) and UDP to the Tor DNSPort (5353) are allowed. There is simply no route for unproxied traffic to escape.

2. **DNS enforcement.** `fella exec` and `fella shell` enter a private mount namespace and bind-mount a custom `resolv.conf` pointing to `10.200.200.1:5353`. Non-torsocks applications cannot accidentally query the ISP resolver.

3. **IPv6 disable.** The netns runs `sysctl net.ipv6.conf.all.disable_ipv6=1`. AAAA lookups and IPv6 direct connections are impossible.

4. **Fail-closed verification.** After `start` or `lockdown`, fella immediately curls `check.torproject.org` via SOCKS. If `IsTor` is false, it automatically calls `stop()` and aborts. The user cannot accidentally operate in a broken state.

5. **Killswitch.** Basic mode drops unexpected INPUT/FORWARD. Strict mode drops all OUTPUT not from the Tor process or to Tor ports. On `stop`, original iptables rules are restored atomically via `iptables-restore`.

**Gaps:**
- ICMP echo (ping) from inside the netns bypasses Tor and leaks the real origin IP to the destination. The netns firewall does not currently block ICMP.
- NTP traffic is not intercepted. If an application calls `gettimeofday` via NTP instead of the system clock, it may leak.
- The host kernel itself is trusted. If the kernel is backdoored, all layers collapse.

### Adversary: Nation-State Firewall (Active Blocker)
**Capabilities:** Blocks known Tor relays and directory authorities. Performs DPI to fingerprint Tor / obfs4 / snowflake.

**How fella counters:**
- Auto-detects `obfs4proxy` or `snowflake-client` and injects bridge lines into `torrc`.
- Embeds default obfs4 bridge lines for censored regions.
- Supports custom bridge configs at `/var/lib/fella/bridges.conf`.

**Gaps:**
- If obfs4/snowflake are not installed, fella falls back to direct Tor and will likely fail in censored countries.
- No active probing resistance beyond what Tor/bridges already provide.

---

## Layer 2: Identity

### Adversary: Network Correlation Across Sessions
**Capabilities:** Correlates your activity across multiple sessions using persistent identifiers: MAC address, hostname, DHCP fingerprint, browser canvas, timezone, locale.

**How fella counters:**

1. **Host identity rotation.** On every `start`, fella changes `/etc/hostname`, `/etc/machine-id`, `/etc/localtime`, and `/etc/default/locale`. Originals are saved to `/var/lib/fella/original` and restored on `stop`.

2. **Vendor-OUI MAC rotation.** Instead of random locally-administered MACs (which look suspicious), fella uses real vendor prefixes (Intel, Realtek, Broadcom, Apple, Dell, HP, Samsung) with randomized last 3 bytes. To a router, it looks like a new laptop joined the network.

3. **Browser fingerprint isolation.** `fella browser` launches an ephemeral Firefox profile inside the netns with:
   - `privacy.resistFingerprinting` enabled
   - WebRTC disabled (prevents local IP leaks via STUN)
   - WebGL and canvas capture disabled
   - Disk cache, session restore, and history disabled
   - Telemetry, SafeBrowsing, and Pocket disabled
   - SOCKS5 proxy configured directly to Tor
   - Profile wiped from `/tmp` on exit

**Gaps:**
- Screen resolution is not spoofed (RFP handles this on some platforms, not all).
- Font list fingerprinting is not mitigated beyond RFP.
- No automatic timezone matching to Tor exit node country.
- No clock skew normalization (system clock is a cross-session fingerprint).

---

## Layer 3: Forensics

### Adversary: Post-Session Disk Examiner
**Capabilities:** Gains physical or remote access to disk after fella has stopped. Looks for artifacts in `/var/lib/fella`, logs, shell history, packet captures.

**How fella counters:**

1. **Anti-forensic wipe.** `fella wipe` performs 3-pass overwrite (random → complement → random) + `fsync` for every file in `/var/lib/fella`, then renames files to random 255-byte names before unlink.

2. **Ephemeral mode.** `fella start --ephemeral` mounts `/var/lib/fella` as a tmpfs. All session state lives in RAM and evaporates on reboot or power loss.

3. **Encrypted state.** `fella init --encrypt` + `FELLA_PASSPHRASE` encrypts the state file with XChaCha20-Poly1305. Even if the disk is imaged, the state is unreadable without the passphrase.

4. **Secure memory.** Sensitive buffers are `mlock`ed to prevent swapping, marked `MADV_DONTDUMP` to exclude from core dumps, and explicitly zeroed on deinit.

**Gaps:**
- RAM freeze / cold-boot attacks can dump tmpfs contents before power loss.
- Swap may contain fella pages unless swap is encrypted or disabled.
- Kernel logs (`dmesg`, auditd, systemd journal) may record MAC changes, namespace creation, iptables modifications.
- The fella binary in `/usr/local/bin/fella` is itself evidence of installation.

---

## Defense-in-Depth (Not Core)

These features are useful but do not serve the three-layer promise directly. They are included as bonus hardening.

| Feature | What it does | Limitation |
|---------|--------------|------------|
| seccomp-bpf | Blocks ptrace, module loading, userfaultfd, etc. | If the attacker already has root, seccomp can be disabled. If the attacker is remote and only sees network traffic, seccomp is irrelevant. |
| Chain backend (VPN→Tor) | Hides Tor usage from ISP; Tor traffic is tunneled through WireGuard first. | Requires a working WireGuard endpoint. Adds latency. Policy routing prevents host connectivity loss. |
| MAC rotation subagent | Rotates veth MAC every 5–15 minutes while active. | Only useful against long-session L2 tracking. Most adversaries correlate at session start. |

---

## Theater (Acknowledged)

These features exist in the codebase but provide limited real security. They are documented honestly.

| Feature | Why it's theater | Status |
|---------|-----------------|--------|
| Process masquerade (`prctl(PR_SET_NAME)`) | `/proc/<pid>/exe` and `/proc/<pid>/cmdline` still reveal the real binary. Only fools `ps` without `-f`. | Kept for casual obfuscation; documented as limited. |
| Container hardening / LD_PRELOAD | Spoofs `/proc/cpuinfo`, `uname()`, etc. If you're in a container, the hypervisor sees everything. If you're on bare metal, this is irrelevant. | Kept as best-effort; not promoted as a primary defense. |
| Traffic padding subagent | Emits HTTP GETs every 30–120s. Not constant-rate at the wire level. A sophisticated adversary can distinguish TLS handshake bursts from application data. | Rewritten to be low-bandwidth and non-abusive; documented as "noise" not "shaping." |

---

## What fella does NOT promise

1. **It does not defeat a global passive adversary.** NSA/Five Eyes with sufficient Tor relay coverage can perform end-to-end confirmation attacks that no client-side tool can fully defeat. Padding helps but is not a cure.

2. **It does not protect against a compromised kernel.** If the Linux kernel is backdoored, all layers collapse.

3. **It does not protect against physical seizure while powered.** Cold-boot attacks, DMA, and JTAG can extract RAM contents including tmpfs data.

4. **It does not make you anonymous to the destination.** If you log into your personal email through Tor, the destination knows who you are. Tor provides unlinkability from your origin IP, not invisibility.

5. **It does not protect against side channels.** Cache timing, power analysis, and electromagnetic emanations are out of scope.

---

## Trust Assumptions

1. The Linux kernel is trustworthy and not backdoored.
2. The underlying hardware is trustworthy (no Intel ME / AMD PSP / BMC compromise).
3. `tor`, `torsocks`, `iptables`, `iproute2`, `wg`, and `obfs4proxy` are not backdoored.
4. The operator does not install unrelated malware during the fella session.
5. The operator's destination (e.g., the website they visit) does not collude with the adversary.

---

## Operational Security Recommendations

- Use `--ephemeral` for any session where physical seizure is plausible.
- Combine with full-disk encryption and encrypted swap.
- Run in a disposable VM or live USB, not on a daily driver.
- Keep bridge configs (`/var/lib/fella/bridges.conf`) up to date.
- Do not reuse identities across sessions — `fella rotate` is cheap.
- Wipe the session (`fella wipe`) before shutdown, even with `--ephemeral`.
- Use `fella browser` for web traffic; do not browse in `fella shell` with a regular browser profile.
- Verify after every start: `fella verify` should show all green.

---

## Changelog

- **v0.5.0** — Focused 3-layer architecture: DNS enforcement, IPv6 disable, fail-closed verify, vendor-OUI MACs, browser fingerprint isolation, honest theater documentation.
- **v0.4.0** — Backend plugin architecture, seccomp-bpf, traffic padding, process masquerade, MAC rotation, ephemeral mode, WireGuard/Chain backends.
- **v0.3.0** — Encrypted state, secure memory, anti-forensic wipe.
- **v0.2.0** — Netns isolation, torsocks transparent proxy.
- **v0.1.0** — Initial identity rotation + Tor backend + killswitch.
