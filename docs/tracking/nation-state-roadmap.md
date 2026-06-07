# fella Nation-State Tier Gap Analysis

> This document maps the delta between v0.1.0 (functional MVP) and a tool that could be deployed in a high-threat environment.

## Threat Model

**Attacker capabilities:**
- Passive network monitoring (ISP, IX, fiber taps)
- Active traffic analysis (correlation, timing, size)
- Local forensic analysis (memory dumps, disk imaging)
- Container/VM introspection (hypervisor, cgroup escape)
- Coercion (compel the operator to reveal state)

**Defender constraints:**
- Single physical machine (no dedicated burner hardware)
- Shared infrastructure (VM/container, not bare metal)
- Limited time to sanitize between sessions

---

## Gap Tiers

### Tier 1: Critical — Leaks That De-Anonymize Immediately

| # | Gap | Attack Vector | v0.1.0 Status | Target Release |
|---|-----|---------------|---------------|----------------|
| 1.1 | **No network namespace isolation** | Tor traffic shares netns with non-Tor apps; any app bypassing proxy leaks real IP | Unaddressed | v0.2 |
| 1.2 | **No IPv6 killswitch** | `ip6tables` untouched; dual-stack hosts leak IPv6 to destinations | Unaddressed | v0.2 |
| 1.3 | **No MAC address spoofing** | Static MAC is a persistent local-network fingerprint | Unaddressed | v0.2 |
| 1.4 | **WebRTC + browser leaks** | Browser can bypass SOCKS and leak local IP via STUN/ICE | Unaddressed | v0.3 |
| 1.5 | **DNS over SOCKS only partially enforced** | System resolver still queries ISP DNS for non-Tor traffic in basic mode | Partial (strict mode only) | v0.2 |

### Tier 2: High — Fingerprinting + Correlation

| # | Gap | Attack Vector | v0.1.0 Status | Target Release |
|---|-----|---------------|---------------|----------------|
| 2.1 | **No traffic padding / shaping** | Traffic timing + size patterns correlate across entry/exit | Unaddressed | v0.4 |
| 2.2 | **No clock skew normalization** | System clock is a cross-session fingerprint; NTP leaks location | Unaddressed | v0.3 |
| 2.3 | **No timezone normalization** | Rotates timezone but doesn't enforce it system-wide or in browser | Partial | v0.3 |
| 2.4 | **No browser fingerprint isolation** | Same browser profile across sessions; canvas, fonts, WebGL leak | Unaddressed | v0.3 |
| 2.5 | **No cover traffic generation** | Absence of traffic is itself a signal; burst patterns stand out | Unaddressed | v0.4 |
| 2.6 | **No anti-traffic-analysis for Tor** | Tor cell timing is vulnerable to end-to-end correlation | Unaddressed | v0.4 |

### Tier 3: Medium — Forensic Resistance + Hardening

| # | Gap | Attack Vector | v0.1.0 Status | Target Release |
|---|-----|---------------|---------------|----------------|
| 3.1 | **No secure memory** | Keys, state, identity buffers not `mlock`ed or explicitly zeroed | Unaddressed | v0.3 |
| 3.2 | **No anti-forensic wipe** | `fella wipe` runs `rm -rf`; doesn't overwrite, leaves slack space | Partial | v0.3 |
| 3.3 | **No seccomp-bpf sandbox** | fella process itself has full syscall access if compromised | Unaddressed | v0.3 |
| 3.4 | **No AppArmor/SELinux policy** | No mandatory access control limiting fella's blast radius | Unaddressed | v0.3 |
| 3.5 | **State file unencrypted** | `/var/lib/fella/state` is plaintext; seizure reveals session history | Unaddressed | v0.3 |
| 3.6 | **No audit log suppression** | `auditd`, `journald`, `lastlog` record fella activity | Unaddressed | v0.2 |

### Tier 4: Advanced — Sophisticated Adversaries

| # | Gap | Attack Vector | v0.1.0 Status | Target Release |
|---|-----|---------------|---------------|----------------|
| 4.1 | **No multi-hop backend chaining** | Single Tor circuit is vulnerable to malicious guard + exit collusion | Unaddressed | v0.4 |
| 4.2 | **No pluggable transports** | Tor traffic is trivially fingerprintable by DPI; blocked in some regions | Unaddressed | v0.4 |
| 4.3 | **No bridge support** | Public Tor relays are enumerated and blocked by censors | Unaddressed | v0.4 |
| 4.4 | **No ACPI/DMI spoofing** | `dmidecode`, `/sys/class/dmi/id` expose hardware serials | Unaddressed | v0.3 |
| 4.5 | **No boot-time identity** | Initramfs, bootloader, kernel cmdline leak boot identity | Unaddressed | v0.4 |
| 4.6 | **No covert channel detection** | Microarchitectural side channels (cache, branch predictor) | Unaddressed | v0.5 |
| 4.7 | **No hardware-level fingerprint randomization** | CPUID, RDTSC, TSC frequency are stable per machine | Unaddressed | v0.5 |

---

## Implementation Plans

### v0.2 — "Fortress" (Network Containment)

**Goal:** Eliminate all network-layer leaks.

#### 1.1 Network Namespace Isolation
```
Architecture:
  - Create dedicated netns "fella"
  - Move Tor process into netns
  - Create veth pair: fella0 (host) ↔ fella1 (netns)
  - Host side: assign 10.200.200.1/30
  - Netns side: assign 10.200.200.2/30, default route via 10.200.200.1
  - Tor binds SOCKS only on 10.200.200.2:9050 (unreachable from host except via proxy)
  
Killswitch enhancement:
  - Host iptables: DROP all OUTPUT not from UID fella or to 10.200.200.2:9050
  - Netns iptables: DROP all OUTPUT not via Tor's SOCKS
  
Impact: Any app not using the proxy simply cannot route.
```

#### 1.2 IPv6 Killswitch
```
Implementation:
  - Mirror all iptables rules in ip6tables
  - Block IPv6 multicast, NDP, SLAAC
  - If strict mode: DROP all IPv6 OUTPUT except ::1
  - If basic mode: same policy as IPv4 (allow outbound but block leaks)
  
Verification:
  - Test: curl -6 https://checkip.amazonaws.com must timeout in strict mode
```

#### 1.3 MAC Address Spoofing
```
Implementation:
  - On start: generate random MAC (OUI from common vendors)
  - ip link set dev $IFACE address $FAKE_MAC
  - On stop: restore original MAC
  - Persist original to /var/lib/fella/original/mac
  
Corner cases:
  - Some hypervisors block MAC changes (OrbStack, VMware) — warn but don't fail
  - Bonded/bridged interfaces need special handling
```

#### 1.5 DNS Enforcement (basic mode)
```
Implementation:
  - Bind mount /etc/resolv.conf to one containing only "nameserver 127.0.0.1"
  - Ensure dnsmasq or Tor DNSPort handles all queries
  - iptables: REDIRECT UDP 53 → 127.0.0.1:5353
  
Verification:
  - tcpdump -i any port 53 must show only 127.0.0.1 destinations
```

#### 3.6 Audit Log Suppression
```
Implementation:
  - If auditd running: temporarily disable rules for fella binary path
  - journald: set Storage=volatile or mask fella unit logs
  - lastlog/utmp: skip recording login sessions in fella shell
  - wtmp: use libutempter or LD_PRELOAD to suppress
```

---

### v0.3 — "Ghost" (Fingerprint + Forensic Resistance)

**Goal:** Make the host forensically indistinguishable from a stock install.

#### 2.2 Clock Skew Normalization
```
Implementation:
  - Stop systemd-timesyncd / ntpd
  - Set system clock to UTC (or matching exit node timezone)
  - Discipline clock against Tor consensus time (not public NTP)
  - On stop: restore real clock from RTC
  
Verification:
  - date +%s should match consensus time ±2s
  - No NTP traffic except via Tor tunnel
```

#### 2.3 Timezone Normalization
```
Implementation:
  - Current: rotates timezone randomly
  - Enhancement: match timezone to Tor exit node country
  - Set TZ env var system-wide
  - Bind mount fake /etc/localtime
  - Update /etc/timezone
  
Verification:
  - date command shows exit-node-local time
  - Browser JS Date() matches
```

#### 2.4 Browser Fingerprint Isolation
```
Implementation:
  - Launch Firefox/Chromium in ephemeral profile via fella shell
  - Pre-configured prefs:
    - privacy.resistFingerprinting = true
    - canvas poisoning randomized per session
    - WebGL disabled
    - no WebRTC (media.peerconnection.enabled = false)
    - spoofed screen resolution (common laptop sizes)
  - Each rotation generates new browser profile
  - Profile destroyed on stop (or optionally encrypted)
```

#### 3.1 Secure Memory
```
Implementation:
  - Wrap sensitive buffers in SecureBuffer(T):
    - mlock() pages on allocation
    - explicit_bzero() on deinit
    - madvise(MADV_DONTDUMP) to exclude from core dumps
  - Apply to:
    - Original identity backups
    - State file contents in memory
    - Persona encryption keys (v0.3)
    - Tor control port auth cookie
```

#### 3.2 Anti-Forensic Wipe
```
Implementation:
  - Replace rm -rf with:
    - 3-pass overwrite (random, complement, random) for each file
    - sync() after each batch
    - Rename files to random 255-byte names before unlink
    - For directories: fill with dummy files, sync, then remove
  - Wipe free space in /var/lib/fella partition (if dedicated)
  - Clear swap: swapoff -a && swapon -a (if swap encrypted, warn)
  
Scope:
  - fella wipe --fast (single overwrite, 1s)
  - fella wipe --thorough (3-pass, 30s)
  - fella wipe --paranoid (35-pass Gutmann, minutes)
```

#### 3.3 Seccomp-BPF Sandbox
```
Implementation:
  - Compile seccomp filter at build time via libseccomp or BPF bytecode
  - Whitelist only necessary syscalls for fella main process:
    - read, write, openat, close, fstat, mmap, mprotect, munmap
    - brk, pread64, pwrite64, lseek, rt_sigaction, rt_sigprocmask
    - ioctl (restricted), getpid, fork, vfork, execve, wait4
    - uname, getcwd, chdir, mkdir, rmdir, unlink, rename
    - socket, connect, bind, listen, accept (for Tor control)
    - mount, umount2 (for hardening)
  - Deny: ptrace, process_vm_readv, perf_event_open, bpf, keyctl
  
Fallback:
  - If seccomp unavailable, warn and continue
```

#### 3.4 MAC Policy (AppArmor)
```
Implementation:
  - Ship apparmor profile: fella.apparmor
  - Restricts:
    - Read: /etc/{passwd,hosts,resolv.conf}, /proc/self/*
    - Write: /var/lib/fella/** only
    - Deny: /home/**, /root/**, /tmp/** (except /tmp/fella_*)
    - Deny: capability sys_ptrace, sys_admin (unless needed)
  - Auto-load on start if AppArmor available
```

#### 3.5 Encrypted State
```
Implementation:
  - Derive key from password + Argon2id
  - Encrypt /var/lib/fella/state with XChaCha20-Poly1305
  - Encrypt persona files (see below)
  - Key derived at runtime, never stored to disk
  - If no password provided: warn that state is unencrypted
  
Persona encryption:
  - Each persona = encrypted tarball of:
    - identity artifacts, browser profile, timezone, locale prefs
  - Decrypted to tmpfs on use, wiped on stop
```

#### 4.4 ACPI/DMI Spoofing
```
Implementation:
  - Kernel module or LD_PRELOAD intercept for /sys/class/dmi/id/*
  - Fake values: Dell/HP/Lenovo common SKUs
  - For containers: already masked by hypervisor, but verify
  - Bind mount fake DMI files if writable
```

---

### v0.4 — "Chameleon" (Traffic Analysis Resistance)

**Goal:** Resist correlation, DPI, and traffic analysis.

#### 2.1 Traffic Padding / Shaping
```
Implementation:
  - Constant-rate background noise:
    - Generate random-sized HTTP requests to decoy endpoints
    - Fixed inter-packet timing (e.g., 1 packet every 50ms)
  - Adaptive padding: pad real traffic to common MTU multiples
  - Cover traffic: fetch random Wikipedia pages via Tor
  
Tradeoffs:
  - Bandwidth cost: 2-5x overhead
  - Battery/latency impact
  - Configurable levels: off / minimal / aggressive
```

#### 2.5 Cover Traffic Generation
```
Implementation:
  - Decoy fetches while idle (every 30-120s, random):
    - HTTPS GET to neutral sites (news, weather, Wikipedia)
    - DNS queries to common domains
  - Goal: traffic volume looks like normal browsing, not bursty
  - Only active when fella is in hardened/lockdown state
```

#### 2.6 Anti-Traffic-Analysis for Tor
```
Implementation:
  - Enable Tor's Padding option (where supported)
  - Use Tor's StreamIsolation for different apps
  - Tune CircuitIdleTimeout to prevent circuit reuse
  - Randomize NEWNYM timing (not just on command)
```

#### 4.1 Multi-Hop Backend Chaining
```
Architecture options:
  a) VPN → Tor → Internet
     - VPN provider sees encrypted Tor, not destination
     - Tor guard sees VPN IP, not real IP
     - Best for: hiding Tor usage from ISP
     
  b) Tor → VPN → Internet
     - Destination sees VPN IP, not Tor exit
     - Best for: sites that block Tor exits
     
  c) VPN → Tor → VPN → Internet
     - Maximum separation, but high latency
     
Implementation:
  - Abstract Backend interface (already started in Tor.zig)
  - WireGuard backend (v0.2+)
  - Chain config: backend_order = ["wg", "tor"]
  - Each backend manages its own netns or routing table
```

#### 4.2 Pluggable Transports
```
Implementation:
  - Integrate obfs4, snowflake, or webtunnel bridges
  - Tor config template expanded with Bridge lines
  - Auto-fetch bridge lines from Tor BridgeDB (via meek)
  - Rotate bridges on each session
```

#### 4.3 Bridge Support
```
Implementation:
  - Configurable bridge list (built-in + user-supplied)
  - Bridge health check: test-connect before using
  - Fallback: if all bridges fail, try direct + warn
```

---

### v0.5 — "Phantom" (Hardware + Side Channel)

**Goal:** Resist physical forensics and side-channel analysis.

#### 4.6 Covert Channel Detection
```
Implementation:
  - Monitor for unexpected cache timing variations
  - Detect anomalous branch predictor patterns
  - Run nosy-neighbor detection (co-tenant VMs)
  - Mostly research-grade; practical defense is netns + sandbox
```

#### 4.7 Hardware Fingerprint Randomization
```
Implementation:
  - CPUID spoofing (where possible via MSR or hypercall)
  - TSC offset randomization
  - RDTSC virtualization (return fake values)
  - Requires kernel module or KVM hypervisor cooperation
  - May be impossible in containers; detect and warn
```

#### 4.5 Boot-Time Identity
```
Implementation:
  - If fella manages initramfs:
    - Regenerate initramfs with randomized module load order
    - Randomize kernel cmdline (if possible via kexec)
  - For live systems: kexec into randomized kernel
  - Out of scope for most deployments; document as advanced
```

---

## Release Schedule (Proposed)

| Version | Codename | Focus | ETA |
|---------|----------|-------|-----|
| v0.1.0 | **Iron** | MVP: identity + Tor + killswitch + hardening | **DONE** |
| v0.2.0 | **Fortress** | Network containment (netns, IPv6, MAC, DNS, audit) | TBD |
| v0.3.0 | **Ghost** | Forensic resistance (secure memory, wipe, sandbox, encrypt, browser) | TBD |
| v0.4.0 | **Chameleon** | Traffic analysis resistance (padding, cover, chaining, bridges) | TBD |
| v0.5.0 | **Phantom** | Hardware + side channel (CPUID, TSC, boot-time) | TBD |

---

## What "Nation-State Tier" Actually Means

It's not magic. It means:

1. **Compartmentalization** — Every session is isolated from every other session and from the host.
2. **Fail-closed** — If any component breaks, traffic stops, not leaks.
3. **Minimal trust** — Don't trust the kernel, don't trust the hypervisor, don't trust the compiler.
4. **Attribution resistance** — No persistent artifact (MAC, serial, timezone, clock skew) links sessions.
5. **Traffic indistinguishability** — Your traffic looks like someone else's traffic.
6. **Forensic deniability** — After `wipe`, an examiner finds nothing.

v0.1.0 covers #1 and #2 partially. v0.2-v0.4 close the rest.
