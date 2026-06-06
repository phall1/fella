# Module Spec: Tor Backend

## 1. What It Does

Manages a dedicated Tor daemon instance. Provides SOCKS5 proxy, DNS proxy, and circuit rotation.

## 2. Inputs

- Tor configuration template
- Control port commands (NEWNYM for rotation)
- Backend chain configuration (optional: route through VPN first)

## 3. Outputs

- Tor daemon process running as `debian-tor` user
- SOCKS5 on `127.0.0.1:9050`
- DNS on `127.0.0.1:5353`
- Control on `127.0.0.1:9051` (no auth for now, localhost only)
- PID file at `/var/lib/fella/run/tor.pid`

## 4. Interface

```zig
const TorBackend = struct {
    pub fn init(alloc: Allocator, config: TorConfig) !TorBackend;
    pub fn start(self: *TorBackend) !void;      // Launch daemon, wait for bootstrap
    pub fn stop(self: *TorBackend) !void;       // Graceful shutdown
    pub fn status(self: *TorBackend) Status;    // stopped | bootstrapping | ready
    pub fn rotate(self: *TorBackend) !void;     // NEWNYM signal
    pub fn health(self: *TorBackend) !bool;     // Can reach check.torproject.org
};
```

## 5. Failure Modes

| Failure | Handling |
|---------|----------|
| Tor binary not found | Error at init time, suggest `apt install tor` |
| Bootstrap timeout (60s) | Kill process, error to caller |
| Control port unreachable | Tor may have crashed; attempt restart once |
| Guard connection blocked | Retry with different guards (built into Tor) |

## 6. Verification

```bash
# Unit: config generation
zig test tests/unit/tor-backend.zig

# Integration
fella init
fella start  # starts Tor
# Verify SOCKS port listening
ss -tlnp | grep 127.0.0.1:9050
# Verify Tor check
proxychains4 curl -s https://check.torproject.org/api/ip | grep -q 'IsTor.*true'
fella stop
# Verify no Tor processes remain
! pgrep -u debian-tor tor
```

## 7. Platform Constraints

- Requires `tor` package (Debian/Ubuntu) or binary in PATH
- Creates `debian-tor` user if missing
- Data directory: `/var/lib/fella/tor/` (owned by debian-tor)

## 8. Security Properties

- Runs as unprivileged `debian-tor` user
- Sandbox enabled in torrc
- No ControlPort auth (localhost-only is sufficient for v0.1)
- Data directory 700 permissions
