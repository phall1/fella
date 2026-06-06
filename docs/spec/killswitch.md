# Module Spec: Network Killswitch

## 1. What It Does

Controls all network traffic using iptables/nftables. Ensures traffic only flows through allowed backends.

## 2. Modes

| Mode | Description |
|------|-------------|
| `disabled` | No firewall rules (for debugging) |
| `basic` | Drop unexpected inbound, allow all outbound |
| `strict` | Only allow loopback and backend traffic |
| `panic` | Drop ALL traffic (emergency) |

## 3. Strict Mode Rules

```
INPUT:   DROP default
  ACCEPT lo
  ACCEPT established/related
  ACCEPT SSH inbound (port 22)
  ACCEPT ICMP echo-reply (if enabled)

OUTPUT:  DROP default
  ACCEPT lo
  ACCEPT established/related
  ACCEPT owner debian-tor (Tor daemon itself)
  ACCEPT tcp to 127.0.0.1:9050 (Tor SOCKS)
  ACCEPT tcp to 127.0.0.1:9051 (Tor Control)
  ACCEPT udp to 127.0.0.1:5353 (Tor DNS)
  ACCEPT ICMP echo-request (if enabled)
```

## 4. Failure Modes

| Failure | Handling |
|---------|----------|
| iptables not available | Try nftables fallback |
| Neither available | Error, cannot enforce killswitch |
| Rules conflict with existing | Save existing, apply ours, restore on stop |
| SSH lockout risk | Always allow inbound SSH in basic mode |

## 5. Verification

```bash
# Integration
fella start  # basic mode
# Direct connection should still work
curl -s https://ipinfo.io > /dev/null || exit 1
fella lockdown  # strict mode
# Direct connection should fail
curl --max-time 5 https://ipinfo.io 2>/dev/null && exit 1
# Proxied should work
proxychains4 curl -s https://ipinfo.io > /dev/null || exit 1
fella stop
# Rules should be restored
iptables -L INPUT | head -1  # should show ACCEPT
```

## 6. Platform Constraints

- Linux only (iptables/nftables)
- Requires root
- IPv4 supported, IPv6 optional (block if unsupported)
