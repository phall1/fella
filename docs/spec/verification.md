# Module Spec: Verification

## 1. What It Does

Tests the system's actual network posture to detect leaks, misconfigurations, and failures.

## 2. Test Suite

### IP Exposure Test
- **Method:** Request IP from multiple endpoints through active proxy
- **Endpoints:** `https://checkip.amazonaws.com`, `https://icanhazip.com`
- **Pass:** All endpoints return same IP, and it's NOT the user's real IP

### Tor Confirmation Test
- **Method:** Query `https://check.torproject.org/api/ip`
- **Pass:** Response contains `"IsTor":true`

### DNS Leak Test
- **Method:** Query `whoami.akamai.net` through proxy DNS
- **Pass:** Resolver IP is from Tor/VPN network, not ISP

### Direct Bypass Test (strict mode only)
- **Method:** Attempt `curl` without proxy
- **Pass:** Connection fails or times out

### Kernel Fingerprint Test
- **Method:** Run `uname -a` with `LD_PRELOAD` active
- **Pass:** Shows configured fake values

### Container Leak Test
- **Method:** Check `/proc/cpuinfo`, `/proc/version`
- **Pass:** Shows fake values if hardening applied

## 3. Reporting

```json
{
  "timestamp": "2026-06-06T20:00:00Z",
  "version": "0.1.0",
  "tests": [
    {"name": "ip_exposure", "status": "pass", "details": "185.246.188.74"},
    {"name": "tor_check", "status": "pass", "details": "IsTor=true"},
    {"name": "dns_leak", "status": "warn", "details": "Resolver: 71.252.1.25"}
  ],
  "summary": {"pass": 2, "fail": 0, "warn": 1}
}
```

## 4. Verification

```bash
fella start
fella verify  # runs all tests
fella verify --json  # JSON output
fella verify --test ip_exposure  # single test
```

## 5. Platform Constraints

- Needs network connectivity
- Some tests require active Tor/VPN backend
