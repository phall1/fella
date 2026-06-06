# fella Development Methodology

> "A tool this sensitive cannot afford to be wrong."

## 1. Module Lifecycle

Every module passes through **four gates** before it is considered complete.

```
Spec → Implementation → Unit Tests → Integration Tests → E2E Validation → Done
```

### Gate 1: Specification
- Module spec written in `docs/spec/<module>.md`
- Contains: Purpose, Interface, Failure Modes, Acceptance Criteria
- Acceptance criteria are **testable statements**, not vague goals
- Must be reviewed before implementation starts

### Gate 2: Implementation
- Code written in `src/`
- Follows platform abstraction (no raw platform code in engine)
- All error paths handled explicitly (no `catch |_|`)
- Logs structured operations via `AuditLog`

### Gate 3: Unit Tests
- Tests live in `tests/unit/<module>.zig` or inline `test {}` blocks
- Each public function has at least one test
- Tests cover **error paths**, not just happy paths
- Mock external dependencies (filesystem, network, processes)

### Gate 4: Integration Tests
- Tests live in `tests/integration/`
- Test real component interactions
- Run in CI on every PR
- Can use real system resources (creates temp files, starts processes)
- Must clean up after themselves

### Gate 5: E2E Validation
- Tests live in `tests/e2e/`
- Test the tool as a black box
- Verify actual real-world behavior (e.g., "traffic actually goes through Tor")
- Require root / container / VM depending on test
- Run manually before releases, run in CI on release candidates

---

## 2. Validation Criteria ("Definition of Done")

A module is **done** when:

1. **Spec approved** — `docs/spec/<module>.md` exists and covers all acceptance criteria
2. **Code complete** — Implementation handles all spec'd cases
3. **Unit tests pass** — `zig test` passes with ≥80% function coverage
4. **Integration tests pass** — Component interacts correctly with dependencies
5. **No regressions** — Full E2E suite still passes
6. **Platform tested** — Works on target platform (Linux x86_64, Linux aarch64)

---

## 3. Current Status

See `docs/tracking/status.md` for live module status.

| Module | Spec | Impl | Unit | Integ | E2E | Status |
|--------|------|------|------|-------|-----|--------|
| Core/Engine | 📝 | ✅ | ⬜ | ⬜ | ⬜ | In Progress |
| Platform Probe | 📝 | ✅ | ⬜ | ⬜ | ⬜ | In Progress |
| Identity Rotation | 📝 | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Tor Backend | 📝 | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Killswitch | 📝 | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Container Hardening | 📝 | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Verification | 📝 | ⬜ | ⬜ | ⬜ | ⬜ | Planned |
| Install/Build | 📝 | ⬜ | ⬜ | ⬜ | ⬜ | Planned |

Legend: 📝 Spec written, ✅ Implemented, ⬜ Not started

---

## 4. Testing Philosophy

### What "Real Testing" Means

**Bad test:**
```zig
test "hostname setter" {
    try setHostname("test-host");
    // Does it work? Who knows.
}
```

**Good test:**
```zig
test "hostname setter actually changes system hostname" {
    const original = try getHostname(arena);
    defer restoreHostname(original) catch {};
    
    try setHostname("fella-test-42");
    const actual = try getHostname(arena);
    
    try std.testing.expectEqualStrings("fella-test-42", actual);
}
```

**Real test (integration):**
```bash
# tests/integration/tor-backend.sh
fella start
ACTUAL_IP=$(proxychains4 curl -s https://checkip.amazonaws.com)
TOR_CHECK=$(proxychains4 curl -s https://check.torproject.org/api/ip)
[[ "$TOR_CHECK" == *'"IsTor":true'* ]] || exit 1
fella stop
```

**E2E test:**
```bash
# tests/e2e/full-session.sh
# Run in isolated VM/container
fella init
fella start
# Attempt direct connection (should fail in strict mode)
if curl --max-time 5 https://ipinfo.io 2>/dev/null; then
    echo "FAIL: Direct connection succeeded"
    exit 1
fi
# Proxied connection should work
proxychains4 curl --max-time 15 https://ipinfo.io >/dev/null || exit 1
# Verify Tor
proxychains4 curl -s https://check.torproject.org/api/ip | grep -q 'IsTor.*true' || exit 1
fella stop
# Verify system restored
[[ "$(hostname)" == "$ORIGINAL_HOSTNAME" ]] || exit 1
```

---

## 5. Running Tests

```bash
# Unit tests only (fast, no root, no network)
zig build test

# Integration tests (needs root, uses real system)
sudo ./scripts/run-tests.sh --integration

# E2E tests (needs isolated environment)
sudo ./scripts/run-tests.sh --e2e

# Validation gate (runs appropriate level)
./scripts/validate.sh          # Unit
sudo ./scripts/validate.sh     # Unit + Integration + E2E

# CI mode
./scripts/validate.sh --ci
```

---

## 6. Acceptance Criteria Template

Every module spec must answer:

1. **What does it do?** (One sentence)
2. **What are the inputs?** (Config, CLI args, system state)
3. **What are the outputs?** (Side effects, return values, logs)
4. **What are the failure modes?** (Each must have explicit error handling)
5. **How do we verify it works?** (Specific test commands/expected outputs)
6. **What are the platform constraints?** (Linux only? Needs CAP_SYS_ADMIN?)
7. **What are the security properties?** (Privileges dropped? Logs sanitized?)

---

## 7. Versioning & Releases

- `0.1.0` — MVP: init/start/stop/rotate with Tor + basic killswitch (Linux)
- `0.2.0` — WireGuard backend, backend chaining
- `0.3.0` — Persona system with persistence
- `0.4.0` — macOS support, container hardening
- `1.0.0` — Full feature set, stable API

Release checklist in `docs/tracking/release-checklist.md`.
