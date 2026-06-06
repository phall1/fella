# Module Spec: Core Engine

## 1. What It Does

Manages the state machine and orchestrates all other modules. The Core Engine is the single source of truth for "what state is fella in right now."

## 2. Inputs

- CLI commands (init, start, stop, lockdown, rotate, etc.)
- Environment probe results (from Platform module)
- Module health status callbacks

## 3. Outputs

- State transitions (off → init → hardened → lockdown)
- Audit log entries (`/var/lib/fella/audit.log`)
- Module activation/deactivation commands

## 4. State Machine

```
        +---------+
        |   OFF   |
        +----+----+
             | init
             v
        +---------+
        |  INIT   |<---------------+
        +----+----+                |
             | start               | init (after stop)
             v                     |
    +------------------+           |
    |    HARDENED      |-----------+
    +----+------+------+
         |      |
    lock |      | relax
         v      v
    +---------+  +----------+
    | LOCKDOWN|  |  RELAXED |
    +----+----+  +-----+----+
         |             |
         +------+------+
                | stop
                v
           +---------+
           |   OFF   |
           +---------+
```

**Transitions are atomic.** If any module fails during transition, rollback occurs.

## 5. Failure Modes

| Failure | Handling |
|---------|----------|
| Module start fails | Rollback to previous state, log error |
| Module stop fails | Log warning, force cleanup, enter OFF |
| State file corrupted | Enter OFF, require `fella init` |
| Concurrent invocation | File lock on state file, wait or error |

## 6. Verification

```bash
# Unit: State machine transitions correctly
zig test tests/unit/engine.zig

# Integration: Start -> verify state file
fella init
fella start
cat /var/lib/fella/state | grep '"state":"hardened"'
fella stop
cat /var/lib/fella/state | grep '"state":"off"'

# E2E: Full lifecycle
fella init && fella start && fella rotate && fella stop
```

## 7. Platform Constraints

- Requires root for most operations (iptables, hostname, etc.)
- State file: `/var/lib/fella/state.json` (root 600)
- Audit log: `/var/lib/fella/audit.log` (root 640, append-only)

## 8. Security Properties

- State file integrity: HMAC-SHA256 optional in v0.2
- Audit log tamper-evident: append-only permissions
- No secrets in state file (no VPN keys, no Tor auth)
