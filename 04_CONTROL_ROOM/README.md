# Section 04 — Control Room

## Purpose

The Control Room is OZAYN's central coordination system, responsible for lifecycle management, state tracking, control flow, component registry, capability discovery, event observation, and policy enforcement across all subsystems.

```text
CONTROL REQUEST
      ↓
VALIDATION
      ↓
TARGET RESOLUTION
      ↓
CAPABILITY CHECK
      ↓
PRECONDITIONS
      ↓
AUTHORIZATION
      ↓
ROUTER
      ↓
DISPATCH
      ↓
RESULT
      ↓
STATE + EVENT + AUDIT
```

## Modules

### Step 01 — Control Room Foundation (`control_room.h/.c`)
Core lifecycle, state, components, capabilities, control requests, event observation, monitors, policy, audit, resource safety.

### Step 03 — Component Registry & Capability Discovery (`component_registry.h/.c`)
Component registration, state management, capability registration, provider validation, dependencies, permissions, queries, discovery, stale data handling, snapshots, events, policy.

### Step 04 — Command Router & Operation Request Foundation (`command_router.h/.c`)
Safe command routing through the Control Room pipeline:
- **Request Validation** — validates request ID, action, target, capability, metadata
- **Target Resolution** — resolves target via Component Registry, checks availability/state
- **Capability Verification** — verifies capability exists, is available, provider exists
- **Precondition Checks** — verifies component state, capability state, dependencies
- **Authorization** — integrates with Section 03 authorization (fail-closed)
- **Operation Lifecycle** — RECEIVED → VALIDATING → RESOLVING → CAPABILITY_CHECK → PRECONDITION_CHECK → AUTHORIZING → QUEUED → DISPATCHING → SUCCEEDED/FAILED/UNSUPPORTED
- **Cancellation** — safe cancellation for non-running operations
- **Idempotency** — duplicate request detection
- **Resource Limits** — bounded queue, concurrency, metadata
- **Event/Audit Integration** — emits events, audits security-sensitive operations

**Security guarantees:**
- No arbitrary command execution
- No shell/script execution
- No authorization bypass
- No secret logging
- Fail-closed on authorization failure

### Step 05 — Operation Queue & Execution Lifecycle (`operation_queue.h/.c`)
Persistent operation queue managing lifecycle from submission to completion:
- **Lifecycle States** — CREATED → QUEUED → WAITING → DISPATCHING → RUNNING → SUCCEEDED/FAILED/CANCELLED/TIMEOUT/EXPIRED
- **Priority Scheduling** — LOW, NORMAL, HIGH, CRITICAL with configurable policy
- **Fairness** — same-priority entries dispatched in FIFO order
- **Enqueue** — validates fields, generates unique IDs, per-component and per-requester resource limits
- **Dequeue** — respects concurrency limit, priority ordering, precondition and authorization rechecks at dispatch time
- **Complete/Fail** — terminal state transitions with result code, error detail, completion timestamp
- **Cancellation** — safe for queued entries, rejects cancellation of running/terminal operations
- **Timeout** — queue timeout and execution timeout with automatic state transition
- **Expiration** — automatic cleanup of completed entries after retention period
- **Retry** — configurable max retries with exhaustion detection
- **Conflict Detection** — detects conflicting operations on same target (e.g., START vs STOP)
- **Conflict Modes** — REJECT (enqueue fails), WAIT (queue delayed), ALLOW (proceed anyway)
- **Idempotency** — duplicate request_id detection for idempotent operations
- **Event/Audit Integration** — emits events, integrates with audit service
- **Cleanup** — cleanup completed/expired entries, cleanup all

**Security guarantees:**
- Authorization recheck at dequeue time
- Precondition recheck (target alive, capability available) at dequeue time
- Fail-closed on missing registry or authorization service
- No secret logging
- Bounded resource usage

## Tests

| Module | Tests |
|--------|-------|
| Control Room | 89/89 |
| Component Registry | 89/89 |
| Command Router | 70/70 |
| Operation Queue | 80/80 |
| **Total** | **328/328** |

## Architecture Notes

- Cross-section dependencies use `void *` pointers (not typed) to avoid header conflicts
- `events.h` cannot be included in Section 04 headers (conflicts with `03_SECURITY/authorization.h`)
- `-I03_SECURITY` is added per-file in Makefile rules, not in global CFLAGS
- Command Router prefix: `ozayn_router_`
- Operation Queue prefix: `ozayn_oq_`
