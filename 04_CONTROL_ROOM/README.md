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

### Step 06 — Operation History & Execution Records (`operation_history.h/.c`)
Persistent, immutable historical records of completed operations, separate from the live queue:
- **Execution Records** — immutable records of completed operations with full context
- **Terminal States** — SUCCEEDED, FAILED, CANCELLED, TIMEOUT, REJECTED, EXPIRED, UNAVAILABLE, UNSUPPORTED
- **Execution Attempts** — multiple attempts per operation (for retries), each independently tracked
- **Timing** — created, queued, started, completed timestamps with duration calculation
- **Structured Results** — result categories (SUCCESS, TARGET_UNAVAILABLE, AUTHORIZATION_FAILED, etc.)
- **Failure Information** — failure categories (COMPONENT_DOWN, AUTH_DENIED, TIMEOUT_EXCEEDED, etc.)
- **History Storage** — static in-memory array with bounded capacity
- **Retention** — configurable max records, max age, security record preservation
- **Query API** — filter by target, capability, action, state, result, requester, time range
- **Pagination** — bounded query results with limit/offset
- **Deterministic Sorting** — consistent ordering for reproducible queries
- **Correlation** — operation_id, request_id, attempt_id, record_id for full traceability
- **Immutability** — finalized records cannot be modified
- **Event Integration** — emits history events (CREATED, ATTEMPT_STARTED/COMPLETED/FAILED, RECORD_FINALIZED, RECORD_EXPIRED)
- **Audit Integration** — records audit events for history operations
- **Security Audit Separation** — operational history is distinct from security audit records

**Security guarantees:**
- No secret storage (passwords, keys, tokens, credentials)
- Authorization via Section 03 (not bypassed)
- Fail-closed on storage failure
- Bounded resource usage
- Deterministic retention (oldest expired first)

### Step 07 — Diagnostics & Health Assessment (`diagnostics.h/.c`)
Diagnostic request management, health assessments, and findings tracking:
- **Diagnostic Requests** — 11-state lifecycle (CREATED → VALIDATING → RESOLVING → CHECKING → AUTHORIZING → EXECUTING → COLLECTING → ASSESSING → RECORDING → COMPLETED/FAILED/CANCELLED/TIMEOUT)
- **Diagnostic Categories** — 10 categories (CONNECTIVITY, LIFECYCLE, CAPABILITY, DEPENDENCY, RESOURCE, SECURITY_INTEGRITY, PERFORMANCE, INTEGRATION, CONFIGURATION, STATE)
- **Health Assessments** — per-component health state (HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN, UNAVAILABLE) with change detection
- **Findings** — diagnostic findings with severity, status tracking (OPEN → RESOLVED/ACKNOWLEDGED/INFORMATIONAL), evidence references
- **Results** — diagnostic results with finding references, error details, health state per result
- **Authorization** — integrates with Section 03 authorization for diagnostic operations
- **Target Resolution** — resolves targets via Component Registry
- **Dependency Handling** — tracks diagnostic dependencies between requests
- **Concurrency Limits** — configurable max concurrent diagnostics
- **Timeout** — configurable per-request timeout
- **Query/Filter** — get by ID, count, filter by component/finding/result
- **Statistics** — request counts, success/failure/cancel/timeout, health changes, active diagnostics
- **Cleanup** — cleanup results, findings, all, with configurable retention
- **Event Integration** — emits diagnostic events (REQUESTED, VALIDATING, EXECUTING, SUCCEEDED, FAILED, TIMEOUT, HEALTH_CHANGED, FINDING_OPENED, FINDING_RESOLVED)
- **Audit Integration** — audit events for diagnostic operations
- **Name Helpers** — string conversion for all enums

**Security guarantees:**
- No secret logging (context and metadata scrubbed)
- Authorization via Section 03 (not bypassed)
- Fail-closed on missing dependency services
- No unbounded resource growth
- Health assessments are immutable after creation

### Step 08 — Safety, Preconditions & Policy Enforcement (`safety.h/.c`)
Structured precondition evaluation, policy decisions, and safety checks before operation dispatch:
- **Preconditions** — 12 categories (TARGET_STATE, TARGET_AVAILABILITY, TARGET_HEALTH, CAPABILITY, DEPENDENCY, AUTHORIZATION, SESSION, RESOURCE, CONFIGURATION, SECURITY, CONFLICT, LIFECYCLE)
- **Precondition Results** — SATISFIED, FAILED, UNKNOWN, UNAVAILABLE, NOT_APPLICABLE
- **Safety Levels** — SAFE, RESTRICTED, SENSITIVE, CRITICAL
- **Policies** — structured operation policies with safety requirements, conflict rules, dependencies, resource requirements, timeout/retry limits
- **Policy Decisions** — ALLOW, DENY, DEFER, UNAVAILABLE with decision records
- **Conflict Detection** — policy-based conflict rules per target/action
- **Authorization Integration** — real `ozayn_authz_authorize()` integration via Section 03
- **Safety Recheck** — re-evaluates conditions before dispatch (TOCTOU protection)
- **Decision Lifetime** — TTL-based expiry with validity checks
- **Default Deny** — operations without matching policy are denied
- **Fail Closed** — missing authorization service = deny
- **Statistics** — evaluations, allowed/denied/deferred, precondition pass/fail, conflicts, rechecks
- **Cleanup** — cleanup expired decisions, cleanup all
- **Event Integration** — emits safety events (PRECOND_EVALUATED/FAILED, POLICY_EVALUATED/ALLOWED/DENIED, SAFETY_CHECK_STARTED/FAILED/PASSED, CONFLICT_DETECTED)
- **Audit Integration** — audit events for safety decisions
- **Validation** — precondition, policy, decision validation
- **Name Helpers** — string conversion for all enums

**Security guarantees:**
- Fail closed when safety decisions cannot be established
- Default deny unless explicitly allowed
- No authorization bypass
- No safety bypass
- No arbitrary command/script execution
- No unbounded dependency traversal
- No unbounded retries
- No secret logging
- No unsafe fallback

### Step 09 — Resource & Capacity Management (`resource.h/.c`)
Resource tracking, capacity pools, reservation lifecycle, and allocation decisions:
- **Resources** — 23 resource types (CPU, MEMORY, GPU, DISK, NETWORK, CAMERA, MICROPHONE, DISPLAY, AUDIO, USB, BLUETOOTH, SENSOR, STORAGE, INPUT_DEVICE, OUTPUT_DEVICE, PROCESSOR, THREAD, CACHE, BANDWIDTH, CONCURRENT_SESSION, RESERVATION_SLOT, PERMISSION_SLOT, EVENT_SLOT)
- **Resource Pools** — capacity allocation, available tracking, overflow protection
- **Reservations** — PENDING → CONFIRMED → ACTIVE → COMPLETED/FAILED/CANCELLED/EXPIRED lifecycle
- **Allocation Decisions** — REQUESTED → CHECKING → APPROVED/DENIED/FAILED/EXPIRED
- **Reservation Lifetime** — TTL-based expiry with automatic cleanup
- **Cleanup** — cleanup expired reservations, cleanup all
- **Statistics** — resources, reservations, allocations, capacity utilization
- **Name Helpers** — string conversion for all enums

### Step 10 — Device & I/O Management (`device_io.h/.c`)
Device discovery, lifecycle, reservation, and capability management:
- **Devices** — 13 device types (CAMERA, MICROPHONE, SPEAKER, HEADSET, KEYBOARD, MOUSE, TOUCHSCREEN, DISPLAY, PRINTER, SCANNER, GAMEPAD, WEBCAM, OTHER)
- **Device States** — DISCOVERED → IDENTIFIED → AVAILABLE → RESERVED → IN_USE → BUSY → ERROR → DISABLED → OFFLINE → RECONNECTING → DISCONNECTED → REMOVED → UNKNOWN
- **Capabilities** — 11 capability types (CAPTURE, STREAM, INPUT, OUTPUT, CONTROL, MONITOR, CONFIGURE, READ, WRITE, EXECUTE, TRANSFER)
- **Reservations** — PENDING → CONFIRMED → ACTIVE → EXPIRED/CANCELLED/RELEASED/FAILED/CONFLICT
- **Exclusive/Shared** — access modes with concurrent user tracking
- **Provider Discovery** — callback-based device discovery from providers
- **Disconnect/Reconnect** — device lifecycle management
- **Statistics** — devices, reservations, capabilities, access patterns

### Step 11 — Device Access Sessions & I/O Ownership (`device_session.h/.c`)
Device access sessions with strict state machine, reservation binding, and privacy controls:
- **Access Modes** — OBSERVE, INPUT, OUTPUT, CONTROL, STREAM
- **Session States** — 13-state lifecycle (REQUESTED → AUTHORIZING → AUTHORIZED → RESERVED → OPENING → ACTIVE ↔ IDLE → CLOSING → CLOSED | EXPIRED | CANCELLED | FAILED | REVOKED)
- **State Machine** — `_valid_transitions[][]` matrix for strict transition validation
- **Reservation Binding** — sessions require reservation_id for RESERVE transition
- **Security Binding** — sessions track security_session_ref, operation_id, required_permission
- **Heartbeat** — activity tracking for ACTIVE and IDLE sessions
- **Expiration** — TTL-based session expiry, checked at authorization time
- **Revocation** — admin revocation with reason tracking
- **Cleanup** — cleanup expired sessions, cleanup idle sessions, cleanup all
- **Events** — ring buffer of session events with sequence numbers
- **Privacy** — camera/mic sessions cannot auto-activate; no secrets in sessions or events
- **Statistics** — created, authorized, opened, expired, revoked, cancelled, heartbeats, state transitions, validation failures
- **Name Helpers** — string conversion for all enums

## Tests

| Module | Tests |
|--------|-------|
| Control Room | 89/89 |
| Component Registry | 89/89 |
| Command Router | 70/70 |
| Operation Queue | 80/80 |
| Operation History | 85/85 |
| Diagnostics | 68/68 |
| Safety & Policy | 80/80 |
| Resource & Capacity | 102/102 |
| Device & I/O | 89/89 |
| Device Sessions | 66/66 |
| **Total** | **818/818** |

## Architecture Notes

- Cross-section dependencies use `void *` pointers (not typed) to avoid header conflicts
- `events.h` cannot be included in Section 04 headers (conflicts with `03_SECURITY/authorization.h`)
- `-I03_SECURITY` is added per-file in Makefile rules, not in global CFLAGS
- Command Router prefix: `ozayn_router_`
- Operation Queue prefix: `ozayn_oq_`
- Operation History prefix: `ozayn_oh_`
- Diagnostics prefix: `ozayn_dha_`
- Safety prefix: `ozayn_spe_`
- Resource prefix: `ozayn_rcm_`
- Device & I/O prefix: `ozayn_dio_`
- Device Sessions prefix: `ozayn_das_`
