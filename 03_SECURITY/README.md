# Section 03 — Secure Data Layer

## Purpose

The Secure Data Layer is OZAYN's foundational internal subsystem for protecting sensitive persistent data. It establishes the controlled boundary between OZAYN's application/runtime components and data that requires protection.

```text
DATA
  ↓
SECURITY LAYER
  ↓
PROTECTION
  ↓
SECURE STORAGE
  ↓
CONTROLLED ACCESS
```

## Why the Security Layer Exists

OZAYN handles sensitive data categories including user preferences, identity information, authentication credentials, conversation history, AI memory, documents, system configuration, security events, and ARWE information. This data must be protected through a dedicated security architecture rather than being managed ad-hoc by individual components.

The Secure Data Layer provides:

- **Centralized protection** — All sensitive data flows through defined security boundaries
- **Separation of concerns** — Each security responsibility has a dedicated subsystem
- **Consistent cross-platform behavior** — Security mechanisms work identically on Linux, Windows, and macOS
- **Auditability** — Security-sensitive operations are observable through controlled audit events
- **Defense in depth** — Multiple layers of protection rather than a single point of failure

## Data Classification

The Secure Data Layer will protect the following categories of data:

| Category | Sensitivity | Description |
|----------|-------------|-------------|
| User Preferences | Medium | UI settings, workflow preferences, display configuration |
| Identity Information | High | User identity records, device identity, identity state |
| Authentication Information | Critical | Credentials, tokens, biometric references, auth state |
| Conversation History | High | AI conversation records, interaction logs |
| AI Memory | High | Learned context, user patterns, semantic associations |
| Documents | Medium-High | User documents, generated content, research data |
| System Configuration | Medium | Runtime configuration, feature flags, system state |
| Security Events | High | Audit logs, security incidents, access records |
| ARWE Information | High | ARWE integration data, cross-project references |

## Architecture

```text
03_SECURITY/
│
├── vault/           Secure storage subsystem
├── identity/        Identity and authentication subsystem
├── keys/            Cryptographic key management
├── sessions/        Session security subsystem
├── permissions/     Authorization subsystem
├── audit/           Security event and audit subsystem
└── backup/          Secure backup and recovery subsystem
```

## Directory Responsibilities

### vault/

Responsible for the secure storage subsystem.

Future responsibilities:
- Encrypted data storage at rest
- Secure data access with authorization checks
- Data lifecycle management (creation, access, rotation, deletion)
- Protection against unauthorized data extraction
- Secure data serialization and deserialization

### identity/

Responsible for the identity subsystem.

Future responsibilities:
- User identity creation and management
- Identity verification mechanisms
- Identity state tracking (verified, unverified, suspended)
- Device identity for multi-device scenarios
- Authentication identity records

### keys/

Responsible for cryptographic key management.

Future responsibilities:
- Key generation and lifecycle management
- Secure key storage (never in plaintext)
- Key rotation policies
- Key access control
- Key protection mechanisms

**CRITICAL:** This directory must never contain real cryptographic secrets. Keys are managed at runtime only. The repository must never expose private keys, secret tokens, or production credentials.

### sessions/

Responsible for session security.

Future responsibilities:
- Session creation with secure tokens
- Session validation and integrity checks
- Session expiration and renewal
- Session termination and cleanup
- Session security state tracking

### permissions/

Responsible for the authorization subsystem.

Future responsibilities:
- Permission definitions and policies
- Resource-level authorization
- Role-based access control
- Security boundary enforcement
- Access decision logging

### audit/

Responsible for security event logging and audit.

Future responsibilities:
- Security event recording
- Authentication event logging
- Authorization event logging
- Data-access event tracking
- Configuration change auditing
- Security failure reporting

### backup/

Responsible for secure backup and recovery.

Future responsibilities:
- Encrypted backup creation
- Backup integrity verification
- Secure recovery procedures
- Backup lifecycle management
- Backup access control

## Authentication vs. Authorization

Understanding the distinction is fundamental to the security architecture:

**Authentication** answers: *"Who are you?"*
- Verifies identity
- Proves the user is who they claim to be
- Managed by the `identity/` subsystem
- Examples: password verification, biometric check, token validation

**Authorization** answers: *"What are you allowed to do?"*
- Controls access to resources
- Enforces permission policies
- Managed by the `permissions/` subsystem
- Examples: role checks, resource access control, permission grants

Both are required for secure operation. Authentication without authorization allows verified users to access anything. Authorization without authentication allows unrestricted access. The Secure Data Layer implements both.

## Public Repository Security

This is a public-facing repository. The following must NEVER be exposed:

- Private encryption keys
- Secret tokens
- Passwords or password hashes
- API credentials
- Authentication secrets
- Biometric templates
- Session secrets
- Recovery secrets
- Production certificates
- Real personal information

**Rules:**
- Do not commit `.env` files containing secrets
- Do not hardcode secrets into source files
- Use clearly non-secret placeholders for configuration templates
- Treat all security-related code as potentially sensitive
- Review all changes for accidental secret exposure before committing

## Integration with OZAYN Core

The Secure Data Layer will eventually integrate with OZAYN through defined interfaces:

```text
OZAYN CORE
    │
    ▼
SECURE DATA LAYER API
    │
    ├── vault/storage.c
    ├── identity/auth.c
    ├── keys/manager.c
    ├── sessions/manager.c
    ├── permissions/policy.c
    ├── audit/logger.c
    └── backup/manager.c
    │
    ▼
Operating System Security APIs
```

Other OZAYN components will interact with protected data through the Security Layer API rather than directly manipulating sensitive storage. This ensures consistent security enforcement across all data access paths.

## Security Dashboard (Future GUI)

The Secure Data Layer will eventually provide safe status information to an OZAYN security dashboard:

```text
SECURITY
────────────────────────

Identity: Verified
Vault: Protected
Session: Active
Security: Normal
```

This dashboard will display only non-sensitive status information. It will never expose:
- Encryption keys
- Authentication credentials
- Internal security state
- Cryptographic material

## Implementation Status

| Step | Subsystem | Status |
|------|-----------|--------|
| 01 | Security Layer Foundation | COMPLETE |
| 02 | Data Classification & Storage Boundary | COMPLETE |
| 03 | Secure Data Object & Validation Contract | COMPLETE |
| 04 | Storage Abstraction & Provider Contract | COMPLETE |
| 05 | Local Persistent Storage Provider | COMPLETE |
| 06 | Encryption Architecture & Protection Boundary | COMPLETE |
| 07 | Production Encryption Implementation | COMPLETE |
| 08 | Key Management Foundation | COMPLETE |
| 09 | Secure Key Storage & Platform Key Store | COMPLETE |
| 10 | Key Lifecycle & Rotation | COMPLETE |
| 11 | Secure Vault Implementation | COMPLETE |
| 12 | Identity Foundation & Identity Data Boundary | COMPLETE |
| 13 | Authentication Architecture & Credential Boundary | COMPLETE |
| 14 | Password Authentication & Credential Protection | COMPLETE |
| 15 | Authentication Attempt Control & Brute-Force Protection | COMPLETE |
| 16 | Secure Session Management Foundation | COMPLETE |
| 17 | Authorization & Access-Control Foundation | COMPLETE |
| 18 | Role-Based Access Control (RBAC) Foundation | COMPLETE |
| 19 | Permission Management & Policy Enforcement | COMPLETE |
| 20 | Multi-Factor Authentication Foundation & Enforcement | COMPLETE |
| 21 | Security Audit & Security Event Logging Foundation | COMPLETE |
| 23 | Secure Backup & Recovery Foundation | COMPLETE |
| 24 | Secure Deletion & Data Destruction Foundation | COMPLETE |
| 25 | Security Recovery, Incident Response & Compromise Handling Foundation | COMPLETE |
| 26 | Security Policy & Configuration Hardening Foundation | COMPLETE |
| 27 | Security Health Monitoring & Security Self-Assessment Foundation | COMPLETE |
| 28 | Security Diagnostics & Self-Diagnostics Foundation | COMPLETE |
| 29 | Security Alerting & Security Notification Foundation | COMPLETE |
| 30 | Security Notification Routing & Delivery Foundation | COMPLETE |
| 31 | Security Event Correlation & Threat Detection Foundation | COMPLETE |
| 32 | Security Threat Intelligence & Evidence Analysis Foundation | COMPLETE |
| 35 | (future) | PENDING |

## Deferred Functionality

The following functionality is intentionally NOT implemented in Step 01 and will be built in later steps:

- Encryption engine
- Key-management engine
- Biometric authentication
- Session engine
- Permission engine
- Audit engine
- Security dashboard
- Secure data serialization
- Cross-platform security API

## Security Health Monitoring (Step 27)

The Security Health Monitoring system provides deterministic internal evaluation of OZAYN's security infrastructure:

```text
SECURITY COMPONENTS
        ↓
HEALTH CHECK PROVIDERS
        ↓
SECURITY HEALTH SERVICE
        ↓
HEALTH AGGREGATION
        ↓
SECURITY HEALTH SNAPSHOT
        ↓
SAFE OPERATION DECISION
        ↓
AUDIT / INCIDENT RESPONSE
```

**Health States:** HEALTHY, DEGRADED, WARNING, CRITICAL, UNAVAILABLE, UNKNOWN, LOCKDOWN

**Monitored Components (23):**
- Security Configuration, Security Policy, Identity, Authentication
- Attempt Control, MFA, Session, Authorization, RBAC, Permissions
- Secure Data, Storage, Protection, Key Management, Key Storage
- Key Lifecycle, Secure Vault, Audit, Audit Integrity, Backup
- Recovery, Secure Deletion, Incident Response

**Key Properties:**
- Fail-closed: UNKNOWN never silently becomes HEALTHY
- Dependency-aware: failures propagate through the security stack
- Freshness semantics: stale health results are not trusted
- No secrets in health data; metadata only
- No health-based authorization bypass
- Operation safety check for security-sensitive operations

## Security Diagnostics & Self-Diagnostics (Step 28)

The Security Diagnostics system provides structured diagnostic evaluation explaining WHY security components are healthy or unhealthy, with actionable recommendations:

```text
DIAGNOSTIC CHECKS (23 built-in)
        ↓
PROVIDER EXTENSION POINT
        ↓
DEPENDENCY GRAPH + CYCLE DETECTION
        ↓
RESULTS (ring buffer, 256 max)
        ↓
SUMMARY + RECOMMENDATIONS
        ↓
SAFE SUMMARY (no secrets, no auth grants)
```

**Diagnostic Checks (23):** Configuration, Policy, Identity, Authentication, Attempt Control, MFA, Session, Authorization, RBAC, Permission, Secure Data, Storage, Protection, Key Management, Key Storage, Key Lifecycle, Vault, Audit, Audit Integrity, Backup, Recovery, Deletion, Incident Response

**16 Check Categories:** Configuration, Policy, Availability, Dependency, Integrity, Storage, Key, Protection, Authentication, Authorization, Audit, Backup, Recovery, Deletion, Incident Response, Resource

**16 Recommendation Codes:** Reload Configuration, Check Security Policy, Check Platform Key Store, Verify Storage, Rotate Compromised Key, Run Backup Validation, Review Security Incident, Check Identity Service, Reauthenticate, Check Audit Integrity, Check Deletion Policy, Verify Protection, Check Key Lifecycle, Check Session Policy, Check Vault Dependencies

**Key Properties:**
- `ozayn_sdiag_` prefix (avoids collision with existing `ozayn_sd_` secure data types)
- Results are metadata only — no secrets, no plaintext, no auth grants
- Cycle detection prevents infinite recursion in dependency graphs
- Mode/cost control: READ_ONLY=LOW only, STANDARD=LOW+MEDIUM, DEEP=all
- Freshness tracking: stale results flagged, not trusted
- Provider extension: custom diagnostic providers can be registered
- Fail-closed: unavailable components produce UNAVAILABLE state, not PASS

## Security Alerting (Step 29)

```text
SECURITY EVENTS
        ↓
ALERT CREATION (type, severity, priority, source)
        ↓
DEDUP + RATE LIMITING
        ↓
ALERT STATE MACHINE
        ↓
ESCALATION + NOTIFICATION
        ↓
HEALTH / DIAGNOSTIC / INCIDENT INTEGRATION
        ↓
CLEANUP + AUDIT
```

**33 Alert Types:** Configuration, Policy, Auth Failure/Attack/Rate Limit, MFA Failure/Attack, Session Anomaly/Compromise, AuthZ Denial, Privilege Escalation, Role/Permission Tampering, Key Availability/Compromise/Storage, Vault Failure/Integrity, Data Integrity, Audit Failure/Integrity, Backup Failure/Integrity, Restore Failure, Deletion Failure, Incident, Health Degraded/Critical, Diagnostic Fail, Component Unavailable, Lockdown, Resource Exhaustion

**Alert State Machine:** DETECTED → CREATED → ACTIVE → ACKNOWLEDGED → RESOLVING → RESOLVED (+ SUPPRESSED, EXPIRED, FAILED, CANCELLED)

**5 Severity Levels:** INFO, NOTICE, WARNING, HIGH, CRITICAL

**5 Priority Levels:** LOW, NORMAL, HIGH, URGENT, IMMEDIATE

**7 Notification Channels:** LOCAL, DESKTOP, EMAIL, SMS, PUSH, CONTROL_ROOM, EXTERNAL

**Key Properties:**
- `ozayn_salert_` prefix (avoids collision with existing naming conventions)
- Ring buffer allocation (512 max alerts, 64 max notify queue)
- Alert deduplication with configurable window and auto-suppress
- Rate limiting per type with sliding window
- Notification provider vtable abstraction (extensible)
- Retry with configurable max retries before FAILED state
- Threshold tracking per type with configurable windows
- Lifecycle operations: acknowledge, resolve, suppress, cancel
- Escalation: increases severity/priority up to max levels
- Health/Diagnostic/Incident integration (respects service availability)
- Cleanup: expired and resolved alerts cleaned automatically
- Safe content: title/body generation excludes secrets
- Audit events for all alert state changes

## Security Notification Routing & Delivery (Step 30)

```text
SECURITY CONDITION
        ↓
SECURITY ALERT (Step 29)
        ↓
ALERT POLICY
        ↓
NOTIFICATION ROUTING
        ↓
NOTIFICATION POLICY
        ↓
CHANNEL SELECTION
        ↓
DELIVERY QUEUE
        ↓
NOTIFICATION PROVIDER
        ↓
DELIVERY RESULT
        ↓
SECURITY AUDIT
```

**Notification States:** CREATED → ROUTING → QUEUED → DELIVERING → DELIVERED (+ DELIVERY_FAILED → RETRY_SCHEDULED → QUEUED, EXHAUSTED, EXPIRED, CANCELLED)

**Destination States:** UNINITIALIZED → AVAILABLE → DISABLED/UNAVAILABLE/SUSPENDED/REVOKED (REVOKED is terminal)

**Delivery Results:** SUCCESS, TEMPORARY_FAILURE, PERMANENT_FAILURE, UNAVAILABLE, REJECTED, TIMEOUT, EXPIRED, CANCELLED

**Security Classifications:** PUBLIC, INTERNAL, SENSITIVE, HIGHLY_SENSITIVE — controls which channels may receive content

**Retry Policy:** Exponential backoff with jitter, bounded retry count, bounded delay, expiration limits

**Key Properties:**
- `ozayn_snotify_` prefix (avoids collision with `ozayn_salert_` from Step 29)
- Deterministic routing via policy-controlled rules (severity/priority/type filtering)
- Default-safe: no route = controlled failure, never invent destination
- External channels disabled by default (EMAIL, SMS, PUSH, EXTERNAL)
- HIGHLY_SENSITIVE classification blocks all channels except LOCAL
- Provider vtable abstraction with timeout support
- Notification deduplication: same alert re-evaluation creates no duplicate
- Suppressed alerts produce no new notifications
- Escalation creates new notification only when severity actually changes
- Audit events for all notification lifecycle transitions
- Credential boundary: providers never receive secrets

## Security Event Correlation & Threat Detection (Step 31)

```text
RAW SECURITY EVENTS (audit, health, diag, incident, alerting)
        ↓
NORMALIZATION (37 event categories)
        ↓
PATTERN EVALUATION (5 types: single, threshold, sequence, correlated, state-transition)
        ↓
CORRELATION ENGINE (ring buffer, window-based, identity/session/resource binding)
        ↓
THREAT FINDING (deduplication, state machine, severity, confidence)
        ↓
INCIDENT RESPONSE INTEGRATION (Step 25)
        ↓
SECURITY ALERTING INTEGRATION (Step 29)
        ↓
AUDIT EVENT LOGGING
        ↓
RESOURCE SAFETY (bounded ring buffers, expiration, cleanup)
```

**37 Normalized Event Categories:** AUTH_SUCCESS/FAILURE/RATE_LIMIT/BLOCKED, MFA_SUCCESS/FAILURE/BLOCKED, SESSION_CREATED/VALIDATED/FAILED/TERMINATED, AUTHZ_ALLOWED/DENIED, PERM_DENIED/MATCHED, ROLE_CREATED/REVOKED/ASSIGNED/ASSIGN_REVOKED, KEY_CREATED/REVOKED/UNAVAILABLE, VAULT_ACCESS/FAILURE/INTEGRITY, AUDIT_FAILURE/INTEGRITY, CONFIG_CHANGED/REJECTED, INTEGRITY_FAILURE, HEALTH_DEGRADED/CRITICAL, COMPONENT_UNAVAILABLE, BACKUP_FAILURE, DELETION_FAILURE, INCIDENT_DETECTED, VIOLATION_DETECTED

**5 Pattern Types:** SINGLE (one event matches), THRESHOLD (N events in window), SEQUENCE (ordered events in window), CORRELATED_SEQ (multi-source sequence), STATE_TRANSITION (component state change)

**7 Correlation States:** NEW → ACTIVE → MATCHED → SUSPICIOUS → CONFIRMED (+ EXPIRED, DISMISSED)

**7 Finding States:** DETECTED → INVESTIGATING → CONFIRMED_THREAT (+ FALSE_POSITIVE, EXPIRED, INCIDENT_CREATED, ALERT_CREATED)

**5 Confidence Levels:** LOW, MEDIUM, HIGH, VERY_HIGH

**Key Properties:**
- `ozayn_sdet_` prefix (avoids collision with existing `ozayn_sd_` secure data types)
- Deterministic detection (no AI/ML) — patterns are rule-based
- Ring buffer allocation (512 events, 128 correlations, 256 findings, 64 patterns)
- Finding deduplication with configurable window
- Audit normalization from all security subsystems
- State machine with guarded transitions
- Incident integration via `ozayn_ir_report` (Step 25)
- Alert integration via `ozayn_salert_create` (Step 29)
- Audit events for all detections
- Resource exhaustion protection (bounded buffers, max limits)
- No secrets in normalized events — metadata only
- Detection informs enforcement but does NOT replace enforcement

## Security Threat Intelligence & Evidence Analysis (Step 32)

```text
RAW SECURITY EVIDENCE (audit, health, diag, detect, incident, alert)
        ↓
EVIDENCE COLLECTION (18 types, dedup, ring buffer)
        ↓
EVIDENCE VALIDATION (integrity, reliability, relevance assessment)
        ↓
EVIDENCE SETS (grouping, role assignment: primary/supporting/conflicting/contextual)
        ↓
THREAT ASSESSMENT (state machine, confidence calculation, explanation codes)
        ↓
INCIDENT INTEGRATION (Step 25)
        ↓
ALERT INTEGRATION (Step 29)
        ↓
AUDIT EVENT LOGGING
        ↓
RESOURCE SAFETY (bounded ring buffers, expiration, cleanup)
```

**18 Evidence Types:** AUDIT_EVENT, AUDIT_INTEGRITY, HEALTH_RESULT, DIAGNOSTIC_RESULT, CORRELATION_RESULT, THREAT_FINDING, AUTH_RESULT, MFA_RESULT, SESSION_RESULT, AUTHZ_RESULT, RBAC_RESULT, PERMISSION_RESULT, KEY_SECURITY, VAULT_SECURITY, BACKUP_SECURITY, DELETION_SECURITY, CONFIG_SECURITY, INCIDENT_RESULT

**5 Reliability Levels:** UNKNOWN, LOW, MEDIUM, HIGH, VERIFIED

**5 Relevance Levels:** IRRELEVANT, LOW, MEDIUM, HIGH, CRITICAL

**4 Evidence Roles:** PRIMARY, SUPPORTING, CONFLICTING, CONTEXTUAL

**4 Confidence Levels:** LOW, MEDIUM, HIGH, VERY_HIGH

**Key Properties:**
- `ozayn_sintel_` prefix
- Evidence-based intelligence (not AI/ML) — deterministic confidence calculation
- Ring buffer allocation (512 evidence, 128 evidence sets, 256 assessments)
- Evidence deduplication with configurable window
- Reliability assessment based on integrity state and evidence type
- Relevance assessment based on severity
- Deterministic confidence calculation from evidence composition
- 16 explanation codes for assessment reasoning
- Incident integration via `ozayn_ir_report` (Step 25)
- Alert integration via `ozayn_salert_create` (Step 29)
- Audit events for all intelligence operations
- Resource exhaustion protection (bounded buffers, max limits)
- No secrets in evidence — metadata only
- Intelligence informs response but does NOT replace enforcement

## Security Risk Scoring & Decision Support (Step 33)

Converts threat findings and evidence assessments into a deterministic, explainable security-risk score and recommends prioritized response actions.

### Files

| File | Purpose |
|------|---------|
| `sec_risk.h` | API, types, enums, service state |
| `sec_risk.c` | Risk calculation, aggregation, dedup, temporal, decisions, integrations |
| `tests/test_sec_risk.c` | 89 unit tests |

### API Prefix

- `ozayn_sr_` prefix

### Key Concepts

- **Deterministic scoring** — Same inputs always produce the same risk score and level
- **Factor-based** — 12 risk factors (threat severity, impact, reliability, confidence, classification, sensitivity, scope, assurance, integrity, persistence, incident state, health)
- **Score→Level mapping** — Score (0-100) maps to UNKNOWN/LOW/MODERATE/HIGH/CRITICAL via policy thresholds
- **Risk aggregation** — Groups related assessments by identity, resource, or incident
- **Deduplication** — Time-windowed dedup prevents duplicate risk assessments
- **Temporal risk** — Evaluates assessment age (CURRENT/AGING/EXPIRED)
- **Decision support** — Recommends actions (MONITOR, INVESTIGATE, ESCALATE_INCIDENT, REQUIRE_MFA, etc.)
- **Safety caps** — UNKNOWN reliability caps at MODERATE; integrity failure caps at MODERATE

### Integration Points

- Intelligence via `ozayn_sintel_*` (Step 32) — threat assessments, evidence
- Detection via `ozayn_sdet_*` (Step 31) — correlated events
- Incident integration via `ozayn_ir_report` (Step 25)
- Alert integration via `ozayn_salert_create` (Step 29)
- Health integration via `ozayn_sh_*` (Step 27) — health impact assessment
- Audit events for all risk operations

## Security Orchestration & Controlled Response (Step 34)

Translates risk decisions into auditable, policy-validated, human-approved response plans that are executed through existing security services.

### Core Principle

**A recommendation is not an authorization.** Every response must pass through:

```text
RECOMMENDATION
    ↓
RESPONSE PLAN (plan creation + action composition)
    ↓
POLICY VALIDATION (config_service + action-level checks)
    ↓
AUTHORIZATION CHECK (authz framework)
    ↓
ASSURANCE CHECK (MFA / re-auth)
    ↓
APPROVAL (auto or explicit human approval)
    ↓
CONTROLLED EXECUTION (per-action dispatch to existing services)
    ↓
VERIFICATION
    ↓
AUDIT TRAIL
```

### Files

| File | Purpose |
|------|---------|
| `sec_response.h` | API, types, enums, service state, policy, config |
| `sec_response.c` | Orchestration lifecycle, plan/action CRUD, validation, authorization, execution, verification, audit |
| `tests/test_sec_response.c` | 77 unit tests |

### API Prefix

- `ozayn_sresp_` prefix

### Key Concepts

- **Plan lifecycle** — CREATED → VALIDATING → VALIDATED → APPROVED → EXECUTING → COMPLETED/PARTIAL/FAILED
- **14 action types** — MONITOR, INVESTIGATE, REQUIRE_REAUTH, REQUIRE_MFA, REVOKE_SESSION, SUSPEND_IDENTITY, REVIEW_*, RESTRICT_RESOURCE, SECURITY_LOCKDOWN
- **3 execution modes** — VALIDATE_ONLY, DRY_RUN, APPROVED_EXECUTION
- **4 assurance levels** — NONE, SINGLE, MULTI, HIGH
- **Policy validation** — Actions checked against configurable policy (approval requirements, assurance, rollback capability)
- **Authorization integration** — Plans checked against `ozayn_authz_*` (Step 15)
- **Precondition checks** — 15 precondition categories before execution
- **Conflict detection** — Identifies conflicting actions across active plans
- **Idempotent execution** — Duplicate action execution detected and skipped
- **Rollback support** — 4 rollback types (FULL, PARTIAL, COMPENSATING, NONE)
- **Audit trail** — Complete execution history with timestamps
- **No autonomous execution** — Every action requires policy + authorization + approval
- **No AI/ML** — All orchestration is deterministic rule-based logic

### Execution Modes

| Mode | Behavior |
|------|----------|
| VALIDATE_ONLY | Validates plan structure and policy; no execution |
| DRY_RUN | Validates and simulates execution; no side effects |
| APPROVED_EXECUTION | Full execution through existing services |

### Integration Points

- Authorization via `ozayn_authz_*` (Step 15)
- Session management via `ozayn_sess_*` (Step 12)
- Identity via `ozayn_id_*` (Step 11)
- MFA via `ozayn_mfa_*` (Step 13)
- Incident response via `ozayn_ir_*` (Step 25)
- Risk scoring via `ozayn_sr_*` (Step 33)
- Threat intelligence via `ozayn_sintel_*` (Step 32)
- Security config via `ozayn_sc_*` (Step 26)
- Security alerts via `ozayn_salert_*` (Step 29)
- Audit events for all orchestration operations

## Design Principles

1. **Least Privilege** — Components receive only the access they require
2. **Separation of Responsibilities** — Storage, identity, keys, sessions, permissions, audit, and backup remain logically separated
3. **No Secret Exposure** — Secrets are never treated as normal application data
4. **Secure by Default** — Security functionality defaults to the safest reasonable state
5. **Explicit Access** — Sensitive data access requires an explicit authorized operation
6. **Auditability** — Security-sensitive operations are observable through controlled audit events
7. **Failure Safety** — Security failures fail safely rather than silently bypassing protection
8. **Cross-Platform Consistency** — Security architecture behaves consistently across all target platforms

## Target Platforms

| Platform | Status |
|----------|--------|
| Linux | Supported |
| Windows | Supported |
| macOS | Supported |

## Technology

- **Primary Language:** C
- **Cross-platform:** Yes
- **External dependencies:** Minimized; OS-native security APIs preferred
