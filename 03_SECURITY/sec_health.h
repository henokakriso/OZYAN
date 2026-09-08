#ifndef OZAYN_SEC_HEALTH_H
#define OZAYN_SEC_HEALTH_H

#include "sec_config.h"
#include "incident.h"
#include "backup.h"
#include "deletion.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * sec_health.h — Security Health Monitoring & Security Self-Assessment
 *                Foundation (Step 27).
 *
 * Provides deterministic internal evaluation of OZAYN's security
 * infrastructure: availability, configuration, integrity, operational
 * status, and safety. Answers the questions:
 *
 *   - Is the security system healthy?
 *   - What component is unhealthy?
 *   - Why is it unhealthy?
 *   - What security capabilities are available?
 *   - Is the system safe to continue operating?
 *
 * Architecture:
 *   SECURITY COMPONENTS
 *          ↓
 *   HEALTH CHECK PROVIDERS
 *          ↓
 *   SECURITY HEALTH SERVICE
 *          ↓
 *   HEALTH AGGREGATION
 *          ↓
 *   SECURITY HEALTH SNAPSHOT
 *          ↓
 *   SAFE OPERATION DECISION
 *          ↓
 *   AUDIT / INCIDENT RESPONSE
 *
 * Design principles:
 *   - Observe and evaluate; do not modify security config
 *   - Fail-closed: UNKNOWN never becomes HEALTHY
 *   - Dependency-aware: failures propagate through the stack
 *   - Freshness semantics: stale results are not trusted
 *   - No secrets in health data; metadata only
 *   - No health-based authorization bypass
 *   - No plaintext fallback
 *
 * NOT in scope:
 *   - GUI / Security dashboard
 *   - SIEM / SOC
 *   - Machine-learning threat detection
 *   - Cloud monitoring
 *   - Control Room UI
 */

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SH_OK                                 =   0,
    OZAYN_SH_ERR                                =  -1,
    OZAYN_SH_ERR_NULL                           =  -2,
    OZAYN_SH_ERR_NOT_INITIALIZED                =  -3,
    OZAYN_SH_ERR_ALREADY_INITIALIZED            =  -4,
    OZAYN_SH_ERR_INVALID_REQUEST                =  -5,
    OZAYN_SH_ERR_INVALID_COMPONENT              =  -6,
    OZAYN_SH_ERR_INVALID_STATE                  =  -7,
    OZAYN_SH_ERR_UNAVAILABLE                    =  -8,
    OZAYN_SH_ERR_CHECK_FAILED                   =  -9,
    OZAYN_SH_ERR_CHECK_TIMEOUT                  = -10,
    OZAYN_SH_ERR_POLICY_INVALID                 = -11,
    OZAYN_SH_ERR_POLICY_UNAVAILABLE             = -12,
    OZAYN_SH_ERR_CONFIGURATION_INVALID          = -13,
    OZAYN_SH_ERR_DEPENDENCY_FAILED              = -14,
    OZAYN_SH_ERR_INTEGRITY_FAILED               = -15,
    OZAYN_SH_ERR_SNAPSHOT_INVALID               = -16,
    OZAYN_SH_ERR_SNAPSHOT_STALE                 = -17,
    OZAYN_SH_ERR_RESOURCE_LIMIT                 = -18,
    OZAYN_SH_ERR_CONCURRENCY_CONFLICT           = -19,
    OZAYN_SH_ERR_LOCKDOWN                       = -20,
    OZAYN_SH_ERR_OPERATION_UNSAFE               = -21
} ozayn_sh_result_t;

/* ============================================================
 * SECTION 2 — HEALTH STATES
 * ============================================================ */

typedef enum {
    OZAYN_SH_HEALTHY                            = 0,
    OZAYN_SH_DEGRADED                            = 1,
    OZAYN_SH_WARNING                             = 2,
    OZAYN_SH_CRITICAL                            = 3,
    OZAYN_SH_UNAVAILABLE                         = 4,
    OZAYN_SH_UNKNOWN                             = 5,
    OZAYN_SH_LOCKDOWN                            = 6
} ozayn_sh_health_state_t;

/* ============================================================
 * SECTION 3 — COMPONENT CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_SH_COMP_SECURITY_CONFIGURATION         =  0,
    OZAYN_SH_COMP_SECURITY_POLICY                =  1,
    OZAYN_SH_COMP_IDENTITY                       =  2,
    OZAYN_SH_COMP_AUTHENTICATION                 =  3,
    OZAYN_SH_COMP_ATTEMPT_CONTROL                =  4,
    OZAYN_SH_COMP_MFA                            =  5,
    OZAYN_SH_COMP_SESSION                        =  6,
    OZAYN_SH_COMP_AUTHORIZATION                  =  7,
    OZAYN_SH_COMP_RBAC                           =  8,
    OZAYN_SH_COMP_PERMISSION                     =  9,
    OZAYN_SH_COMP_SECURE_DATA                    = 10,
    OZAYN_SH_COMP_STORAGE                        = 11,
    OZAYN_SH_COMP_PROTECTION                     = 12,
    OZAYN_SH_COMP_KEY_MANAGEMENT                 = 13,
    OZAYN_SH_COMP_KEY_STORAGE                    = 14,
    OZAYN_SH_COMP_KEY_LIFECYCLE                  = 15,
    OZAYN_SH_COMP_SECURE_VAULT                   = 16,
    OZAYN_SH_COMP_AUDIT                          = 17,
    OZAYN_SH_COMP_AUDIT_INTEGRITY                = 18,
    OZAYN_SH_COMP_BACKUP                         = 19,
    OZAYN_SH_COMP_RECOVERY                       = 20,
    OZAYN_SH_COMP_SECURE_DELETION                = 21,
    OZAYN_SH_COMP_INCIDENT_RESPONSE              = 22
} ozayn_sh_component_id_t;

#define OZAYN_SH_MAX_COMPONENTS             24
#define OZAYN_SH_MAX_COMPONENT_NAME_LEN     32
#define OZAYN_SH_MAX_DETAIL_LEN            128

/* ============================================================
 * SECTION 4 — COMPONENT HEALTH MODEL
 * ============================================================ */

typedef enum {
    OZAYN_SH_INTEGRITY_UNKNOWN                  = 0,
    OZAYN_SH_INTEGRITY_VALID                    = 1,
    OZAYN_SH_INTEGRITY_INVALID                  = 2,
    OZAYN_SH_INTEGRITY_CHECK_FAILED             = 3
} ozayn_sh_integrity_state_t;

typedef enum {
    OZAYN_SH_CONFIG_UNKNOWN                     = 0,
    OZAYN_SH_CONFIG_VALID                       = 1,
    OZAYN_SH_CONFIG_INVALID                     = 2,
    OZAYN_SH_CONFIG_MISSING                     = 3,
    OZAYN_SH_CONFIG_CHECK_FAILED                = 4
} ozayn_sh_config_state_t;

typedef enum {
    OZAYN_SH_POLICY_UNKNOWN                     = 0,
    OZAYN_SH_POLICY_VALID                       = 1,
    OZAYN_SH_POLICY_INVALID                     = 2,
    OZAYN_SH_POLICY_MISSING                     = 3,
    OZAYN_SH_POLICY_CHECK_FAILED                = 4
} ozayn_sh_policy_state_t;

typedef struct {
    ozayn_sh_component_id_t     component_id;
    char                        component_name[OZAYN_SH_MAX_COMPONENT_NAME_LEN];
    ozayn_sh_health_state_t     health_state;
    int                         available;
    ozayn_sh_integrity_state_t  integrity_state;
    ozayn_sh_config_state_t     config_state;
    ozayn_sh_policy_state_t     policy_state;
    time_t                      last_check_time;
    uint32_t                    check_version;
    int                         failure_code;
    int                         required;
    int                         dependency_count;
    ozayn_sh_component_id_t     dependencies[8];
    char                        detail[OZAYN_SH_MAX_DETAIL_LEN];
} ozayn_sh_component_health_t;

/* ============================================================
 * SECTION 5 — HEALTH CHECK TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SH_CHECK_AVAILABILITY                 = 0,
    OZAYN_SH_CHECK_CONFIGURATION                = 1,
    OZAYN_SH_CHECK_POLICY                       = 2,
    OZAYN_SH_CHECK_INTEGRITY                    = 3,
    OZAYN_SH_CHECK_DEPENDENCY                   = 4,
    OZAYN_SH_CHECK_STORAGE                      = 5,
    OZAYN_SH_CHECK_KEY_AVAILABILITY             = 6,
    OZAYN_SH_CHECK_AUTHENTICATION               = 7,
    OZAYN_SH_CHECK_AUTHORIZATION                = 8,
    OZAYN_SH_CHECK_AUDIT                        = 9,
    OZAYN_SH_CHECK_RECOVERY                     = 10,
    OZAYN_SH_CHECK_RESOURCE                     = 11
} ozayn_sh_check_type_t;

/* ============================================================
 * SECTION 6 — HEALTH CHECK PROVIDER
 * ============================================================ */

typedef struct {
    int (*check)(const void *provider_ctx,
                 ozayn_sh_component_health_t *out_health);
    int (*is_available)(const void *provider_ctx);
    const char *(*get_component_name)(const void *provider_ctx);
} ozayn_sh_provider_vtable_t;

typedef struct {
    const ozayn_sh_provider_vtable_t *vtable;
    const void                      *context;
    int                              registered;
} ozayn_sh_provider_t;

/* ============================================================
 * SECTION 7 — HEALTH AGGREGATION RULES
 * ============================================================ */

#define OZAYN_SH_SNAPSHOT_VERSION            1

typedef struct {
    ozayn_sh_health_state_t     overall_state;
    int                         healthy_count;
    int                         degraded_count;
    int                         warning_count;
    int                         critical_count;
    int                         unavailable_count;
    int                         unknown_count;
    int                         lockdown_count;
    int                         required_healthy_count;
    int                         required_total_count;
    int                         optional_healthy_count;
    int                         optional_total_count;
    uint64_t                    last_aggregation_time;
    uint32_t                    aggregation_version;
} ozayn_sh_aggregation_t;

/* ============================================================
 * SECTION 8 — HEALTH SNAPSHOT
 * ============================================================ */

typedef struct {
    uint32_t                    snapshot_id;
    uint32_t                    snapshot_version;
    time_t                      timestamp;
    ozayn_sh_health_state_t     overall_state;
    ozayn_sh_component_health_t components[OZAYN_SH_MAX_COMPONENTS];
    int                         component_count;
    ozayn_sh_aggregation_t      aggregation;
    uint32_t                    policy_version;
    uint32_t                    config_version;
    ozayn_sh_integrity_state_t  integrity_state;
    int                         active_incidents;
    int                         lockdown_active;
    char                        summary[512];
} ozayn_sh_snapshot_t;

/* ============================================================
 * SECTION 9 — HEALTH EVENTS
 * ============================================================ */

typedef enum {
    OZAYN_SH_EVENT_CHECK_STARTED                =  0,
    OZAYN_SH_EVENT_CHECK_COMPLETED              =  1,
    OZAYN_SH_EVENT_HEALTH_DEGRADED              =  2,
    OZAYN_SH_EVENT_HEALTH_WARNING               =  3,
    OZAYN_SH_EVENT_HEALTH_CRITICAL              =  4,
    OZAYN_SH_EVENT_HEALTH_UNKNOWN               =  5,
    OZAYN_SH_EVENT_HEALTH_LOCKDOWN              =  6,
    OZAYN_SH_EVENT_COMPONENT_UNAVAILABLE        =  7,
    OZAYN_SH_EVENT_COMPONENT_RECOVERED          =  8,
    OZAYN_SH_EVENT_INTEGRITY_CHECK_FAILED       =  9,
    OZAYN_SH_EVENT_POLICY_HEALTH_FAILED         = 10,
    OZAYN_SH_EVENT_DEPENDENCY_FAILURE           = 11,
    OZAYN_SH_EVENT_SNAPSHOT_GENERATED           = 12,
    OZAYN_SH_EVENT_OPERATION_UNSAFE             = 13
} ozayn_sh_event_type_t;

#define OZAYN_SH_MAX_EVENTS          128
#define OZAYN_SH_MAX_EVENT_DETAIL    128

typedef struct {
    ozayn_sh_event_type_t       event_type;
    time_t                      timestamp;
    ozayn_sh_component_id_t     component_id;
    ozayn_sh_health_state_t     health_state;
    char                        detail[OZAYN_SH_MAX_EVENT_DETAIL];
    uint64_t                    sequence;
} ozayn_sh_event_t;

/* ============================================================
 * SECTION 10 — HEALTH CHECK MODES
 * ============================================================ */

typedef enum {
    OZAYN_SH_MODE_ON_DEMAND                     = 0,
    OZAYN_SH_MODE_STARTUP                       = 1,
    OZAYN_SH_MODE_PERIODIC                      = 2,
    OZAYN_SH_MODE_EVENT_TRIGGERED               = 3
} ozayn_sh_check_mode_t;

/* ============================================================
 * SECTION 11 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    int                         max_components;
    int                         max_events;
    int                         check_timeout_ms;
    int                         max_concurrent_checks;
    int                         event_threshold;
    ozayn_sc_service_t         *config_service;
    ozayn_ir_service_t         *incident_service;
    ozayn_audit_service_t      *audit;
} ozayn_sh_service_config_t;

/* ============================================================
 * SECTION 12 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                         initialized;
    ozayn_sh_component_health_t components[OZAYN_SH_MAX_COMPONENTS];
    int                         component_count;
    ozayn_sh_provider_t         providers[OZAYN_SH_MAX_COMPONENTS];
    int                         provider_count;
    ozayn_sh_aggregation_t      aggregation;
    uint32_t                    check_version;
    uint64_t                    total_checks;
    uint64_t                    total_events;

    /* Health events (ring buffer) */
    ozayn_sh_event_t            events[OZAYN_SH_MAX_EVENTS];
    int                         event_head;
    int                         event_count;
    uint64_t                    event_sequence;

    /* Dependencies (not owned) */
    ozayn_sc_service_t         *config_service;
    ozayn_ir_service_t         *incident_service;
    ozayn_audit_service_t      *audit;

    /* Limits */
    int                         max_concurrent_checks;
    int                         active_checks;
} ozayn_sh_service_t;

/* ============================================================
 * SECTION 13 — LIFECYCLE
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_service_init(ozayn_sh_service_t *svc,
                                         const ozayn_sh_service_config_t *cfg);

void              ozayn_sh_service_shutdown(ozayn_sh_service_t *svc);

int               ozayn_sh_service_is_initialized(
                      const ozayn_sh_service_t *svc);

/* ============================================================
 * SECTION 14 — COMPONENT REGISTRATION
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_register_component(
    ozayn_sh_service_t *svc,
    ozayn_sh_component_id_t component_id,
    const char *component_name,
    int required,
    const ozayn_sh_component_id_t *dependencies,
    int dependency_count);

ozayn_sh_result_t ozayn_sh_register_provider(
    ozayn_sh_service_t *svc,
    const ozayn_sh_provider_vtable_t *vtable,
    const void *context);

/* ============================================================
 * SECTION 15 — HEALTH CHECK
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_check(
    ozayn_sh_service_t *svc,
    ozayn_sh_component_id_t component_id,
    ozayn_sh_component_health_t *out_health);

ozayn_sh_result_t ozayn_sh_check_all(ozayn_sh_service_t *svc);

/* ============================================================
 * SECTION 16 — STATUS QUERY
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_get_status(
    const ozayn_sh_service_t *svc,
    ozayn_sh_health_state_t *out_state);

ozayn_sh_result_t ozayn_sh_get_component_status(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_id_t component_id,
    ozayn_sh_component_health_t *out_health);

const char *ozayn_sh_get_safe_summary(
    const ozayn_sh_service_t *svc);

/* ============================================================
 * SECTION 17 — OPERATION SAFETY CHECK
 * ============================================================ */

typedef enum {
    OZAYN_SH_OP_VAULT_ACCESS                   = 0,
    OZAYN_SH_OP_KEY_ACCESS                     = 1,
    OZAYN_SH_OP_ENCRYPT                        = 2,
    OZAYN_SH_OP_DECRYPT                        = 3,
    OZAYN_SH_OP_AUTHENTICATE                   = 4,
    OZAYN_SH_OP_AUTHORIZE                      = 5,
    OZAYN_SH_OP_BACKUP                         = 6,
    OZAYN_SH_OP_RESTORE                        = 7,
    OZAYN_SH_OP_DELETE                         = 8,
    OZAYN_SH_OP_CONFIG_CHANGE                  = 9,
    OZAYN_SH_OP_AUDIT_READ                    = 10,
    OZAYN_SH_OP_INCIDENT_REPORT               = 11
} ozayn_sh_operation_type_t;

typedef enum {
    OZAYN_SH_SAFE_ALLOW                         = 0,
    OZAYN_SH_SAFE_RESTRICT                      = 1,
    OZAYN_SH_SAFE_DENY                          = 2
} ozayn_sh_operation_safety_t;

ozayn_sh_result_t ozayn_sh_is_operation_safe(
    const ozayn_sh_service_t *svc,
    ozayn_sh_operation_type_t operation,
    ozayn_sh_operation_safety_t *out_safety);

/* ============================================================
 * SECTION 18 — HEALTH SNAPSHOT
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_generate_snapshot(
    const ozayn_sh_service_t *svc,
    ozayn_sh_snapshot_t *out_snapshot);

ozayn_sh_result_t ozayn_sh_snapshot_is_fresh(
    const ozayn_sh_snapshot_t *snapshot,
    int max_age_seconds,
    int *out_is_fresh);

/* ============================================================
 * SECTION 19 — DEPENDENCY EVALUATION
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_evaluate_dependencies(
    ozayn_sh_service_t *svc);

/* ============================================================
 * SECTION 20 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sh_result_name(ozayn_sh_result_t r);

const char *ozayn_sh_health_state_name(ozayn_sh_health_state_t s);

const char *ozayn_sh_component_name(ozayn_sh_component_id_t c);

const char *ozayn_sh_check_type_name(ozayn_sh_check_type_t t);

const char *ozayn_sh_integrity_state_name(ozayn_sh_integrity_state_t s);

const char *ozayn_sh_config_state_name(ozayn_sh_config_state_t s);

const char *ozayn_sh_policy_state_name(ozayn_sh_policy_state_t s);

const char *ozayn_sh_event_type_name(ozayn_sh_event_type_t e);

const char *ozayn_sh_operation_type_name(ozayn_sh_operation_type_t o);

const char *ozayn_sh_operation_safety_name(ozayn_sh_operation_safety_t s);

/* ============================================================
 * SECTION 21 — HEALTH EVENT LOG
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_record_event(
    ozayn_sh_service_t *svc,
    ozayn_sh_event_type_t event_type,
    ozayn_sh_component_id_t component_id,
    ozayn_sh_health_state_t health_state,
    const char *detail);

int ozayn_sh_get_event_count(const ozayn_sh_service_t *svc);

ozayn_sh_result_t ozayn_sh_get_event(
    const ozayn_sh_service_t *svc,
    int index,
    ozayn_sh_event_t *out_event);

/* ============================================================
 * SECTION 22 — CHANGE DETECTION
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_detect_changes(
    const ozayn_sh_service_t *svc,
    int *out_changes_detected);

/* ============================================================
 * SECTION 23 — HEALTH STATE AGGREGATION HELPERS
 * ============================================================ */

ozayn_sh_health_state_t ozayn_sh_worse_state(
    ozayn_sh_health_state_t a,
    ozayn_sh_health_state_t b);

int ozayn_sh_state_is_usable(ozayn_sh_health_state_t s);

int ozayn_sh_state_allows_operation(
    ozayn_sh_health_state_t state,
    ozayn_sh_operation_type_t operation);

/* ============================================================
 * SECTION 24 — GLOBAL SERVICE ACCESSOR
 * ============================================================ */

ozayn_sh_service_t *ozayn_sh_get_global(void);

#endif /* OZAYN_SEC_HEALTH_H */
