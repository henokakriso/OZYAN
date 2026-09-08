#ifndef OZAYN_INCIDENT_H
#define OZAYN_INCIDENT_H

#include "secure_vault.h"
#include "key_lifecycle.h"
#include "protection_provider.h"
#include "storage_provider.h"
#include "data_classification.h"
#include "secure_data_object.h"
#include "audit.h"
#include "identity.h"
#include "session_management.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * incident.h — Security Recovery, Incident Response & Compromise
 *              Handling Foundation (Step 25).
 *
 * Provides controlled detection, classification, containment,
 * recovery, verification, and resolution of security incidents.
 * Coordinates existing security components without replacing them.
 *
 * Architecture:
 *   SECURITY EVENT
 *        ↓
 *   EVENT / INTEGRITY ANALYSIS
 *        ↓
 *   INCIDENT DETECTION
 *        ↓
 *   INCIDENT CLASSIFICATION
 *        ↓
 *   INCIDENT RESPONSE POLICY
 *        ↓
 *   CONTAINMENT
 *        ↓
 *   RECOVERY
 *        ↓
 *   VERIFICATION
 *        ↓
 *   AUDIT
 *
 * Step 25 scope:
 *   - Incident model (ID, type, severity, state, metadata)
 *   - Incident taxonomy (21 types)
 *   - Severity model (INFO through CRITICAL)
 *   - Incident lifecycle (DETECTED through RESOLVED/RECOVERY_FAILED)
 *   - Compromise level model (NORMAL through SECURITY_LOCKDOWN)
 *   - Incident service with vault/audit integration
 *   - Containment boundary (session revoke, identity suspend)
 *   - Recovery workflow with verification
 *   - Lockdown boundary
 *   - Policy-driven response
 *   - Audit integration for all operations
 *   - Resource limits (bounded incident storage)
 *   - Deduplication of rapid-fire incidents
 *   - No hidden bypass, no master recovery password
 *   - Fail-closed behavior
 *
 * NOT in scope:
 *   - SIEM / SOC
 *   - Machine-learning anomaly detection
 *   - Cloud incident response
 *   - Distributed security monitoring
 *   - GUI
 */

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_IR_OK                                 =   0,
    OZAYN_IR_ERR                                =  -1,
    OZAYN_IR_ERR_NULL                           =  -2,
    OZAYN_IR_ERR_NOT_INITIALIZED                =  -3,
    OZAYN_IR_ERR_ALREADY_INITIALIZED            =  -4,
    OZAYN_IR_ERR_INVALID_REQUEST                =  -5,
    OZAYN_IR_ERR_INVALID_ID                     =  -6,
    OZAYN_IR_ERR_INVALID_TYPE                   =  -7,
    OZAYN_IR_ERR_INVALID_SEVERITY               =  -8,
    OZAYN_IR_ERR_NOT_FOUND                      =  -9,
    OZAYN_IR_ERR_ALREADY_RESOLVED               = -10,
    OZAYN_IR_ERR_STATE_INVALID                  = -11,
    OZAYN_IR_ERR_STATE_TRANSITION_INVALID       = -12,
    OZAYN_IR_ERR_POLICY_INVALID                 = -13,
    OZAYN_IR_ERR_POLICY_UNAVAILABLE             = -14,
    OZAYN_IR_ERR_CONTAINMENT_FAILED             = -15,
    OZAYN_IR_ERR_RECOVERY_FAILED                = -16,
    OZAYN_IR_ERR_VERIFICATION_FAILED            = -17,
    OZAYN_IR_ERR_UNAUTHORIZED                   = -18,
    OZAYN_IR_ERR_MFA_REQUIRED                   = -19,
    OZAYN_IR_ERR_STORAGE_ERROR                  = -20,
    OZAYN_IR_ERR_AUDIT_FAILURE                  = -21,
    OZAYN_IR_ERR_INTEGRITY_FAILURE              = -22,
    OZAYN_IR_ERR_LOCKDOWN_REQUIRED              = -23,
    OZAYN_IR_ERR_LOCKDOWN_FAILED                = -24,
    OZAYN_IR_ERR_RECOVERY_UNAVAILABLE           = -25,
    OZAYN_IR_ERR_RECOVERY_UNSAFE                = -26,
    OZAYN_IR_ERR_STORAGE_FULL                   = -27,
    OZAYN_IR_ERR_DUPLICATE                      = -28
} ozayn_ir_result_t;

/* ============================================================
 * SECTION 2 — INCIDENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_IR_TYPE_AUTHENTICATION_ATTACK         =  0,
    OZAYN_IR_TYPE_AUTHENTICATION_ANOMALY        =  1,
    OZAYN_IR_TYPE_CREDENTIAL_COMPROMISE         =  2,
    OZAYN_IR_TYPE_IDENTITY_COMPROMISE           =  3,
    OZAYN_IR_TYPE_SESSION_COMPROMISE            =  4,
    OZAYN_IR_TYPE_AUTHORIZATION_VIOLATION       =  5,
    OZAYN_IR_TYPE_PRIVILEGE_ESCALATION          =  6,
    OZAYN_IR_TYPE_PERMISSION_TAMPERING          =  7,
    OZAYN_IR_TYPE_ROLE_TAMPERING                =  8,
    OZAYN_IR_TYPE_KEY_COMPROMISE                =  9,
    OZAYN_IR_TYPE_KEY_STORAGE_FAILURE           = 10,
    OZAYN_IR_TYPE_VAULT_COMPROMISE              = 11,
    OZAYN_IR_TYPE_DATA_INTEGRITY_FAILURE        = 12,
    OZAYN_IR_TYPE_AUDIT_INTEGRITY_FAILURE       = 13,
    OZAYN_IR_TYPE_BACKUP_INTEGRITY_FAILURE      = 14,
    OZAYN_IR_TYPE_RESTORE_FAILURE               = 15,
    OZAYN_IR_TYPE_SECURE_DELETION_FAILURE       = 16,
    OZAYN_IR_TYPE_CONFIG_VIOLATION              = 17,
    OZAYN_IR_TYPE_COMPONENT_FAILURE             = 18,
    OZAYN_IR_TYPE_SUSPICIOUS_ACTIVITY           = 19,
    OZAYN_IR_TYPE_UNKNOWN                       = 20
} ozayn_ir_type_t;

/* ============================================================
 * SECTION 3 — INCIDENT SEVERITY
 * ============================================================ */

typedef enum {
    OZAYN_IR_SEV_INFO                           = 0,
    OZAYN_IR_SEV_LOW                            = 1,
    OZAYN_IR_SEV_MEDIUM                         = 2,
    OZAYN_IR_SEV_HIGH                           = 3,
    OZAYN_IR_SEV_CRITICAL                       = 4
} ozayn_ir_severity_t;

/* ============================================================
 * SECTION 4 — INCIDENT STATES
 * ============================================================ */

typedef enum {
    OZAYN_IR_STATE_DETECTED                     = 0,
    OZAYN_IR_STATE_CLASSIFIED                   = 1,
    OZAYN_IR_STATE_CONTAINMENT_REQUIRED         = 2,
    OZAYN_IR_STATE_CONTAINING                   = 3,
    OZAYN_IR_STATE_CONTAINED                    = 4,
    OZAYN_IR_STATE_RECOVERY_REQUIRED            = 5,
    OZAYN_IR_STATE_RECOVERING                   = 6,
    OZAYN_IR_STATE_VERIFIED                     = 7,
    OZAYN_IR_STATE_RESOLVED                     = 8,
    OZAYN_IR_STATE_RECOVERY_FAILED              = 9
} ozayn_ir_state_t;

/* ============================================================
 * SECTION 5 — COMPROMISE LEVEL
 * ============================================================ */

typedef enum {
    OZAYN_IR_COMPROMISE_NORMAL                  = 0,
    OZAYN_IR_COMPROMISE_DEGRADED                = 1,
    OZAYN_IR_COMPROMISE_SUSPICIOUS              = 2,
    OZAYN_IR_COMPROMISE_CONTAINMENT_REQUIRED    = 3,
    OZAYN_IR_COMPROMISE_CONTAINED               = 4,
    OZAYN_IR_COMPROMISE_RECOVERY_REQUIRED       = 5,
    OZAYN_IR_COMPROMISE_RECOVERY_FAILED         = 6,
    OZAYN_IR_COMPROMISE_LOCKDOWN                = 7
} ozayn_ir_compromise_level_t;

/* ============================================================
 * SECTION 6 — CONTAINMENT ACTIONS
 * ============================================================ */

typedef enum {
    OZAYN_IR_CONTAIN_NONE                       = 0,
    OZAYN_IR_CONTAIN_REVOKE_SESSION             = 1,
    OZAYN_IR_CONTAIN_SUSPEND_IDENTITY           = 2,
    OZAYN_IR_CONTAIN_REVOKE_IDENTITY            = 3,
    OZAYN_IR_CONTAIN_REVOKE_KEY                 = 4,
    OZAYN_IR_CONTAIN_RESTRICT_RESOURCE          = 5,
    OZAYN_IR_CONTAIN_ENTER_LOCKDOWN             = 6
} ozayn_ir_containment_action_t;

/* ============================================================
 * SECTION 7 — INCIDENT OBJECT
 * ============================================================ */

#define OZAYN_IR_MAX_ID_LEN         64
#define OZAYN_IR_MAX_SOURCE_LEN     64
#define OZAYN_IR_MAX_DETAIL_LEN     256
#define OZAYN_IR_MAX_INCIDENTS      256

typedef struct {
    char                        incident_id[OZAYN_IR_MAX_ID_LEN];
    uint32_t                    incident_version;
    ozayn_ir_type_t             incident_type;
    ozayn_ir_severity_t         severity;
    ozayn_ir_state_t            state;
    time_t                      detection_time;
    time_t                      last_updated;
    char                        source_component[OZAYN_IR_MAX_SOURCE_LEN];
    char                        identity_id[OZAYN_IR_MAX_ID_LEN];
    char                        session_id[OZAYN_IR_MAX_ID_LEN];
    char                        resource_id[OZAYN_IR_MAX_ID_LEN];
    char                        correlation_id[OZAYN_IR_MAX_ID_LEN];
    ozayn_ir_containment_action_t containment_action;
    int                         containment_completed;
    int                         recovery_completed;
    char                        detail[OZAYN_IR_MAX_DETAIL_LEN];
} ozayn_ir_incident_t;

/* ============================================================
 * SECTION 8 — INCIDENT RESPONSE POLICY
 * ============================================================ */

typedef struct {
    int                         max_incidents;
    int                         auto_contain_critical;
    int                         require_mfa_for_recovery;
    int                         lockdown_threshold;
    int                         incident_retention_count;
    int                         dedup_window_seconds;
    ozayn_ir_severity_t         min_lockdown_severity;
} ozayn_ir_policy_t;

/* ============================================================
 * SECTION 9 — INCIDENT RESPONSE SERVICE
 * ============================================================ */

typedef struct {
    int                         initialized;
    ozayn_ir_compromise_level_t compromise_level;
    int                         lockdown_active;
    ozayn_ir_policy_t           policy;

    /* Dependencies (not owned) */
    ozayn_vault_t              *vault;
    ozayn_kl_manager_t         *key_lifecycle;
    ozayn_protection_provider_t *protection;
    ozayn_storage_provider_t   *storage;
    ozayn_audit_service_t      *audit;
    ozayn_identity_service_t   *identity;
    ozayn_sess_service_t       *session;

    /* Incident storage */
    ozayn_ir_incident_t         incidents[OZAYN_IR_MAX_INCIDENTS];
    int                         incident_count;

    /* Stats */
    uint64_t                    total_incidents_reported;
    uint64_t                    total_incidents_resolved;
    uint64_t                    total_containments;
    uint64_t                    total_recoveries;
    uint64_t                    total_lockdowns;
} ozayn_ir_service_t;

/* ============================================================
 * SECTION 10 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_vault_t              *vault;
    ozayn_kl_manager_t         *key_lifecycle;
    ozayn_protection_provider_t *protection;
    ozayn_storage_provider_t   *storage;
    ozayn_audit_service_t      *audit;
    ozayn_identity_service_t   *identity;
    ozayn_sess_service_t       *session;
} ozayn_ir_service_config_t;

/* ============================================================
 * SECTION 11 — LIFECYCLE
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_service_init(ozayn_ir_service_t *svc,
                                         const ozayn_ir_service_config_t *cfg);

void               ozayn_ir_service_shutdown(ozayn_ir_service_t *svc);

int                ozayn_ir_service_is_initialized(const ozayn_ir_service_t *svc);

/* ============================================================
 * SECTION 12 — INCIDENT REPORTING
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_report(ozayn_ir_service_t *svc,
                                   ozayn_ir_type_t type,
                                   ozayn_ir_severity_t severity,
                                   const char *source_component,
                                   const char *identity_id,
                                   const char *session_id,
                                   const char *resource_id,
                                   const char *correlation_id,
                                   const char *detail,
                                   ozayn_ir_incident_t **out_incident);

/* ============================================================
 * SECTION 13 — INCIDENT QUERY
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_get(const ozayn_ir_service_t *svc,
                                const char *incident_id,
                                ozayn_ir_incident_t **out_incident);

int               ozayn_ir_list(const ozayn_ir_service_t *svc,
                                 ozayn_ir_type_t filter_type,
                                 ozayn_ir_incident_t **out_incidents,
                                 int max_count);

/* ============================================================
 * SECTION 14 — INCIDENT LIFECYCLE
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_classify(ozayn_ir_service_t *svc,
                                     const char *incident_id,
                                     ozayn_ir_type_t type,
                                     ozayn_ir_severity_t severity);

ozayn_ir_result_t ozayn_ir_update_state(ozayn_ir_service_t *svc,
                                          const char *incident_id,
                                          ozayn_ir_state_t new_state);

/* ============================================================
 * SECTION 15 — CONTAINMENT
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_contain(ozayn_ir_service_t *svc,
                                    const char *incident_id,
                                    ozayn_ir_containment_action_t action);

/* ============================================================
 * SECTION 16 — RECOVERY
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_recover(ozayn_ir_service_t *svc,
                                    const char *incident_id);

ozayn_ir_result_t ozayn_ir_verify(ozayn_ir_service_t *svc,
                                   const char *incident_id);

ozayn_ir_result_t ozayn_ir_resolve(ozayn_ir_service_t *svc,
                                    const char *incident_id);

/* ============================================================
 * SECTION 17 — COMPROMISE LEVEL & LOCKDOWN
 * ============================================================ */

ozayn_ir_compromise_level_t ozayn_ir_get_compromise_level(
    const ozayn_ir_service_t *svc);

int               ozayn_ir_is_lockdown_active(const ozayn_ir_service_t *svc);

ozayn_ir_result_t ozayn_ir_enter_lockdown(ozayn_ir_service_t *svc);

ozayn_ir_result_t ozayn_ir_exit_lockdown(ozayn_ir_service_t *svc);

/* ============================================================
 * SECTION 18 — POLICY
 * ============================================================ */

ozayn_ir_result_t ozayn_ir_set_policy(ozayn_ir_service_t *svc,
                                       const ozayn_ir_policy_t *policy);

const ozayn_ir_policy_t *ozayn_ir_get_policy(const ozayn_ir_service_t *svc);

ozayn_ir_policy_t ozayn_ir_default_policy(void);

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ir_result_name(ozayn_ir_result_t r);

const char *ozayn_ir_type_name(ozayn_ir_type_t t);

const char *ozayn_ir_severity_name(ozayn_ir_severity_t s);

const char *ozayn_ir_state_name(ozayn_ir_state_t s);

const char *ozayn_ir_compromise_level_name(ozayn_ir_compromise_level_t l);

const char *ozayn_ir_containment_action_name(ozayn_ir_containment_action_t a);

/* ============================================================
 * SECTION 20 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_ir_state_transition_valid(ozayn_ir_state_t from,
                                     ozayn_ir_state_t to);

/* ============================================================
 * SECTION 21 — GLOBAL SERVICE ACCESSOR
 * ============================================================ */

ozayn_ir_service_t *ozayn_ir_get_global(void);

#endif /* OZAYN_INCIDENT_H */
