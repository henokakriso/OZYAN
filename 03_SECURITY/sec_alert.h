#ifndef OZAYN_SEC_ALERT_H
#define OZAYN_SEC_ALERT_H

#include "sec_health.h"
#include "sec_diag.h"
#include "incident.h"
#include "audit.h"
#include "sec_config.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * sec_alert.h — Security Alerting & Security Notification Foundation
 *               (Step 29).
 *
 * Provides structured alert creation, lifecycle management,
 * deduplication, suppression, threshold evaluation, escalation,
 * notification abstraction, and integration with health, diagnostics,
 * incident response, and audit.
 *
 * Architecture:
 *   SECURITY CONDITION
 *          |
 *          v
 *   ALERT EVALUATION
 *          |
 *          v
 *   ALERT POLICY
 *          |
 *          v
 *   ALERT GENERATION
 *          |
 *          v
 *   ALERT DEDUPLICATION
 *          |
 *          v
 *   ALERT PRIORITIZATION
 *          |
 *          v
 *   ALERT STATE
 *          |
 *          +-----> SECURITY AUDIT
 *          |
 *          +-----> NOTIFICATION PROVIDER
 *
 * Design principles:
 *   - Alerting is DOWNSTREAM of security enforcement
 *   - Alerting must never become a security bypass
 *   - No secrets in alert data
 *   - Fail-closed: invalid policy is rejected
 *   - Bounded resource usage
 *   - Notification failure does not disable security
 *   - Rate limiting prevents notification storms
 *   - Deduplication prevents alert flooding
 *
 * NOT in scope:
 *   - Control Room GUI
 *   - Email/SMS/Push delivery infrastructure
 *   - SIEM integration
 *   - External alert management platforms
 *   - Mobile notifications
 *   - ML-based alert detection
 */

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_OK                             =   0,
    OZAYN_SALERT_ERR                            =  -1,
    OZAYN_SALERT_ERR_NULL                       =  -2,
    OZAYN_SALERT_ERR_NOT_INITIALIZED            =  -3,
    OZAYN_SALERT_ERR_ALREADY_INITIALIZED        =  -4,
    OZAYN_SALERT_ERR_INVALID_REQUEST            =  -5,
    OZAYN_SALERT_ERR_INVALID_ID                 =  -6,
    OZAYN_SALERT_ERR_INVALID_TYPE               =  -7,
    OZAYN_SALERT_ERR_INVALID_SEVERITY           =  -8,
    OZAYN_SALERT_ERR_INVALID_PRIORITY           =  -9,
    OZAYN_SALERT_ERR_INVALID_STATE              = -10,
    OZAYN_SALERT_ERR_INVALID_SOURCE             = -11,
    OZAYN_SALERT_ERR_NOT_FOUND                  = -12,
    OZAYN_SALERT_ERR_ALREADY_EXISTS             = -13,
    OZAYN_SALERT_ERR_STATE_TRANSITION_INVALID   = -14,
    OZAYN_SALERT_ERR_POLICY_INVALID             = -15,
    OZAYN_SALERT_ERR_POLICY_REJECTED            = -16,
    OZAYN_SALERT_ERR_THRESHOLD_INVALID          = -17,
    OZAYN_SALERT_ERR_DEDUPLICATION_ERROR        = -18,
    OZAYN_SALERT_ERR_SUPPRESSION_REJECTED       = -19,
    OZAYN_SALERT_ERR_RATE_LIMITED               = -20,
    OZAYN_SALERT_ERR_LIMIT_REACHED              = -21,
    OZAYN_SALERT_ERR_STORAGE_ERROR              = -22,
    OZAYN_SALERT_ERR_AUDIT_FAILURE              = -23,
    OZAYN_SALERT_ERR_NOTIFICATION_ERROR         = -24,
    OZAYN_SALERT_ERR_NOTIFICATION_UNAVAILABLE   = -25,
    OZAYN_SALERT_ERR_NOTIFICATION_REJECTED      = -26,
    OZAYN_SALERT_ERR_ESCALATION_REJECTED        = -27,
    OZAYN_SALERT_ERR_CORRELATION_INVALID        = -28,
    OZAYN_SALERT_ERR_SOURCE_INVALID             = -29,
    OZAYN_SALERT_ERR_RESOURCE_LIMIT             = -30,
    OZAYN_SALERT_ERR_CONCURRENCY_CONFLICT       = -31,
    OZAYN_SALERT_ERR_UNAVAILABLE                = -32
} ozayn_salert_err_t;

/* ============================================================
 * SECTION 2 — ALERT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_TYPE_CONFIGURATION             =  0,
    OZAYN_SALERT_TYPE_POLICY                    =  1,
    OZAYN_SALERT_TYPE_AUTH_FAILURE              =  2,
    OZAYN_SALERT_TYPE_AUTH_ATTACK               =  3,
    OZAYN_SALERT_TYPE_AUTH_RATE_LIMIT           =  4,
    OZAYN_SALERT_TYPE_MFA_FAILURE               =  5,
    OZAYN_SALERT_TYPE_MFA_ATTACK                =  6,
    OZAYN_SALERT_TYPE_SESSION_ANOMALY           =  7,
    OZAYN_SALERT_TYPE_SESSION_COMPROMISE        =  8,
    OZAYN_SALERT_TYPE_AUTHZ_DENIAL              =  9,
    OZAYN_SALERT_TYPE_PRIVILEGE_ESCALATION      = 10,
    OZAYN_SALERT_TYPE_ROLE_TAMPERING            = 11,
    OZAYN_SALERT_TYPE_PERMISSION_TAMPERING      = 12,
    OZAYN_SALERT_TYPE_KEY_AVAILABILITY          = 13,
    OZAYN_SALERT_TYPE_KEY_COMPROMISE            = 14,
    OZAYN_SALERT_TYPE_KEY_STORAGE               = 15,
    OZAYN_SALERT_TYPE_VAULT_FAILURE             = 16,
    OZAYN_SALERT_TYPE_VAULT_INTEGRITY           = 17,
    OZAYN_SALERT_TYPE_DATA_INTEGRITY            = 18,
    OZAYN_SALERT_TYPE_AUDIT_FAILURE             = 19,
    OZAYN_SALERT_TYPE_AUDIT_INTEGRITY           = 20,
    OZAYN_SALERT_TYPE_BACKUP_FAILURE            = 21,
    OZAYN_SALERT_TYPE_BACKUP_INTEGRITY          = 22,
    OZAYN_SALERT_TYPE_RESTORE_FAILURE           = 23,
    OZAYN_SALERT_TYPE_DELETION_FAILURE          = 24,
    OZAYN_SALERT_TYPE_INCIDENT                  = 25,
    OZAYN_SALERT_TYPE_HEALTH_DEGRADED           = 26,
    OZAYN_SALERT_TYPE_HEALTH_CRITICAL           = 27,
    OZAYN_SALERT_TYPE_DIAGNOSTIC_FAIL           = 28,
    OZAYN_SALERT_TYPE_COMPONENT_UNAVAILABLE     = 29,
    OZAYN_SALERT_TYPE_LOCKDOWN                  = 30,
    OZAYN_SALERT_TYPE_RESOURCE_EXHAUSTION       = 31,
    OZAYN_SALERT_TYPE_UNKNOWN                   = 32
} ozayn_salert_type_t;

/* ============================================================
 * SECTION 3 — ALERT SEVERITY
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_SEV_INFO                       = 0,
    OZAYN_SALERT_SEV_NOTICE                     = 1,
    OZAYN_SALERT_SEV_WARNING                    = 2,
    OZAYN_SALERT_SEV_HIGH                       = 3,
    OZAYN_SALERT_SEV_CRITICAL                   = 4
} ozayn_salert_severity_t;

/* ============================================================
 * SECTION 4 — ALERT PRIORITY
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_PRIO_LOW                       = 0,
    OZAYN_SALERT_PRIO_NORMAL                    = 1,
    OZAYN_SALERT_PRIO_HIGH                      = 2,
    OZAYN_SALERT_PRIO_URGENT                    = 3,
    OZAYN_SALERT_PRIO_IMMEDIATE                 = 4
} ozayn_salert_priority_t;

/* ============================================================
 * SECTION 5 — ALERT STATES
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_STATE_DETECTED                 = 0,
    OZAYN_SALERT_STATE_CREATED                  = 1,
    OZAYN_SALERT_STATE_ACTIVE                   = 2,
    OZAYN_SALERT_STATE_ACKNOWLEDGED             = 3,
    OZAYN_SALERT_STATE_RESOLVING                = 4,
    OZAYN_SALERT_STATE_RESOLVED                 = 5,
    OZAYN_SALERT_STATE_SUPPRESSED               = 6,
    OZAYN_SALERT_STATE_EXPIRED                  = 7,
    OZAYN_SALERT_STATE_FAILED                   = 8,
    OZAYN_SALERT_STATE_CANCELLED                = 9
} ozayn_salert_state_t;

/* ============================================================
 * SECTION 6 — ALERT SOURCES
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_SOURCE_SECURITY_EVENT          =  0,
    OZAYN_SALERT_SOURCE_SECURITY_HEALTH         =  1,
    OZAYN_SALERT_SOURCE_SECURITY_DIAGNOSTICS    =  2,
    OZAYN_SALERT_SOURCE_INCIDENT_RESPONSE       =  3,
    OZAYN_SALERT_SOURCE_AUTHENTICATION          =  4,
    OZAYN_SALERT_SOURCE_MFA                     =  5,
    OZAYN_SALERT_SOURCE_SESSION                 =  6,
    OZAYN_SALERT_SOURCE_AUTHORIZATION           =  7,
    OZAYN_SALERT_SOURCE_RBAC                    =  8,
    OZAYN_SALERT_SOURCE_PERMISSIONS             =  9,
    OZAYN_SALERT_SOURCE_KEY_MANAGEMENT          = 10,
    OZAYN_SALERT_SOURCE_KEY_STORAGE             = 11,
    OZAYN_SALERT_SOURCE_VAULT                   = 12,
    OZAYN_SALERT_SOURCE_BACKUP                  = 13,
    OZAYN_SALERT_SOURCE_RECOVERY                = 14,
    OZAYN_SALERT_SOURCE_DELETION                = 15,
    OZAYN_SALERT_SOURCE_CONFIGURATION           = 16,
    OZAYN_SALERT_SOURCE_SYSTEM                  = 17
} ozayn_salert_source_t;

/* ============================================================
 * SECTION 7 — NOTIFICATION CHANNELS
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_NOTIFY_LOCAL                   = 0,
    OZAYN_SALERT_NOTIFY_DESKTOP                 = 1,
    OZAYN_SALERT_NOTIFY_EMAIL                   = 2,
    OZAYN_SALERT_NOTIFY_SMS                     = 3,
    OZAYN_SALERT_NOTIFY_PUSH                    = 4,
    OZAYN_SALERT_NOTIFY_CONTROL_ROOM            = 5,
    OZAYN_SALERT_NOTIFY_EXTERNAL                = 6
} ozayn_salert_notify_channel_t;

/* ============================================================
 * SECTION 8 — NOTIFICATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_SALERT_NOTIFY_STATE_NONE              = 0,
    OZAYN_SALERT_NOTIFY_STATE_PENDING           = 1,
    OZAYN_SALERT_NOTIFY_STATE_SENT              = 2,
    OZAYN_SALERT_NOTIFY_STATE_FAILED            = 3,
    OZAYN_SALERT_NOTIFY_STATE_UNAVAILABLE       = 4,
    OZAYN_SALERT_NOTIFY_STATE_RATE_LIMITED      = 5
} ozayn_salert_notify_state_t;

/* ============================================================
 * SECTION 9 — ALERT MODEL
 * ============================================================ */

#define OZAYN_SALERT_MAX_ID_LEN         64
#define OZAYN_SALERT_MAX_SOURCE_LEN     64
#define OZAYN_SALERT_MAX_DETAIL_LEN     256
#define OZAYN_SALERT_MAX_SUMMARY_LEN    256
#define OZAYN_SALERT_MAX_DEDUP_KEY_LEN  128
#define OZAYN_SALERT_MAX_CORR_ID_LEN    64

typedef struct {
    char                        alert_id[OZAYN_SALERT_MAX_ID_LEN];
    uint32_t                    alert_version;
    ozayn_salert_type_t         alert_type;
    ozayn_salert_severity_t     severity;
    ozayn_salert_priority_t     priority;
    ozayn_salert_state_t        state;
    ozayn_salert_source_t       source;

    /* Source references */
    char                        source_component[OZAYN_SALERT_MAX_SOURCE_LEN];
    char                        event_id[OZAYN_SALERT_MAX_ID_LEN];
    char                        diagnostic_id[OZAYN_SALERT_MAX_ID_LEN];
    char                        incident_id[OZAYN_SALERT_MAX_ID_LEN];
    char                        identity_id[OZAYN_SALERT_MAX_ID_LEN];
    char                        session_id[OZAYN_SALERT_MAX_ID_LEN];
    char                        resource_id[OZAYN_SALERT_MAX_ID_LEN];
    char                        action_ref[OZAYN_SALERT_MAX_ID_LEN];

    /* Correlation */
    char                        correlation_id[OZAYN_SALERT_MAX_CORR_ID_LEN];
    char                        dedup_key[OZAYN_SALERT_MAX_DEDUP_KEY_LEN];

    /* Timestamps */
    time_t                      created_time;
    time_t                      updated_time;
    time_t                      acknowledged_time;
    time_t                      resolved_time;
    time_t                      expiration_time;

    /* Content (safe - no secrets) */
    char                        safe_summary[OZAYN_SALERT_MAX_SUMMARY_LEN];
    char                        safe_detail[OZAYN_SALERT_MAX_DETAIL_LEN];

    /* Notification */
    ozayn_salert_notify_state_t notify_state;
    int                         notify_count;
    int                         notify_channel;

    /* Deduplication */
    int                         dedup_count;
    time_t                      dedup_first_time;
    time_t                      dedup_last_time;

    /* Suppression */
    int                         suppressed;
    int                         suppression_reason;

    /* Escalation */
    int                         escalation_level;
    int                         escalation_count;
} ozayn_salert_alert_t;

/* ============================================================
 * SECTION 10 — ALERT POLICY
 * ============================================================ */

#define OZAYN_SALERT_MAX_ALERTS          512
#define OZAYN_SALERT_MAX_NOTIFY_QUEUE    128
#define OZAYN_SALERT_MAX_CORR_GROUPS     64
#define OZAYN_SALERT_MAX_DEDUP_STATE     256

typedef struct {
    int                         enabled;
    int                         max_active_alerts;
    int                         max_history;
    int                         dedup_window_seconds;
    int                         max_notify_per_window;
    int                         notify_window_seconds;
    int                         max_notify_retries;
    int                         alert_retention_seconds;
    int                         auto_suppress_duplicates;
    int                         require_ack_for_critical;
    int                         escalation_threshold;
    int                         escalation_window_seconds;
    int                         max_escalation_level;
} ozayn_salert_policy_t;

/* ============================================================
 * SECTION 11 — THRESHOLD DEFINITIONS
 * ============================================================ */

typedef struct {
    ozayn_salert_type_t         alert_type;
    int                         threshold_count;
    int                         window_seconds;
    ozayn_salert_severity_t     resulting_severity;
    int                         enabled;
} ozayn_salert_threshold_t;

#define OZAYN_SALERT_MAX_THRESHOLDS     32

/* ============================================================
 * SECTION 12 — NOTIFICATION PROVIDER
 * ============================================================ */

typedef struct {
    int (*notify)(const void *provider_ctx,
                  const ozayn_salert_alert_t *alert,
                  const char *safe_title,
                  const char *safe_body);
    int (*is_available)(const void *provider_ctx);
    const char *(*get_provider_id)(const void *provider_ctx);
    int (*get_capabilities)(const void *provider_ctx,
                            ozayn_salert_notify_channel_t *out_channels,
                            int max_channels);
} ozayn_salert_notify_provider_vtable_t;

typedef struct {
    const ozayn_salert_notify_provider_vtable_t *vtable;
    const void                              *context;
    int                                      registered;
    ozayn_salert_notify_channel_t           channel;
    int                                      enabled;
    int                                      available;
    int                                      fail_count;
    time_t                                  last_fail_time;
} ozayn_salert_notify_provider_t;

/* ============================================================
 * SECTION 13 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_sc_service_t         *config_service;
    ozayn_sh_service_t         *health_service;
    ozayn_sdiag_service_t      *diag_service;
    ozayn_ir_service_t         *incident_service;
    ozayn_audit_service_t      *audit;
    int                         max_alerts;
    int                         max_notify_queue;
    int                         max_thresholds;
} ozayn_salert_service_config_t;

/* ============================================================
 * SECTION 14 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                         initialized;

    /* Alerts (ring buffer) */
    ozayn_salert_alert_t        alerts[OZAYN_SALERT_MAX_ALERTS];
    int                         alert_head;
    int                         alert_count;
    uint32_t                    alert_sequence;

    /* Active alert tracking */
    int                         active_count;

    /* Notification queue */
    struct {
        uint32_t                alert_id_hash;
        ozayn_salert_notify_channel_t channel;
        time_t                  queued_time;
        int                     retry_count;
    } notify_queue[OZAYN_SALERT_MAX_NOTIFY_QUEUE];
    int                         notify_queue_head;
    int                         notify_queue_count;

    /* Providers */
    ozayn_salert_notify_provider_t providers[8];
    int                         provider_count;

    /* Thresholds */
    ozayn_salert_threshold_t    thresholds[OZAYN_SALERT_MAX_THRESHOLDS];
    int                         threshold_count;

    /* Threshold counters (per type, ring per window) */
    struct {
        ozayn_salert_type_t     alert_type;
        int                     counts[16];
        time_t                  window_start;
        int                     window_index;
    } threshold_state[OZAYN_SALERT_MAX_THRESHOLDS];

    /* Deduplication state */
    struct {
        char                    dedup_key[OZAYN_SALERT_MAX_DEDUP_KEY_LEN];
        uint32_t                alert_id_hash;
        time_t                  first_time;
        time_t                  last_time;
        int                     count;
    } dedup_state[OZAYN_SALERT_MAX_DEDUP_STATE];
    int                         dedup_count;

    /* Policy */
    ozayn_salert_policy_t       policy;

    /* Dependencies (not owned) */
    ozayn_sc_service_t         *config_service;
    ozayn_sh_service_t         *health_service;
    ozayn_sdiag_service_t      *diag_service;
    ozayn_ir_service_t         *incident_service;
    ozayn_audit_service_t      *audit;

    /* Limits */
    int                         max_concurrent_ops;
    int                         active_ops;

    /* Stats */
    uint64_t                    total_alerts_created;
    uint64_t                    total_alerts_deduplicated;
    uint64_t                    total_alerts_suppressed;
    uint64_t                    total_alerts_resolved;
    uint64_t                    total_notifications_sent;
    uint64_t                    total_notifications_failed;
    uint64_t                    total_rate_limited;
    uint64_t                    total_escalations;
} ozayn_salert_service_t;

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_service_init(
    ozayn_salert_service_t *svc,
    const ozayn_salert_service_config_t *cfg);

void ozayn_salert_service_shutdown(ozayn_salert_service_t *svc);

int ozayn_salert_service_is_initialized(const ozayn_salert_service_t *svc);

/* ============================================================
 * SECTION 16 — ALERT CREATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_create(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t type,
    ozayn_salert_severity_t severity,
    ozayn_salert_priority_t priority,
    ozayn_salert_source_t source,
    const char *source_component,
    const char *correlation_id,
    const char *safe_summary,
    const char *safe_detail,
    ozayn_salert_alert_t **out_alert);

/* ============================================================
 * SECTION 17 — ALERT QUERY
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_get(
    const ozayn_salert_service_t *svc,
    const char *alert_id,
    ozayn_salert_alert_t **out_alert);

int ozayn_salert_list(
    const ozayn_salert_service_t *svc,
    int filter_type,
    int filter_state,
    ozayn_salert_alert_t **out_alerts,
    int max_count);

int ozayn_salert_get_active_count(const ozayn_salert_service_t *svc);

int ozayn_salert_get_total_count(const ozayn_salert_service_t *svc);

/* ============================================================
 * SECTION 18 — ALERT LIFECYCLE
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_acknowledge(
    ozayn_salert_service_t *svc,
    const char *alert_id);

ozayn_salert_err_t ozayn_salert_resolve(
    ozayn_salert_service_t *svc,
    const char *alert_id);

ozayn_salert_err_t ozayn_salert_suppress(
    ozayn_salert_service_t *svc,
    const char *alert_id,
    int reason);

ozayn_salert_err_t ozayn_salert_cancel(
    ozayn_salert_service_t *svc,
    const char *alert_id);

/* ============================================================
 * SECTION 19 — ESCALATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_escalate(
    ozayn_salert_service_t *svc,
    const char *alert_id);

int ozayn_salert_get_escalation_level(
    const ozayn_salert_service_t *svc,
    const char *alert_id);

/* ============================================================
 * SECTION 20 — DEDUPLICATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_check_dedup(
    ozayn_salert_service_t *svc,
    const char *dedup_key,
    int *is_duplicate,
    uint32_t *existing_alert_hash);

ozayn_salert_err_t ozayn_salert_register_dedup(
    ozayn_salert_service_t *svc,
    const char *dedup_key,
    uint32_t alert_id_hash);

int ozayn_salert_is_in_dedup_window(
    const ozayn_salert_service_t *svc,
    const char *dedup_key);

/* ============================================================
 * SECTION 21 — THRESHOLD MANAGEMENT
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_add_threshold(
    ozayn_salert_service_t *svc,
    const ozayn_salert_threshold_t *threshold);

ozayn_salert_err_t ozayn_salert_check_threshold(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type,
    int *threshold_exceeded,
    ozayn_salert_severity_t *resulting_severity);

ozayn_salert_err_t ozayn_salert_record_threshold_event(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type);

/* ============================================================
 * SECTION 22 — NOTIFICATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_register_provider(
    ozayn_salert_service_t *svc,
    const ozayn_salert_notify_provider_vtable_t *vtable,
    const void *context,
    ozayn_salert_notify_channel_t channel);

ozayn_salert_err_t ozayn_salert_queue_notification(
    ozayn_salert_service_t *svc,
    const char *alert_id,
    ozayn_salert_notify_channel_t channel);

ozayn_salert_err_t ozayn_salert_process_notifications(
    ozayn_salert_service_t *svc);

int ozayn_salert_get_notify_queue_count(
    const ozayn_salert_service_t *svc);

/* ============================================================
 * SECTION 23 — RATE LIMITING
 * ============================================================ */

int ozayn_salert_check_rate_limit(
    const ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type);

ozayn_salert_err_t ozayn_salert_record_rate_event(
    ozayn_salert_service_t *svc,
    ozayn_salert_type_t alert_type);

/* ============================================================
 * SECTION 24 — HEALTH INTEGRATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_evaluate_health(
    ozayn_salert_service_t *svc);

/* ============================================================
 * SECTION 25 — DIAGNOSTIC INTEGRATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_evaluate_diagnostics(
    ozayn_salert_service_t *svc);

/* ============================================================
 * SECTION 26 — INCIDENT INTEGRATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_evaluate_incidents(
    ozayn_salert_service_t *svc);

/* ============================================================
 * SECTION 27 — POLICY
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_set_policy(
    ozayn_salert_service_t *svc,
    const ozayn_salert_policy_t *policy);

const ozayn_salert_policy_t *ozayn_salert_get_policy(
    const ozayn_salert_service_t *svc);

ozayn_salert_policy_t ozayn_salert_default_policy(void);

/* ============================================================
 * SECTION 28 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_salert_state_transition_valid(
    ozayn_salert_state_t from,
    ozayn_salert_state_t to);

/* ============================================================
 * SECTION 29 — NAME HELPERS
 * ============================================================ */

const char *ozayn_salert_err_name(ozayn_salert_err_t r);

const char *ozayn_salert_type_name(ozayn_salert_type_t t);

const char *ozayn_salert_severity_name(ozayn_salert_severity_t s);

const char *ozayn_salert_priority_name(ozayn_salert_priority_t p);

const char *ozayn_salert_state_name(ozayn_salert_state_t s);

const char *ozayn_salert_source_name(ozayn_salert_source_t s);

const char *ozayn_salert_notify_channel_name(ozayn_salert_notify_channel_t c);

const char *ozayn_salert_notify_state_name(ozayn_salert_notify_state_t s);

/* ============================================================
 * SECTION 30 — SEVERITY / PRIORITY HELPERS
 * ============================================================ */

ozayn_salert_severity_t ozayn_salert_worse_severity(
    ozayn_salert_severity_t a,
    ozayn_salert_severity_t b);

ozayn_salert_priority_t ozayn_salert_higher_priority(
    ozayn_salert_priority_t a,
    ozayn_salert_priority_t b);

int ozayn_salert_severity_meets_threshold(
    ozayn_salert_severity_t severity,
    ozayn_salert_severity_t threshold);

/* ============================================================
 * SECTION 31 — SAFE CONTENT GENERATION
 * ============================================================ */

ozayn_salert_err_t ozayn_salert_generate_safe_title(
    const ozayn_salert_alert_t *alert,
    char *out_title,
    int max_len);

ozayn_salert_err_t ozayn_salert_generate_safe_body(
    const ozayn_salert_alert_t *alert,
    char *out_body,
    int max_len);

/* ============================================================
 * SECTION 32 — CLEANUP
 * ============================================================ */

int ozayn_salert_cleanup_expired(ozayn_salert_service_t *svc);

int ozayn_salert_cleanup_resolved(ozayn_salert_service_t *svc,
                                   int max_age_seconds);

/* ============================================================
 * SECTION 33 — GLOBAL SERVICE ACCESSOR
 * ============================================================ */

ozayn_salert_service_t *ozayn_salert_get_global(void);

#endif /* OZAYN_SEC_ALERT_H */
