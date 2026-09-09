/*
 * sec_notify.h — Security Notification Routing & Delivery Foundation (Step 30).
 *
 * Determines WHERE, WHEN, and HOW an approved alert notification is routed
 * and delivered.  Operates downstream of security enforcement and alerting.
 *
 * Flow:
 *   SECURITY CONDITION → ALERT (Step 29) → ROUTING → POLICY → QUEUE
 *   → PROVIDER → DELIVERY RESULT → AUDIT
 *
 * Design:
 *   - Notification delivery must NEVER weaken security controls
 *   - Providers never receive secrets
 *   - Routing is deterministic and policy-controlled
 *   - Fallback only when explicitly permitted by policy
 *   - All operations auditable
 */

#ifndef OZAYN_SEC_NOTIFY_H
#define OZAYN_SEC_NOTIFY_H

#include "sec_alert.h"
#include "sec_config.h"
#include "audit.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SNOTIFY_OK                       =   0,
    OZAYN_SNOTIFY_ERR_NULL                 =  -1,
    OZAYN_SNOTIFY_ERR_NOT_INITIALIZED      =  -2,
    OZAYN_SNOTIFY_ERR_ALREADY_INITIALIZED  =  -3,
    OZAYN_SNOTIFY_ERR_INVALID_PARAM        =  -4,
    OZAYN_SNOTIFY_ERR_LIMIT_REACHED        =  -5,
    OZAYN_SNOTIFY_ERR_NOT_FOUND            =  -6,
    OZAYN_SNOTIFY_ERR_STATE_INVALID        =  -7,
    OZAYN_SNOTIFY_ERR_STATE_TRANSITION     =  -8,
    OZAYN_SNOTIFY_ERR_POLICY_REJECTED      =  -9,
    OZAYN_SNOTIFY_ERR_RATE_LIMITED         = -10,
    OZAYN_SNOTIFY_ERR_PROVIDER_UNAVAILABLE = -11,
    OZAYN_SNOTIFY_ERR_PROVIDER_FAILED      = -12,
    OZAYN_SNOTIFY_ERR_ROUTING_FAILED       = -13,
    OZAYN_SNOTIFY_ERR_DESTINATION_INVALID  = -14,
    OZAYN_SNOTIFY_ERR_DESTINATION_DISABLED = -15,
    OZAYN_SNOTIFY_ERR_DESTINATION_REVOKED  = -16,
    OZAYN_SNOTIFY_ERR_QUEUE_FULL           = -17,
    OZAYN_SNOTIFY_ERR_EXPIRED              = -18,
    OZAYN_SNOTIFY_ERR_RETRY_EXHAUSTED      = -19,
    OZAYN_SNOTIFY_ERR_TIMEOUT              = -20,
    OZAYN_SNOTIFY_ERR_CLASSIFICATION       = -21,
    OZAYN_SNOTIFY_ERR_CONTENT_REJECTED     = -22,
    OZAYN_SNOTIFY_ERR_CONFLICT             = -23,
    OZAYN_SNOTIFY_ERR_UNAVAILABLE          = -24
} ozayn_snotify_err_t;

/* ============================================================
 * SECTION 2 — NOTIFICATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_SNOTIFY_STATE_CREATED            = 0,
    OZAYN_SNOTIFY_STATE_ROUTING            = 1,
    OZAYN_SNOTIFY_STATE_QUEUED             = 2,
    OZAYN_SNOTIFY_STATE_DELIVERING         = 3,
    OZAYN_SNOTIFY_STATE_DELIVERED          = 4,
    OZAYN_SNOTIFY_STATE_DELIVERY_FAILED    = 5,
    OZAYN_SNOTIFY_STATE_RETRY_SCHEDULED    = 6,
    OZAYN_SNOTIFY_STATE_EXHAUSTED          = 7,
    OZAYN_SNOTIFY_STATE_EXPIRED            = 8,
    OZAYN_SNOTIFY_STATE_CANCELLED          = 9
} ozayn_snotify_state_t;

/* ============================================================
 * SECTION 3 — DELIVERY RESULTS
 * ============================================================ */

typedef enum {
    OZAYN_SNOTIFY_RESULT_NONE              = 0,
    OZAYN_SNOTIFY_RESULT_SUCCESS           = 1,
    OZAYN_SNOTIFY_RESULT_TEMPORARY_FAILURE = 2,
    OZAYN_SNOTIFY_RESULT_PERMANENT_FAILURE = 3,
    OZAYN_SNOTIFY_RESULT_UNAVAILABLE       = 4,
    OZAYN_SNOTIFY_RESULT_REJECTED          = 5,
    OZAYN_SNOTIFY_RESULT_TIMEOUT           = 6,
    OZAYN_SNOTIFY_RESULT_EXPIRED           = 7,
    OZAYN_SNOTIFY_RESULT_CANCELLED         = 8
} ozayn_snotify_result_t;

/* ============================================================
 * SECTION 4 — DESTINATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_SNOTIFY_DEST_UNINITIALIZED       = 0,
    OZAYN_SNOTIFY_DEST_AVAILABLE           = 1,
    OZAYN_SNOTIFY_DEST_DISABLED            = 2,
    OZAYN_SNOTIFY_DEST_UNAVAILABLE         = 3,
    OZAYN_SNOTIFY_DEST_SUSPENDED           = 4,
    OZAYN_SNOTIFY_DEST_REVOKED             = 5
} ozayn_snotify_dest_state_t;

/* ============================================================
 * SECTION 5 — DESTINATION TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SNOTIFY_DEST_TYPE_UNKNOWN        = 0,
    OZAYN_SNOTIFY_DEST_TYPE_LOCAL          = 1,
    OZAYN_SNOTIFY_DEST_TYPE_CONSOLE        = 2,
    OZAYN_SNOTIFY_DEST_TYPE_CALLBACK       = 3,
    OZAYN_SNOTIFY_DEST_TYPE_FILE           = 4,
    OZAYN_SNOTIFY_DEST_TYPE_SOCKET         = 5
} ozayn_snotify_dest_type_t;

/* ============================================================
 * SECTION 6 — SECURITY CLASSIFICATION
 * ============================================================ */

typedef enum {
    OZAYN_SNOTIFY_CLASS_PUBLIC             = 0,
    OZAYN_SNOTIFY_CLASS_INTERNAL           = 1,
    OZAYN_SNOTIFY_CLASS_SENSITIVE          = 2,
    OZAYN_SNOTIFY_CLASS_HIGHLY_SENSITIVE   = 3
} ozayn_snotify_classification_t;

/* ============================================================
 * SECTION 7 — NOTIFICATION CONTENT
 * ============================================================ */

typedef struct {
    char title[256];
    char body[512];
    char reference_id[64];
    ozayn_snotify_classification_t classification;
} ozayn_snotify_content_t;

/* ============================================================
 * SECTION 8 — NOTIFICATION DESTINATION
 * ============================================================ */

#define OZAYN_SNOTIFY_MAX_DEST_ID_LEN     64
#define OZAYN_SNOTIFY_MAX_DEST_NAME_LEN  128
#define OZAYN_SNOTIFY_MAX_DEST_META_LEN  256

typedef struct {
    char dest_id[OZAYN_SNOTIFY_MAX_DEST_ID_LEN];
    char name[OZAYN_SNOTIFY_MAX_DEST_NAME_LEN];
    ozayn_salert_notify_channel_t channel;
    ozayn_snotify_dest_type_t dest_type;
    ozayn_snotify_dest_state_t state;
    ozayn_snotify_classification_t max_classification;
    char safe_metadata[OZAYN_SNOTIFY_MAX_DEST_META_LEN];
    time_t created_time;
    time_t updated_time;
    int valid_transitions[6];
} ozayn_snotify_destination_t;

/* ============================================================
 * SECTION 9 — NOTIFICATION ROUTING RULE
 * ============================================================ */

#define OZAYN_SNOTIFY_MAX_RULE_ID_LEN     64

typedef struct {
    char rule_id[OZAYN_SNOTIFY_MAX_RULE_ID_LEN];
    int enabled;
    int priority_order;
    ozayn_salert_severity_t min_severity;
    ozayn_salert_severity_t max_severity;
    ozayn_salert_priority_t min_priority;
    ozayn_salert_priority_t max_priority;
    ozayn_salert_type_t alert_type;
    int type_filter_active;
    ozayn_salert_notify_channel_t required_channel;
    int require_channel;
    ozayn_salert_notify_channel_t fallback_channel;
    int has_fallback;
    int enabled_channels[7];
} ozayn_snotify_routing_rule_t;

/* ============================================================
 * SECTION 10 — RETRY POLICY
 * ============================================================ */

typedef struct {
    int max_retries;
    int base_delay_ms;
    int max_delay_ms;
    double backoff_multiplier;
    int jitter_enabled;
    int expiration_seconds;
} ozayn_snotify_retry_policy_t;

/* ============================================================
 * SECTION 11 — NOTIFICATION POLICY
 * ============================================================ */

typedef struct {
    int enabled;
    int enabled_channels[7];
    ozayn_snotify_retry_policy_t retry_policy;
    int timeout_seconds;
    int expiration_seconds;
    int max_rate_per_window;
    int rate_window_seconds;
    int max_queue_size;
    int max_destinations;
    int max_providers;
    int max_routing_rules;
    ozayn_snotify_classification_t default_classification;
    int max_notification_size;
    int max_metadata_size;
} ozayn_snotify_policy_t;

/* ============================================================
 * SECTION 12 — NOTIFICATION MODEL
 * ============================================================ */

#define OZAYN_SNOTIFY_MAX_NOTIF_ID_LEN    64
#define OZAYN_SNOTIFY_MAX_ALERT_REF_LEN   64
#define OZAYN_SNOTIFY_MAX_DEST_REF_LEN    64
#define OZAYN_SNOTIFY_MAX_CORR_ID_LEN     64
#define OZAYN_SNOTIFY_MAX_POLICY_REF_LEN  64
#define OZAYN_SNOTIFY_MAX_META_LEN       256

typedef struct {
    char notif_id[OZAYN_SNOTIFY_MAX_NOTIF_ID_LEN];
    uint32_t notif_version;
    char alert_id[OZAYN_SNOTIFY_MAX_ALERT_REF_LEN];
    char dest_id[OZAYN_SNOTIFY_MAX_DEST_REF_LEN];
    ozayn_salert_notify_channel_t channel;
    ozayn_salert_severity_t severity;
    ozayn_salert_priority_t priority;
    ozayn_snotify_state_t state;
    ozayn_snotify_result_t delivery_result;
    time_t created_time;
    time_t scheduled_time;
    time_t expiration_time;
    int attempt_count;
    time_t last_attempt_time;
    time_t next_retry_time;
    int max_attempts;
    char correlation_id[OZAYN_SNOTIFY_MAX_CORR_ID_LEN];
    char policy_ref[OZAYN_SNOTIFY_MAX_POLICY_REF_LEN];
    char safe_metadata[OZAYN_SNOTIFY_MAX_META_LEN];
    ozayn_snotify_content_t content;
    ozayn_snotify_classification_t classification;
} ozayn_snotify_notification_t;

/* ============================================================
 * SECTION 13 — DELIVERY RESULT RECORD
 * ============================================================ */

typedef struct {
    char notif_id[OZAYN_SNOTIFY_MAX_NOTIF_ID_LEN];
    char provider_id[64];
    ozayn_salert_notify_channel_t channel;
    ozayn_snotify_result_t result;
    ozayn_snotify_state_t delivery_state;
    int attempt_number;
    time_t timestamp;
    int retry_recommended;
    char safe_failure_code[128];
    char safe_metadata[OZAYN_SNOTIFY_MAX_META_LEN];
} ozayn_snotify_delivery_result_t;

/* ============================================================
 * SECTION 14 — NOTIFICATION PROVIDER ABSTRACTION
 * ============================================================ */

typedef struct {
    int (*send)(const void *provider_ctx,
                const ozayn_snotify_notification_t *notif,
                const ozayn_snotify_content_t *content,
                ozayn_snotify_delivery_result_t *out_result);
    int (*is_available)(const void *provider_ctx);
    const char *(*get_provider_id)(const void *provider_ctx);
    int (*get_channel)(const void *provider_ctx,
                       ozayn_salert_notify_channel_t *out_channel);
    int (*validate_destination)(const void *provider_ctx,
                                const ozayn_snotify_destination_t *dest);
    int (*get_timeout_ms)(const void *provider_ctx);
} ozayn_snotify_provider_vtable_t;

typedef struct {
    const ozayn_snotify_provider_vtable_t *vtable;
    const void *context;
    int registered;
    int enabled;
    int available;
    ozayn_salert_notify_channel_t channel;
    int fail_count;
    time_t last_fail_time;
    time_t last_available_check;
} ozayn_snotify_provider_t;

/* ============================================================
 * SECTION 15 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_salert_service_t *alert_service;
    ozayn_sc_service_t *config_service;
    ozayn_audit_service_t *audit;
    int max_notifications;
    int max_destinations;
    int max_routing_rules;
    int max_providers;
    int max_delivery_results;
} ozayn_snotify_service_config_t;

/* ============================================================
 * SECTION 16 — SERVICE STATE
 * ============================================================ */

#define OZAYN_SNOTIFY_MAX_NOTIFICATIONS   256
#define OZAYN_SNOTIFY_MAX_DESTINATIONS     32
#define OZAYN_SNOTIFY_MAX_ROUTING_RULES    32
#define OZAYN_SNOTIFY_MAX_PROVIDERS         8
#define OZAYN_SNOTIFY_MAX_DELIVERY_RESULTS 128

typedef struct {
    int initialized;

    /* Notifications ring buffer */
    ozayn_snotify_notification_t notifications[OZAYN_SNOTIFY_MAX_NOTIFICATIONS];
    int notif_head;
    int notif_count;
    uint32_t notif_sequence;

    /* Destinations */
    ozayn_snotify_destination_t destinations[OZAYN_SNOTIFY_MAX_DESTINATIONS];
    int dest_count;

    /* Routing rules */
    ozayn_snotify_routing_rule_t rules[OZAYN_SNOTIFY_MAX_ROUTING_RULES];
    int rule_count;

    /* Providers */
    ozayn_snotify_provider_t providers[OZAYN_SNOTIFY_MAX_PROVIDERS];
    int provider_count;

    /* Delivery results ring buffer */
    ozayn_snotify_delivery_result_t results[OZAYN_SNOTIFY_MAX_DELIVERY_RESULTS];
    int result_head;
    int result_count;

    /* Policy */
    ozayn_snotify_policy_t policy;

    /* Dependencies */
    ozayn_salert_service_t *alert_service;
    ozayn_sc_service_t *config_service;
    ozayn_audit_service_t *audit;

    /* Statistics */
    uint64_t total_created;
    uint64_t total_routed;
    uint64_t total_queued;
    uint64_t total_delivered;
    uint64_t total_failed;
    uint64_t total_expired;
    uint64_t total_cancelled;
    uint64_t total_retries;
    uint64_t total_rate_limited;
    uint64_t total_routing_failed;
    uint64_t total_classified_rejected;
} ozayn_snotify_service_t;

/* ============================================================
 * SECTION 17 — LIFECYCLE
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_service_init(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_service_config_t *cfg);

void ozayn_snotify_service_shutdown(ozayn_snotify_service_t *svc);

int ozayn_snotify_service_is_initialized(
    const ozayn_snotify_service_t *svc);

/* ============================================================
 * SECTION 18 — STATE HELPERS
 * ============================================================ */

const char *ozayn_snotify_state_name(ozayn_snotify_state_t state);
const char *ozayn_snotify_result_name(ozayn_snotify_result_t result);
const char *ozayn_snotify_dest_state_name(ozayn_snotify_dest_state_t state);
const char *ozayn_snotify_dest_type_name(ozayn_snotify_dest_type_t type);
const char *ozayn_snotify_classification_name(ozayn_snotify_classification_t c);
const char *ozayn_snotify_err_name(ozayn_snotify_err_t err);

int ozayn_snotify_state_transition_valid(
    ozayn_snotify_state_t from,
    ozayn_snotify_state_t to);

int ozayn_snotify_dest_transition_valid(
    ozayn_snotify_dest_state_t from,
    ozayn_snotify_dest_state_t to);

/* ============================================================
 * SECTION 19 — DESTINATION MANAGEMENT
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_dest_add(
    ozayn_snotify_service_t *svc,
    const char *dest_id,
    const char *name,
    ozayn_salert_notify_channel_t channel,
    ozayn_snotify_dest_type_t dest_type,
    ozayn_snotify_classification_t max_classification,
    const char *safe_metadata,
    ozayn_snotify_destination_t **out_dest);

ozayn_snotify_err_t ozayn_snotify_dest_remove(
    ozayn_snotify_service_t *svc,
    const char *dest_id);

ozayn_snotify_destination_t *ozayn_snotify_dest_get(
    ozayn_snotify_service_t *svc,
    const char *dest_id);

int ozayn_snotify_dest_count(
    const ozayn_snotify_service_t *svc);

ozayn_snotify_err_t ozayn_snotify_dest_set_state(
    ozayn_snotify_service_t *svc,
    const char *dest_id,
    ozayn_snotify_dest_state_t new_state);

int ozayn_snotify_dest_is_usable(
    const ozayn_snotify_destination_t *dest);

/* ============================================================
 * SECTION 20 — ROUTING RULES
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_routing_add(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_routing_rule_t *rule);

ozayn_snotify_err_t ozayn_snotify_routing_remove(
    ozayn_snotify_service_t *svc,
    const char *rule_id);

ozayn_snotify_err_t ozayn_snotify_routing_evaluate(
    const ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert,
    ozayn_salert_notify_channel_t *out_channel,
    char *out_dest_id,
    int max_dest_len);

ozayn_snotify_err_t ozayn_snotify_routing_evaluate_default(
    const ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert,
    ozayn_salert_notify_channel_t *out_channel);

/* ============================================================
 * SECTION 21 — NOTIFICATION POLICY
 * ============================================================ */

ozayn_snotify_policy_t ozayn_snotify_default_policy(void);

ozayn_snotify_err_t ozayn_snotify_set_policy(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_policy_t *policy);

const ozayn_snotify_policy_t *ozayn_snotify_get_policy(
    const ozayn_snotify_service_t *svc);

int ozayn_snotify_channel_enabled(
    const ozayn_snotify_service_t *svc,
    ozayn_salert_notify_channel_t channel);

/* ============================================================
 * SECTION 22 — NOTIFICATION CREATION & ROUTING
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_create(
    ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert,
    ozayn_snotify_notification_t **out_notif);

ozayn_snotify_err_t ozayn_snotify_route(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif);

ozayn_snotify_err_t ozayn_snotify_enqueue(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif);

/* ============================================================
 * SECTION 23 — DELIVERY
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_deliver(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif);

ozayn_snotify_err_t ozayn_snotify_process_queue(
    ozayn_snotify_service_t *svc);

/* ============================================================
 * SECTION 24 — RETRY & BACKOFF
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_retry(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif);

int ozayn_snotify_calculate_backoff_ms(
    const ozayn_snotify_retry_policy_t *policy,
    int attempt);

int ozayn_snotify_retry_allowed(
    const ozayn_snotify_notification_t *notif);

/* ============================================================
 * SECTION 25 — EXPIRATION
 * ============================================================ */

int ozayn_snotify_is_expired(
    const ozayn_snotify_notification_t *notif);

ozayn_snotify_err_t ozayn_snotify_expire(
    ozayn_snotify_service_t *svc,
    ozayn_snotify_notification_t *notif);

int ozayn_snotify_cleanup_expired(
    ozayn_snotify_service_t *svc);

/* ============================================================
 * SECTION 26 — QUERY
 * ============================================================ */

ozayn_snotify_notification_t *ozayn_snotify_get(
    ozayn_snotify_service_t *svc,
    const char *notif_id);

int ozayn_snotify_list(
    const ozayn_snotify_service_t *svc,
    int filter_state,
    ozayn_snotify_notification_t **out_notifs,
    int max_count);

int ozayn_snotify_get_queue_count(
    const ozayn_snotify_service_t *svc);

int ozayn_snotify_get_total_count(
    const ozayn_snotify_service_t *svc);

/* ============================================================
 * SECTION 27 — DELIVERY RESULTS
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_record_result(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_delivery_result_t *result);

ozayn_snotify_err_t ozayn_snotify_get_last_result(
    const ozayn_snotify_service_t *svc,
    const char *notif_id,
    ozayn_snotify_delivery_result_t *out_result);

/* ============================================================
 * SECTION 28 — ALERT INTEGRATION
 * ============================================================ */

int ozayn_snotify_should_notify(
    const ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert);

ozayn_snotify_err_t ozayn_snotify_process_alert(
    ozayn_snotify_service_t *svc,
    const ozayn_salert_alert_t *alert);

/* ============================================================
 * SECTION 29 — CANCELLATION
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_cancel(
    ozayn_snotify_service_t *svc,
    const char *notif_id);

/* ============================================================
 * SECTION 30 — PROVIDER MANAGEMENT
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_register_provider(
    ozayn_snotify_service_t *svc,
    const ozayn_snotify_provider_vtable_t *vtable,
    const void *context,
    ozayn_salert_notify_channel_t channel);

ozayn_snotify_err_t ozayn_snotify_unregister_provider(
    ozayn_snotify_service_t *svc,
    const char *provider_id);

ozayn_snotify_provider_t *ozayn_snotify_get_provider(
    ozayn_snotify_service_t *svc,
    ozayn_salert_notify_channel_t channel);

/* ============================================================
 * SECTION 31 — CONCURRENCY & RESOURCE SAFETY
 * ============================================================ */

int ozayn_snotify_queue_is_full(
    const ozayn_snotify_service_t *svc);

int ozayn_snotify_dest_is_full(
    const ozayn_snotify_service_t *svc);

int ozayn_snotify_rule_is_full(
    const ozayn_snotify_service_t *svc);

/* ============================================================
 * SECTION 32 — RATE LIMITING
 * ============================================================ */

int ozayn_snotify_check_rate_limit(
    ozayn_snotify_service_t *svc,
    ozayn_salert_notify_channel_t channel);

/* ============================================================
 * SECTION 33 — AUDIT INTEGRATION
 * ============================================================ */

ozayn_snotify_err_t ozayn_snotify_audit_event(
    ozayn_snotify_service_t *svc,
    const char *event_type,
    const ozayn_snotify_notification_t *notif);

/* ============================================================
 * SECTION 34 — CLASSIFICATION
 * ============================================================ */

ozayn_snotify_classification_t ozayn_snotify_severity_to_classification(
    ozayn_salert_severity_t severity);

int ozayn_snotify_classification_allows_channel(
    ozayn_snotify_classification_t classification,
    ozayn_salert_notify_channel_t channel);

/* ============================================================
 * SECTION 35 — RETRY POLICY HELPERS
 * ============================================================ */

ozayn_snotify_retry_policy_t ozayn_snotify_default_retry_policy(void);

int ozayn_snotify_result_is_retryable(ozayn_snotify_result_t result);

/* ============================================================
 * SECTION 36 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_snotify_service_t *ozayn_snotify_get_global(void);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SEC_NOTIFY_H */
