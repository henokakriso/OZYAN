#ifndef OZAYN_OPERATIONAL_ALERT_H
#define OZAYN_OPERATIONAL_ALERT_H

#include <stdint.h>
#include <time.h>

#define OZAYN_OAN_MAX_ALERT_NAME        64
#define OZAYN_OAN_MAX_ALERT_TITLE       128
#define OZAYN_OAN_MAX_ALERT_DESC        256
#define OZAYN_OAN_MAX_ALERT_SOURCE      64
#define OZAYN_OAN_MAX_ALERT_ID_LEN      64
#define OZAYN_OAN_MAX_CORRELATION_LEN   64
#define OZAYN_OAN_MAX_RULE_NAME         64
#define OZAYN_OAN_MAX_RULE_DESC         128
#define OZAYN_OAN_MAX_NOTIF_TITLE       128
#define OZAYN_OAN_MAX_NOTIF_BODY        256
#define OZAYN_OAN_MAX_NOTIF_CHANNEL     32
#define OZAYN_OAN_MAX_RECIPIENT_LEN     64
#define OZAYN_OAN_MAX_GROUP_KEY         64

#define OZAYN_OAN_MAX_ALERTS            256
#define OZAYN_OAN_MAX_RULES             128
#define OZAYN_OAN_MAX_NOTIFICATIONS     64
#define OZAYN_OAN_MAX_POLICIES          32
#define OZAYN_OAN_MAX_DEDUP             64
#define OZAYN_OAN_MAX_QUERY_RESULTS     32

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_OAN_ERR_OK = 0,
    OZAYN_OAN_ERR_NULL_PTR,
    OZAYN_OAN_ERR_NOT_INITIALIZED,
    OZAYN_OAN_ERR_ALREADY_INITIALIZED,
    OZAYN_OAN_ERR_NOT_FOUND,
    OZAYN_OAN_ERR_FULL,
    OZAYN_OAN_ERR_DUPLICATE,
    OZAYN_OAN_ERR_INVALID_PARAM,
    OZAYN_OAN_ERR_INVALID_STATE,
    OZAYN_OAN_ERR_STATE_TRANSITION,
    OZAYN_OAN_ERR_EXPIRED,
    OZAYN_OAN_ERR_SUPPRESSED,
    OZAYN_OAN_ERR_RATE_LIMITED,
    OZAYN_OAN_ERR_RULE_DISABLED,
    OZAYN_OAN_ERR_RULE_EVAL_FAILED,
    OZAYN_OAN_ERR_NOTIFICATION_FULL,
    OZAYN_OAN_ERR_NOTIFICATION_FAILED,
    OZAYN_OAN_ERR_NOTIFICATION_UNAVAILABLE,
    OZAYN_OAN_ERR_NOTIFICATION_RETRY_LIMIT,
    OZAYN_OAN_ERR_NOTIFICATION_EXPIRED,
    OZAYN_OAN_ERR_AUTH_FAILED,
    OZAYN_OAN_ERR_UNAVAILABLE,
    OZAYN_OAN_ERR_INTERNAL
} ozayn_oan_err_t;

/* ============================================================
 * ALERT CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_OAN_CAT_SYSTEM = 0,
    OZAYN_OAN_CAT_PERFORMANCE,
    OZAYN_OAN_CAT_RESOURCE,
    OZAYN_OAN_CAT_DEVICE,
    OZAYN_OAN_CAT_OPERATION,
    OZAYN_OAN_CAT_WORKFLOW,
    OZAYN_OAN_CAT_PIPELINE,
    OZAYN_OAN_CAT_EXECUTION,
    OZAYN_OAN_CAT_FAILURE,
    OZAYN_OAN_CAT_SECURITY,
    OZAYN_OAN_CAT_SAFETY,
    OZAYN_OAN_CAT_READINESS,
    OZAYN_OAN_CAT_RECOVERY,
    OZAYN_OAN_CAT_CONFIGURATION,
    OZAYN_OAN_CAT_EVENT,
    OZAYN_OAN_CAT_STORAGE,
    OZAYN_OAN_CAT_CAPACITY,
    OZAYN_OAN_CAT_COUNT
} ozayn_oan_category_t;

/* ============================================================
 * ALERT SEVERITY
 * ============================================================ */

typedef enum {
    OZAYN_OAN_SEV_INFO = 0,
    OZAYN_OAN_SEV_LOW,
    OZAYN_OAN_SEV_MEDIUM,
    OZAYN_OAN_SEV_HIGH,
    OZAYN_OAN_SEV_CRITICAL
} ozayn_oan_severity_t;

/* ============================================================
 * ALERT STATES
 * ============================================================ */

typedef enum {
    OZAYN_OAN_STATE_CREATED = 0,
    OZAYN_OAN_STATE_ACTIVE,
    OZAYN_OAN_STATE_ACKNOWLEDGED,
    OZAYN_OAN_STATE_SUPPRESSED,
    OZAYN_OAN_STATE_RESOLVED,
    OZAYN_OAN_STATE_EXPIRED,
    OZAYN_OAN_STATE_CANCELLED,
    OZAYN_OAN_STATE_CLOSED
} ozayn_oan_state_t;

/* ============================================================
 * ALERT SOURCES
 * ============================================================ */

typedef enum {
    OZAYN_OAN_SRC_EVENT_ENGINE = 0,
    OZAYN_OAN_SRC_TIMELINE,
    OZAYN_OAN_SRC_METRICS,
    OZAYN_OAN_SRC_DIAGNOSTICS,
    OZAYN_OAN_SRC_HEALTH,
    OZAYN_OAN_SRC_FAILURE,
    OZAYN_OAN_SRC_RESOURCE,
    OZAYN_OAN_SRC_DEVICE,
    OZAYN_OAN_SRC_READINESS,
    OZAYN_OAN_SRC_MODE,
    OZAYN_OAN_SRC_OPERATION,
    OZAYN_OAN_SRC_WORKFLOW,
    OZAYN_OAN_SRC_PIPELINE,
    OZAYN_OAN_SRC_MANUAL,
    OZAYN_OAN_SRC_COUNT
} ozayn_oan_source_t;

/* ============================================================
 * ALERT TRIGGER TYPES
 * ============================================================ */

typedef enum {
    OZAYN_OAN_TRIGGER_EVENT = 0,
    OZAYN_OAN_TRIGGER_METRIC_THRESHOLD,
    OZAYN_OAN_TRIGGER_FAILURE,
    OZAYN_OAN_TRIGGER_HEALTH_CHANGE,
    OZAYN_OAN_TRIGGER_RESOURCE_THRESHOLD,
    OZAYN_OAN_TRIGGER_DEVICE_STATE,
    OZAYN_OAN_TRIGGER_READINESS_CHANGE,
    OZAYN_OAN_TRIGGER_MODE_CHANGE,
    OZAYN_OAN_TRIGGER_OPERATION_FAILURE,
    OZAYN_OAN_TRIGGER_WORKFLOW_FAILURE,
    OZAYN_OAN_TRIGGER_PIPELINE_FAILURE,
    OZAYN_OAN_TRIGGER_RECOVERY_FAILURE,
    OZAYN_OAN_TRIGGER_CONFIG_CHANGE,
    OZAYN_OAN_TRIGGER_COUNT
} ozayn_oan_trigger_type_t;

/* ============================================================
 * NOTIFICATION CHANNELS
 * ============================================================ */

typedef enum {
    OZAYN_OAN_CHAN_INTERNAL_EVENT = 0,
    OZAYN_OAN_CHAN_LOCAL_LOG,
    OZAYN_OAN_CHAN_SYSTEM_NOTIFICATION,
    OZAYN_OAN_CHAN_EMAIL,
    OZAYN_OAN_CHAN_WEBHOOK,
    OZAYN_OAN_CHAN_FUTURE,
    OZAYN_OAN_CHAN_COUNT
} ozayn_oan_channel_t;

/* ============================================================
 * NOTIFICATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_OAN_NSTATE_CREATED = 0,
    OZAYN_OAN_NSTATE_QUEUED,
    OZAYN_OAN_NSTATE_SENDING,
    OZAYN_OAN_NSTATE_SENT,
    OZAYN_OAN_NSTATE_DELIVERED,
    OZAYN_OAN_NSTATE_FAILED,
    OZAYN_OAN_NSTATE_CANCELLED,
    OZAYN_OAN_NSTATE_EXPIRED,
    OZAYN_OAN_NSTATE_RETRYING
} ozayn_oan_nstate_t;

/* ============================================================
 * ALERT STRUCT
 * ============================================================ */

typedef struct {
    uint64_t alert_id;
    uint32_t version;
    ozayn_oan_category_t category;
    ozayn_oan_severity_t severity;
    ozayn_oan_state_t state;
    ozayn_oan_source_t source;
    ozayn_oan_trigger_type_t trigger_type;
    char title[OZAYN_OAN_MAX_ALERT_TITLE];
    char description[OZAYN_OAN_MAX_ALERT_DESC];
    char source_component[OZAYN_OAN_MAX_ALERT_SOURCE];
    char event_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char metric_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char operation_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char workflow_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char pipeline_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char resource_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char device_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char failure_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    char correlation_id[OZAYN_OAN_MAX_CORRELATION_LEN];
    char group_key[OZAYN_OAN_MAX_GROUP_KEY];
    uint64_t rule_id;
    time_t created_time;
    time_t updated_time;
    time_t expiration_time;
    time_t resolution_time;
    int64_t trigger_value;
    int64_t threshold_value;
    uint32_t ack_count;
    uint32_t notification_count;
    int active;
} ozayn_oan_alert_t;

/* ============================================================
 * ACKNOWLEDGEMENT STRUCT
 * ============================================================ */

typedef struct {
    uint64_t alert_id;
    char ack_identity[OZAYN_OAN_MAX_RECIPIENT_LEN];
    char reason[OZAYN_OAN_MAX_ALERT_DESC];
    time_t ack_time;
} ozayn_oan_ack_t;

/* ============================================================
 * ALERT RULE STRUCT
 * ============================================================ */

typedef struct {
    uint64_t rule_id;
    char name[OZAYN_OAN_MAX_RULE_NAME];
    char description[OZAYN_OAN_MAX_RULE_DESC];
    int enabled;
    ozayn_oan_trigger_type_t trigger_type;
    ozayn_oan_category_t category;
    ozayn_oan_severity_t severity;
    char source_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    int64_t warning_threshold;
    int64_t critical_threshold;
    uint64_t cooldown_seconds;
    uint64_t expiration_seconds;
    uint32_t max_active_alerts;
    char notification_policy_ref[OZAYN_OAN_MAX_ALERT_ID_LEN];
    uint64_t dedup_window_seconds;
    uint32_t max_group_size;
    time_t last_triggered_time;
    uint64_t trigger_count;
    int active;
} ozayn_oan_rule_t;

/* ============================================================
 * NOTIFICATION STRUCT
 * ============================================================ */

typedef struct {
    uint64_t notif_id;
    uint64_t alert_id;
    char recipient[OZAYN_OAN_MAX_RECIPIENT_LEN];
    ozayn_oan_channel_t channel;
    ozayn_oan_severity_t priority;
    ozayn_oan_nstate_t state;
    char title[OZAYN_OAN_MAX_NOTIF_TITLE];
    char body[OZAYN_OAN_MAX_NOTIF_BODY];
    time_t created_time;
    time_t scheduled_time;
    time_t sent_time;
    time_t delivered_time;
    time_t expiration_time;
    uint32_t attempt_count;
    uint32_t max_attempts;
    uint64_t alert_ref;
    int active;
} ozayn_oan_notification_t;

/* ============================================================
 * NOTIFICATION POLICY STRUCT
 * ============================================================ */

typedef struct {
    uint64_t policy_id;
    char name[OZAYN_OAN_MAX_ALERT_NAME];
    int enabled;
    int category_mask[OZAYN_OAN_CAT_COUNT];
    ozayn_oan_severity_t min_severity;
    int allowed_channels[OZAYN_OAN_CHAN_COUNT];
    uint64_t cooldown_seconds;
    uint32_t max_notifications_per_hour;
    uint32_t retry_limit;
    uint64_t retry_delay_seconds;
    uint64_t expiration_seconds;
    int active;
} ozayn_oan_policy_t;

/* ============================================================
 * DEDUP ENTRY
 * ============================================================ */

typedef struct {
    char dedup_key[OZAYN_OAN_MAX_GROUP_KEY];
    uint64_t rule_id;
    uint64_t last_alert_id;
    uint32_t count;
    time_t first_time;
    time_t last_time;
    int active;
} ozayn_oan_dedup_t;

/* ============================================================
 * STATS
 * ============================================================ */

typedef struct {
    uint64_t total_alerts_created;
    uint64_t total_alerts_activated;
    uint64_t total_alerts_acknowledged;
    uint64_t total_alerts_suppressed;
    uint64_t total_alerts_resolved;
    uint64_t total_alerts_expired;
    uint64_t total_alerts_cancelled;
    uint64_t total_rules_evaluated;
    uint64_t total_duplicates_detected;
    uint64_t total_notifications_created;
    uint64_t total_notifications_sent;
    uint64_t total_notifications_delivered;
    uint64_t total_notifications_failed;
    uint64_t total_notifications_retries;
    uint64_t total_rate_limited;
    uint64_t total_suppressed;
    uint64_t total_groups_formed;
    uint32_t current_active_alerts;
    uint32_t current_pending_notifications;
    uint32_t current_rules;
} ozayn_oan_stats_t;

/* ============================================================
 * ALERT SUMMARY
 * ============================================================ */

typedef struct {
    uint32_t active_count;
    uint32_t critical_count;
    uint32_t high_count;
    uint32_t medium_count;
    uint32_t low_count;
    uint32_t info_count;
    uint32_t acknowledged_count;
    uint32_t suppressed_count;
    uint32_t recently_resolved_count;
    uint32_t notification_failures;
    uint32_t total_active;
    uint32_t total_notifications_pending;
} ozayn_oan_summary_t;

/* ============================================================
 * SUBSYSTEM BIND
 * ============================================================ */

typedef struct {
    void *operational_metrics;
    void *operational_timeline;
    void *diagnostics;
    void *resource_manager;
    void *startup_recovery;
    void *events_engine;
} ozayn_oan_subsys_bind_t;

/* ============================================================
 * SERVICE
 * ============================================================ */

typedef struct {
    int initialized;
    uint64_t sequence;
    ozayn_oan_alert_t alerts[OZAYN_OAN_MAX_ALERTS];
    uint64_t alert_count;
    ozayn_oan_rule_t rules[OZAYN_OAN_MAX_RULES];
    uint64_t rule_count;
    ozayn_oan_notification_t notifications[OZAYN_OAN_MAX_NOTIFICATIONS];
    uint64_t notif_count;
    ozayn_oan_policy_t policies[OZAYN_OAN_MAX_POLICIES];
    uint64_t policy_count;
    ozayn_oan_dedup_t dedup[OZAYN_OAN_MAX_DEDUP];
    uint64_t dedup_count;
    ozayn_oan_stats_t stats;
    ozayn_oan_subsys_bind_t bind;
    uint64_t alerts_per_window;
    uint64_t window_start_time;
    uint32_t alerts_in_window;
    uint64_t notifs_per_window;
    uint64_t notif_window_start;
    uint32_t notifs_in_window;
} ozayn_oan_service_t;

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_oan_err_name(ozayn_oan_err_t e);
const char *ozayn_oan_category_name(ozayn_oan_category_t c);
const char *ozayn_oan_severity_name(ozayn_oan_severity_t s);
const char *ozayn_oan_state_name(ozayn_oan_state_t s);
const char *ozayn_oan_source_name(ozayn_oan_source_t s);
const char *ozayn_oan_trigger_name(ozayn_oan_trigger_type_t t);
const char *ozayn_oan_channel_name(ozayn_oan_channel_t c);
const char *ozayn_oan_nstate_name(ozayn_oan_nstate_t s);

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

int ozayn_oan_init(ozayn_oan_service_t *svc);
int ozayn_oan_shutdown(ozayn_oan_service_t *svc);
int ozayn_oan_is_initialized(const ozayn_oan_service_t *svc);

int ozayn_oan_bind_subsystems(ozayn_oan_service_t *svc, const ozayn_oan_subsys_bind_t *bind);

/* ============================================================
 * ALERT RULES
 * ============================================================ */

int ozayn_oan_rule_create(ozayn_oan_service_t *svc,
                          const char *name,
                          const char *description,
                          ozayn_oan_trigger_type_t trigger_type,
                          ozayn_oan_category_t category,
                          ozayn_oan_severity_t severity,
                          const char *source_ref,
                          int64_t warning_threshold,
                          int64_t critical_threshold,
                          uint64_t cooldown_seconds,
                          uint64_t expiration_seconds,
                          uint64_t dedup_window_seconds,
                          uint64_t *out_rule_id);

int ozayn_oan_rule_enable(ozayn_oan_service_t *svc, uint64_t rule_id);
int ozayn_oan_rule_disable(ozayn_oan_service_t *svc, uint64_t rule_id);
int ozayn_oan_rule_remove(ozayn_oan_service_t *svc, uint64_t rule_id);

int ozayn_oan_rule_get(const ozayn_oan_service_t *svc,
                       uint64_t rule_id,
                       const ozayn_oan_rule_t **out_rule);

int ozayn_oan_rule_evaluate(ozayn_oan_service_t *svc, uint64_t rule_id,
                            int64_t current_value,
                            ozayn_oan_severity_t *out_severity);

int ozayn_oan_rule_evaluate_all(ozayn_oan_service_t *svc);

/* ============================================================
 * ALERT LIFECYCLE
 * ============================================================ */

int ozayn_oan_alert_create(ozayn_oan_service_t *svc,
                           ozayn_oan_category_t category,
                           ozayn_oan_severity_t severity,
                           ozayn_oan_source_t source,
                           ozayn_oan_trigger_type_t trigger_type,
                           const char *title,
                           const char *description,
                           const char *source_component,
                           const char *correlation_id,
                           uint64_t rule_id,
                           int64_t trigger_value,
                           int64_t threshold_value,
                           uint64_t *out_alert_id);

int ozayn_oan_alert_activate(ozayn_oan_service_t *svc, uint64_t alert_id);
int ozayn_oan_alert_acknowledge(ozayn_oan_service_t *svc, uint64_t alert_id,
                                const char *identity, const char *reason);
int ozayn_oan_alert_suppress(ozayn_oan_service_t *svc, uint64_t alert_id);
int ozayn_oan_alert_resolve(ozayn_oan_service_t *svc, uint64_t alert_id);
int ozayn_oan_alert_cancel(ozayn_oan_service_t *svc, uint64_t alert_id);
int ozayn_oan_alert_close(ozayn_oan_service_t *svc, uint64_t alert_id);
int ozayn_oan_alert_expire(ozayn_oan_service_t *svc, uint64_t alert_id);

int ozayn_oan_alert_set_refs(ozayn_oan_service_t *svc, uint64_t alert_id,
                             const char *event_ref,
                             const char *metric_ref,
                             const char *operation_ref,
                             const char *workflow_ref,
                             const char *pipeline_ref,
                             const char *resource_ref,
                             const char *device_ref,
                             const char *failure_ref);

int ozayn_oan_alert_set_group_key(ozayn_oan_service_t *svc, uint64_t alert_id,
                                  const char *group_key);

/* ============================================================
 * ALERT QUERIES
 * ============================================================ */

int ozayn_oan_alert_get(const ozayn_oan_service_t *svc,
                        uint64_t alert_id,
                        const ozayn_oan_alert_t **out_alert);

int ozayn_oan_alert_get_by_correlation(const ozayn_oan_service_t *svc,
                                       const char *correlation_id,
                                       const ozayn_oan_alert_t **out_alert);

int ozayn_oan_alert_list_active(const ozayn_oan_service_t *svc,
                                const ozayn_oan_alert_t **out_alerts,
                                uint32_t max_results,
                                uint32_t *out_count);

int ozayn_oan_alert_list_by_severity(const ozayn_oan_service_t *svc,
                                     ozayn_oan_severity_t severity,
                                     const ozayn_oan_alert_t **out_alerts,
                                     uint32_t max_results,
                                     uint32_t *out_count);

int ozayn_oan_alert_list_by_category(const ozayn_oan_service_t *svc,
                                     ozayn_oan_category_t category,
                                     const ozayn_oan_alert_t **out_alerts,
                                     uint32_t max_results,
                                     uint32_t *out_count);

int ozayn_oan_alert_list_by_source(const ozayn_oan_service_t *svc,
                                   ozayn_oan_source_t source,
                                   const ozayn_oan_alert_t **out_alerts,
                                   uint32_t max_results,
                                   uint32_t *out_count);

int64_t ozayn_oan_alert_active_count(const ozayn_oan_service_t *svc);
int64_t ozayn_oan_alert_total_count(const ozayn_oan_service_t *svc);

/* ============================================================
 * ALERT SUMMARY
 * ============================================================ */

int ozayn_oan_summary(const ozayn_oan_service_t *svc, ozayn_oan_summary_t *out_summary);

/* ============================================================
 * DEDUP
 * ============================================================ */

int ozayn_oan_dedup_check(const ozayn_oan_service_t *svc,
                          uint64_t rule_id,
                          const char *group_key);

int ozayn_oan_dedup_register(ozayn_oan_service_t *svc,
                             uint64_t rule_id,
                             const char *group_key,
                             uint64_t alert_id);

int ozayn_oan_dedup_cleanup(ozayn_oan_service_t *svc, uint64_t window_seconds);

/* ============================================================
 * NOTIFICATIONS
 * ============================================================ */

int ozayn_oan_notif_create(ozayn_oan_service_t *svc,
                           uint64_t alert_id,
                           const char *recipient,
                           ozayn_oan_channel_t channel,
                           ozayn_oan_severity_t priority,
                           const char *title,
                           const char *body,
                           uint64_t *out_notif_id);

int ozayn_oan_notif_get(const ozayn_oan_service_t *svc,
                        uint64_t notif_id,
                        const ozayn_oan_notification_t **out_notif);

int ozayn_oan_notif_list_by_alert(const ozayn_oan_service_t *svc,
                                  uint64_t alert_id,
                                  const ozayn_oan_notification_t **out_notifs,
                                  uint32_t max_results,
                                  uint32_t *out_count);

int ozayn_oan_notif_advance(ozayn_oan_service_t *svc, uint64_t notif_id,
                            ozayn_oan_nstate_t new_state);

int ozayn_oan_notif_cancel(ozayn_oan_service_t *svc, uint64_t notif_id);

int64_t ozayn_oan_notif_pending_count(const ozayn_oan_service_t *svc);

/* ============================================================
 * NOTIFICATION POLICIES
 * ============================================================ */

int ozayn_oan_policy_create(ozayn_oan_service_t *svc,
                            const char *name,
                            ozayn_oan_severity_t min_severity,
                            uint64_t cooldown_seconds,
                            uint32_t max_notifications_per_hour,
                            uint32_t retry_limit,
                            uint64_t retry_delay_seconds,
                            uint64_t expiration_seconds,
                            uint64_t *out_policy_id);

int ozayn_oan_policy_enable(ozayn_oan_service_t *svc, uint64_t policy_id);
int ozayn_oan_policy_disable(ozayn_oan_service_t *svc, uint64_t policy_id);

int ozayn_oan_policy_get(const ozayn_oan_service_t *svc,
                         uint64_t policy_id,
                         const ozayn_oan_policy_t **out_policy);

int ozayn_oan_policy_set_category(ozayn_oan_service_t *svc, uint64_t policy_id,
                                  ozayn_oan_category_t category, int enabled);

int ozayn_oan_policy_set_channel(ozayn_oan_service_t *svc, uint64_t policy_id,
                                 ozayn_oan_channel_t channel, int enabled);

int ozayn_oan_policy_evaluate(const ozayn_oan_service_t *svc,
                              ozayn_oan_category_t category,
                              ozayn_oan_severity_t severity,
                              const ozayn_oan_policy_t **out_policy);

/* ============================================================
 * RATE LIMITING
 * ============================================================ */

int ozayn_oan_rate_check_alerts(ozayn_oan_service_t *svc, uint64_t max_per_window);
int ozayn_oan_rate_check_notifications(ozayn_oan_service_t *svc, uint64_t max_per_window);
int ozayn_oan_rate_record_alert(ozayn_oan_service_t *svc);
int ozayn_oan_rate_record_notification(ozayn_oan_service_t *svc);

/* ============================================================
 * EXPIRATION
 * ============================================================ */

int ozayn_oan_cleanup_expired(ozayn_oan_service_t *svc);

/* ============================================================
 * SHUTDOWN
 * ============================================================ */

int ozayn_oan_shutdown_drain(ozayn_oan_service_t *svc,
                             uint64_t *out_active_alerts,
                             uint64_t *out_pending_notifs);

/* ============================================================
 * STATS
 * ============================================================ */

ozayn_oan_stats_t ozayn_oan_get_stats(const ozayn_oan_service_t *svc);

/* ============================================================
 * STATE VALIDATION
 * ============================================================ */

int ozayn_oan_state_transition_valid(ozayn_oan_state_t from, ozayn_oan_state_t to);
int ozayn_oan_nstate_transition_valid(ozayn_oan_nstate_t from, ozayn_oan_nstate_t to);

#endif
