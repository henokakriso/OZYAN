#ifndef OZAYN_PIPELINE_SCHEDULER_H
#define OZAYN_PIPELINE_SCHEDULER_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SPA_OK                            =   0,
    OZAYN_SPA_ERR_NULL                      =  -1,
    OZAYN_SPA_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_SPA_ERR_ALREADY_INIT              =  -3,
    OZAYN_SPA_ERR_INVALID_PARAM             =  -4,
    OZAYN_SPA_ERR_LIMIT_REACHED             =  -5,
    OZAYN_SPA_ERR_NOT_FOUND                 =  -6,
    OZAYN_SPA_ERR_DUPLICATE                 =  -7,
    OZAYN_SPA_ERR_STATE_INVALID             =  -8,
    OZAYN_SPA_ERR_AUTH_FAILED               =  -9,
    OZAYN_SPA_ERR_PERMISSION_DENIED         = -10,
    OZAYN_SPA_ERR_UNAVAILABLE               = -11,
    OZAYN_SPA_ERR_PIPELINE_INVALID          = -12,
    OZAYN_SPA_ERR_PIPELINE_NOT_FOUND        = -13,
    OZAYN_SPA_ERR_PIPELINE_CONFLICT         = -14,
    OZAYN_SPA_ERR_PIPELINE_UNAVAILABLE      = -15,
    OZAYN_SPA_ERR_RESOURCE_UNAVAILABLE      = -16,
    OZAYN_SPA_ERR_RESOURCE_CONFLICT         = -17,
    OZAYN_SPA_ERR_RESERVATION_FAILED        = -18,
    OZAYN_SPA_ERR_RESERVATION_EXPIRED       = -19,
    OZAYN_SPA_ERR_DEPENDENCY_FAILED         = -20,
    OZAYN_SPA_ERR_DEPENDENCY_CYCLE          = -21,
    OZAYN_SPA_ERR_DEPENDENCY_TIMEOUT        = -22,
    OZAYN_SPA_ERR_SAFETY_CHECK_FAILED       = -23,
    OZAYN_SPA_ERR_SAFETY_RECHECK_FAILED     = -24,
    OZAYN_SPA_ERR_POLICY_DENIED             = -25,
    OZAYN_SPA_ERR_DEADLINE_EXPIRED          = -26,
    OZAYN_SPA_ERR_CANCELLED                 = -27,
    OZAYN_SPA_ERR_TIMEOUT                   = -28,
    OZAYN_SPA_ERR_CONCURRENCY               = -29,
    OZAYN_SPA_ERR_CONFIGURATION             = -30,
    OZAYN_SPA_ERR_EVENT_ERROR               = -31,
    OZAYN_SPA_ERR_HISTORY_ERROR             = -32,
    OZAYN_SPA_ERR_RESOURCE_MANAGER          = -33,
    OZAYN_SPA_ERR_PIPELINE_MANAGER          = -34,
    OZAYN_SPA_ERR_QUEUE_FULL                = -35,
    OZAYN_SPA_ERR_CAPACITY_LIMIT            = -36,
    OZAYN_SPA_ERR_EXPIRED                   = -37,
    OZAYN_SPA_ERR_REJECTED                  = -38
} ozayn_spa_err_t;

/* ============================================================
 * SECTION 2 — SCHEDULING STATES
 * ============================================================ */

typedef enum {
    OZAYN_SPA_SCHED_CREATED = 0,
    OZAYN_SPA_SCHED_QUEUED,
    OZAYN_SPA_SCHED_WAITING,
    OZAYN_SPA_SCHED_ELIGIBLE,
    OZAYN_SPA_SCHED_SCHEDULED,
    OZAYN_SPA_SCHED_RESERVED,
    OZAYN_SPA_SCHED_STARTING,
    OZAYN_SPA_SCHED_RUNNING,
    OZAYN_SPA_SCHED_PAUSED,
    OZAYN_SPA_SCHED_DRAINING,
    OZAYN_SPA_SCHED_COMPLETED,
    OZAYN_SPA_SCHED_FAILED,
    OZAYN_SPA_SCHED_CANCELLED,
    OZAYN_SPA_SCHED_EXPIRED,
    OZAYN_SPA_SCHED_REJECTED,
    OZAYN_SPA_SCHED_UNAVAILABLE,
    OZAYN_SPA_SCHED_STATE_COUNT
} ozayn_spa_sched_state_t;

/* ============================================================
 * SECTION 3 — PRIORITY LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_SPA_PRIORITY_LOW      = 0,
    OZAYN_SPA_PRIORITY_NORMAL   = 1,
    OZAYN_SPA_PRIORITY_HIGH     = 2,
    OZAYN_SPA_PRIORITY_CRITICAL = 3,
    OZAYN_SPA_PRIORITY_COUNT
} ozayn_spa_priority_t;

/* ============================================================
 * SECTION 4 — SCHEDULING DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_SPA_DECISION_SCHEDULE = 0,
    OZAYN_SPA_DECISION_WAIT,
    OZAYN_SPA_DECISION_DEFER,
    OZAYN_SPA_DECISION_REJECT,
    OZAYN_SPA_DECISION_EXPIRE,
    OZAYN_SPA_DECISION_UNAVAILABLE,
    OZAYN_SPA_DECISION_COUNT
} ozayn_spa_decision_t;

/* ============================================================
 * SECTION 5 — BLOCK / WAIT REASONS
 * ============================================================ */

typedef enum {
    OZAYN_SPA_WAIT_NONE = 0,
    OZAYN_SPA_WAIT_RESOURCE,
    OZAYN_SPA_WAIT_DEVICE,
    OZAYN_SPA_WAIT_STREAM,
    OZAYN_SPA_WAIT_ROUTE,
    OZAYN_SPA_WAIT_DEPENDENCY,
    OZAYN_SPA_WAIT_AUTHORIZATION,
    OZAYN_SPA_WAIT_SAFETY,
    OZAYN_SPA_WAIT_CONCURRENCY,
    OZAYN_SPA_WAIT_CONFLICT,
    OZAYN_SPA_WAIT_DEADLINE,
    OZAYN_SPA_WAIT_COUNT
} ozayn_spa_wait_reason_t;

/* ============================================================
 * SECTION 6 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_SPA_EVENT_SCHEDULER_STARTED = 0,
    OZAYN_SPA_EVENT_SCHEDULER_STOPPED,
    OZAYN_SPA_EVENT_PIPELINE_SCHEDULED,
    OZAYN_SPA_EVENT_PIPELINE_WAITING,
    OZAYN_SPA_EVENT_PIPELINE_ELIGIBLE,
    OZAYN_SPA_EVENT_PIPELINE_DEFERRED,
    OZAYN_SPA_EVENT_PIPELINE_REJECTED,
    OZAYN_SPA_EVENT_PIPELINE_EXPIRED,
    OZAYN_SPA_EVENT_PIPELINE_CANCELLED,
    OZAYN_SPA_EVENT_PIPELINE_COMPLETED,
    OZAYN_SPA_EVENT_PIPELINE_FAILED,
    OZAYN_SPA_EVENT_RESOURCE_CONFLICT,
    OZAYN_SPA_EVENT_PIPELINE_CONFLICT,
    OZAYN_SPA_EVENT_DEPENDENCY_WAIT,
    OZAYN_SPA_EVENT_DEPENDENCY_READY,
    OZAYN_SPA_EVENT_RESERVATION_REQUESTED,
    OZAYN_SPA_EVENT_RESERVATION_GRANTED,
    OZAYN_SPA_EVENT_RESERVATION_FAILED,
    OZAYN_SPA_EVENT_RESERVATION_RELEASED,
    OZAYN_SPA_EVENT_AUTHORIZATION_FAILED,
    OZAYN_SPA_EVENT_POLICY_DENIED,
    OZAYN_SPA_EVENT_SAFETY_RECHECK_FAILED,
    OZAYN_SPA_EVENT_CAPACITY_REACHED,
    OZAYN_SPA_EVENT_DEADLINE_EXPIRED,
    OZAYN_SPA_EVENT_FAIRNESS_ADJUSTED,
    OZAYN_SPA_EVENT_TICK_EVALUATED,
    OZAYN_SPA_EVENT_COUNT
} ozayn_spa_event_type_t;

/* ============================================================
 * SECTION 7 — CLOSE / REJECTION REASONS
 * ============================================================ */

typedef enum {
    OZAYN_SPA_CLOSE_NONE = 0,
    OZAYN_SPA_CLOSE_MANUAL_CANCEL,
    OZAYN_SPA_CLOSE_DEADLINE_EXPIRED,
    OZAYN_SPA_CLOSE_RESOURCE_EXHAUSTED,
    OZAYN_SPA_CLOSE_DEVICE_UNAVAILABLE,
    OZAYN_SPA_CLOSE_STREAM_FAILED,
    OZAYN_SPA_CLOSE_ROUTE_FAILED,
    OZAYN_SPA_CLOSE_AUTHORIZATION_FAILED,
    OZAYN_SPA_CLOSE_SAFETY_DENIED,
    OZAYN_SPA_CLOSE_POLICY_DENIED,
    OZAYN_SPA_CLOSE_DEPENDENCY_FAILED,
    OZAYN_SPA_CLOSE_DEPENDENCY_CYCLE,
    OZAYN_SPA_CLOSE_CONFLICT,
    OZAYN_SPA_CLOSE_CONCURRENCY_LIMIT,
    OZAYN_SPA_CLOSE_TIMEOUT,
    OZAYN_SPA_CLOSE_SHUTDOWN,
    OZAYN_SPA_CLOSE_COUNT
} ozayn_spa_close_reason_t;

/* ============================================================
 * SECTION 8 — CONSTANTS
 * ============================================================ */

#define OZAYN_SPA_MAX_ENTRIES              32
#define OZAYN_SPA_MAX_DEPENDENCIES         8
#define OZAYN_SPA_MAX_REQUIRED_RESOURCES   8
#define OZAYN_SPA_MAX_REQUIRED_DEVICES     4
#define OZAYN_SPA_MAX_REQUIRED_STREAMS     4
#define OZAYN_SPA_MAX_REQUIRED_ROUTES      4
#define OZAYN_SPA_MAX_EVENTS              64
#define OZAYN_SPA_MAX_ID_LEN              64
#define OZAYN_SPA_MAX_METADATA_LEN       256

#define OZAYN_SPA_DEFAULT_MAX_RUNNING        8
#define OZAYN_SPA_DEFAULT_MAX_WAITING       16
#define OZAYN_SPA_DEFAULT_MAX_SCHEDULED     32
#define OZAYN_SPA_DEFAULT_MAX_SCHEDULING_ATTEMPTS  3
#define OZAYN_SPA_DEFAULT_MAX_PRIORITY_BOOST       2
#define OZAYN_SPA_DEFAULT_MAX_WAIT_TIME_MS  60000
#define OZAYN_SPA_DEFAULT_ENTRY_TTL_MS     300000
#define OZAYN_SPA_DEFAULT_TICK_INTERVAL_MS   100
#define OZAYN_SPA_DEFAULT_AGING_INTERVAL_S    10

/* ============================================================
 * SECTION 9 — SCHEDULING ENTRY RECORD
 * ============================================================ */

typedef struct {
    int      active;
    char     entry_id[OZAYN_SPA_MAX_ID_LEN];
    char     pipeline_id[OZAYN_SPA_MAX_ID_LEN];
    char     operation_id[OZAYN_SPA_MAX_ID_LEN];
    char     request_id[OZAYN_SPA_MAX_ID_LEN];

    ozayn_spa_priority_t    priority;
    ozayn_spa_priority_t    effective_priority;
    int                     age_boost;

    ozayn_spa_sched_state_t state;
    ozayn_spa_wait_reason_t wait_reason;
    ozayn_spa_close_reason_t close_reason;

    time_t  submitted_at;
    time_t  eligibility_time;
    time_t  last_evaluated_at;
    time_t  scheduled_at;
    time_t  deadline_ms;
    time_t  max_wait_time_ms;
    time_t  entry_ttl_ms;
    time_t  expiration_time;

    char    required_resources[OZAYN_SPA_MAX_REQUIRED_RESOURCES][OZAYN_SPA_MAX_ID_LEN];
    int     required_resource_count;
    char    required_devices[OZAYN_SPA_MAX_REQUIRED_DEVICES][OZAYN_SPA_MAX_ID_LEN];
    int     required_device_count;
    char    required_streams[OZAYN_SPA_MAX_REQUIRED_STREAMS][OZAYN_SPA_MAX_ID_LEN];
    int     required_stream_count;
    char    required_routes[OZAYN_SPA_MAX_REQUIRED_ROUTES][OZAYN_SPA_MAX_ID_LEN];
    int     required_route_count;

    char    dependencies[OZAYN_SPA_MAX_DEPENDENCIES][OZAYN_SPA_MAX_ID_LEN];
    int     dependency_count;

    char    security_session_ref[OZAYN_SPA_MAX_ID_LEN];
    char    authorization_ref[OZAYN_SPA_MAX_ID_LEN];
    char    safety_decision_ref[OZAYN_SPA_MAX_ID_LEN];
    char    reservation_ref[OZAYN_SPA_MAX_ID_LEN];

    int     attempt_count;
    int     max_attempts;

    char    safe_metadata[OZAYN_SPA_MAX_METADATA_LEN];
} ozayn_spa_entry_t;

/* ============================================================
 * SECTION 10 — SCHEDULING DECISION RECORD
 * ============================================================ */

typedef struct {
    int      active;
    char     decision_id[OZAYN_SPA_MAX_ID_LEN];
    char     entry_id[OZAYN_SPA_MAX_ID_LEN];
    char     pipeline_id[OZAYN_SPA_MAX_ID_LEN];
    char     operation_id[OZAYN_SPA_MAX_ID_LEN];

    ozayn_spa_decision_t    decision;
    ozayn_spa_priority_t    priority;
    ozayn_spa_wait_reason_t wait_reason;
    ozayn_spa_close_reason_t close_reason;

    int     eligibility_ok;
    int     resource_ok;
    int     conflict_detected;
    int     dependency_ok;
    int     authorization_ok;
    int     safety_ok;

    char    reject_reason[OZAYN_SPA_MAX_METADATA_LEN];
    time_t  decision_time;
    time_t  expiration;
} ozayn_spa_decision_record_t;

/* ============================================================
 * SECTION 11 — EVENT RECORD
 * ============================================================ */

typedef struct {
    ozayn_spa_event_type_t type;
    char     entry_id[OZAYN_SPA_MAX_ID_LEN];
    char     pipeline_id[OZAYN_SPA_MAX_ID_LEN];
    char     message[OZAYN_SPA_MAX_METADATA_LEN];
    time_t   timestamp;
    uint64_t sequence;
} ozayn_spa_event_t;

/* ============================================================
 * SECTION 12 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_submitted;
    uint64_t total_scheduled;
    uint64_t total_completed;
    uint64_t total_failed;
    uint64_t total_cancelled;
    uint64_t total_expired;
    uint64_t total_rejected;
    uint64_t total_deferred;
    uint64_t total_ticks;
    uint64_t total_fairness_adjustments;
    uint64_t total_resource_conflicts;
    uint64_t total_pipeline_conflicts;
    uint64_t total_dependency_waits;
    uint64_t total_deadline_expirations;
    uint64_t total_scheduling_failures;
    int      current_queued;
    int      current_waiting;
    int      current_eligible;
    int      current_scheduled;
    int      current_running;
    int      current_paused;
    int      current_blocked;
} ozayn_spa_stats_t;

/* ============================================================
 * SECTION 13 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *component_registry;
    void *safety_engine;
    void *resource_manager;
    void *operation_queue;
    void *pipeline_coordinator;
    void *diagnostics;
    void *audit;

    int  max_entries;
    int  max_running;
    int  max_waiting;
    int  max_scheduled;
    int  max_scheduling_attempts;
    int  max_priority_boost;
    int  max_wait_time_ms;
    int  entry_ttl_ms;
    int  tick_interval_ms;
    int  aging_enabled;
    int  aging_interval_s;
} ozayn_spa_service_config_t;

/* ============================================================
 * SECTION 14 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int   initialized;

    ozayn_spa_entry_t          entries[OZAYN_SPA_MAX_ENTRIES];
    int                        entry_count;
    uint64_t                   entry_sequence;

    ozayn_spa_decision_record_t decisions[OZAYN_SPA_MAX_ENTRIES];
    int                        decision_count;
    uint64_t                   decision_sequence;

    ozayn_spa_event_t          events[OZAYN_SPA_MAX_EVENTS];
    int                        event_head;
    int                        event_count;
    uint64_t                   event_sequence;

    ozayn_spa_stats_t          stats;

    ozayn_spa_service_config_t config;

    void *component_registry;
    void *safety_engine;
    void *resource_manager;
    void *operation_queue;
    void *pipeline_coordinator;
    void *diagnostics;
    void *audit;

    time_t last_aging_time;
    time_t last_tick_time;
} ozayn_spa_service_t;

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_service_init(ozayn_spa_service_t *svc,
                                       const ozayn_spa_service_config_t *cfg);
ozayn_spa_err_t ozayn_spa_service_shutdown(ozayn_spa_service_t *svc);
int             ozayn_spa_service_is_initialized(const ozayn_spa_service_t *svc);
ozayn_spa_service_t *ozayn_spa_get_global(void);

/* ============================================================
 * SECTION 16 — SCHEDULING ENTRY MANAGEMENT
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_submit(ozayn_spa_service_t *svc,
                                 const char *pipeline_id,
                                 const char *operation_id,
                                 const char *request_id,
                                 ozayn_spa_priority_t priority,
                                 const char *metadata);

ozayn_spa_err_t ozayn_spa_cancel(ozayn_spa_service_t *svc,
                                 const char *entry_id,
                                 ozayn_spa_close_reason_t reason);

ozayn_spa_err_t ozayn_spa_remove(ozayn_spa_service_t *svc,
                                 const char *entry_id);

/* ============================================================
 * SECTION 17 — DEPENDENCY MANAGEMENT
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_add_dependency(ozayn_spa_service_t *svc,
                                         const char *entry_id,
                                         const char *dependency_entry_id);

/* ============================================================
 * SECTION 18 — RESOURCE REQUIREMENTS
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_set_required_resources(ozayn_spa_service_t *svc,
                                                 const char *entry_id,
                                                 const char resource_ids[][OZAYN_SPA_MAX_ID_LEN],
                                                 int count);

ozayn_spa_err_t ozayn_spa_set_required_devices(ozayn_spa_service_t *svc,
                                               const char *entry_id,
                                               const char device_ids[][OZAYN_SPA_MAX_ID_LEN],
                                               int count);

ozayn_spa_err_t ozayn_spa_set_required_streams(ozayn_spa_service_t *svc,
                                               const char *entry_id,
                                               const char stream_ids[][OZAYN_SPA_MAX_ID_LEN],
                                               int count);

ozayn_spa_err_t ozayn_spa_set_required_routes(ozayn_spa_service_t *svc,
                                              const char *entry_id,
                                              const char route_ids[][OZAYN_SPA_MAX_ID_LEN],
                                              int count);

/* ============================================================
 * SECTION 19 — DEADLINE / TIMING
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_set_deadline(ozayn_spa_service_t *svc,
                                       const char *entry_id,
                                       time_t deadline_ms);

ozayn_spa_err_t ozayn_spa_set_max_wait_time(ozayn_spa_service_t *svc,
                                             const char *entry_id,
                                             time_t max_wait_ms);

/* ============================================================
 * SECTION 20 — SECURITY REFERENCES
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_set_security_session(ozayn_spa_service_t *svc,
                                               const char *entry_id,
                                               const char *session_ref);

ozayn_spa_err_t ozayn_spa_set_authorization_ref(ozayn_spa_service_t *svc,
                                                const char *entry_id,
                                                const char *auth_ref);

ozayn_spa_err_t ozayn_spa_set_safety_decision_ref(ozayn_spa_service_t *svc,
                                                   const char *entry_id,
                                                   const char *safety_ref);

/* ============================================================
 * SECTION 21 — SCHEDULER EVALUATION (TICK)
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_tick(ozayn_spa_service_t *svc);

/* ============================================================
 * SECTION 22 — READINESS EVALUATION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_evaluate_entry(ozayn_spa_service_t *svc,
                                         const char *entry_id,
                                         ozayn_spa_decision_record_t *out_decision);

/* ============================================================
 * SECTION 23 — SCHEDULING DECISION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_schedule_next(ozayn_spa_service_t *svc,
                                        char *out_entry_id,
                                        int out_entry_id_len);

/* ============================================================
 * SECTION 24 — RESOURCE ARBITRATION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_check_conflicts(ozayn_spa_service_t *svc,
                                          const char *entry_id,
                                          int *out_has_conflict,
                                          char *out_conflicting_entry,
                                           int out_len);

/* ============================================================
 * SECTION 25 — STATE TRANSITION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_transition(ozayn_spa_service_t *svc,
                                     const char *entry_id,
                                     ozayn_spa_sched_state_t new_state);

/* ============================================================
 * SECTION 26 — QUERY
 * ============================================================ */

const ozayn_spa_entry_t *ozayn_spa_find_entry(const ozayn_spa_service_t *svc,
                                               const char *entry_id);

const ozayn_spa_entry_t *ozayn_spa_find_entry_by_pipeline(const ozayn_spa_service_t *svc,
                                                           const char *pipeline_id);

int ozayn_spa_entry_count(const ozayn_spa_service_t *svc);
int ozayn_spa_running_count(const ozayn_spa_service_t *svc);
int ozayn_spa_waiting_count(const ozayn_spa_service_t *svc);
int ozayn_spa_eligible_count(const ozayn_spa_service_t *svc);
int ozayn_spa_queue_full(const ozayn_spa_service_t *svc);
int ozayn_spa_running_limit(const ozayn_spa_service_t *svc);

/* ============================================================
 * SECTION 27 — EVENTS
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_emit_event(ozayn_spa_service_t *svc,
                                     ozayn_spa_event_type_t type,
                                     const char *entry_id,
                                     const char *pipeline_id,
                                     const char *message);

const ozayn_spa_event_t *ozayn_spa_get_event(const ozayn_spa_service_t *svc,
                                              int index);

int ozayn_spa_event_count(const ozayn_spa_service_t *svc);

/* ============================================================
 * SECTION 28 — CLEANUP
 * ============================================================ */

int ozayn_spa_cleanup_expired(ozayn_spa_service_t *svc);
int ozayn_spa_cleanup_terminal(ozayn_spa_service_t *svc);
int ozayn_spa_cleanup_all(ozayn_spa_service_t *svc);

/* ============================================================
 * SECTION 29 — STATISTICS
 * ============================================================ */

ozayn_spa_stats_t ozayn_spa_get_stats(const ozayn_spa_service_t *svc);

/* ============================================================
 * SECTION 30 — VALIDATION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_validate_entry(const ozayn_spa_service_t *svc,
                                         const ozayn_spa_entry_t *entry);
ozayn_spa_err_t ozayn_spa_validate_config(const ozayn_spa_service_config_t *cfg);

/* ============================================================
 * SECTION 31 — NAME HELPERS
 * ============================================================ */

const char *ozayn_spa_err_name(ozayn_spa_err_t err);
const char *ozayn_spa_sched_state_name(ozayn_spa_sched_state_t state);
const char *ozayn_spa_priority_name(ozayn_spa_priority_t priority);
const char *ozayn_spa_decision_name(ozayn_spa_decision_t decision);
const char *ozayn_spa_wait_reason_name(ozayn_spa_wait_reason_t reason);
const char *ozayn_spa_event_type_name(ozayn_spa_event_type_t type);
const char *ozayn_spa_close_reason_name(ozayn_spa_close_reason_t reason);

/* ============================================================
 * SECTION 32 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_spa_is_valid_transition(ozayn_spa_sched_state_t from,
                                  ozayn_spa_sched_state_t to);

int ozayn_spa_is_terminal_state(ozayn_spa_sched_state_t state);

#endif
