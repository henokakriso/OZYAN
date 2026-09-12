#ifndef OZAYN_DEVICE_SESSION_H
#define OZAYN_DEVICE_SESSION_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_DAS_OK                          =   0,
    OZAYN_DAS_ERR_NULL                    =  -1,
    OZAYN_DAS_ERR_NOT_INITIALIZED         =  -2,
    OZAYN_DAS_ERR_ALREADY_INIT            =  -3,
    OZAYN_DAS_ERR_INVALID_PARAM           =  -4,
    OZAYN_DAS_ERR_LIMIT_REACHED           =  -5,
    OZAYN_DAS_ERR_NOT_FOUND               =  -6,
    OZAYN_DAS_ERR_STATE_INVALID           =  -7,
    OZAYN_DAS_ERR_AUTH_FAILED             =  -8,
    OZAYN_DAS_ERR_PERMISSION_DENIED       =  -9,
    OZAYN_DAS_ERR_RESERVATION_INVALID     = -10,
    OZAYN_DAS_ERR_RESERVATION_EXPIRED     = -11,
    OZAYN_DAS_ERR_DEVICE_UNAVAILABLE      = -12,
    OZAYN_DAS_ERR_CAPABILITY_UNAVAILABLE  = -13,
    OZAYN_DAS_ERR_OPEN_FAILED             = -14,
    OZAYN_DAS_ERR_CLOSE_FAILED            = -15,
    OZAYN_DAS_ERR_TIMEOUT                 = -16,
    OZAYN_DAS_ERR_EXPIRED                 = -17,
    OZAYN_DAS_ERR_REVOKED                 = -18,
    OZAYN_DAS_ERR_RESOURCE_UNAVAILABLE    = -19,
    OZAYN_DAS_ERR_POLICY_DENIED           = -20,
    OZAYN_DAS_ERR_SECURITY_INVALID        = -21,
    OZAYN_DAS_ERR_PROVIDER_ERROR          = -22,
    OZAYN_DAS_ERR_CONCURRENCY             = -23
} ozayn_das_err_t;

/* ============================================================
 * SECTION 2 — ACCESS MODES
 * ============================================================ */

typedef enum {
    OZAYN_DAS_MODE_OBSERVE = 0,
    OZAYN_DAS_MODE_INPUT,
    OZAYN_DAS_MODE_OUTPUT,
    OZAYN_DAS_MODE_CONTROL,
    OZAYN_DAS_MODE_STREAM,
    OZAYN_DAS_MODE_COUNT
} ozayn_das_access_mode_t;

/* ============================================================
 * SECTION 3 — SESSION STATES
 * ============================================================ */

typedef enum {
    OZAYN_DAS_STATE_REQUESTED = 0,
    OZAYN_DAS_STATE_AUTHORIZING,
    OZAYN_DAS_STATE_AUTHORIZED,
    OZAYN_DAS_STATE_RESERVED,
    OZAYN_DAS_STATE_OPENING,
    OZAYN_DAS_STATE_ACTIVE,
    OZAYN_DAS_STATE_IDLE,
    OZAYN_DAS_STATE_CLOSING,
    OZAYN_DAS_STATE_CLOSED,
    OZAYN_DAS_STATE_EXPIRED,
    OZAYN_DAS_STATE_CANCELLED,
    OZAYN_DAS_STATE_FAILED,
    OZAYN_DAS_STATE_REVOKED,
    OZAYN_DAS_STATE_COUNT
} ozayn_das_session_state_t;

/* ============================================================
 * SECTION 4 — CLOSE REASONS
 * ============================================================ */

typedef enum {
    OZAYN_DAS_CLOSE_NONE = 0,
    OZAYN_DAS_CLOSE_SECURITY_EXPIRED,
    OZAYN_DAS_CLOSE_AUTH_REVOKED,
    OZAYN_DAS_CLOSE_RESERVATION_EXPIRED,
    OZAYN_DAS_CLOSE_DEVICE_UNAVAILABLE,
    OZAYN_DAS_CLOSE_DEVICE_ERROR,
    OZAYN_DAS_CLOSE_POLICY_CHANGED,
    OZAYN_DAS_CLOSE_RESOURCE_LIMIT,
    OZAYN_DAS_CLOSE_MANUAL_CLOSE,
    OZAYN_DAS_CLOSE_TIMEOUT,
    OZAYN_DAS_CLOSE_SYSTEM_SHUTDOWN,
    OZAYN_DAS_CLOSE_PROVIDER_ERROR,
    OZAYN_DAS_CLOSE_OPEN_FAILED,
    OZAYN_DAS_CLOSE_CONCURRENT_ERROR,
    OZAYN_DAS_CLOSE_REASON_COUNT
} ozayn_das_close_reason_t;

/* ============================================================
 * SECTION 5 — SESSION EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_DAS_EVENT_SESSION_REQUESTED = 0,
    OZAYN_DAS_EVENT_SESSION_AUTHORIZED,
    OZAYN_DAS_EVENT_SESSION_REJECTED,
    OZAYN_DAS_EVENT_SESSION_RESERVED,
    OZAYN_DAS_EVENT_SESSION_OPENING,
    OZAYN_DAS_EVENT_SESSION_ACTIVE,
    OZAYN_DAS_EVENT_SESSION_IDLE,
    OZAYN_DAS_EVENT_SESSION_CLOSING,
    OZAYN_DAS_EVENT_SESSION_CLOSED,
    OZAYN_DAS_EVENT_SESSION_EXPIRED,
    OZAYN_DAS_EVENT_SESSION_REVOKED,
    OZAYN_DAS_EVENT_SESSION_FAILED,
    OZAYN_DAS_EVENT_SESSION_HEARTBEAT,
    OZAYN_DAS_EVENT_COUNT
} ozayn_das_event_type_t;

/* ============================================================
 * SECTION 6 — LIMITS
 * ============================================================ */

#define OZAYN_DAS_MAX_SESSIONS             32
#define OZAYN_DAS_MAX_EVENTS              64
#define OZAYN_DAS_MAX_ID_LEN              64
#define OZAYN_DAS_MAX_PERMISSION_LEN      64
#define OZAYN_DAS_MAX_METADATA_LEN       256
#define OZAYN_DAS_MAX_DESCRIPTION_LEN    256
#define OZAYN_DAS_DEFAULT_SESSION_TTL_MS 300000
#define OZAYN_DAS_DEFAULT_IDLE_TIMEOUT_MS 60000

/* ============================================================
 * SECTION 7 — SESSION DESCRIPTOR
 * ============================================================ */

typedef struct {
    char session_id[OZAYN_DAS_MAX_ID_LEN];
    char device_id[OZAYN_DAS_MAX_ID_LEN];
    char capability[OZAYN_DAS_MAX_ID_LEN];
    ozayn_das_access_mode_t access_mode;
    char reservation_id[OZAYN_DAS_MAX_ID_LEN];
    char requester_ref[OZAYN_DAS_MAX_ID_LEN];
    char security_session_ref[OZAYN_DAS_MAX_ID_LEN];
    char operation_id[OZAYN_DAS_MAX_ID_LEN];
    char required_permission[OZAYN_DAS_MAX_PERMISSION_LEN];
    ozayn_das_session_state_t state;
    ozayn_das_close_reason_t close_reason;
    time_t created_time;
    time_t activated_time;
    time_t last_activity_time;
    time_t expiry_time;
    time_t closed_time;
    int active;
    char metadata[OZAYN_DAS_MAX_METADATA_LEN];
} ozayn_das_session_t;

/* ============================================================
 * SECTION 8 — SESSION EVENT
 * ============================================================ */

typedef struct {
    ozayn_das_event_type_t type;
    char session_id[OZAYN_DAS_MAX_ID_LEN];
    char device_id[OZAYN_DAS_MAX_ID_LEN];
    char message[OZAYN_DAS_MAX_DESCRIPTION_LEN];
    time_t timestamp;
} ozayn_das_event_t;

/* ============================================================
 * SECTION 9 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_sessions_created;
    uint64_t total_sessions_authorized;
    uint64_t total_sessions_rejected;
    uint64_t total_sessions_opened;
    uint64_t total_sessions_closed;
    uint64_t total_sessions_expired;
    uint64_t total_sessions_revoked;
    uint64_t total_sessions_failed;
    uint64_t total_sessions_cancelled;
    uint64_t total_heartbeats;
    uint64_t total_state_transitions;
    uint64_t total_validation_failures;
    uint64_t total_errors;
    int current_active_sessions;
    int current_idle_sessions;
    int current_opening_sessions;
} ozayn_das_stats_t;

/* ============================================================
 * SECTION 10 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *device_io;
    void *resource_manager;
    void *safety_engine;
    void *diagnostics;
    void *audit;
    int max_sessions;
    int session_ttl_ms;
    int idle_timeout_ms;
} ozayn_das_service_config_t;

/* ============================================================
 * SECTION 11 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    ozayn_das_session_t sessions[OZAYN_DAS_MAX_SESSIONS];
    int session_count;
    uint32_t session_sequence;

    ozayn_das_event_t events[OZAYN_DAS_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;

    ozayn_das_stats_t stats;
    ozayn_das_service_config_t config;
} ozayn_das_service_t;

/* ============================================================
 * SECTION 12 — LIFECYCLE
 * ============================================================ */

ozayn_das_err_t ozayn_das_service_init(ozayn_das_service_t *svc,
                                        const ozayn_das_service_config_t *cfg);
void ozayn_das_service_shutdown(ozayn_das_service_t *svc);
int ozayn_das_service_is_initialized(const ozayn_das_service_t *svc);
ozayn_das_service_t *ozayn_das_get_global(void);

/* ============================================================
 * SECTION 13 — SESSION MANAGEMENT
 * ============================================================ */

ozayn_das_err_t ozayn_das_session_create(ozayn_das_service_t *svc,
                                          const char *device_id,
                                          const char *capability,
                                          ozayn_das_access_mode_t access_mode,
                                          const char *reservation_id,
                                          const char *requester_ref,
                                          const char *security_session_ref,
                                          const char *operation_id,
                                          const char *required_permission,
                                          ozayn_das_session_t **out_session);
ozayn_das_err_t ozayn_das_session_close(ozayn_das_service_t *svc,
                                         const char *session_id,
                                         ozayn_das_close_reason_t reason);
ozayn_das_err_t ozayn_das_session_revoke(ozayn_das_service_t *svc,
                                          const char *session_id,
                                          ozayn_das_close_reason_t reason);
ozayn_das_err_t ozayn_das_session_cancel(ozayn_das_service_t *svc,
                                          const char *session_id);

/* ============================================================
 * SECTION 14 — STATE TRANSITIONS
 * ============================================================ */

ozayn_das_err_t ozayn_das_session_authorize(ozayn_das_service_t *svc,
                                             const char *session_id);
ozayn_das_err_t ozayn_das_session_reserve(ozayn_das_service_t *svc,
                                           const char *session_id);
ozayn_das_err_t ozayn_das_session_open(ozayn_das_service_t *svc,
                                        const char *session_id);
ozayn_das_err_t ozayn_das_session_activate(ozayn_das_service_t *svc,
                                            const char *session_id);
ozayn_das_err_t ozayn_das_session_set_idle(ozayn_das_service_t *svc,
                                            const char *session_id);
ozayn_das_err_t ozayn_das_session_heartbeat(ozayn_das_service_t *svc,
                                             const char *session_id);

/* ============================================================
 * SECTION 15 — SESSION QUERY
 * ============================================================ */

const ozayn_das_session_t *ozayn_das_session_get(
    const ozayn_das_service_t *svc,
    const char *session_id);
const ozayn_das_session_t *ozayn_das_session_get_by_device(
    const ozayn_das_service_t *svc,
    const char *device_id);
const ozayn_das_session_t *ozayn_das_session_get_by_reservation(
    const ozayn_das_service_t *svc,
    const char *reservation_id);
int ozayn_das_session_count(const ozayn_das_service_t *svc);
int ozayn_das_session_count_by_device(const ozayn_das_service_t *svc,
                                      const char *device_id);
int ozayn_das_session_is_active(const ozayn_das_service_t *svc,
                                const char *session_id);
int ozayn_das_session_is_expired(const ozayn_das_service_t *svc,
                                 const char *session_id);

/* ============================================================
 * SECTION 16 — EVENTS
 * ============================================================ */

ozayn_das_err_t ozayn_das_emit_event(ozayn_das_service_t *svc,
                                      ozayn_das_event_type_t type,
                                      const char *session_id,
                                      const char *device_id,
                                      const char *message);
const ozayn_das_event_t *ozayn_das_event_get(const ozayn_das_service_t *svc,
                                              int index);
int ozayn_das_event_count(const ozayn_das_service_t *svc);

/* ============================================================
 * SECTION 17 — CLEANUP
 * ============================================================ */

int ozayn_das_cleanup_expired_sessions(ozayn_das_service_t *svc);
int ozayn_das_cleanup_idle_sessions(ozayn_das_service_t *svc);
int ozayn_das_cleanup_all(ozayn_das_service_t *svc);

/* ============================================================
 * SECTION 18 — STATISTICS
 * ============================================================ */

ozayn_das_err_t ozayn_das_get_stats(const ozayn_das_service_t *svc,
                                     ozayn_das_stats_t *out_stats);

/* ============================================================
 * SECTION 19 — VALIDATION
 * ============================================================ */

int ozayn_das_session_validate(const ozayn_das_session_t *session);
int ozayn_das_state_transition_valid(ozayn_das_session_state_t from,
                                     ozayn_das_session_state_t to);

/* ============================================================
 * SECTION 20 — NAME HELPERS
 * ============================================================ */

const char *ozayn_das_access_mode_name(ozayn_das_access_mode_t mode);
const char *ozayn_das_session_state_name(ozayn_das_session_state_t state);
const char *ozayn_das_close_reason_name(ozayn_das_close_reason_t reason);
const char *ozayn_das_event_type_name(ozayn_das_event_type_t type);
const char *ozayn_das_err_name(ozayn_das_err_t err);

#endif /* OZAYN_DEVICE_SESSION_H */
