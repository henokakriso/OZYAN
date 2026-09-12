#ifndef OZAYN_IO_STREAM_H
#define OZAYN_IO_STREAM_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_IOS_OK                            =   0,
    OZAYN_IOS_ERR_NULL                      =  -1,
    OZAYN_IOS_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_IOS_ERR_ALREADY_INIT              =  -3,
    OZAYN_IOS_ERR_INVALID_PARAM             =  -4,
    OZAYN_IOS_ERR_LIMIT_REACHED             =  -5,
    OZAYN_IOS_ERR_NOT_FOUND                 =  -6,
    OZAYN_IOS_ERR_STATE_INVALID             =  -7,
    OZAYN_IOS_ERR_AUTH_FAILED               =  -8,
    OZAYN_IOS_ERR_PERMISSION_DENIED         =  -9,
    OZAYN_IOS_ERR_SESSION_INVALID           = -10,
    OZAYN_IOS_ERR_SESSION_EXPIRED           = -11,
    OZAYN_IOS_ERR_SESSION_REVOKED           = -12,
    OZAYN_IOS_ERR_DEVICE_UNAVAILABLE        = -13,
    OZAYN_IOS_ERR_CAPABILITY_INVALID        = -14,
    OZAYN_IOS_ERR_CAPABILITY_UNAVAILABLE    = -15,
    OZAYN_IOS_ERR_POLICY_DENIED             = -16,
    OZAYN_IOS_ERR_PRECONDITION_FAILED       = -17,
    OZAYN_IOS_ERR_RESOURCE_UNAVAILABLE      = -18,
    OZAYN_IOS_ERR_RESOURCE_LIMIT            = -19,
    OZAYN_IOS_ERR_BUFFER_LIMIT              = -20,
    OZAYN_IOS_ERR_QUEUE_LIMIT               = -21,
    OZAYN_IOS_ERR_RATE_LIMIT                = -22,
    OZAYN_IOS_ERR_BACKPRESSURE              = -23,
    OZAYN_IOS_ERR_OVERFLOW                  = -24,
    OZAYN_IOS_ERR_TIMEOUT                   = -25,
    OZAYN_IOS_ERR_EXPIRED                   = -26,
    OZAYN_IOS_ERR_REVOKED                   = -27,
    OZAYN_IOS_ERR_OPEN_FAILED               = -28,
    OZAYN_IOS_ERR_CLOSE_FAILED              = -29,
    OZAYN_IOS_ERR_DEVICE_DISCONNECTED       = -30,
    OZAYN_IOS_ERR_PROVIDER_ERROR            = -31,
    OZAYN_IOS_ERR_CONCURRENCY               = -32,
    OZAYN_IOS_ERR_EXECUTION                 = -33
} ozayn_ios_err_t;

/* ============================================================
 * SECTION 2 — STREAM DIRECTIONS
 * ============================================================ */

typedef enum {
    OZAYN_IOS_DIR_INPUT = 0,
    OZAYN_IOS_DIR_OUTPUT,
    OZAYN_IOS_DIR_BIDIRECTIONAL,
    OZAYN_IOS_DIR_COUNT
} ozayn_ios_direction_t;

/* ============================================================
 * SECTION 3 — DATA TYPES
 * ============================================================ */

typedef enum {
    OZAYN_IOS_DATA_CAMERA_FRAME = 0,
    OZAYN_IOS_DATA_AUDIO_SAMPLE,
    OZAYN_IOS_DATA_AUDIO_BUFFER,
    OZAYN_IOS_DATA_INPUT_EVENT,
    OZAYN_IOS_DATA_DISPLAY_OUTPUT,
    OZAYN_IOS_DATA_GPU_BUFFER,
    OZAYN_IOS_DATA_NETWORK_DATA,
    OZAYN_IOS_DATA_GENERIC_SAFE,
    OZAYN_IOS_DATA_COUNT
} ozayn_ios_data_type_t;

/* ============================================================
 * SECTION 4 — STREAM STATES
 * ============================================================ */

typedef enum {
    OZAYN_IOS_STATE_REQUESTED = 0,
    OZAYN_IOS_STATE_AUTHORIZING,
    OZAYN_IOS_STATE_AUTHORIZED,
    OZAYN_IOS_STATE_OPENING,
    OZAYN_IOS_STATE_ACTIVE,
    OZAYN_IOS_STATE_PAUSED,
    OZAYN_IOS_STATE_BACKPRESSURED,
    OZAYN_IOS_STATE_DRAINING,
    OZAYN_IOS_STATE_CLOSING,
    OZAYN_IOS_STATE_CLOSED,
    OZAYN_IOS_STATE_FAILED,
    OZAYN_IOS_STATE_EXPIRED,
    OZAYN_IOS_STATE_REVOKED,
    OZAYN_IOS_STATE_UNAVAILABLE,
    OZAYN_IOS_STATE_COUNT
} ozayn_ios_stream_state_t;

/* ============================================================
 * SECTION 5 — BUFFER POLICIES
 * ============================================================ */

typedef enum {
    OZAYN_IOS_POLICY_BLOCK = 0,
    OZAYN_IOS_POLICY_DROP_OLDEST,
    OZAYN_IOS_POLICY_DROP_NEWEST,
    OZAYN_IOS_POLICY_PAUSE_PRODUCER,
    OZAYN_IOS_POLICY_FAIL_STREAM,
    OZAYN_IOS_POLICY_COUNT
} ozayn_ios_buffer_policy_t;

/* ============================================================
 * SECTION 6 — CLOSE REASONS
 * ============================================================ */

typedef enum {
    OZAYN_IOS_CLOSE_NONE = 0,
    OZAYN_IOS_CLOSE_MANUAL_CLOSE,
    OZAYN_IOS_CLOSE_SESSION_EXPIRED,
    OZAYN_IOS_CLOSE_SESSION_REVOKED,
    OZAYN_IOS_CLOSE_DEVICE_UNAVAILABLE,
    OZAYN_IOS_CLOSE_DEVICE_DISCONNECTED,
    OZAYN_IOS_CLOSE_POLICY_CHANGED,
    OZAYN_IOS_CLOSE_RESOURCE_EXHAUSTED,
    OZAYN_IOS_CLOSE_BUFFER_OVERFLOW,
    OZAYN_IOS_CLOSE_RATE_EXCEEDED,
    OZAYN_IOS_CLOSE_TIMEOUT,
    OZAYN_IOS_CLOSE_SYSTEM_SHUTDOWN,
    OZAYN_IOS_CLOSE_PROVIDER_ERROR,
    OZAYN_IOS_CLOSE_OPEN_FAILED,
    OZAYN_IOS_CLOSE_CONCURRENT_ERROR,
    OZAYN_IOS_CLOSE_REASON_COUNT
} ozayn_ios_close_reason_t;

/* ============================================================
 * SECTION 7 — STREAM EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_IOS_EVENT_STREAM_REQUESTED = 0,
    OZAYN_IOS_EVENT_STREAM_AUTHORIZING,
    OZAYN_IOS_EVENT_STREAM_AUTHORIZED,
    OZAYN_IOS_EVENT_STREAM_OPENING,
    OZAYN_IOS_EVENT_STREAM_OPENED,
    OZAYN_IOS_EVENT_STREAM_ACTIVE,
    OZAYN_IOS_EVENT_STREAM_PAUSED,
    OZAYN_IOS_EVENT_STREAM_RESUMED,
    OZAYN_IOS_EVENT_STREAM_BACKPRESSURED,
    OZAYN_IOS_EVENT_STREAM_DATA_DROPPED,
    OZAYN_IOS_EVENT_STREAM_OVERFLOW_PROTECTED,
    OZAYN_IOS_EVENT_STREAM_DRAINING,
    OZAYN_IOS_EVENT_STREAM_CLOSING,
    OZAYN_IOS_EVENT_STREAM_CLOSED,
    OZAYN_IOS_EVENT_STREAM_EXPIRED,
    OZAYN_IOS_EVENT_STREAM_REVOKED,
    OZAYN_IOS_EVENT_STREAM_UNAVAILABLE,
    OZAYN_IOS_EVENT_STREAM_FAILED,
    OZAYN_IOS_EVENT_STREAM_DEVICE_DISCONNECTED,
    OZAYN_IOS_EVENT_COUNT
} ozayn_ios_event_type_t;

/* ============================================================
 * SECTION 8 — LIMITS
 * ============================================================ */

#define OZAYN_IOS_MAX_STREAMS               32
#define OZAYN_IOS_MAX_EVENTS                64
#define OZAYN_IOS_MAX_ID_LEN                64
#define OZAYN_IOS_MAX_PERMISSION_LEN        64
#define OZAYN_IOS_MAX_METADATA_LEN         256
#define OZAYN_IOS_MAX_DESCRIPTION_LEN      256
#define OZAYN_IOS_DEFAULT_STREAM_TTL_MS   300000
#define OZAYN_IOS_DEFAULT_IDLE_TIMEOUT_MS  60000
#define OZAYN_IOS_DEFAULT_OPEN_TIMEOUT_MS  30000
#define OZAYN_IOS_DEFAULT_DRAIN_TIMEOUT_MS 10000
#define OZAYN_IOS_DEFAULT_MAX_BUFFER_SIZE  (1024 * 1024)
#define OZAYN_IOS_DEFAULT_MAX_QUEUE_DEPTH  256
#define OZAYN_IOS_DEFAULT_MAX_RATE         1000
#define OZAYN_IOS_DEFAULT_MAX_DATA_SIZE    (64 * 1024)

/* ============================================================
 * SECTION 9 — STREAM DESCRIPTOR
 * ============================================================ */

typedef struct {
    char stream_id[OZAYN_IOS_MAX_ID_LEN];
    uint32_t version;
    char device_session_id[OZAYN_IOS_MAX_ID_LEN];
    char device_id[OZAYN_IOS_MAX_ID_LEN];
    char capability_id[OZAYN_IOS_MAX_ID_LEN];
    char operation_id[OZAYN_IOS_MAX_ID_LEN];
    ozayn_ios_direction_t direction;
    ozayn_ios_data_type_t data_type;
    ozayn_ios_stream_state_t state;
    ozayn_ios_buffer_policy_t buffer_policy;
    ozayn_ios_close_reason_t close_reason;

    int max_buffer_size;
    int max_queue_depth;
    int max_rate;
    int max_data_size;

    int buffer_occupied;
    int queue_depth;
    int rate_counter;
    uint64_t total_bytes_produced;
    uint64_t total_bytes_consumed;
    uint64_t total_units_produced;
    uint64_t total_units_consumed;
    uint64_t total_units_dropped;
    uint64_t total_backpressure_events;

    char owner_ref[OZAYN_IOS_MAX_ID_LEN];
    char producer_ref[OZAYN_IOS_MAX_ID_LEN];
    char consumer_ref[OZAYN_IOS_MAX_ID_LEN];
    char security_session_ref[OZAYN_IOS_MAX_ID_LEN];
    char required_permission[OZAYN_IOS_MAX_PERMISSION_LEN];

    time_t created_time;
    time_t activated_time;
    time_t last_activity_time;
    time_t expiry_time;
    time_t closed_time;

    int active;
    char metadata[OZAYN_IOS_MAX_METADATA_LEN];
} ozayn_ios_stream_t;

/* ============================================================
 * SECTION 10 — STREAM REQUEST
 * ============================================================ */

typedef struct {
    char device_session_id[OZAYN_IOS_MAX_ID_LEN];
    char device_id[OZAYN_IOS_MAX_ID_LEN];
    char capability_id[OZAYN_IOS_MAX_ID_LEN];
    char operation_id[OZAYN_IOS_MAX_ID_LEN];
    ozayn_ios_direction_t direction;
    ozayn_ios_data_type_t data_type;
    ozayn_ios_buffer_policy_t buffer_policy;
    int requested_rate;
    int requested_buffer_size;
    int requested_max_data_size;
    int requested_duration_ms;
    char requester_ref[OZAYN_IOS_MAX_ID_LEN];
    char security_session_ref[OZAYN_IOS_MAX_ID_LEN];
    char required_permission[OZAYN_IOS_MAX_PERMISSION_LEN];
    char metadata[OZAYN_IOS_MAX_METADATA_LEN];
} ozayn_ios_stream_request_t;

/* ============================================================
 * SECTION 11 — STREAM EVENT
 * ============================================================ */

typedef struct {
    ozayn_ios_event_type_t type;
    char stream_id[OZAYN_IOS_MAX_ID_LEN];
    char device_id[OZAYN_IOS_MAX_ID_LEN];
    char session_id[OZAYN_IOS_MAX_ID_LEN];
    char message[OZAYN_IOS_MAX_DESCRIPTION_LEN];
    time_t timestamp;
} ozayn_ios_event_t;

/* ============================================================
 * SECTION 12 — DATA UNIT ENVELOPE
 * ============================================================ */

typedef struct {
    char unit_id[OZAYN_IOS_MAX_ID_LEN];
    char stream_id[OZAYN_IOS_MAX_ID_LEN];
    uint64_t sequence_number;
    time_t timestamp;
    int payload_size;
    ozayn_ios_data_type_t data_type;
    uint32_t flags;
    char metadata[OZAYN_IOS_MAX_METADATA_LEN];
} ozayn_ios_data_unit_t;

/* ============================================================
 * SECTION 13 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_streams_created;
    uint64_t total_streams_authorized;
    uint64_t total_streams_opened;
    uint64_t total_streams_active;
    uint64_t total_streams_paused;
    uint64_t total_streams_closed;
    uint64_t total_streams_expired;
    uint64_t total_streams_revoked;
    uint64_t total_streams_failed;
    uint64_t total_data_units_produced;
    uint64_t total_data_units_consumed;
    uint64_t total_data_units_dropped;
    uint64_t total_backpressure_events;
    uint64_t total_rate_limit_events;
    uint64_t total_overflow_events;
    uint64_t total_state_transitions;
    uint64_t total_validation_failures;
    uint64_t total_errors;
    int current_active_streams;
    int current_paused_streams;
    int current_opening_streams;
    int current_draining_streams;
    int total_buffer_bytes_in_use;
} ozayn_ios_stats_t;

/* ============================================================
 * SECTION 14 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *device_session_service;
    void *resource_manager;
    void *safety_engine;
    void *diagnostics;
    void *audit;
    int max_streams;
    int stream_ttl_ms;
    int idle_timeout_ms;
    int open_timeout_ms;
    int drain_timeout_ms;
    int default_max_buffer_size;
    int default_max_queue_depth;
    int default_max_rate;
    int default_max_data_size;
} ozayn_ios_service_config_t;

/* ============================================================
 * SECTION 15 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    ozayn_ios_stream_t streams[OZAYN_IOS_MAX_STREAMS];
    int stream_count;
    uint32_t stream_sequence;

    ozayn_ios_event_t events[OZAYN_IOS_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;

    ozayn_ios_stats_t stats;
    ozayn_ios_service_config_t config;
} ozayn_ios_service_t;

/* ============================================================
 * SECTION 16 — LIFECYCLE
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_service_init(ozayn_ios_service_t *svc,
                                       const ozayn_ios_service_config_t *cfg);
void ozayn_ios_service_shutdown(ozayn_ios_service_t *svc);
int ozayn_ios_service_is_initialized(const ozayn_ios_service_t *svc);
ozayn_ios_service_t *ozayn_ios_get_global(void);

/* ============================================================
 * SECTION 17 — STREAM CREATION
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_create(ozayn_ios_service_t *svc,
                                         const ozayn_ios_stream_request_t *req,
                                         ozayn_ios_stream_t **out_stream);
ozayn_ios_err_t ozayn_ios_stream_authorize(ozayn_ios_service_t *svc,
                                            const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_open(ozayn_ios_service_t *svc,
                                       const char *stream_id);

/* ============================================================
 * SECTION 18 — STREAM LIFECYCLE OPERATIONS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_activate(ozayn_ios_service_t *svc,
                                           const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_pause(ozayn_ios_service_t *svc,
                                        const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_resume(ozayn_ios_service_t *svc,
                                         const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_drain(ozayn_ios_service_t *svc,
                                        const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_close(ozayn_ios_service_t *svc,
                                        const char *stream_id,
                                        ozayn_ios_close_reason_t reason);
ozayn_ios_err_t ozayn_ios_stream_revoke(ozayn_ios_service_t *svc,
                                         const char *stream_id,
                                         ozayn_ios_close_reason_t reason);

/* ============================================================
 * SECTION 19 — DATA FLOW OPERATIONS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_push_data(ozayn_ios_service_t *svc,
                                            const char *stream_id,
                                            const ozayn_ios_data_unit_t *unit);
ozayn_ios_err_t ozayn_ios_stream_pull_data(ozayn_ios_service_t *svc,
                                            const char *stream_id,
                                            ozayn_ios_data_unit_t *out_unit);
ozayn_ios_err_t ozayn_ios_stream_heartbeat(ozayn_ios_service_t *svc,
                                            const char *stream_id);

/* ============================================================
 * SECTION 20 — PRODUCER / CONSUMER
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_attach_producer(ozayn_ios_service_t *svc,
                                                  const char *stream_id,
                                                  const char *producer_ref);
ozayn_ios_err_t ozayn_ios_stream_attach_consumer(ozayn_ios_service_t *svc,
                                                  const char *stream_id,
                                                  const char *consumer_ref);
ozayn_ios_err_t ozayn_ios_stream_detach_producer(ozayn_ios_service_t *svc,
                                                  const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_detach_consumer(ozayn_ios_service_t *svc,
                                                  const char *stream_id);

/* ============================================================
 * SECTION 21 — DEVICE DISCONNECT HANDLING
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_stream_device_disconnected(ozayn_ios_service_t *svc,
                                                      const char *stream_id);
ozayn_ios_err_t ozayn_ios_stream_device_reconnected(ozayn_ios_service_t *svc,
                                                     const char *stream_id);

/* ============================================================
 * SECTION 22 — SESSION CHANGE HANDLING
 * ============================================================ */

int ozayn_ios_streams_for_session(ozayn_ios_service_t *svc,
                                   const char *session_id,
                                   ozayn_ios_stream_t **out_streams,
                                   int max_out);

/* ============================================================
 * SECTION 23 — QUERY
 * ============================================================ */

const ozayn_ios_stream_t *ozayn_ios_stream_get(const ozayn_ios_service_t *svc,
                                                const char *stream_id);
const ozayn_ios_stream_t *ozayn_ios_stream_get_by_device(
    const ozayn_ios_service_t *svc, const char *device_id);
const ozayn_ios_stream_t *ozayn_ios_stream_get_by_session(
    const ozayn_ios_service_t *svc, const char *session_id);
int ozayn_ios_stream_count(const ozayn_ios_service_t *svc);
int ozayn_ios_stream_count_by_device(const ozayn_ios_service_t *svc,
                                      const char *device_id);
int ozayn_ios_stream_count_by_session(const ozayn_ios_service_t *svc,
                                       const char *session_id);
int ozayn_ios_stream_is_active(const ozayn_ios_service_t *svc,
                                const char *stream_id);
int ozayn_ios_stream_is_expired(const ozayn_ios_service_t *svc,
                                 const char *stream_id);

/* ============================================================
 * SECTION 24 — EVENTS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_emit_event(ozayn_ios_service_t *svc,
                                      ozayn_ios_event_type_t type,
                                      const char *stream_id,
                                      const char *device_id,
                                      const char *session_id,
                                      const char *message);
const ozayn_ios_event_t *ozayn_ios_event_get(const ozayn_ios_service_t *svc,
                                              int index);
int ozayn_ios_event_count(const ozayn_ios_service_t *svc);

/* ============================================================
 * SECTION 25 — CLEANUP
 * ============================================================ */

int ozayn_ios_cleanup_expired_streams(ozayn_ios_service_t *svc);
int ozayn_ios_cleanup_idle_streams(ozayn_ios_service_t *svc);
int ozayn_ios_cleanup_closed_streams(ozayn_ios_service_t *svc);
int ozayn_ios_cleanup_all(ozayn_ios_service_t *svc);

/* ============================================================
 * SECTION 26 — STATISTICS
 * ============================================================ */

ozayn_ios_err_t ozayn_ios_get_stats(const ozayn_ios_service_t *svc,
                                     ozayn_ios_stats_t *out_stats);

/* ============================================================
 * SECTION 27 — VALIDATION
 * ============================================================ */

int ozayn_ios_stream_validate(const ozayn_ios_stream_t *stream);
int ozayn_ios_stream_request_validate(const ozayn_ios_stream_request_t *req);
int ozayn_ios_state_transition_valid(ozayn_ios_stream_state_t from,
                                      ozayn_ios_stream_state_t to);

/* ============================================================
 * SECTION 28 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ios_err_name(ozayn_ios_err_t err);
const char *ozayn_ios_direction_name(ozayn_ios_direction_t dir);
const char *ozayn_ios_data_type_name(ozayn_ios_data_type_t dt);
const char *ozayn_ios_stream_state_name(ozayn_ios_stream_state_t state);
const char *ozayn_ios_buffer_policy_name(ozayn_ios_buffer_policy_t policy);
const char *ozayn_ios_close_reason_name(ozayn_ios_close_reason_t reason);
const char *ozayn_ios_event_type_name(ozayn_ios_event_type_t type);

#endif /* OZAYN_IO_STREAM_H */
