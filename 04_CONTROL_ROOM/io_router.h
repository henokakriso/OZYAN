#ifndef OZAYN_IO_ROUTER_H
#define OZAYN_IO_ROUTER_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_IOR_OK                            =   0,
    OZAYN_IOR_ERR_NULL                      =  -1,
    OZAYN_IOR_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_IOR_ERR_ALREADY_INIT              =  -3,
    OZAYN_IOR_ERR_INVALID_PARAM             =  -4,
    OZAYN_IOR_ERR_LIMIT_REACHED             =  -5,
    OZAYN_IOR_ERR_NOT_FOUND                 =  -6,
    OZAYN_IOR_ERR_STATE_INVALID             =  -7,
    OZAYN_IOR_ERR_AUTH_FAILED               =  -8,
    OZAYN_IOR_ERR_PERMISSION_DENIED         =  -9,
    OZAYN_IOR_ERR_STREAM_INVALID            = -10,
    OZAYN_IOR_ERR_STREAM_UNAVAILABLE        = -11,
    OZAYN_IOR_ERR_SOURCE_INVALID            = -12,
    OZAYN_IOR_ERR_SOURCE_NOT_FOUND          = -13,
    OZAYN_IOR_ERR_DESTINATION_INVALID       = -14,
    OZAYN_IOR_ERR_DESTINATION_NOT_FOUND     = -15,
    OZAYN_IOR_ERR_ENDPOINT_UNAVAILABLE      = -16,
    OZAYN_IOR_ERR_DATA_TYPE_MISMATCH        = -17,
    OZAYN_IOR_ERR_DIRECTION_INVALID         = -18,
    OZAYN_IOR_ERR_POLICY_DENIED             = -19,
    OZAYN_IOR_ERR_PRECONDITION_FAILED       = -20,
    OZAYN_IOR_ERR_RESOURCE_UNAVAILABLE      = -21,
    OZAYN_IOR_ERR_RESOURCE_LIMIT            = -22,
    OZAYN_IOR_ERR_BUFFER_LIMIT              = -23,
    OZAYN_IOR_ERR_RATE_LIMIT                = -24,
    OZAYN_IOR_ERR_LOOP_DETECTED             = -25,
    OZAYN_IOR_ERR_TIMEOUT                   = -26,
    OZAYN_IOR_ERR_EXPIRED                   = -27,
    OZAYN_IOR_ERR_REVOKED                   = -28,
    OZAYN_IOR_ERR_DEVICE_DISCONNECTED       = -29,
    OZAYN_IOR_ERR_CONCURRENCY               = -30,
    OZAYN_IOR_ERR_PROVIDER_ERROR            = -31,
    OZAYN_IOR_ERR_EXECUTION                 = -32
} ozayn_ior_err_t;

/* ============================================================
 * SECTION 2 — ROUTE STATES
 * ============================================================ */

typedef enum {
    OZAYN_IOR_ROUTE_REQUESTED = 0,
    OZAYN_IOR_ROUTE_VALIDATING,
    OZAYN_IOR_ROUTE_AUTHORIZED,
    OZAYN_IOR_ROUTE_WAITING,
    OZAYN_IOR_ROUTE_CONNECTING,
    OZAYN_IOR_ROUTE_ACTIVE,
    OZAYN_IOR_ROUTE_PAUSED,
    OZAYN_IOR_ROUTE_BACKPRESSURED,
    OZAYN_IOR_ROUTE_DISCONNECTING,
    OZAYN_IOR_ROUTE_CLOSED,
    OZAYN_IOR_ROUTE_FAILED,
    OZAYN_IOR_ROUTE_EXPIRED,
    OZAYN_IOR_ROUTE_REVOKED,
    OZAYN_IOR_ROUTE_UNAVAILABLE,
    OZAYN_IOR_ROUTE_STATE_COUNT
} ozayn_ior_route_state_t;

/* ============================================================
 * SECTION 3 — ENDPOINT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_IOR_ENDPOINT_DEVICE = 0,
    OZAYN_IOR_ENDPOINT_DEVICE_SESSION,
    OZAYN_IOR_ENDPOINT_STREAM,
    OZAYN_IOR_ENDPOINT_CORE_COMPONENT,
    OZAYN_IOR_ENDPOINT_MODULE,
    OZAYN_IOR_ENDPOINT_TASK,
    OZAYN_IOR_ENDPOINT_CONTROLLED_SERVICE,
    OZAYN_IOR_ENDPOINT_COUNT
} ozayn_ior_endpoint_type_t;

/* ============================================================
 * SECTION 4 — ROUTE CLOSE REASONS
 * ============================================================ */

typedef enum {
    OZAYN_IOR_CLOSE_NONE = 0,
    OZAYN_IOR_CLOSE_MANUAL_CLOSE,
    OZAYN_IOR_CLOSE_STREAM_CLOSED,
    OZAYN_IOR_CLOSE_STREAM_EXPIRED,
    OZAYN_IOR_CLOSE_STREAM_REVOKED,
    OZAYN_IOR_CLOSE_DEVICE_DISCONNECTED,
    OZAYN_IOR_CLOSE_SESSION_EXPIRED,
    OZAYN_IOR_CLOSE_SESSION_REVOKED,
    OZAYN_IOR_CLOSE_ENDPOINT_UNAVAILABLE,
    OZAYN_IOR_CLOSE_POLICY_CHANGED,
    OZAYN_IOR_CLOSE_RESOURCE_EXHAUSTED,
    OZAYN_IOR_CLOSE_BUFFER_OVERFLOW,
    OZAYN_IOR_CLOSE_RATE_EXCEEDED,
    OZAYN_IOR_CLOSE_TIMEOUT,
    OZAYN_IOR_CLOSE_SYSTEM_SHUTDOWN,
    OZAYN_IOR_CLOSE_LOOP_DETECTED,
    OZAYN_IOR_CLOSE_CONCURRENT_ERROR,
    OZAYN_IOR_CLOSE_REASON_COUNT
} ozayn_ior_close_reason_t;

/* ============================================================
 * SECTION 5 — ROUTE EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_IOR_EVENT_ROUTE_REQUESTED = 0,
    OZAYN_IOR_EVENT_ROUTE_VALIDATED,
    OZAYN_IOR_EVENT_ROUTE_AUTHORIZED,
    OZAYN_IOR_EVENT_ROUTE_REJECTED,
    OZAYN_IOR_EVENT_ROUTE_CONNECTING,
    OZAYN_IOR_EVENT_ROUTE_ACTIVE,
    OZAYN_IOR_EVENT_ROUTE_PAUSED,
    OZAYN_IOR_EVENT_ROUTE_RESUMED,
    OZAYN_IOR_EVENT_ROUTE_BACKPRESSURED,
    OZAYN_IOR_EVENT_ROUTE_DATA_DROPPED,
    OZAYN_IOR_EVENT_ROUTE_DISCONNECTING,
    OZAYN_IOR_EVENT_ROUTE_CLOSED,
    OZAYN_IOR_EVENT_ROUTE_EXPIRED,
    OZAYN_IOR_EVENT_ROUTE_REVOKED,
    OZAYN_IOR_EVENT_ROUTE_UNAVAILABLE,
    OZAYN_IOR_EVENT_ROUTE_FAILED,
    OZAYN_IOR_EVENT_ROUTE_LOOP_DETECTED,
    OZAYN_IOR_EVENT_ROUTE_ENDPOINT_UNAVAILABLE,
    OZAYN_IOR_EVENT_COUNT
} ozayn_ior_event_type_t;

/* ============================================================
 * SECTION 6 — ROUTE MODES
 * ============================================================ */

typedef enum {
    OZAYN_IOR_MODE_ONE_TO_ONE = 0,
    OZAYN_IOR_MODE_ONE_TO_MANY,
    OZAYN_IOR_MODE_COUNT
} ozayn_ior_route_mode_t;

/* ============================================================
 * SECTION 7 — LIMITS
 * ============================================================ */

#define OZAYN_IOR_MAX_ROUTES                32
#define OZAYN_IOR_MAX_EVENTS                64
#define OZAYN_IOR_MAX_ENDPOINTS             32
#define OZAYN_IOR_MAX_ID_LEN                64
#define OZAYN_IOR_MAX_PERMISSION_LEN        64
#define OZAYN_IOR_MAX_METADATA_LEN         256
#define OZAYN_IOR_MAX_DESCRIPTION_LEN      256
#define OZAYN_IOR_DEFAULT_ROUTE_TTL_MS    300000
#define OZAYN_IOR_DEFAULT_IDLE_TIMEOUT_MS  60000
#define OZAYN_IOR_MAX_LOOP_DEPTH              8

/* ============================================================
 * SECTION 8 — ROUTE DESCRIPTOR
 * ============================================================ */

typedef struct {
    char route_id[OZAYN_IOR_MAX_ID_LEN];
    uint32_t version;
    char stream_id[OZAYN_IOR_MAX_ID_LEN];
    char source_id[OZAYN_IOR_MAX_ID_LEN];
    ozayn_ior_endpoint_type_t source_type;
    char destination_id[OZAYN_IOR_MAX_ID_LEN];
    ozayn_ior_endpoint_type_t destination_type;
    ozayn_ior_route_mode_t mode;
    ozayn_ior_route_state_t state;
    ozayn_ior_close_reason_t close_reason;
    char device_session_id[OZAYN_IOR_MAX_ID_LEN];
    char device_id[OZAYN_IOR_MAX_ID_LEN];
    char capability_id[OZAYN_IOR_MAX_ID_LEN];
    char operation_id[OZAYN_IOR_MAX_ID_LEN];
    char security_session_ref[OZAYN_IOR_MAX_ID_LEN];
    char requester_ref[OZAYN_IOR_MAX_ID_LEN];
    char required_permission[OZAYN_IOR_MAX_PERMISSION_LEN];
    time_t created_time;
    time_t activated_time;
    time_t last_activity_time;
    time_t expiry_time;
    time_t closed_time;
    int active;
    char metadata[OZAYN_IOR_MAX_METADATA_LEN];
} ozayn_ior_route_t;

/* ============================================================
 * SECTION 9 — ROUTE REQUEST
 * ============================================================ */

typedef struct {
    char stream_id[OZAYN_IOR_MAX_ID_LEN];
    char source_id[OZAYN_IOR_MAX_ID_LEN];
    ozayn_ior_endpoint_type_t source_type;
    char destination_id[OZAYN_IOR_MAX_ID_LEN];
    ozayn_ior_endpoint_type_t destination_type;
    ozayn_ior_route_mode_t mode;
    char requester_ref[OZAYN_IOR_MAX_ID_LEN];
    char security_session_ref[OZAYN_IOR_MAX_ID_LEN];
    char required_permission[OZAYN_IOR_MAX_PERMISSION_LEN];
    char device_session_id[OZAYN_IOR_MAX_ID_LEN];
    int lifetime_ms;
    char metadata[OZAYN_IOR_MAX_METADATA_LEN];
} ozayn_ior_route_request_t;

/* ============================================================
 * SECTION 10 — ENDPOINT DESCRIPTOR
 * ============================================================ */

typedef struct {
    char endpoint_id[OZAYN_IOR_MAX_ID_LEN];
    ozayn_ior_endpoint_type_t type;
    char provider[OZAYN_IOR_MAX_ID_LEN];
    uint32_t version;
    int available;
    int health;
    char supported_data_types[OZAYN_IOR_MAX_METADATA_LEN];
    char accepted_directions[OZAYN_IOR_MAX_METADATA_LEN];
    char required_permissions[OZAYN_IOR_MAX_PERMISSION_LEN];
    time_t registered_time;
    time_t last_update;
    int active;
    char metadata[OZAYN_IOR_MAX_METADATA_LEN];
} ozayn_ior_endpoint_t;

/* ============================================================
 * SECTION 11 — ROUTE EVENT
 * ============================================================ */

typedef struct {
    ozayn_ior_event_type_t type;
    char route_id[OZAYN_IOR_MAX_ID_LEN];
    char stream_id[OZAYN_IOR_MAX_ID_LEN];
    char source_id[OZAYN_IOR_MAX_ID_LEN];
    char destination_id[OZAYN_IOR_MAX_ID_LEN];
    char message[OZAYN_IOR_MAX_DESCRIPTION_LEN];
    time_t timestamp;
} ozayn_ior_event_t;

/* ============================================================
 * SECTION 12 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_routes_created;
    uint64_t total_routes_authorized;
    uint64_t total_routes_connected;
    uint64_t total_routes_active;
    uint64_t total_routes_paused;
    uint64_t total_routes_closed;
    uint64_t total_routes_expired;
    uint64_t total_routes_revoked;
    uint64_t total_routes_failed;
    uint64_t total_routes_rejected;
    uint64_t total_loop_detections;
    uint64_t total_state_transitions;
    uint64_t total_validation_failures;
    uint64_t total_errors;
    int current_active_routes;
    int current_paused_routes;
    int current_connecting_routes;
    int endpoints_registered;
} ozayn_ior_stats_t;

/* ============================================================
 * SECTION 13 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *io_stream_service;
    void *device_session_service;
    void *resource_manager;
    void *safety_engine;
    void *diagnostics;
    void *audit;
    int max_routes;
    int max_endpoints;
    int route_ttl_ms;
    int idle_timeout_ms;
    int max_loop_depth;
} ozayn_ior_service_config_t;

/* ============================================================
 * SECTION 14 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    ozayn_ior_route_t routes[OZAYN_IOR_MAX_ROUTES];
    int route_count;
    uint32_t route_sequence;

    ozayn_ior_endpoint_t endpoints[OZAYN_IOR_MAX_ENDPOINTS];
    int endpoint_count;

    ozayn_ior_event_t events[OZAYN_IOR_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;

    ozayn_ior_stats_t stats;
    ozayn_ior_service_config_t config;
} ozayn_ior_service_t;

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_service_init(ozayn_ior_service_t *svc,
                                        const ozayn_ior_service_config_t *cfg);
void ozayn_ior_service_shutdown(ozayn_ior_service_t *svc);
int ozayn_ior_service_is_initialized(const ozayn_ior_service_t *svc);
ozayn_ior_service_t *ozayn_ior_get_global(void);

/* ============================================================
 * SECTION 16 — ENDPOINT REGISTRATION
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_endpoint_register(ozayn_ior_service_t *svc,
                                             const ozayn_ior_endpoint_t *ep);
ozayn_ior_err_t ozayn_ior_endpoint_unregister(ozayn_ior_service_t *svc,
                                               const char *endpoint_id);
const ozayn_ior_endpoint_t *ozayn_ior_endpoint_get(
    const ozayn_ior_service_t *svc, const char *endpoint_id);
int ozayn_ior_endpoint_count(const ozayn_ior_service_t *svc);
int ozayn_ior_endpoint_is_available(const ozayn_ior_service_t *svc,
                                     const char *endpoint_id);

/* ============================================================
 * SECTION 17 — ROUTE CREATION
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_route_create(ozayn_ior_service_t *svc,
                                        const ozayn_ior_route_request_t *req,
                                        ozayn_ior_route_t **out_route);
ozayn_ior_err_t ozayn_ior_route_authorize(ozayn_ior_service_t *svc,
                                           const char *route_id);
ozayn_ior_err_t ozayn_ior_route_connect(ozayn_ior_service_t *svc,
                                         const char *route_id);

/* ============================================================
 * SECTION 18 — ROUTE LIFECYCLE OPERATIONS
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_route_activate(ozayn_ior_service_t *svc,
                                          const char *route_id);
ozayn_ior_err_t ozayn_ior_route_pause(ozayn_ior_service_t *svc,
                                       const char *route_id);
ozayn_ior_err_t ozayn_ior_route_resume(ozayn_ior_service_t *svc,
                                        const char *route_id);
ozayn_ior_err_t ozayn_ior_route_disconnect(ozayn_ior_service_t *svc,
                                            const char *route_id);
ozayn_ior_err_t ozayn_ior_route_close(ozayn_ior_service_t *svc,
                                       const char *route_id,
                                       ozayn_ior_close_reason_t reason);
ozayn_ior_err_t ozayn_ior_route_revoke(ozayn_ior_service_t *svc,
                                        const char *route_id,
                                        ozayn_ior_close_reason_t reason);
ozayn_ior_err_t ozayn_ior_route_remove(ozayn_ior_service_t *svc,
                                        const char *route_id);

/* ============================================================
 * SECTION 19 — ROUTE QUERY
 * ============================================================ */

const ozayn_ior_route_t *ozayn_ior_route_get(const ozayn_ior_service_t *svc,
                                              const char *route_id);
const ozayn_ior_route_t *ozayn_ior_route_get_by_stream(
    const ozayn_ior_service_t *svc, const char *stream_id);
const ozayn_ior_route_t *ozayn_ior_route_get_by_source(
    const ozayn_ior_service_t *svc, const char *source_id);
const ozayn_ior_route_t *ozayn_ior_route_get_by_destination(
    const ozayn_ior_service_t *svc, const char *destination_id);
int ozayn_ior_route_count(const ozayn_ior_service_t *svc);
int ozayn_ior_route_count_by_stream(const ozayn_ior_service_t *svc,
                                     const char *stream_id);
int ozayn_ior_route_is_active(const ozayn_ior_service_t *svc,
                               const char *route_id);

/* ============================================================
 * SECTION 20 — STREAM CHANGE HANDLING
 * ============================================================ */

int ozayn_ior_routes_for_stream(ozayn_ior_service_t *svc,
                                 const char *stream_id,
                                 ozayn_ior_route_t **out_routes,
                                 int max_out);
ozayn_ior_err_t ozayn_ior_stream_closed(ozayn_ior_service_t *svc,
                                         const char *stream_id);
ozayn_ior_err_t ozayn_ior_device_disconnected(ozayn_ior_service_t *svc,
                                               const char *device_id);

/* ============================================================
 * SECTION 21 — EVENTS
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_emit_event(ozayn_ior_service_t *svc,
                                      ozayn_ior_event_type_t type,
                                      const char *route_id,
                                      const char *stream_id,
                                      const char *source_id,
                                      const char *destination_id,
                                      const char *message);
const ozayn_ior_event_t *ozayn_ior_event_get(const ozayn_ior_service_t *svc,
                                              int index);
int ozayn_ior_event_count(const ozayn_ior_service_t *svc);

/* ============================================================
 * SECTION 22 — CLEANUP
 * ============================================================ */

int ozayn_ior_cleanup_expired_routes(ozayn_ior_service_t *svc);
int ozayn_ior_cleanup_idle_routes(ozayn_ior_service_t *svc);
int ozayn_ior_cleanup_closed_routes(ozayn_ior_service_t *svc);
int ozayn_ior_cleanup_all(ozayn_ior_service_t *svc);

/* ============================================================
 * SECTION 23 — STATISTICS
 * ============================================================ */

ozayn_ior_err_t ozayn_ior_get_stats(const ozayn_ior_service_t *svc,
                                     ozayn_ior_stats_t *out_stats);

/* ============================================================
 * SECTION 24 — VALIDATION
 * ============================================================ */

int ozayn_ior_route_validate(const ozayn_ior_route_t *route);
int ozayn_ior_route_request_validate(const ozayn_ior_route_request_t *req);
int ozayn_ior_state_transition_valid(ozayn_ior_route_state_t from,
                                      ozayn_ior_route_state_t to);

/* ============================================================
 * SECTION 25 — NAME HELPERS
 * ============================================================ */

const char *ozayn_ior_err_name(ozayn_ior_err_t err);
const char *ozayn_ior_route_state_name(ozayn_ior_route_state_t state);
const char *ozayn_ior_endpoint_type_name(ozayn_ior_endpoint_type_t type);
const char *ozayn_ior_close_reason_name(ozayn_ior_close_reason_t reason);
const char *ozayn_ior_event_type_name(ozayn_ior_event_type_t type);
const char *ozayn_ior_route_mode_name(ozayn_ior_route_mode_t mode);

#endif /* OZAYN_IO_ROUTER_H */
