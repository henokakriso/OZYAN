#ifndef OZAYN_PIPELINE_H
#define OZAYN_PIPELINE_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_OK                            =   0,
    OZAYN_PCO_ERR_NULL                      =  -1,
    OZAYN_PCO_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_PCO_ERR_ALREADY_INIT              =  -3,
    OZAYN_PCO_ERR_INVALID_PARAM             =  -4,
    OZAYN_PCO_ERR_LIMIT_REACHED             =  -5,
    OZAYN_PCO_ERR_NOT_FOUND                 =  -6,
    OZAYN_PCO_ERR_DUPLICATE                 =  -7,
    OZAYN_PCO_ERR_STATE_INVALID             =  -8,
    OZAYN_PCO_ERR_AUTH_FAILED               =  -9,
    OZAYN_PCO_ERR_PERMISSION_DENIED         = -10,
    OZAYN_PCO_ERR_UNAVAILABLE               = -11,
    OZAYN_PCO_ERR_GRAPH_INVALID             = -12,
    OZAYN_PCO_ERR_GRAPH_CYCLE               = -13,
    OZAYN_PCO_ERR_DEPENDENCY_FAILED         = -14,
    OZAYN_PCO_ERR_ROUTE_INVALID             = -15,
    OZAYN_PCO_ERR_ROUTE_NOT_FOUND           = -16,
    OZAYN_PCO_ERR_STREAM_INVALID            = -17,
    OZAYN_PCO_ERR_STREAM_NOT_FOUND          = -18,
    OZAYN_PCO_ERR_STAGE_NOT_FOUND           = -19,
    OZAYN_PCO_ERR_ENDPOINT_UNAVAILABLE      = -20,
    OZAYN_PCO_ERR_DEVICE_DISCONNECTED       = -21,
    OZAYN_PCO_ERR_RESOURCE_UNAVAILABLE      = -22,
    OZAYN_PCO_ERR_RESOURCE_LIMIT            = -23,
    OZAYN_PCO_ERR_RESERVATION_FAILED        = -24,
    OZAYN_PCO_ERR_POLICY_DENIED             = -25,
    OZAYN_PCO_ERR_SAFETY_CHECK_FAILED       = -26,
    OZAYN_PCO_ERR_SYNC_FAILED               = -27,
    OZAYN_PCO_ERR_SYNC_TIMEOUT              = -28,
    OZAYN_PCO_ERR_ORDER_ERROR               = -29,
    OZAYN_PCO_ERR_BACKPRESSURE              = -30,
    OZAYN_PCO_ERR_BUFFER_LIMIT              = -31,
    OZAYN_PCO_ERR_RATE_LIMIT                = -32,
    OZAYN_PCO_ERR_START_FAILED              = -33,
    OZAYN_PCO_ERR_PAUSE_FAILED              = -34,
    OZAYN_PCO_ERR_RESUME_FAILED             = -35,
    OZAYN_PCO_ERR_DRAIN_FAILED              = -36,
    OZAYN_PCO_ERR_DRAIN_TIMEOUT             = -37,
    OZAYN_PCO_ERR_STOP_FAILED               = -38,
    OZAYN_PCO_ERR_TIMEOUT                   = -39,
    OZAYN_PCO_ERR_EXPIRED                   = -40,
    OZAYN_PCO_ERR_REVOKED                   = -41,
    OZAYN_PCO_ERR_CANCELLED                 = -42,
    OZAYN_PCO_ERR_CONCURRENCY               = -43,
    OZAYN_PCO_ERR_CONFIGURATION             = -44,
    OZAYN_PCO_ERR_EVENT_ERROR               = -45,
    OZAYN_PCO_ERR_HISTORY_ERROR             = -46,
    OZAYN_PCO_ERR_EXECUTION                 = -47
} ozayn_pco_err_t;

/* ============================================================
 * SECTION 2 — PIPELINE STATES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_PIPELINE_CREATED = 0,
    OZAYN_PCO_PIPELINE_VALIDATING,
    OZAYN_PCO_PIPELINE_AUTHORIZED,
    OZAYN_PCO_PIPELINE_READY,
    OZAYN_PCO_PIPELINE_STARTING,
    OZAYN_PCO_PIPELINE_ACTIVE,
    OZAYN_PCO_PIPELINE_PAUSING,
    OZAYN_PCO_PIPELINE_PAUSED,
    OZAYN_PCO_PIPELINE_RESUMING,
    OZAYN_PCO_PIPELINE_DRAINING,
    OZAYN_PCO_PIPELINE_STOPPING,
    OZAYN_PCO_PIPELINE_STOPPED,
    OZAYN_PCO_PIPELINE_FAILED,
    OZAYN_PCO_PIPELINE_DEGRADED,
    OZAYN_PCO_PIPELINE_EXPIRED,
    OZAYN_PCO_PIPELINE_REVOKED,
    OZAYN_PCO_PIPELINE_UNAVAILABLE,
    OZAYN_PCO_PIPELINE_CANCELLED,
    OZAYN_PCO_PIPELINE_STATE_COUNT
} ozayn_pco_pipeline_state_t;

/* ============================================================
 * SECTION 3 — PIPELINE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_PIPELINE_TYPE_LINEAR = 0,
    OZAYN_PCO_PIPELINE_TYPE_FAN_OUT,
    OZAYN_PCO_PIPELINE_TYPE_FAN_IN,
    OZAYN_PCO_PIPELINE_TYPE_COMPLEX,
    OZAYN_PCO_PIPELINE_TYPE_COUNT
} ozayn_pco_pipeline_type_t;

/* ============================================================
 * SECTION 4 — STAGE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_STAGE_SOURCE = 0,
    OZAYN_PCO_STAGE_ROUTE,
    OZAYN_PCO_STAGE_BUFFER,
    OZAYN_PCO_STAGE_SYNC,
    OZAYN_PCO_STAGE_TRANSFORM_BOUNDARY,
    OZAYN_PCO_STAGE_DESTINATION,
    OZAYN_PCO_STAGE_COUNT
} ozayn_pco_stage_type_t;

/* ============================================================
 * SECTION 5 — STAGE STATES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_STAGE_CREATED = 0,
    OZAYN_PCO_STAGE_VALIDATING,
    OZAYN_PCO_STAGE_READY,
    OZAYN_PCO_STAGE_STARTING,
    OZAYN_PCO_STAGE_ACTIVE,
    OZAYN_PCO_STAGE_PAUSED,
    OZAYN_PCO_STAGE_DRAINING,
    OZAYN_PCO_STAGE_COMPLETED,
    OZAYN_PCO_STAGE_FAILED,
    OZAYN_PCO_STAGE_UNAVAILABLE,
    OZAYN_PCO_STAGE_STATE_COUNT
} ozayn_pco_stage_state_t;

/* ============================================================
 * SECTION 6 — FLOW STATES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_FLOW_NORMAL = 0,
    OZAYN_PCO_FLOW_THROTTLED,
    OZAYN_PCO_FLOW_BACKPRESSURED,
    OZAYN_PCO_FLOW_DRAINING,
    OZAYN_PCO_FLOW_BLOCKED,
    OZAYN_PCO_FLOW_FAILED,
    OZAYN_PCO_FLOW_COUNT
} ozayn_pco_flow_state_t;

/* ============================================================
 * SECTION 7 — PIPELINE EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_PCO_EVENT_PIPELINE_CREATED = 0,
    OZAYN_PCO_EVENT_PIPELINE_VALIDATING,
    OZAYN_PCO_EVENT_PIPELINE_AUTHORIZED,
    OZAYN_PCO_EVENT_PIPELINE_READY,
    OZAYN_PCO_EVENT_PIPELINE_STARTING,
    OZAYN_PCO_EVENT_PIPELINE_ACTIVE,
    OZAYN_PCO_EVENT_PIPELINE_PAUSING,
    OZAYN_PCO_EVENT_PIPELINE_PAUSED,
    OZAYN_PCO_EVENT_PIPELINE_RESUMING,
    OZAYN_PCO_EVENT_PIPELINE_DRAINING,
    OZAYN_PCO_EVENT_PIPELINE_STOPPING,
    OZAYN_PCO_EVENT_PIPELINE_STOPPED,
    OZAYN_PCO_EVENT_PIPELINE_DEGRADED,
    OZAYN_PCO_EVENT_PIPELINE_FAILED,
    OZAYN_PCO_EVENT_PIPELINE_EXPIRED,
    OZAYN_PCO_EVENT_PIPELINE_REVOKED,
    OZAYN_PCO_EVENT_PIPELINE_CANCELLED,
    OZAYN_PCO_EVENT_STAGE_READY,
    OZAYN_PCO_EVENT_STAGE_STARTED,
    OZAYN_PCO_EVENT_STAGE_PAUSED,
    OZAYN_PCO_EVENT_STAGE_COMPLETED,
    OZAYN_PCO_EVENT_STAGE_FAILED,
    OZAYN_PCO_EVENT_BACKPRESSURED,
    OZAYN_PCO_EVENT_THROTTLED,
    OZAYN_PCO_EVENT_BLOCKED,
    OZAYN_PCO_EVENT_DRAIN_TIMEOUT,
    OZAYN_PCO_EVENT_SYNC_WAIT,
    OZAYN_PCO_EVENT_SYNC_READY,
    OZAYN_PCO_EVENT_SYNC_TIMEOUT,
    OZAYN_PCO_EVENT_ORDER_ERROR,
    OZAYN_PCO_EVENT_RESOURCE_UNAVAILABLE,
    OZAYN_PCO_EVENT_AUTHORIZATION_FAILED,
    OZAYN_PCO_EVENT_POLICY_DENIED,
    OZAYN_PCO_EVENT_DEPENDENCY_FAILED,
    OZAYN_PCO_EVENT_DEVICE_DISCONNECTED,
    OZAYN_PCO_EVENT_ROUTE_FAILED,
    OZAYN_PCO_EVENT_STREAM_FAILED,
    OZAYN_PCO_EVENT_COUNT
} ozayn_pco_event_type_t;

/* ============================================================
 * SECTION 8 — CLOSE REASONS
 * ============================================================ */

typedef enum {
    OZAYN_PCO_CLOSE_NONE = 0,
    OZAYN_PCO_CLOSE_MANUAL_STOP,
    OZAYN_PCO_CLOSE_DRAIN_COMPLETE,
    OZAYN_PCO_CLOSE_DRAIN_TIMEOUT,
    OZAYN_PCO_CLOSE_ROUTE_FAILED,
    OZAYN_PCO_CLOSE_STREAM_FAILED,
    OZAYN_PCO_CLOSE_DEVICE_DISCONNECTED,
    OZAYN_PCO_CLOSE_RESOURCE_EXHAUSTED,
    OZAYN_PCO_CLOSE_AUTHORIZATION_EXPIRED,
    OZAYN_PCO_CLOSE_AUTHORIZATION_REVOKED,
    OZAYN_PCO_CLOSE_POLICY_CHANGED,
    OZAYN_PCO_CLOSE_SAFETY_REJECTION,
    OZAYN_PCO_CLOSE_TIMEOUT,
    OZAYN_PCO_CLOSE_EXPIRED,
    OZAYN_PCO_CLOSE_SYSTEM_SHUTDOWN,
    OZAYN_PCO_CLOSE_STAGE_FAILURE,
    OZAYN_PCO_CLOSE_GRAPH_ERROR,
    OZAYN_PCO_CLOSE_CONCURRENT_ERROR,
    OZAYN_PCO_CLOSE_REASON_COUNT
} ozayn_pco_close_reason_t;

/* ============================================================
 * SECTION 9 — EDGE DIRECTIONS
 * ============================================================ */

typedef enum {
    OZAYN_PCO_EDGE_OUTPUT = 0,
    OZAYN_PCO_EDGE_INPUT,
    OZAYN_PCO_EDGE_BIDIRECTIONAL,
    OZAYN_PCO_EDGE_DIRECTION_COUNT
} ozayn_pco_edge_direction_t;

/* ============================================================
 * SECTION 10 — LIMITS
 * ============================================================ */

#define OZAYN_PCO_MAX_PIPELINES            16
#define OZAYN_PCO_MAX_STAGES               32
#define OZAYN_PCO_MAX_EDGES                64
#define OZAYN_PCO_MAX_ROUTES_PER_PIPELINE  32
#define OZAYN_PCO_MAX_STREAMS_PER_PIPELINE 32
#define OZAYN_PCO_MAX_EVENTS               64
#define OZAYN_PCO_MAX_ID_LEN               64
#define OZAYN_PCO_MAX_NAME_LEN            128
#define OZAYN_PCO_MAX_DESCRIPTION_LEN     256
#define OZAYN_PCO_MAX_METADATA_LEN        256
#define OZAYN_PCO_MAX_PERMISSION_LEN       64
#define OZAYN_PCO_MAX_RESOURCE_REFS        16
#define OZAYN_PCO_MAX_DEP_REFS             16
#define OZAYN_PCO_MAX_FAN_OUT              16
#define OZAYN_PCO_MAX_FAN_IN               16
#define OZAYN_PCO_DEFAULT_PIPELINE_TTL_MS  300000
#define OZAYN_PCO_DEFAULT_DRAIN_TIMEOUT_MS  30000
#define OZAYN_PCO_DEFAULT_SYNC_TIMEOUT_MS   10000
#define OZAYN_PCO_DEFAULT_MAX_RUNTIME_MS   600000
#define OZAYN_PCO_MAX_CONCURRENT_PIPELINES   8

/* ============================================================
 * SECTION 11 — PIPELINE DESCRIPTOR
 * ============================================================ */

typedef struct {
    char pipeline_id[OZAYN_PCO_MAX_ID_LEN];
    uint32_t version;
    char name[OZAYN_PCO_MAX_NAME_LEN];
    char description[OZAYN_PCO_MAX_DESCRIPTION_LEN];
    ozayn_pco_pipeline_state_t state;
    ozayn_pco_pipeline_type_t type;
    ozayn_pco_flow_state_t flow_state;
    ozayn_pco_close_reason_t close_reason;

    int stage_count;
    int edge_count;

    char route_refs[OZAYN_PCO_MAX_ROUTES_PER_PIPELINE][OZAYN_PCO_MAX_ID_LEN];
    int route_ref_count;
    char stream_refs[OZAYN_PCO_MAX_STREAMS_PER_PIPELINE][OZAYN_PCO_MAX_ID_LEN];
    int stream_ref_count;

    char resource_refs[OZAYN_PCO_MAX_RESOURCE_REFS][OZAYN_PCO_MAX_ID_LEN];
    int resource_ref_count;

    char security_session_ref[OZAYN_PCO_MAX_ID_LEN];
    char authorization_ref[OZAYN_PCO_MAX_ID_LEN];
    char safety_decision_ref[OZAYN_PCO_MAX_ID_LEN];
    char requester_ref[OZAYN_PCO_MAX_ID_LEN];
    char owner_ref[OZAYN_PCO_MAX_ID_LEN];

    time_t created_time;
    time_t activation_time;
    time_t last_update_time;
    time_t expiry_time;
    time_t closed_time;

    int active;
    char metadata[OZAYN_PCO_MAX_METADATA_LEN];
} ozayn_pco_pipeline_t;

/* ============================================================
 * SECTION 12 — PIPELINE STAGE
 * ============================================================ */

typedef struct {
    char stage_id[OZAYN_PCO_MAX_ID_LEN];
    char pipeline_id[OZAYN_PCO_MAX_ID_LEN];
    ozayn_pco_stage_type_t type;
    ozayn_pco_stage_state_t state;
    int order;
    int is_optional;

    char input_route_ref[OZAYN_PCO_MAX_ID_LEN];
    char input_stream_ref[OZAYN_PCO_MAX_ID_LEN];
    char output_route_ref[OZAYN_PCO_MAX_ID_LEN];
    char output_stream_ref[OZAYN_PCO_MAX_ID_LEN];

    char required_capability[OZAYN_PCO_MAX_ID_LEN];
    char required_resource_refs[OZAYN_PCO_MAX_RESOURCE_REFS][OZAYN_PCO_MAX_ID_LEN];
    int required_resource_count;
    char required_permission[OZAYN_PCO_MAX_PERMISSION_LEN];

    char dependency_stage_ids[OZAYN_PCO_MAX_DEP_REFS][OZAYN_PCO_MAX_ID_LEN];
    int dependency_count;

    int timeout_ms;
    uint64_t sequence_number;

    time_t created_time;
    time_t activation_time;
    time_t last_update_time;
    int active;

    char metadata[OZAYN_PCO_MAX_METADATA_LEN];
} ozayn_pco_stage_t;

/* ============================================================
 * SECTION 13 — PIPELINE GRAPH EDGE
 * ============================================================ */

typedef struct {
    char edge_id[OZAYN_PCO_MAX_ID_LEN];
    char pipeline_id[OZAYN_PCO_MAX_ID_LEN];
    char source_stage_id[OZAYN_PCO_MAX_ID_LEN];
    char destination_stage_id[OZAYN_PCO_MAX_ID_LEN];
    char route_id[OZAYN_PCO_MAX_ID_LEN];
    char stream_id[OZAYN_PCO_MAX_ID_LEN];
    ozayn_pco_edge_direction_t direction;
    int data_type;
    int flow_policy;
    int active;

    time_t created_time;
    int active_flow;
} ozayn_pco_edge_t;

/* ============================================================
 * SECTION 14 — PIPELINE REQUEST
 * ============================================================ */

typedef struct {
    char name[OZAYN_PCO_MAX_NAME_LEN];
    char description[OZAYN_PCO_MAX_DESCRIPTION_LEN];
    ozayn_pco_pipeline_type_t type;
    char requester_ref[OZAYN_PCO_MAX_ID_LEN];
    char owner_ref[OZAYN_PCO_MAX_ID_LEN];
    char security_session_ref[OZAYN_PCO_MAX_ID_LEN];
    char authorization_ref[OZAYN_PCO_MAX_ID_LEN];
    char safety_decision_ref[OZAYN_PCO_MAX_ID_LEN];
    int lifetime_ms;
    char metadata[OZAYN_PCO_MAX_METADATA_LEN];
} ozayn_pco_pipeline_request_t;

/* ============================================================
 * SECTION 15 — PIPELINE EVENT
 * ============================================================ */

typedef struct {
    ozayn_pco_event_type_t type;
    char pipeline_id[OZAYN_PCO_MAX_ID_LEN];
    char stage_id[OZAYN_PCO_MAX_ID_LEN];
    char route_id[OZAYN_PCO_MAX_ID_LEN];
    char stream_id[OZAYN_PCO_MAX_ID_LEN];
    char message[OZAYN_PCO_MAX_DESCRIPTION_LEN];
    time_t timestamp;
} ozayn_pco_event_t;

/* ============================================================
 * SECTION 16 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_pipelines_created;
    uint64_t total_pipelines_authorized;
    uint64_t total_pipelines_started;
    uint64_t total_pipelines_active;
    uint64_t total_pipelines_paused;
    uint64_t total_pipelines_stopped;
    uint64_t total_pipelines_expired;
    uint64_t total_pipelines_revoked;
    uint64_t total_pipelines_failed;
    uint64_t total_pipelines_cancelled;
    uint64_t total_stages_created;
    uint64_t total_stages_completed;
    uint64_t total_stages_failed;
    uint64_t total_edges_created;
    uint64_t total_state_transitions;
    uint64_t total_validation_failures;
    uint64_t total_sync_timeouts;
    uint64_t total_order_errors;
    uint64_t total_backpressure_events;
    uint64_t total_drain_timeouts;
    uint64_t total_errors;
    int current_active_pipelines;
    int current_paused_pipelines;
    int current_stages_active;
    int current_edges_active;
} ozayn_pco_stats_t;

/* ============================================================
 * SECTION 17 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *io_stream_service;
    void *io_router_service;
    void *device_session_service;
    void *resource_manager;
    void *safety_engine;
    void *diagnostics;
    void *audit;
    int max_pipelines;
    int max_stages;
    int max_edges;
    int max_fan_out;
    int max_fan_in;
    int pipeline_ttl_ms;
    int drain_timeout_ms;
    int sync_timeout_ms;
    int max_runtime_ms;
    int max_concurrent_pipelines;
} ozayn_pco_service_config_t;

/* ============================================================
 * SECTION 18 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;

    ozayn_pco_pipeline_t pipelines[OZAYN_PCO_MAX_PIPELINES];
    int pipeline_count;
    uint32_t pipeline_sequence;

    ozayn_pco_stage_t stages[OZAYN_PCO_MAX_STAGES * OZAYN_PCO_MAX_PIPELINES];
    int stage_count;

    ozayn_pco_edge_t edges[OZAYN_PCO_MAX_EDGES * OZAYN_PCO_MAX_PIPELINES];
    int edge_count;

    ozayn_pco_event_t events[OZAYN_PCO_MAX_EVENTS];
    int event_head;
    int event_count;
    uint32_t event_sequence;

    ozayn_pco_stats_t stats;
    ozayn_pco_service_config_t config;
} ozayn_pco_service_t;

/* ============================================================
 * SECTION 19 — LIFECYCLE
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_service_init(ozayn_pco_service_t *svc,
                                        const ozayn_pco_service_config_t *cfg);
void ozayn_pco_service_shutdown(ozayn_pco_service_t *svc);
int ozayn_pco_service_is_initialized(const ozayn_pco_service_t *svc);
ozayn_pco_service_t *ozayn_pco_get_global(void);

/* ============================================================
 * SECTION 20 — PIPELINE OPERATIONS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_pipeline_create(ozayn_pco_service_t *svc,
                                           const ozayn_pco_pipeline_request_t *req,
                                           ozayn_pco_pipeline_t **out_pipeline);
ozayn_pco_err_t ozayn_pco_pipeline_validate(ozayn_pco_service_t *svc,
                                             const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_authorize(ozayn_pco_service_t *svc,
                                              const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_start(ozayn_pco_service_t *svc,
                                          const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_pause(ozayn_pco_service_t *svc,
                                          const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_resume(ozayn_pco_service_t *svc,
                                           const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_drain(ozayn_pco_service_t *svc,
                                          const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_stop(ozayn_pco_service_t *svc,
                                         const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_cancel(ozayn_pco_service_t *svc,
                                           const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_pipeline_close(ozayn_pco_service_t *svc,
                                          const char *pipeline_id,
                                          ozayn_pco_close_reason_t reason);
ozayn_pco_err_t ozayn_pco_pipeline_revoke(ozayn_pco_service_t *svc,
                                           const char *pipeline_id,
                                           ozayn_pco_close_reason_t reason);
ozayn_pco_err_t ozayn_pco_pipeline_remove(ozayn_pco_service_t *svc,
                                           const char *pipeline_id);

/* ============================================================
 * SECTION 21 — STAGE OPERATIONS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_stage_add(ozayn_pco_service_t *svc,
                                     const char *pipeline_id,
                                     const ozayn_pco_stage_t *stage_def,
                                     ozayn_pco_stage_t **out_stage);
ozayn_pco_err_t ozayn_pco_stage_get(const ozayn_pco_service_t *svc,
                                     const char *pipeline_id,
                                     const char *stage_id,
                                     const ozayn_pco_stage_t **out_stage);
ozayn_pco_err_t ozayn_pco_stage_remove(ozayn_pco_service_t *svc,
                                        const char *pipeline_id,
                                        const char *stage_id);
int ozayn_pco_stage_count(const ozayn_pco_service_t *svc,
                           const char *pipeline_id);
int ozayn_pco_stages_for_pipeline(ozayn_pco_service_t *svc,
                                   const char *pipeline_id,
                                   ozayn_pco_stage_t **out_stages,
                                   int max_out);

/* ============================================================
 * SECTION 22 — GRAPH EDGE OPERATIONS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_edge_add(ozayn_pco_service_t *svc,
                                    const char *pipeline_id,
                                    const ozayn_pco_edge_t *edge_def,
                                    ozayn_pco_edge_t **out_edge);
ozayn_pco_err_t ozayn_pco_edge_get(const ozayn_pco_service_t *svc,
                                    const char *pipeline_id,
                                    const char *edge_id,
                                    const ozayn_pco_edge_t **out_edge);
ozayn_pco_err_t ozayn_pco_edge_remove(ozayn_pco_service_t *svc,
                                       const char *pipeline_id,
                                       const char *edge_id);
int ozayn_pco_edge_count(const ozayn_pco_service_t *svc,
                          const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_graph_validate(const ozayn_pco_service_t *svc,
                                          const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_graph_check_cycle(const ozayn_pco_service_t *svc,
                                             const char *pipeline_id);

/* ============================================================
 * SECTION 23 — FLOW CONTROL
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_flow_get_state(const ozayn_pco_service_t *svc,
                                          const char *pipeline_id,
                                          ozayn_pco_flow_state_t *out_state);
ozayn_pco_err_t ozayn_pco_flow_set_state(ozayn_pco_service_t *svc,
                                          const char *pipeline_id,
                                          ozayn_pco_flow_state_t new_state);
int ozayn_pco_flow_is_blocked(const ozayn_pco_service_t *svc,
                               const char *pipeline_id);
int ozayn_pco_flow_is_backpressured(const ozayn_pco_service_t *svc,
                                     const char *pipeline_id);

/* ============================================================
 * SECTION 24 — SYNCHRONIZATION
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_sync_check_stage(const ozayn_pco_service_t *svc,
                                            const char *pipeline_id,
                                            const char *stage_id);
int ozayn_pco_sync_all_stages_ready(const ozayn_pco_service_t *svc,
                                     const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_sync_advance_stage(ozayn_pco_service_t *svc,
                                              const char *pipeline_id,
                                              const char *stage_id);

/* ============================================================
 * SECTION 25 — QUERY
 * ============================================================ */

const ozayn_pco_pipeline_t *ozayn_pco_pipeline_get(
    const ozayn_pco_service_t *svc, const char *pipeline_id);
const ozayn_pco_pipeline_t *ozayn_pco_pipeline_get_by_name(
    const ozayn_pco_service_t *svc, const char *name);
int ozayn_pco_pipeline_count(const ozayn_pco_service_t *svc);
int ozayn_pco_pipeline_count_by_state(const ozayn_pco_service_t *svc,
                                       ozayn_pco_pipeline_state_t state);
int ozayn_pco_pipeline_is_active(const ozayn_pco_service_t *svc,
                                  const char *pipeline_id);
ozayn_pco_err_t ozayn_pco_health_get(const ozayn_pco_service_t *svc,
                                      const char *pipeline_id,
                                      int *out_healthy,
                                      int *out_degraded,
                                      int *out_failed);

/* ============================================================
 * SECTION 26 — EVENTS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_emit_event(ozayn_pco_service_t *svc,
                                      ozayn_pco_event_type_t type,
                                      const char *pipeline_id,
                                      const char *stage_id,
                                      const char *route_id,
                                      const char *stream_id,
                                      const char *message);
const ozayn_pco_event_t *ozayn_pco_event_get(const ozayn_pco_service_t *svc,
                                              int index);
int ozayn_pco_event_count(const ozayn_pco_service_t *svc);

/* ============================================================
 * SECTION 27 — CLEANUP
 * ============================================================ */

int ozayn_pco_cleanup_expired_pipelines(ozayn_pco_service_t *svc);
int ozayn_pco_cleanup_stopped_pipelines(ozayn_pco_service_t *svc);
int ozayn_pco_cleanup_all(ozayn_pco_service_t *svc);

/* ============================================================
 * SECTION 28 — STATISTICS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_get_stats(const ozayn_pco_service_t *svc,
                                     ozayn_pco_stats_t *out_stats);

/* ============================================================
 * SECTION 29 — VALIDATION
 * ============================================================ */

int ozayn_pco_pipeline_validate_fields(const ozayn_pco_pipeline_t *pipeline);
int ozayn_pco_pipeline_request_validate(const ozayn_pco_pipeline_request_t *req);
int ozayn_pco_stage_validate(const ozayn_pco_stage_t *stage);
int ozayn_pco_edge_validate(const ozayn_pco_edge_t *edge);
int ozayn_pco_pipeline_state_transition_valid(ozayn_pco_pipeline_state_t from,
                                               ozayn_pco_pipeline_state_t to);
int ozayn_pco_stage_state_transition_valid(ozayn_pco_stage_state_t from,
                                            ozayn_pco_stage_state_t to);

/* ============================================================
 * SECTION 30 — NAME HELPERS
 * ============================================================ */

const char *ozayn_pco_err_name(ozayn_pco_err_t err);
const char *ozayn_pco_pipeline_state_name(ozayn_pco_pipeline_state_t state);
const char *ozayn_pco_pipeline_type_name(ozayn_pco_pipeline_type_t type);
const char *ozayn_pco_stage_type_name(ozayn_pco_stage_type_t type);
const char *ozayn_pco_stage_state_name(ozayn_pco_stage_state_t state);
const char *ozayn_pco_flow_state_name(ozayn_pco_flow_state_t state);
const char *ozayn_pco_event_type_name(ozayn_pco_event_type_t type);
const char *ozayn_pco_close_reason_name(ozayn_pco_close_reason_t reason);
const char *ozayn_pco_edge_direction_name(ozayn_pco_edge_direction_t dir);

#endif /* OZAYN_PIPELINE_H */
