#ifndef OZAYN_RESOURCE_H
#define OZAYN_RESOURCE_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — CONSTANTS & LIMITS
 * ============================================================ */

#define OZAYN_RCM_MAX_RESOURCES        64
#define OZAYN_RCM_MAX_SNAPSHOTS        16
#define OZAYN_RCM_MAX_REQUIREMENTS     32
#define OZAYN_RCM_MAX_DECISIONS        64
#define OZAYN_RCM_MAX_RESERVATIONS     32
#define OZAYN_RCM_MAX_ID_LEN           64
#define OZAYN_RCM_MAX_NAME_LEN         128
#define OZAYN_RCM_MAX_PROVIDER_LEN     64
#define OZAYN_RCM_MAX_UNIT_LEN         32
#define OZAYN_RCM_MAX_METADATA_LEN     256
#define OZAYN_RCM_MAX_FAILED_REQS      8
#define OZAYN_RCM_MAX_RESOURCE_REFS    8
#define OZAYN_RCM_MAX_WARNINGS         8
#define OZAYN_RCM_DEFAULT_RESERVATION_TTL_MS  60000
#define OZAYN_RCM_STALE_THRESHOLD_SECONDS     300

/* ============================================================
 * SECTION 2 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_RCM_OK                        = 0,
    OZAYN_RCM_ERR_NULL                  = -1,
    OZAYN_RCM_ERR_NOT_INITIALIZED       = -2,
    OZAYN_RCM_ERR_ALREADY_INITIALIZED   = -3,
    OZAYN_RCM_ERR_INVALID_PARAM         = -4,
    OZAYN_RCM_ERR_LIMIT_REACHED         = -5,
    OZAYN_RCM_ERR_NOT_FOUND             = -6,
    OZAYN_RCM_ERR_DUPLICATE             = -7,
    OZAYN_RCM_ERR_INVALID               = -8,
    OZAYN_RCM_ERR_UNAVAILABLE           = -9,
    OZAYN_RCM_ERR_UNSUPPORTED           = -10,
    OZAYN_RCM_ERR_MEASUREMENT_FAILED    = -11,
    OZAYN_RCM_ERR_CAPACITY_INVALID      = -12,
    OZAYN_RCM_ERR_REQUIREMENT_FAILED    = -13,
    OZAYN_RCM_ERR_CONFLICT              = -14,
    OZAYN_RCM_ERR_RESERVATION_FAILED    = -15,
    OZAYN_RCM_ERR_RESERVATION_EXPIRED   = -16,
    OZAYN_RCM_ERR_RESERVATION_NOT_FOUND = -17,
    OZAYN_RCM_ERR_RESERVATION_CONFLICT  = -18,
    OZAYN_RCM_ERR_LIMIT_REACHED_RES     = -19,
    OZAYN_RCM_ERR_TIMEOUT               = -20,
    OZAYN_RCM_ERR_CONCURRENCY           = -21,
    OZAYN_RCM_ERR_PROVIDER_ERROR        = -22
} ozayn_rcm_err_t;

/* ============================================================
 * SECTION 3 — RESOURCE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_RCM_RES_CPU = 0,
    OZAYN_RCM_RES_MEMORY,
    OZAYN_RCM_RES_STORAGE,
    OZAYN_RCM_RES_WORKER_CAPACITY,
    OZAYN_RCM_RES_QUEUE_CAPACITY,
    OZAYN_RCM_RES_GPU,
    OZAYN_RCM_RES_AUDIO,
    OZAYN_RCM_RES_CAMERA,
    OZAYN_RCM_RES_MICROPHONE,
    OZAYN_RCM_RES_NETWORK,
    OZAYN_RCM_RES_TYPE_COUNT
} ozayn_rcm_resource_type_t;

/* ============================================================
 * SECTION 4 — RESOURCE STATES
 * ============================================================ */

typedef enum {
    OZAYN_RCM_STATE_UNKNOWN = 0,
    OZAYN_RCM_STATE_AVAILABLE,
    OZAYN_RCM_STATE_BUSY,
    OZAYN_RCM_STATE_DEGRADED,
    OZAYN_RCM_STATE_EXHAUSTED,
    OZAYN_RCM_STATE_UNAVAILABLE,
    OZAYN_RCM_STATE_UNSUPPORTED,
    OZAYN_RCM_STATE_ERROR,
    OZAYN_RCM_STATE_COUNT
} ozayn_rcm_resource_state_t;

/* ============================================================
 * SECTION 5 — RESOURCE HEALTH (separate from state)
 * ============================================================ */

typedef enum {
    OZAYN_RCM_HEALTH_UNKNOWN = 0,
    OZAYN_RCM_HEALTH_HEALTHY,
    OZAYN_RCM_HEALTH_DEGRADED,
    OZAYN_RCM_HEALTH_UNHEALTHY,
    OZAYN_RCM_HEALTH_FAILED,
    OZAYN_RCM_HEALTH_COUNT
} ozayn_rcm_resource_health_t;

/* ============================================================
 * SECTION 6 — AVAILABILITY
 * ============================================================ */

typedef enum {
    OZAYN_RCM_AVAIL_UNKNOWN = 0,
    OZAYN_RCM_AVAIL_AVAILABLE,
    OZAYN_RCM_AVAIL_UNAVAILABLE,
    OZAYN_RCM_AVAIL_LIMITED,
    OZAYN_RCM_AVAIL_COUNT
} ozayn_rcm_availability_t;

/* ============================================================
 * SECTION 7 — RESOURCE DECISIONS
 * ============================================================ */

typedef enum {
    OZAYN_RCM_DECISION_AVAILABLE = 0,
    OZAYN_RCM_DECISION_INSUFFICIENT,
    OZAYN_RCM_DECISION_UNAVAILABLE,
    OZAYN_RCM_DECISION_UNKNOWN,
    OZAYN_RCM_DECISION_RESERVED,
    OZAYN_RCM_DECISION_CONFLICT,
    OZAYN_RCM_DECISION_COUNT
} ozayn_rcm_decision_result_t;

/* ============================================================
 * SECTION 8 — RESERVATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_RCM_RESERV_REQUESTED = 0,
    OZAYN_RCM_RESERV_RESERVED,
    OZAYN_RCM_RESERV_ACTIVE,
    OZAYN_RCM_RESERV_RELEASED,
    OZAYN_RCM_RESERV_EXPIRED,
    OZAYN_RCM_RESERV_CANCELLED,
    OZAYN_RCM_RESERV_FAILED,
    OZAYN_RCM_RESERV_COUNT
} ozayn_rcm_reservation_state_t;

/* ============================================================
 * SECTION 9 — PRIORITY
 * ============================================================ */

typedef enum {
    OZAYN_RCM_PRIORITY_LOW = 0,
    OZAYN_RCM_PRIORITY_NORMAL,
    OZAYN_RCM_PRIORITY_HIGH,
    OZAYN_RCM_PRIORITY_CRITICAL,
    OZAYN_RCM_PRIORITY_COUNT
} ozayn_rcm_priority_t;

/* ============================================================
 * SECTION 10 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_RCM_EVENT_RESOURCE_REGISTERED = 0,
    OZAYN_RCM_EVENT_RESOURCE_UPDATED,
    OZAYN_RCM_EVENT_RESOURCE_UNAVAILABLE,
    OZAYN_RCM_EVENT_RESOURCE_DEGRADED,
    OZAYN_RCM_EVENT_RESOURCE_EXHAUSTED,
    OZAYN_RCM_EVENT_RESERVATION_CREATED,
    OZAYN_RCM_EVENT_RESERVATION_RESERVED,
    OZAYN_RCM_EVENT_RESERVATION_RELEASED,
    OZAYN_RCM_EVENT_RESERVATION_EXPIRED,
    OZAYN_RCM_EVENT_RESERVATION_FAILED,
    OZAYN_RCM_EVENT_CAPACITY_CHANGED,
    OZAYN_RCM_EVENT_CONFLICT_DETECTED,
    OZAYN_RCM_EVENT_COUNT
} ozayn_rcm_event_type_t;

/* ============================================================
 * SECTION 11 — CAPACITY
 * ============================================================ */

typedef struct {
    uint64_t total;
    uint64_t used;
    uint64_t reserved;
    uint64_t available;
} ozayn_rcm_capacity_t;

/* ============================================================
 * SECTION 12 — RESOURCE DESCRIPTOR
 * ============================================================ */

typedef struct {
    char resource_id[OZAYN_RCM_MAX_ID_LEN];
    ozayn_rcm_resource_type_t type;
    char name[OZAYN_RCM_MAX_NAME_LEN];
    char provider[OZAYN_RCM_MAX_PROVIDER_LEN];
    int version;
    ozayn_rcm_availability_t availability;
    ozayn_rcm_capacity_t capacity;
    char unit[OZAYN_RCM_MAX_UNIT_LEN];
    ozayn_rcm_resource_state_t state;
    ozayn_rcm_resource_health_t health;
    time_t last_update;
    int active;
    char metadata[OZAYN_RCM_MAX_METADATA_LEN];
} ozayn_rcm_resource_desc_t;

/* ============================================================
 * SECTION 13 — RESOURCE SNAPSHOT
 * ============================================================ */

typedef struct {
    char snapshot_id[OZAYN_RCM_MAX_ID_LEN];
    uint32_t version;
    time_t timestamp;
    int resource_count;
    char resource_ids[OZAYN_RCM_MAX_RESOURCES][OZAYN_RCM_MAX_ID_LEN];
    ozayn_rcm_resource_state_t overall_state;
    ozayn_rcm_capacity_t summary;
    char metadata[OZAYN_RCM_MAX_METADATA_LEN];
} ozayn_rcm_snapshot_t;

/* ============================================================
 * SECTION 14 — RESOURCE REQUIREMENT
 * ============================================================ */

typedef struct {
    char requirement_id[OZAYN_RCM_MAX_ID_LEN];
    ozayn_rcm_resource_type_t resource_type;
    char resource_id[OZAYN_RCM_MAX_ID_LEN];
    uint64_t min_capacity;
    uint64_t max_usage;
    ozayn_rcm_availability_t required_availability;
    int reservation_required;
    ozayn_rcm_priority_t priority;
    int timeout_ms;
    char metadata[OZAYN_RCM_MAX_METADATA_LEN];
} ozayn_rcm_resource_requirement_t;

/* ============================================================
 * SECTION 15 — RESOURCE DECISION RECORD
 * ============================================================ */

typedef struct {
    char decision_id[OZAYN_RCM_MAX_ID_LEN];
    char operation_id[OZAYN_RCM_MAX_ID_LEN];
    char resource_refs[OZAYN_RCM_MAX_RESOURCE_REFS][OZAYN_RCM_MAX_ID_LEN];
    uint64_t min_capacities[OZAYN_RCM_MAX_RESOURCE_REFS];
    int resource_ref_count;
    ozayn_rcm_decision_result_t decision;
    ozayn_rcm_capacity_t capacity_observed;
    int requirement_count;
    char failed_requirements[OZAYN_RCM_MAX_FAILED_REQS][OZAYN_RCM_MAX_ID_LEN];
    int failed_requirement_count;
    time_t evaluation_time;
    time_t expiry_time;
    int active;
    char metadata[OZAYN_RCM_MAX_METADATA_LEN];
} ozayn_rcm_resource_decision_t;

/* ============================================================
 * SECTION 16 — RESOURCE RESERVATION
 * ============================================================ */

typedef struct {
    char reservation_id[OZAYN_RCM_MAX_ID_LEN];
    char operation_id[OZAYN_RCM_MAX_ID_LEN];
    char resource_id[OZAYN_RCM_MAX_ID_LEN];
    ozayn_rcm_resource_type_t resource_type;
    uint64_t requested_capacity;
    uint64_t reserved_capacity;
    time_t created_time;
    time_t expiry_time;
    ozayn_rcm_reservation_state_t state;
    int active;
} ozayn_rcm_reservation_t;

/* ============================================================
 * SECTION 17 — RESOURCE EVENT
 * ============================================================ */

typedef struct {
    ozayn_rcm_event_type_t type;
    char resource_id[OZAYN_RCM_MAX_ID_LEN];
    char message[OZAYN_RCM_MAX_METADATA_LEN];
    time_t timestamp;
} ozayn_rcm_event_t;

/* ============================================================
 * SECTION 18 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t total_resources_registered;
    uint64_t total_resources_updated;
    uint64_t total_snapshots;
    uint64_t total_decisions;
    uint64_t total_available;
    uint64_t total_insufficient;
    uint64_t total_unavailable;
    uint64_t total_unknown;
    uint64_t total_reservations_created;
    uint64_t total_reservations_released;
    uint64_t total_reservations_expired;
    uint64_t total_reservations_failed;
    uint64_t total_capacity_checks;
    uint64_t total_rechecks;
    int current_active_reservations;
    int current_active_decisions;
} ozayn_rcm_stats_t;

/* ============================================================
 * SECTION 19 — SERVICE CONFIG
 * ============================================================ */

typedef struct {
    int max_resources;
    int max_decisions;
    int max_reservations;
    int reservation_ttl_ms;
    int max_reservation_duration_ms;
    int max_concurrent_operations;
    int max_workers;
    int max_queue_size;
    void *component_registry;
    void *diagnostics;
    void *audit;
    void *authorization;
} ozayn_rcm_service_config_t;

/* ============================================================
 * SECTION 20 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int initialized;
    ozayn_rcm_resource_desc_t resources[OZAYN_RCM_MAX_RESOURCES];
    int resource_count;
    int max_resources;
    ozayn_rcm_snapshot_t snapshots[OZAYN_RCM_MAX_SNAPSHOTS];
    int snapshot_count;
    ozayn_rcm_resource_decision_t decisions[OZAYN_RCM_MAX_DECISIONS];
    int decision_count;
    int decision_head;
    int max_decisions;
    ozayn_rcm_reservation_t reservations[OZAYN_RCM_MAX_RESERVATIONS];
    int reservation_count;
    int max_reservations;
    int reservation_ttl_ms;
    int max_reservation_duration_ms;
    int max_concurrent_operations;
    int max_workers;
    int max_queue_size;
    uint32_t resource_sequence;
    uint32_t decision_sequence;
    uint32_t reservation_sequence;
    uint32_t snapshot_sequence;
    uint32_t requirement_sequence;
    void *component_registry;
    void *diagnostics;
    void *audit;
    void *authorization;
    ozayn_rcm_stats_t stats;
    ozayn_rcm_event_t events[OZAYN_RCM_MAX_DECISIONS];
    int event_head;
    int event_count;
} ozayn_rcm_service_t;

/* ============================================================
 * SECTION 21 — LIFECYCLE
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_service_init(ozayn_rcm_service_t *svc,
                                        const ozayn_rcm_service_config_t *cfg);

void ozayn_rcm_service_shutdown(ozayn_rcm_service_t *svc);

int ozayn_rcm_service_is_initialized(const ozayn_rcm_service_t *svc);

ozayn_rcm_service_t *ozayn_rcm_get_global(void);

/* ============================================================
 * SECTION 22 — RESOURCE REGISTRATION & MANAGEMENT
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_resource_register(ozayn_rcm_service_t *svc,
                                             ozayn_rcm_resource_type_t type,
                                             const char *name,
                                             const char *provider,
                                             const char *unit,
                                             uint64_t total_capacity,
                                             ozayn_rcm_resource_desc_t **out_resource);

ozayn_rcm_err_t ozayn_rcm_resource_unregister(ozayn_rcm_service_t *svc,
                                               const char *resource_id);

const ozayn_rcm_resource_desc_t *ozayn_rcm_resource_get(
    const ozayn_rcm_service_t *svc,
    const char *resource_id);

const ozayn_rcm_resource_desc_t *ozayn_rcm_resource_get_by_type(
    const ozayn_rcm_service_t *svc,
    ozayn_rcm_resource_type_t type);

int ozayn_rcm_resource_count(const ozayn_rcm_service_t *svc);

int ozayn_rcm_resource_full(const ozayn_rcm_service_t *svc);

/* ============================================================
 * SECTION 23 — RESOURCE STATE UPDATES
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_resource_update_usage(ozayn_rcm_service_t *svc,
                                                 const char *resource_id,
                                                 uint64_t used);

ozayn_rcm_err_t ozayn_rcm_resource_update_state(ozayn_rcm_service_t *svc,
                                                 const char *resource_id,
                                                 ozayn_rcm_resource_state_t state);

ozayn_rcm_err_t ozayn_rcm_resource_update_health(ozayn_rcm_service_t *svc,
                                                  const char *resource_id,
                                                  ozayn_rcm_resource_health_t health);

ozayn_rcm_err_t ozayn_rcm_resource_update_availability(ozayn_rcm_service_t *svc,
                                                        const char *resource_id,
                                                        ozayn_rcm_availability_t avail);

/* ============================================================
 * SECTION 24 — CAPACITY ASSESSMENT
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_capacity_get(const ozayn_rcm_service_t *svc,
                                        const char *resource_id,
                                        ozayn_rcm_capacity_t *out_capacity);

ozayn_rcm_err_t ozayn_rcm_capacity_check(const ozayn_rcm_service_t *svc,
                                          const char *resource_id,
                                          uint64_t required,
                                          int *sufficient);

ozayn_rcm_err_t ozayn_rcm_capacity_check_all(
    const ozayn_rcm_service_t *svc,
    const ozayn_rcm_resource_requirement_t *reqs,
    int req_count,
    int *all_met);

/* ============================================================
 * SECTION 25 — RESOURCE REQUIREMENTS & DECISIONS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_requirement_create(ozayn_rcm_service_t *svc,
                                              ozayn_rcm_resource_type_t type,
                                              const char *resource_id,
                                              uint64_t min_capacity,
                                              uint64_t max_usage,
                                              ozayn_rcm_availability_t required_avail,
                                              int reservation_required,
                                              ozayn_rcm_priority_t priority,
                                              int timeout_ms,
                                              ozayn_rcm_resource_requirement_t **out_req);

ozayn_rcm_err_t ozayn_rcm_evaluate(ozayn_rcm_service_t *svc,
                                    const char *operation_id,
                                    const ozayn_rcm_resource_requirement_t *reqs,
                                    int req_count,
                                    ozayn_rcm_resource_decision_t **out_decision);

const ozayn_rcm_resource_decision_t *ozayn_rcm_decision_get(
    const ozayn_rcm_service_t *svc,
    const char *decision_id);

const ozayn_rcm_resource_decision_t *ozayn_rcm_decision_get_by_operation(
    const ozayn_rcm_service_t *svc,
    const char *operation_id);

int ozayn_rcm_decision_count(const ozayn_rcm_service_t *svc);

int ozayn_rcm_decision_is_valid(const ozayn_rcm_service_t *svc,
                                 const char *decision_id);

/* ============================================================
 * SECTION 26 — RESOURCE RECHECK
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_recheck(ozayn_rcm_service_t *svc,
                                   const char *decision_id);

/* ============================================================
 * SECTION 27 — RESERVATIONS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_reservation_create(ozayn_rcm_service_t *svc,
                                              const char *operation_id,
                                              const char *resource_id,
                                              ozayn_rcm_resource_type_t type,
                                              uint64_t requested_capacity,
                                              ozayn_rcm_reservation_t **out_reservation);

ozayn_rcm_err_t ozayn_rcm_reservation_activate(ozayn_rcm_service_t *svc,
                                                 const char *reservation_id);

ozayn_rcm_err_t ozayn_rcm_reservation_release(ozayn_rcm_service_t *svc,
                                               const char *reservation_id);

ozayn_rcm_err_t ozayn_rcm_reservation_cancel(ozayn_rcm_service_t *svc,
                                              const char *reservation_id);

const ozayn_rcm_reservation_t *ozayn_rcm_reservation_get(
    const ozayn_rcm_service_t *svc,
    const char *reservation_id);

int ozayn_rcm_reservation_count(const ozayn_rcm_service_t *svc);

int ozayn_rcm_reservation_count_by_resource(const ozayn_rcm_service_t *svc,
                                             const char *resource_id);

/* ============================================================
 * SECTION 28 — SNAPSHOTS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_snapshot_create(ozayn_rcm_service_t *svc,
                                           ozayn_rcm_snapshot_t **out_snapshot);

const ozayn_rcm_snapshot_t *ozayn_rcm_snapshot_get(
    const ozayn_rcm_service_t *svc,
    const char *snapshot_id);

int ozayn_rcm_snapshot_count(const ozayn_rcm_service_t *svc);

/* ============================================================
 * SECTION 29 — CLEANUP
 * ============================================================ */

int ozayn_rcm_cleanup_expired_reservations(ozayn_rcm_service_t *svc);

int ozayn_rcm_cleanup_expired_decisions(ozayn_rcm_service_t *svc);

int ozayn_rcm_cleanup_all(ozayn_rcm_service_t *svc);

/* ============================================================
 * SECTION 30 — STATISTICS
 * ============================================================ */

ozayn_rcm_err_t ozayn_rcm_get_stats(const ozayn_rcm_service_t *svc,
                                     ozayn_rcm_stats_t *out_stats);

/* ============================================================
 * SECTION 31 — VALIDATION
 * ============================================================ */

int ozayn_rcm_resource_validate(const ozayn_rcm_resource_desc_t *res);

int ozayn_rcm_capacity_validate(const ozayn_rcm_capacity_t *cap);

int ozayn_rcm_decision_validate(const ozayn_rcm_resource_decision_t *dec);

int ozayn_rcm_reservation_validate(const ozayn_rcm_reservation_t *res);

int ozayn_rcm_requirement_validate(const ozayn_rcm_resource_requirement_t *req);

/* ============================================================
 * SECTION 32 — NAME HELPERS
 * ============================================================ */

const char *ozayn_rcm_resource_type_name(ozayn_rcm_resource_type_t val);

const char *ozayn_rcm_resource_state_name(ozayn_rcm_resource_state_t val);

const char *ozayn_rcm_resource_health_name(ozayn_rcm_resource_health_t val);

const char *ozayn_rcm_availability_name(ozayn_rcm_availability_t val);

const char *ozayn_rcm_resource_decision_name(ozayn_rcm_decision_result_t val);

const char *ozayn_rcm_reservation_state_name(ozayn_rcm_reservation_state_t val);

const char *ozayn_rcm_priority_name(ozayn_rcm_priority_t val);

const char *ozayn_rcm_event_type_name(ozayn_rcm_event_type_t val);

const char *ozayn_rcm_err_name(ozayn_rcm_err_t val);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_RESOURCE_H */
