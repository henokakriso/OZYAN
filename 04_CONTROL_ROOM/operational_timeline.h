#ifndef OZAYN_OPERATIONAL_TIMELINE_H
#define OZAYN_OPERATIONAL_TIMELINE_H

#include <stdint.h>
#include <time.h>

#define OZAYN_OTL_MAX_ID_LEN 64
#define OZAYN_OTL_MAX_MSG_LEN 128
#define OZAYN_OTL_MAX_TIMELINES 32
#define OZAYN_OTL_MAX_EVENTS 512
#define OZAYN_OTL_MAX_EVENTS_PER_TIMELINE 128
#define OZAYN_OTL_MAX_CORRELATION_CHAIN 16
#define OZAYN_OTL_MAX_QUERY_RESULTS 64
#define OZAYN_OTL_MAX_METADATA_LEN 64

typedef enum {
    OZAYN_OTL_ERR_OK = 0,
    OZAYN_OTL_ERR_NULL_PTR,
    OZAYN_OTL_ERR_NOT_INITIALIZED,
    OZAYN_OTL_ERR_ALREADY_INITIALIZED,
    OZAYN_OTL_ERR_INVALID_ID,
    OZAYN_OTL_ERR_NOT_FOUND,
    OZAYN_OTL_ERR_DUPLICATE,
    OZAYN_OTL_ERR_FULL,
    OZAYN_OTL_ERR_INVALID_STATE,
    OZAYN_OTL_ERR_INVALID_TRANSITION,
    OZAYN_OTL_ERR_INVALID_EVENT,
    OZAYN_OTL_ERR_CORRELATION_FAILED,
    OZAYN_OTL_ERR_QUERY_INVALID,
    OZAYN_OTL_ERR_QUERY_LIMIT,
    OZAYN_OTL_ERR_STORAGE_ERROR,
    OZAYN_OTL_ERR_SUBSYSTEM_UNAVAILABLE,
    OZAYN_OTL_ERR_UNAUTHORIZED,
    OZAYN_OTL_ERR_INTERNAL
} ozayn_otl_err_t;

typedef enum {
    OZAYN_OTL_CAT_SYSTEM = 0,
    OZAYN_OTL_CAT_STARTUP,
    OZAYN_OTL_CAT_SHUTDOWN,
    OZAYN_OTL_CAT_LIFECYCLE,
    OZAYN_OTL_CAT_COMPONENT,
    OZAYN_OTL_CAT_CAPABILITY,
    OZAYN_OTL_CAT_OPERATION,
    OZAYN_OTL_CAT_QUEUE,
    OZAYN_OTL_CAT_SCHEDULER,
    OZAYN_OTL_CAT_WORKFLOW,
    OZAYN_OTL_CAT_PIPELINE,
    OZAYN_OTL_CAT_ADMISSION,
    OZAYN_OTL_CAT_ENFORCEMENT,
    OZAYN_OTL_CAT_EXECUTION,
    OZAYN_OTL_CAT_RECONCILIATION,
    OZAYN_OTL_CAT_RESOURCE,
    OZAYN_OTL_CAT_DEVICE,
    OZAYN_OTL_CAT_IO,
    OZAYN_OTL_CAT_SECURITY,
    OZAYN_OTL_CAT_SAFETY,
    OZAYN_OTL_CAT_DIAGNOSTIC,
    OZAYN_OTL_CAT_RECOVERY,
    OZAYN_OTL_CAT_CONFIGURATION,
    OZAYN_OTL_CAT_ERROR
} ozayn_otl_category_t;

typedef enum {
    OZAYN_OTL_SEV_INFO = 0,
    OZAYN_OTL_SEV_LOW,
    OZAYN_OTL_SEV_MEDIUM,
    OZAYN_OTL_SEV_HIGH,
    OZAYN_OTL_SEV_CRITICAL
} ozayn_otl_severity_t;

typedef enum {
    OZAYN_OTL_REL_NONE = 0,
    OZAYN_OTL_REL_PARENT,
    OZAYN_OTL_REL_CHILD,
    OZAYN_OTL_REL_PRECEDES,
    OZAYN_OTL_REL_FOLLOWS,
    OZAYN_OTL_REL_CAUSED_BY,
    OZAYN_OTL_REL_RESULT_OF,
    OZAYN_OTL_REL_PART_OF,
    OZAYN_OTL_REL_RETRY_OF,
    OZAYN_OTL_REL_COMPENSATES,
    OZAYN_OTL_REL_RECONCILES,
    OZAYN_OTL_REL_DEPENDS_ON,
    OZAYN_OTL_REL_AFFECTS
} ozayn_otl_relationship_t;

typedef enum {
    OZAYN_OTL_CORR_EXACT = 0,
    OZAYN_OTL_CORR_EXPLICIT,
    OZAYN_OTL_CORR_DERIVED,
    OZAYN_OTL_CORR_PARTIAL,
    OZAYN_OTL_CORR_UNKNOWN,
    OZAYN_OTL_CORR_INVALID
} ozayn_otl_confidence_t;

typedef enum {
    OZAYN_OTL_TL_CREATED = 0,
    OZAYN_OTL_TL_ACTIVE,
    OZAYN_OTL_TL_COMPLETED,
    OZAYN_OTL_TL_FAILED,
    OZAYN_OTL_TL_PARTIAL,
    OZAYN_OTL_TL_CANCELLED,
    OZAYN_OTL_TL_EXPIRED,
    OZAYN_OTL_TL_UNKNOWN,
    OZAYN_OTL_TL_UNAVAILABLE
} ozayn_otl_timeline_state_t;

typedef enum {
    OZAYN_OTL_EVT_NORMAL = 0,
    OZAYN_OTL_EVT_DUPLICATE_DETECTED,
    OZAYN_OTL_EVT_OUT_OF_ORDER,
    OZAYN_OTL_EVT_LATE_ARRIVAL,
    OZAYN_OTL_EVT_INCONSISTENCY_DETECTED
} ozayn_otl_event_state_t;

typedef enum {
    OZAYN_OTL_EVENT_TIMELINE_CREATED = 0,
    OZAYN_OTL_EVENT_TIMELINE_UPDATED,
    OZAYN_OTL_EVENT_TIMELINE_COMPLETED,
    OZAYN_OTL_EVENT_TIMELINE_FAILED,
    OZAYN_OTL_EVENT_TIMELINE_PARTIAL,
    OZAYN_OTL_EVENT_TIMELINE_EXPIRED,
    OZAYN_OTL_EVENT_CORRELATION_STARTED,
    OZAYN_OTL_EVENT_CORRELATED,
    OZAYN_OTL_EVENT_CORRELATION_PARTIAL,
    OZAYN_OTL_EVENT_CORRELATION_UNKNOWN,
    OZAYN_OTL_EVENT_CORRELATION_INVALID,
    OZAYN_OTL_EVENT_DUPLICATE_DETECTED,
    OZAYN_OTL_EVENT_OUT_OF_ORDER,
    OZAYN_OTL_EVENT_LATE_ARRIVAL,
    OZAYN_OTL_EVENT_INCONSISTENCY_DETECTED,
    OZAYN_OTL_EVENT_RECONCILIATION_REQUIRED
} ozayn_otl_emit_type_t;

typedef struct {
    uint64_t event_id;
    ozayn_otl_category_t category;
    ozayn_otl_severity_t severity;
    ozayn_otl_event_state_t state;
    char event_type_name[OZAYN_OTL_MAX_MSG_LEN];
    char source_component_id[OZAYN_OTL_MAX_ID_LEN];
    char source_component_type[OZAYN_OTL_MAX_ID_LEN];
    char operation_id[OZAYN_OTL_MAX_ID_LEN];
    char request_id[OZAYN_OTL_MAX_ID_LEN];
    char execution_record_id[OZAYN_OTL_MAX_ID_LEN];
    char workflow_id[OZAYN_OTL_MAX_ID_LEN];
    char workflow_stage_id[OZAYN_OTL_MAX_ID_LEN];
    char pipeline_id[OZAYN_OTL_MAX_ID_LEN];
    char pipeline_stage_id[OZAYN_OTL_MAX_ID_LEN];
    char target_component_id[OZAYN_OTL_MAX_ID_LEN];
    char capability_id[OZAYN_OTL_MAX_ID_LEN];
    char device_id[OZAYN_OTL_MAX_ID_LEN];
    char resource_id[OZAYN_OTL_MAX_ID_LEN];
    char security_session_ref[OZAYN_OTL_MAX_ID_LEN];
    char correlation_id[OZAYN_OTL_MAX_ID_LEN];
    char parent_event_id[OZAYN_OTL_MAX_ID_LEN];
    char failure_id[OZAYN_OTL_MAX_ID_LEN];
    char admission_id[OZAYN_OTL_MAX_ID_LEN];
    char enforcement_id[OZAYN_OTL_MAX_ID_LEN];
    char reconciliation_id[OZAYN_OTL_MAX_ID_LEN];
    char description[OZAYN_OTL_MAX_MSG_LEN];
    time_t occurrence_time;
    time_t ingestion_time;
    uint64_t source_sequence;
    ozayn_otl_confidence_t correlation_confidence;
    int has_parent;
    int has_correlation_id;
    char metadata[OZAYN_OTL_MAX_METADATA_LEN];
    int active;
} ozayn_otl_event_t;

typedef struct {
    uint64_t from_event_id;
    uint64_t to_event_id;
    ozayn_otl_relationship_t relationship;
    ozayn_otl_confidence_t confidence;
    char description[OZAYN_OTL_MAX_MSG_LEN];
    int active;
} ozayn_otl_relationship_edge_t;

typedef struct {
    uint64_t timeline_id;
    char correlation_id[OZAYN_OTL_MAX_ID_LEN];
    char operation_id[OZAYN_OTL_MAX_ID_LEN];
    char request_id[OZAYN_OTL_MAX_ID_LEN];
    char workflow_id[OZAYN_OTL_MAX_ID_LEN];
    char pipeline_id[OZAYN_OTL_MAX_ID_LEN];
    ozayn_otl_timeline_state_t state;
    time_t start_time;
    time_t end_time;
    time_t last_event_time;
    uint64_t event_count;
    uint64_t root_event_id;
    uint64_t current_event_id;
    uint64_t event_refs[OZAYN_OTL_MAX_EVENTS_PER_TIMELINE];
    uint64_t event_ref_count;
    uint64_t relationship_refs[OZAYN_OTL_MAX_EVENTS_PER_TIMELINE];
    uint64_t relationship_ref_count;
    char metadata[OZAYN_OTL_MAX_METADATA_LEN];
    int active;
} ozayn_otl_timeline_t;

typedef struct {
    uint64_t from_event_id;
    uint64_t to_event_id;
    ozayn_otl_relationship_t type;
    ozayn_otl_confidence_t confidence;
    int active;
} ozayn_otl_edge_t;

typedef struct {
    uint64_t event_id;
    int found;
} ozayn_otl_event_ref_t;

typedef struct {
    uint64_t event_id;
    ozayn_otl_category_t category;
    ozayn_otl_severity_t severity;
    ozayn_otl_event_state_t state;
    char operation_id[OZAYN_OTL_MAX_ID_LEN];
    char request_id[OZAYN_OTL_MAX_ID_LEN];
    char workflow_id[OZAYN_OTL_MAX_ID_LEN];
    char pipeline_id[OZAYN_OTL_MAX_ID_LEN];
    char target_component_id[OZAYN_OTL_MAX_ID_LEN];
    char correlation_id[OZAYN_OTL_MAX_ID_LEN];
    time_t occurrence_time;
    char description[OZAYN_OTL_MAX_MSG_LEN];
} ozayn_otl_query_result_t;

typedef struct {
    uint64_t total_events_ingested;
    uint64_t total_timelines_created;
    uint64_t total_timelines_completed;
    uint64_t total_timelines_failed;
    uint64_t total_correlations_formed;
    uint64_t total_duplicates_detected;
    uint64_t total_out_of_order;
    uint64_t total_late_arrivals;
    uint64_t total_inconsistencies;
    uint64_t total_query_count;
    uint64_t current_active_timelines;
    uint64_t current_events_stored;
} ozayn_otl_stats_t;

typedef struct {
    void *operation_history;
    void *workflow_orchestrator;
    void *pipeline_coordinator;
    void *pipeline_scheduler;
    void *execution_result;
    void *runtime_admission_gate;
    void *runtime_enforcement;
    void *diagnostics;
    void *events_engine;
    void *audit;
} ozayn_otl_subsystem_bind_t;

typedef struct {
    int initialized;
    uint64_t sequence;
    ozayn_otl_event_t events[OZAYN_OTL_MAX_EVENTS];
    uint64_t event_head;
    uint64_t event_count;
    ozayn_otl_timeline_t timelines[OZAYN_OTL_MAX_TIMELINES];
    uint64_t timeline_head;
    uint64_t timeline_count;
    ozayn_otl_edge_t edges[OZAYN_OTL_MAX_EVENTS];
    uint64_t edge_head;
    uint64_t edge_count;
    ozayn_otl_stats_t stats;
    ozayn_otl_subsystem_bind_t bind;
} ozayn_otl_service_t;

const char *ozayn_otl_err_name(ozayn_otl_err_t e);
const char *ozayn_otl_category_name(ozayn_otl_category_t c);
const char *ozayn_otl_severity_name(ozayn_otl_severity_t s);
const char *ozayn_otl_relationship_name(ozayn_otl_relationship_t r);
const char *ozayn_otl_confidence_name(ozayn_otl_confidence_t c);
const char *ozayn_otl_timeline_state_name(ozayn_otl_timeline_state_t s);
const char *ozayn_otl_event_state_name(ozayn_otl_event_state_t s);
const char *ozayn_otl_emit_type_name(ozayn_otl_emit_type_t t);

int ozayn_otl_init(ozayn_otl_service_t *svc);
int ozayn_otl_shutdown(ozayn_otl_service_t *svc);
int ozayn_otl_is_initialized(const ozayn_otl_service_t *svc);

int ozayn_otl_bind_subsystems(ozayn_otl_service_t *svc, const ozayn_otl_subsystem_bind_t *bind);

int ozayn_otl_event_ingest(ozayn_otl_service_t *svc,
                           const ozayn_otl_event_t *event,
                           uint64_t *out_event_id);

int ozayn_otl_event_ingest_simple(ozayn_otl_service_t *svc,
                                  ozayn_otl_category_t category,
                                  ozayn_otl_severity_t severity,
                                  const char *event_type_name,
                                  const char *source_component_id,
                                  const char *operation_id,
                                  const char *request_id,
                                  const char *target_component_id,
                                  const char *description,
                                  time_t occurrence_time,
                                  uint64_t *out_event_id);

int ozayn_otl_event_get(const ozayn_otl_service_t *svc,
                        uint64_t event_id,
                        const ozayn_otl_event_t **out_event);

int ozayn_otl_event_get_by_operation(const ozayn_otl_service_t *svc,
                                     const char *operation_id,
                                     const ozayn_otl_event_t **out_events,
                                     uint64_t max_count,
                                     uint64_t *out_count);

int ozayn_otl_event_get_by_request(const ozayn_otl_service_t *svc,
                                   const char *request_id,
                                   const ozayn_otl_event_t **out_events,
                                   uint64_t max_count,
                                   uint64_t *out_count);

int ozayn_otl_event_get_by_correlation(const ozayn_otl_service_t *svc,
                                       const char *correlation_id,
                                       const ozayn_otl_event_t **out_events,
                                       uint64_t max_count,
                                       uint64_t *out_count);

int ozayn_otl_event_get_by_category(const ozayn_otl_service_t *svc,
                                    ozayn_otl_category_t category,
                                    const ozayn_otl_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count);

int ozayn_otl_event_get_by_component(const ozayn_otl_service_t *svc,
                                     const char *component_id,
                                     const ozayn_otl_event_t **out_events,
                                     uint64_t max_count,
                                     uint64_t *out_count);

int ozayn_otl_event_get_by_severity(const ozayn_otl_service_t *svc,
                                    ozayn_otl_severity_t min_severity,
                                    const ozayn_otl_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count);

int ozayn_otl_event_get_by_time_range(const ozayn_otl_service_t *svc,
                                      time_t start_time,
                                      time_t end_time,
                                      const ozayn_otl_event_t **out_events,
                                      uint64_t max_count,
                                      uint64_t *out_count);

int ozayn_otl_event_get_recent(const ozayn_otl_service_t *svc,
                               uint64_t count,
                               const ozayn_otl_event_t **out_events,
                               uint64_t *out_count);

int ozayn_otl_event_get_duplicate_check(const ozayn_otl_service_t *svc,
                                        uint64_t event_id,
                                        const char *source_component_id,
                                        uint64_t source_sequence);

int ozayn_otl_event_set_correlation(ozayn_otl_service_t *svc,
                                    uint64_t event_id,
                                    const char *correlation_id,
                                    ozayn_otl_confidence_t confidence);

int ozayn_otl_event_set_parent(ozayn_otl_service_t *svc,
                               uint64_t event_id,
                               uint64_t parent_event_id,
                               ozayn_otl_relationship_t relationship);

int ozayn_otl_event_set_description(ozayn_otl_service_t *svc,
                                    uint64_t event_id,
                                    const char *description);

int ozayn_otl_relationship_add(ozayn_otl_service_t *svc,
                               uint64_t from_event_id,
                               uint64_t to_event_id,
                               ozayn_otl_relationship_t relationship,
                               ozayn_otl_confidence_t confidence,
                               uint64_t *out_edge_id);

int ozayn_otl_relationship_get_by_event(const ozayn_otl_service_t *svc,
                                        uint64_t event_id,
                                        const ozayn_otl_edge_t **out_edges,
                                        uint64_t max_count,
                                        uint64_t *out_count);

int ozayn_otl_timeline_create(ozayn_otl_service_t *svc,
                              const char *correlation_id,
                              const char *operation_id,
                              const char *request_id,
                              const char *workflow_id,
                              const char *pipeline_id,
                              uint64_t *out_timeline_id);

int ozayn_otl_timeline_add_event(ozayn_otl_service_t *svc,
                                 uint64_t timeline_id,
                                 uint64_t event_id);

int ozayn_otl_timeline_complete(ozayn_otl_service_t *svc,
                                uint64_t timeline_id,
                                ozayn_otl_timeline_state_t final_state);

int ozayn_otl_timeline_get(const ozayn_otl_service_t *svc,
                           uint64_t timeline_id,
                           const ozayn_otl_timeline_t **out_timeline);

int ozayn_otl_timeline_get_by_correlation(const ozayn_otl_service_t *svc,
                                          const char *correlation_id,
                                          const ozayn_otl_timeline_t **out_timeline);

int ozayn_otl_timeline_get_by_operation(const ozayn_otl_service_t *svc,
                                        const char *operation_id,
                                        const ozayn_otl_timeline_t **out_timeline);

int ozayn_otl_timeline_get_active(const ozayn_otl_service_t *svc,
                                  const ozayn_otl_timeline_t **out_timelines,
                                  uint64_t max_count,
                                  uint64_t *out_count);

int ozayn_otl_timeline_get_events(const ozayn_otl_service_t *svc,
                                  uint64_t timeline_id,
                                  const ozayn_otl_event_t **out_events,
                                  uint64_t max_count,
                                  uint64_t *out_count);

int ozayn_otl_timeline_get_operation_chain(const ozayn_otl_service_t *svc,
                                           const char *operation_id,
                                           const ozayn_otl_event_t **out_events,
                                           uint64_t max_count,
                                           uint64_t *out_count);

int ozayn_otl_timeline_get_workflow_chain(const ozayn_otl_service_t *svc,
                                          const char *workflow_id,
                                          const ozayn_otl_event_t **out_events,
                                          uint64_t max_count,
                                          uint64_t *out_count);

int ozayn_otl_timeline_get_pipeline_chain(const ozayn_otl_service_t *svc,
                                           const char *pipeline_id,
                                           const ozayn_otl_event_t **out_events,
                                           uint64_t max_count,
                                           uint64_t *out_count);

int ozayn_otl_timeline_get_children(const ozayn_otl_service_t *svc,
                                    uint64_t event_id,
                                    const ozayn_otl_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count);

int ozayn_otl_timeline_get_predecessors(const ozayn_otl_service_t *svc,
                                        uint64_t event_id,
                                        const ozayn_otl_event_t **out_events,
                                        uint64_t max_count,
                                        uint64_t *out_count);

int ozayn_otl_timeline_get_successors(const ozayn_otl_service_t *svc,
                                      uint64_t event_id,
                                      const ozayn_otl_event_t **out_events,
                                      uint64_t max_count,
                                      uint64_t *out_count);

int ozayn_otl_consistency_check(const ozayn_otl_service_t *svc,
                                uint64_t timeline_id,
                                int *out_consistent,
                                char *out_issue,
                                uint64_t issue_len);

int ozayn_otl_stats_get(const ozayn_otl_service_t *svc,
                        ozayn_otl_stats_t *out_stats);

int64_t ozayn_otl_event_count(const ozayn_otl_service_t *svc);
int64_t ozayn_otl_timeline_count(const ozayn_otl_service_t *svc);
int64_t ozayn_otl_active_timeline_count(const ozayn_otl_service_t *svc);

int ozayn_otl_shutdown_drain(ozayn_otl_service_t *svc,
                             const ozayn_otl_timeline_t **out_active,
                             uint64_t max_count,
                             uint64_t *out_count);

int ozayn_otl_retention_prune(ozayn_otl_service_t *svc,
                              uint64_t max_events,
                              uint64_t max_age_seconds,
                              uint64_t *out_pruned);

#endif
