#ifndef OZAYN_EXECUTION_RESULT_H
#define OZAYN_EXECUTION_RESULT_H

#include <stdint.h>
#include <time.h>

#define OZAYN_XR_MAX_ERROR_DETAIL 128
#define OZAYN_XR_MAX_RESULT_HISTORY 64
#define OZAYN_XR_MAX_RECONCILIATION_HISTORY 64
#define OZAYN_XR_MAX_EVENTS 64
#define OZAYN_XR_MAX_COMPONENT_ID 64
#define OZAYN_XR_MAX_ID_LEN 64

typedef enum {
    OZAYN_XR_ERR_OK = 0,
    OZAYN_XR_ERR_NULL_PTR,
    OZAYN_XR_ERR_NOT_INITIALIZED,
    OZAYN_XR_ERR_ALREADY_INITIALIZED,
    OZAYN_XR_ERR_INVALID_ID,
    OZAYN_XR_ERR_NOT_FOUND,
    OZAYN_XR_ERR_DUPLICATE,
    OZAYN_XR_ERR_FULL,
    OZAYN_XR_ERR_INVALID_STATE,
    OZAYN_XR_ERR_INVALID_TRANSITION,
    OZAYN_XR_ERR_TIMEOUT,
    OZAYN_XR_ERR_CANCELLED,
    OZAYN_XR_ERR_DEPENDENCY_MISSING,
    OZAYN_XR_ERR_SUBSYSTEM_UNAVAILABLE,
    OZAYN_XR_ERR_RESOURCE_EXHAUSTED,
    OZAYN_XR_ERR_UNAUTHORIZED,
    OZAYN_XR_ERR_UNSAFE,
    OZAYN_XR_ERR_INTERNAL
} ozayn_xr_err_t;

typedef enum {
    OZAYN_XR_EXEC_STARTED = 0,
    OZAYN_XR_EXEC_SUCCEEDED,
    OZAYN_XR_EXEC_FAILED,
    OZAYN_XR_EXEC_PARTIAL,
    OZAYN_XR_EXEC_CANCELLED,
    OZAYN_XR_EXEC_TIMEOUT,
    OZAYN_XR_EXEC_INTERRUPTED,
    OZAYN_XR_EXEC_UNKNOWN,
    OZAYN_XR_EXEC_UNAVAILABLE
} ozayn_xr_exec_state_t;

typedef enum {
    OZAYN_XR_RESULT_SUCCESS = 0,
    OZAYN_XR_RESULT_FAILED,
    OZAYN_XR_RESULT_PARTIAL,
    OZAYN_XR_RESULT_CANCELLED,
    OZAYN_XR_RESULT_TIMEOUT,
    OZAYN_XR_RESULT_INTERRUPTED,
    OZAYN_XR_RESULT_UNKNOWN,
    OZAYN_XR_RESULT_UNAVAILABLE,
    OZAYN_XR_RESULT_DUPLICATE
} ozayn_xr_result_outcome_t;

typedef enum {
    OZAYN_XR_RECON_PENDING = 0,
    OZAYN_XR_RECON_IN_PROGRESS,
    OZAYN_XR_RECON_CONSISTENT,
    OZAYN_XR_RECON_STATE_CHANGED_AS_EXPECTED,
    OZAYN_XR_RECON_STATE_CHANGED_UNEXPECTEDLY,
    OZAYN_XR_RECON_PARTIAL,
    OZAYN_XR_RECON_INCONSISTENT,
    OZAYN_XR_RECON_UNKNOWN,
    OZAYN_XR_RECON_UNAVAILABLE,
    OZAYN_XR_RECON_REQUIRES_DIAGNOSTICS
} ozayn_xr_recon_state_t;

typedef enum {
    OZAYN_XR_EVENT_EXEC_STARTED = 0,
    OZAYN_XR_EVENT_EXEC_COMPLETED,
    OZAYN_XR_EVENT_EXEC_SUCCEEDED,
    OZAYN_XR_EVENT_EXEC_FAILED,
    OZAYN_XR_EVENT_EXEC_PARTIAL,
    OZAYN_XR_EVENT_EXEC_CANCELLED,
    OZAYN_XR_EVENT_EXEC_TIMEOUT,
    OZAYN_XR_EVENT_EXEC_INTERRUPTED,
    OZAYN_XR_EVENT_EXEC_UNKNOWN,
    OZAYN_XR_EVENT_RECON_STARTED,
    OZAYN_XR_EVENT_RECON_COMPLETED,
    OZAYN_XR_EVENT_RECON_CONSISTENT,
    OZAYN_XR_EVENT_RECON_INCONSISTENT,
    OZAYN_XR_EVENT_RECON_PARTIAL,
    OZAYN_XR_EVENT_RECON_UNKNOWN,
    OZAYN_XR_EVENT_RECON_REQUIRED,
    OZAYN_XR_EVENT_RESULT_RECORDED,
    OZAYN_XR_EVENT_STATE_RECON_REQUIRED
} ozayn_xr_event_type_t;

typedef enum {
    OZAYN_XR_TARGET_AVAILABLE = 0,
    OZAYN_XR_TARGET_UNAVAILABLE,
    OZAYN_XR_TARGET_UNKNOWN
} ozayn_xr_target_state_t;

typedef enum {
    OZAYN_XR_RESOURCE_OK = 0,
    OZAYN_XR_RESOURCE_LEAK_DETECTED,
    OZAYN_XR_RESOURCE_EXHAUSTED,
    OZAYN_XR_RESOURCE_MISMATCH,
    OZAYN_XR_RESOURCE_UNKNOWN,
    OZAYN_XR_RESOURCE_UNAVAILABLE
} ozayn_xr_resource_state_t;

typedef enum {
    OZAYN_XR_DEVICE_OK = 0,
    OZAYN_XR_DEVICE_DISCONNECTED,
    OZAYN_XR_DEVICE_SESSION_CLOSED,
    OZAYN_XR_DEVICE_RESERVATION_LOST,
    OZAYN_XR_DEVICE_UNKNOWN,
    OZAYN_XR_DEVICE_UNAVAILABLE
} ozayn_xr_device_state_t;

typedef enum {
    OZAYN_XR_WORKFLOW_OK = 0,
    OZAYN_XR_WORKFLOW_STAGE_FAILED,
    OZAYN_XR_WORKFLOW_CANCELLED,
    OZAYN_XR_WORKFLOW_UNKNOWN,
    OZAYN_XR_WORKFLOW_UNAVAILABLE
} ozayn_xr_workflow_state_t;

typedef enum {
    OZAYN_XR_PIPELINE_OK = 0,
    OZAYN_XR_PIPELINE_STAGE_FAILED,
    OZAYN_XR_PIPELINE_FAILED,
    OZAYN_XR_PIPELINE_UNKNOWN,
    OZAYN_XR_PIPELINE_UNAVAILABLE
} ozayn_xr_pipeline_state_t;

typedef enum {
    OZAYN_XR_SCHEDULER_RELEASED = 0,
    OZAYN_XR_SCHEDULER_STILL_RUNNING,
    OZAYN_XR_SCHEDULER_UNKNOWN,
    OZAYN_XR_SCHEDULER_UNAVAILABLE
} ozayn_xr_scheduler_state_t;

typedef enum {
    OZAYN_XR_DIAG_NONE = 0,
    OZAYN_XR_DIAG_REQUESTED,
    OZAYN_XR_DIAG_COMPLETED,
    OZAYN_XR_DIAG_UNAVAILABLE
} ozayn_xr_diagnostic_state_t;

typedef struct {
    ozayn_xr_exec_state_t exec_state;
    ozayn_xr_result_outcome_t outcome;
    int result_code;
    char error_detail[OZAYN_XR_MAX_ERROR_DETAIL];
    time_t started_time;
    time_t completed_time;
    int64_t duration_ms;
} ozayn_xr_execution_result_t;

typedef struct {
    ozayn_xr_recon_state_t recon_state;
    ozayn_xr_target_state_t target_state;
    ozayn_xr_resource_state_t resource_state;
    ozayn_xr_device_state_t device_state;
    ozayn_xr_workflow_state_t workflow_state;
    ozayn_xr_pipeline_state_t pipeline_state;
    ozayn_xr_scheduler_state_t scheduler_state;
    ozayn_xr_diagnostic_state_t diagnostic_state;
    char target_expected_state[OZAYN_XR_MAX_COMPONENT_ID];
    char target_actual_state[OZAYN_XR_MAX_COMPONENT_ID];
    int state_comparison_valid;
    int requires_diagnostics;
} ozayn_xr_reconciliation_t;

typedef struct {
    uint64_t record_id;
    char result_id[OZAYN_XR_MAX_ID_LEN];
    char execution_record_id[OZAYN_XR_MAX_ID_LEN];
    char operation_id[OZAYN_XR_MAX_ID_LEN];
    char request_id[OZAYN_XR_MAX_ID_LEN];
    char target_component_id[OZAYN_XR_MAX_ID_LEN];
    char capability_id[OZAYN_XR_MAX_ID_LEN];
    char action[OZAYN_XR_MAX_COMPONENT_ID];
    char requester_identity[OZAYN_XR_MAX_ID_LEN];
    char session_id[OZAYN_XR_MAX_ID_LEN];
    ozayn_xr_execution_result_t result;
    ozayn_xr_reconciliation_t reconciliation;
    int64_t admission_ref;
    int64_t enforcement_ref;
    int64_t history_record_id;
    int64_t diagnostic_request_id;
    time_t recorded_time;
    int finalized;
} ozayn_xr_result_record_t;

typedef struct {
    uint64_t event_id;
    ozayn_xr_event_type_t event_type;
    char operation_id[OZAYN_XR_MAX_ID_LEN];
    char result_id[OZAYN_XR_MAX_ID_LEN];
    char target_component_id[OZAYN_XR_MAX_ID_LEN];
    time_t event_time;
} ozayn_xr_event_t;

typedef struct {
    uint64_t total_results_received;
    uint64_t total_succeeded;
    uint64_t total_failed;
    uint64_t total_partial;
    uint64_t total_cancelled;
    uint64_t total_timeout;
    uint64_t total_interrupted;
    uint64_t total_unknown;
    uint64_t total_unavailable;
    uint64_t total_duplicate_results;
    uint64_t total_reconciliations;
    uint64_t total_consistent;
    uint64_t total_inconsistent;
    uint64_t total_partial_reconciliations;
    uint64_t total_unknown_reconciliations;
    uint64_t total_requires_diagnostics;
    uint64_t current_pending;
    uint64_t current_finalized;
} ozayn_xr_stats_t;

typedef struct {
    void *component_registry;
    void *resource_manager;
    void *device_session;
    void *workflow_orchestrator;
    void *pipeline_coordinator;
    void *operation_history;
    void *operation_queue;
    void *pipeline_scheduler;
    void *diagnostics;
    void *events_engine;
    void *audit;
    void *runtime_enforcement;
} ozayn_xr_subsystem_bind_t;

typedef struct {
    int initialized;
    uint64_t sequence;
    ozayn_xr_result_record_t results[OZAYN_XR_MAX_RESULT_HISTORY];
    uint64_t result_head;
    uint64_t result_count;
    ozayn_xr_result_record_t reconciliations[OZAYN_XR_MAX_RECONCILIATION_HISTORY];
    uint64_t recon_head;
    uint64_t recon_count;
    ozayn_xr_event_t events[OZAYN_XR_MAX_EVENTS];
    uint64_t event_head;
    uint64_t event_count;
    ozayn_xr_stats_t stats;
    ozayn_xr_subsystem_bind_t bind;
} ozayn_xr_service_t;

const char *ozayn_xr_exec_state_name(ozayn_xr_exec_state_t s);
const char *ozayn_xr_result_outcome_name(ozayn_xr_result_outcome_t o);
const char *ozayn_xr_recon_state_name(ozayn_xr_recon_state_t s);
const char *ozayn_xr_event_type_name(ozayn_xr_event_type_t t);
const char *ozayn_xr_target_state_name(ozayn_xr_target_state_t s);
const char *ozayn_xr_resource_state_name(ozayn_xr_resource_state_t s);
const char *ozayn_xr_device_state_name(ozayn_xr_device_state_t s);
const char *ozayn_xr_workflow_state_name(ozayn_xr_workflow_state_t s);
const char *ozayn_xr_pipeline_state_name(ozayn_xr_pipeline_state_t s);
const char *ozayn_xr_scheduler_state_name(ozayn_xr_scheduler_state_t s);
const char *ozayn_xr_diagnostic_state_name(ozayn_xr_diagnostic_state_t s);

int ozayn_xr_init(ozayn_xr_service_t *svc);
int ozayn_xr_shutdown(ozayn_xr_service_t *svc);
int ozayn_xr_is_initialized(const ozayn_xr_service_t *svc);

int ozayn_xr_bind_subsystems(ozayn_xr_service_t *svc, const ozayn_xr_subsystem_bind_t *bind);

int ozayn_xr_result_record(ozayn_xr_service_t *svc,
                           const char *result_id,
                           const char *execution_record_id,
                           const char *operation_id,
                           const char *request_id,
                           const char *target_component_id,
                           const char *capability_id,
                           const char *action,
                           const char *requester_identity,
                           const char *session_id,
                           ozayn_xr_exec_state_t exec_state,
                           ozayn_xr_result_outcome_t outcome,
                           int result_code,
                           const char *error_detail,
                           time_t started_time,
                           time_t completed_time,
                           int64_t duration_ms,
                           int64_t admission_ref,
                           int64_t enforcement_ref,
                           ozayn_xr_result_record_t **out_record);

int ozayn_xr_result_record_duplicate_check(const ozayn_xr_service_t *svc,
                                           const char *result_id,
                                           const char *operation_id,
                                           const char *execution_record_id);

int ozayn_xr_result_update(ozayn_xr_service_t *svc,
                           uint64_t record_id,
                           ozayn_xr_exec_state_t exec_state,
                           ozayn_xr_result_outcome_t outcome,
                           int result_code,
                           const char *error_detail,
                           time_t completed_time,
                           int64_t duration_ms);

int ozayn_xr_reconcile(ozayn_xr_service_t *svc,
                       uint64_t record_id,
                       ozayn_xr_recon_state_t *out_recon_state);

int ozayn_xr_reconcile_full(ozayn_xr_service_t *svc,
                            uint64_t record_id,
                            ozayn_xr_reconciliation_t *out_recon);

int ozayn_xr_reconcile_target(ozayn_xr_service_t *svc,
                              uint64_t record_id,
                              const char *expected_state,
                              const char *actual_state,
                              ozayn_xr_recon_state_t *out_recon_state);

int ozayn_xr_result_finalize(ozayn_xr_service_t *svc,
                             uint64_t record_id);

int ozayn_xr_result_get(const ozayn_xr_service_t *svc,
                        uint64_t record_id,
                        const ozayn_xr_result_record_t **out_record);

int ozayn_xr_result_get_by_operation(const ozayn_xr_service_t *svc,
                                     const char *operation_id,
                                     const ozayn_xr_result_record_t **out_record);

int ozayn_xr_result_get_pending(const ozayn_xr_service_t *svc,
                                const ozayn_xr_result_record_t **out_records,
                                uint64_t max_count,
                                uint64_t *out_count);

int ozayn_xr_result_get_finalized(const ozayn_xr_service_t *svc,
                                  const ozayn_xr_result_record_t **out_records,
                                  uint64_t max_count,
                                  uint64_t *out_count);

int ozayn_xr_recon_get(const ozayn_xr_service_t *svc,
                       uint64_t record_id,
                       const ozayn_xr_result_record_t **out_record);

int ozayn_xr_recon_get_by_operation(const ozayn_xr_service_t *svc,
                                    const char *operation_id,
                                    const ozayn_xr_result_record_t **out_record);

int ozayn_xr_event_emit(ozayn_xr_service_t *svc,
                        ozayn_xr_event_type_t event_type,
                        const char *operation_id,
                        const char *result_id,
                        const char *target_component_id);

int ozayn_xr_event_get(const ozayn_xr_service_t *svc,
                       uint64_t event_id,
                       const ozayn_xr_event_t **out_event);

int ozayn_xr_event_get_by_operation(const ozayn_xr_service_t *svc,
                                    const char *operation_id,
                                    const ozayn_xr_event_t **out_events,
                                    uint64_t max_count,
                                    uint64_t *out_count);

int ozayn_xr_stats_get(const ozayn_xr_service_t *svc,
                       ozayn_xr_stats_t *out_stats);

int64_t ozayn_xr_pending_count(const ozayn_xr_service_t *svc);
int64_t ozayn_xr_finalized_count(const ozayn_xr_service_t *svc);

int ozayn_xr_shutdown_drain(ozayn_xr_service_t *svc,
                            ozayn_xr_result_record_t **out_unresolved,
                            uint64_t max_count,
                            uint64_t *out_count);

int ozayn_xr_is_exec_terminal(ozayn_xr_exec_state_t state);
int ozayn_xr_is_recon_terminal(ozayn_xr_recon_state_t state);

#endif
