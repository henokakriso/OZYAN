#ifndef OZAYN_OPERATIONAL_METRICS_H
#define OZAYN_OPERATIONAL_METRICS_H

#include <stdint.h>
#include <time.h>

#define OZAYN_OM_MAX_METRIC_NAME 64
#define OZAYN_OM_MAX_SOURCE_LEN 64
#define OZAYN_OM_MAX_METRICS 256
#define OZAYN_OM_MAX_HISTOGRAMS 64
#define OZAYN_OM_MAX_THRESHOLDS 64
#define OZAYN_OM_MAX_SNAPSHOTS 16
#define OZAYN_OM_MAX_HISTOGRAM_BUCKETS 16
#define OZAYN_OM_MAX_SNAPSHOT_SAMPLES 64

typedef enum {
    OZAYN_OM_ERR_OK = 0,
    OZAYN_OM_ERR_NULL_PTR,
    OZAYN_OM_ERR_NOT_INITIALIZED,
    OZAYN_OM_ERR_ALREADY_INITIALIZED,
    OZAYN_OM_ERR_NOT_FOUND,
    OZAYN_OM_ERR_FULL,
    OZAYN_OM_ERR_DUPLICATE,
    OZAYN_OM_ERR_INVALID_TYPE,
    OZAYN_OM_ERR_INVALID_VALUE,
    OZAYN_OM_ERR_OVERFLOW,
    OZAYN_OM_ERR_STORAGE_ERROR,
    OZAYN_OM_ERR_QUERY_INVALID,
    OZAYN_OM_ERR_QUERY_LIMIT,
    OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE,
    OZAYN_OM_ERR_CONCURRENCY_ERROR,
    OZAYN_OM_ERR_INTERNAL
} ozayn_om_err_t;

typedef enum {
    OZAYN_OM_TYPE_COUNTER = 0,
    OZAYN_OM_TYPE_GAUGE,
    OZAYN_OM_TYPE_HISTOGRAM,
    OZAYN_OM_TYPE_DURATION,
    OZAYN_OM_TYPE_RATE,
    OZAYN_OM_TYPE_RATIO
} ozayn_om_metric_type_t;

typedef enum {
    OZAYN_OM_CAT_SYSTEM = 0,
    OZAYN_OM_CAT_CORE,
    OZAYN_OM_CAT_COMPONENT,
    OZAYN_OM_CAT_OPERATION,
    OZAYN_OM_CAT_QUEUE,
    OZAYN_OM_CAT_SCHEDULER,
    OZAYN_OM_CAT_WORKFLOW,
    OZAYN_OM_CAT_PIPELINE,
    OZAYN_OM_CAT_EXECUTION,
    OZAYN_OM_CAT_RESOURCE,
    OZAYN_OM_CAT_DEVICE,
    OZAYN_OM_CAT_IO,
    OZAYN_OM_CAT_SECURITY,
    OZAYN_OM_CAT_DIAGNOSTIC,
    OZAYN_OM_CAT_RECOVERY,
    OZAYN_OM_CAT_EVENT,
    OZAYN_OM_CAT_ERROR,
    OZAYN_OM_CAT_STARTUP,
    OZAYN_OM_CAT_SHUTDOWN
} ozayn_om_category_t;

typedef enum {
    OZAYN_OM_UNIT_NONE = 0,
    OZAYN_OM_UNIT_COUNT,
    OZAYN_OM_UNIT_BYTES,
    OZAYN_OM_UNIT_US,
    OZAYN_OM_UNIT_MS,
    OZAYN_OM_UNIT_SECONDS,
    OZAYN_OM_UNIT_PERCENT,
    OZAYN_OM_UNIT_RATE_PER_SEC
} ozayn_om_unit_t;

typedef enum {
    OZAYN_OM_COLLECTED = 0,
    OZAYN_OM_UNAVAILABLE,
    OZAYN_OM_UNSUPPORTED,
    OZAYN_OM_ERROR
} ozayn_om_collection_status_t;

typedef enum {
    OZAYN_OM_SCOPE_GLOBAL = 0,
    OZAYN_OM_SCOPE_COMPONENT,
    OZAYN_OM_SCOPE_OPERATION,
    OZAYN_OM_SCOPE_WORKFLOW,
    OZAYN_OM_SCOPE_PIPELINE
} ozayn_om_scope_t;

typedef enum {
    OZAYN_OM_THRESH_NORMAL = 0,
    OZAYN_OM_THRESH_ELEVATED,
    OZAYN_OM_THRESH_HIGH,
    OZAYN_OM_THRESH_CRITICAL
} ozayn_om_threshold_state_t;

typedef enum {
    OZAYN_OM_THRESH_CAPACITY_WARNING = 0,
    OZAYN_OM_THRESH_CAPACITY_CRITICAL,
    OZAYN_OM_THRESH_LATENCY_WARNING,
    OZAYN_OM_THRESH_LATENCY_CRITICAL,
    OZAYN_OM_THRESH_EVENT_BACKLOG,
    OZAYN_OM_THRESH_ERROR_RATE
} ozayn_om_threshold_type_t;

typedef enum {
    OZAYN_OM_EMIT_THRESHOLD_REACHED = 0,
    OZAYN_OM_EMIT_THRESHOLD_CLEARED,
    OZAYN_OM_EMIT_CAPACITY_WARNING,
    OZAYN_OM_EMIT_CAPACITY_CRITICAL,
    OZAYN_OM_EMIT_LATENCY_WARNING,
    OZAYN_OM_EMIT_EVENT_BACKLOG
} ozayn_om_emit_type_t;

typedef struct {
    uint64_t metric_id;
    char name[OZAYN_OM_MAX_METRIC_NAME];
    ozayn_om_metric_type_t type;
    ozayn_om_category_t category;
    ozayn_om_unit_t unit;
    ozayn_om_scope_t scope;
    ozayn_om_collection_status_t status;
    char source_component[OZAYN_OM_MAX_SOURCE_LEN];
    char correlation_id[64];
    int active;
} ozayn_om_metric_def_t;

typedef struct {
    uint64_t metric_id;
    int64_t value;
    int64_t prev_value;
    time_t timestamp;
    uint64_t update_count;
} ozayn_om_counter_t;

typedef struct {
    uint64_t metric_id;
    int64_t value;
    int64_t min_value;
    int64_t max_value;
    time_t timestamp;
    uint64_t update_count;
} ozayn_om_gauge_t;

typedef struct {
    uint64_t metric_id;
    int64_t boundaries[OZAYN_OM_MAX_HISTOGRAM_BUCKETS];
    uint64_t bucket_counts[OZAYN_OM_MAX_HISTOGRAM_BUCKETS];
    int bucket_count;
    uint64_t total_count;
    int64_t total_sum;
    int64_t min_value;
    int64_t max_value;
    time_t timestamp;
} ozayn_om_histogram_t;

typedef struct {
    uint64_t metric_id;
    int64_t value;
    int64_t min_value;
    int64_t max_value;
    int64_t last_value;
    uint64_t sample_count;
    time_t timestamp;
} ozayn_om_duration_t;

typedef struct {
    uint64_t metric_id;
    double value;
    int64_t numerator;
    int64_t denominator;
    time_t timestamp;
} ozayn_om_rate_t;

typedef struct {
    uint64_t metric_id;
    double value;
    int64_t numerator;
    int64_t denominator;
    time_t timestamp;
} ozayn_om_ratio_t;

typedef struct {
    char name[OZAYN_OM_MAX_METRIC_NAME];
    ozayn_om_threshold_type_t type;
    ozayn_om_category_t category;
    int64_t warning_threshold;
    int64_t critical_threshold;
    ozayn_om_threshold_state_t current_state;
    int active;
} ozayn_om_threshold_t;

typedef struct {
    uint64_t event_id;
    ozayn_om_emit_type_t type;
    char metric_name[OZAYN_OM_MAX_METRIC_NAME];
    ozayn_om_threshold_state_t threshold_state;
    int64_t current_value;
    int64_t threshold_value;
    time_t timestamp;
    int active;
} ozayn_om_alert_t;

typedef struct {
    uint64_t snapshot_id;
    time_t timestamp;
    uint64_t uptime_us;
    uint32_t active_operations;
    uint32_t queued_operations;
    uint32_t active_workflows;
    uint32_t active_pipelines;
    uint32_t active_device_sessions;
    uint32_t active_streams;
    uint32_t active_routes;
    uint32_t event_queue_depth;
    uint32_t failure_count;
    uint32_t resource_count;
    uint32_t device_count;
    double cpu_usage_pct;
    double memory_usage_pct;
    double queue_utilization_pct;
    double scheduler_utilization_pct;
    double admission_latency_us;
    double enforcement_latency_us;
    double execution_duration_us;
    double reconciliation_duration_us;
    double event_latency_us;
    int64_t operations_received;
    int64_t operations_succeeded;
    int64_t operations_failed;
    int64_t events_received;
    int64_t events_correlated;
    int64_t failures_detected;
    int64_t recoveries_attempted;
    int64_t recoveries_succeeded;
    int active;
} ozayn_om_snapshot_t;

typedef struct {
    void *operation_queue;
    void *operation_history;
    void *pipeline_scheduler;
    void *workflow_orchestrator;
    void *pipeline_coordinator;
    void *execution_result;
    void *runtime_admission_gate;
    void *runtime_enforcement;
    void *operational_timeline;
    void *resource_manager;
    void *diagnostics;
    void *events_engine;
    void *health_tracker;
    void *audit;
    void *workflow_recovery;
} ozayn_om_subsystem_bind_t;

typedef struct {
    uint64_t total_metrics_registered;
    uint64_t total_counter_updates;
    uint64_t total_gauge_updates;
    uint64_t total_histogram_updates;
    uint64_t total_duration_records;
    uint64_t total_snapshots_created;
    uint64_t total_threshold_checks;
    uint64_t total_threshold_breaches;
    uint64_t total_alerts_emitted;
    uint64_t total_queries;
    uint64_t total_collection_failures;
    uint32_t current_metrics;
    uint32_t current_histograms;
    uint32_t current_thresholds;
    uint32_t current_alerts;
    uint32_t current_snapshots;
} ozayn_om_stats_t;

typedef struct {
    int initialized;
    uint64_t sequence;
    ozayn_om_metric_def_t metrics[OZAYN_OM_MAX_METRICS];
    uint64_t metric_count;
    ozayn_om_counter_t counters[OZAYN_OM_MAX_METRICS];
    uint64_t counter_count;
    ozayn_om_gauge_t gauges[OZAYN_OM_MAX_METRICS];
    uint64_t gauge_count;
    ozayn_om_histogram_t histograms[OZAYN_OM_MAX_HISTOGRAMS];
    uint64_t histogram_count;
    ozayn_om_duration_t durations[OZAYN_OM_MAX_METRICS];
    uint64_t duration_count;
    ozayn_om_rate_t rates[OZAYN_OM_MAX_METRICS];
    uint64_t rate_count;
    ozayn_om_ratio_t ratios[OZAYN_OM_MAX_METRICS];
    uint64_t ratio_count;
    ozayn_om_threshold_t thresholds[OZAYN_OM_MAX_THRESHOLDS];
    uint64_t threshold_count;
    ozayn_om_alert_t alerts[OZAYN_OM_MAX_METRICS];
    uint64_t alert_head;
    uint64_t alert_count;
    ozayn_om_snapshot_t snapshots[OZAYN_OM_MAX_SNAPSHOTS];
    uint64_t snapshot_head;
    uint64_t snapshot_count;
    ozayn_om_stats_t stats;
    ozayn_om_subsystem_bind_t bind;
} ozayn_om_service_t;

const char *ozayn_om_err_name(ozayn_om_err_t e);
const char *ozayn_om_metric_type_name(ozayn_om_metric_type_t t);
const char *ozayn_om_category_name(ozayn_om_category_t c);
const char *ozayn_om_unit_name(ozayn_om_unit_t u);
const char *ozayn_om_scope_name(ozayn_om_scope_t s);
const char *ozayn_om_collection_status_name(ozayn_om_collection_status_t s);
const char *ozayn_om_threshold_state_name(ozayn_om_threshold_state_t s);
const char *ozayn_om_threshold_type_name(ozayn_om_threshold_type_t t);
const char *ozayn_om_emit_type_name(ozayn_om_emit_type_t t);

int ozayn_om_init(ozayn_om_service_t *svc);
int ozayn_om_shutdown(ozayn_om_service_t *svc);
int ozayn_om_is_initialized(const ozayn_om_service_t *svc);

int ozayn_om_bind_subsystems(ozayn_om_service_t *svc, const ozayn_om_subsystem_bind_t *bind);

int ozayn_om_register_metric(ozayn_om_service_t *svc,
                             const char *name,
                             ozayn_om_metric_type_t type,
                             ozayn_om_category_t category,
                             ozayn_om_unit_t unit,
                             ozayn_om_scope_t scope,
                             const char *source_component,
                             uint64_t *out_metric_id);

int ozayn_om_unregister_metric(ozayn_om_service_t *svc, uint64_t metric_id);

int ozayn_om_get_metric_def(const ozayn_om_service_t *svc,
                            uint64_t metric_id,
                            const ozayn_om_metric_def_t **out_def);

int ozayn_om_get_metric_by_name(const ozayn_om_service_t *svc,
                                const char *name,
                                const ozayn_om_metric_def_t **out_def);

int ozayn_om_counter_increment(ozayn_om_service_t *svc, uint64_t metric_id, int64_t delta);

int ozayn_om_counter_get(const ozayn_om_service_t *svc, uint64_t metric_id, int64_t *out_value);

int ozayn_om_gauge_set(ozayn_om_service_t *svc, uint64_t metric_id, int64_t value);

int ozayn_om_gauge_update(ozayn_om_service_t *svc, uint64_t metric_id, int64_t delta);

int ozayn_om_gauge_get(const ozayn_om_service_t *svc, uint64_t metric_id, int64_t *out_value);

int ozayn_om_histogram_create(ozayn_om_service_t *svc,
                              uint64_t metric_id,
                              const int64_t *boundaries,
                              int boundary_count);

int ozayn_om_histogram_record(ozayn_om_service_t *svc, uint64_t metric_id, int64_t value);

int ozayn_om_histogram_get(const ozayn_om_service_t *svc,
                           uint64_t metric_id,
                           const uint64_t **out_bucket_counts,
                           int *out_bucket_count,
                           uint64_t *out_total_count,
                           int64_t *out_total_sum);

int ozayn_om_duration_record(ozayn_om_service_t *svc, uint64_t metric_id, int64_t duration_us);

int ozayn_om_duration_get(const ozayn_om_service_t *svc, uint64_t metric_id,
                          int64_t *out_min, int64_t *out_max, uint64_t *out_count);

int ozayn_om_rate_update(ozayn_om_service_t *svc, uint64_t metric_id,
                         int64_t numerator, int64_t denominator);

int ozayn_om_rate_get(const ozayn_om_service_t *svc, uint64_t metric_id, double *out_rate);

int ozayn_om_ratio_update(ozayn_om_service_t *svc, uint64_t metric_id,
                          int64_t numerator, int64_t denominator);

int ozayn_om_ratio_get(const ozayn_om_service_t *svc, uint64_t metric_id, double *out_ratio);

int ozayn_om_threshold_register(ozayn_om_service_t *svc,
                                const char *metric_name,
                                ozayn_om_threshold_type_t type,
                                ozayn_om_category_t category,
                                int64_t warning_threshold,
                                int64_t critical_threshold);

int ozayn_om_threshold_evaluate(ozayn_om_service_t *svc,
                                const char *metric_name,
                                int64_t current_value,
                                ozayn_om_threshold_state_t *out_state);

int ozayn_om_threshold_get_state(const ozayn_om_service_t *svc,
                                 const char *metric_name,
                                 ozayn_om_threshold_state_t *out_state);

int ozayn_om_alert_get(const ozayn_om_service_t *svc,
                       uint64_t event_id,
                       const ozayn_om_alert_t **out_alert);

int ozayn_om_alert_get_recent(const ozayn_om_service_t *svc,
                              uint64_t count,
                              const ozayn_om_alert_t **out_alerts,
                              uint64_t *out_count);

int ozayn_om_snapshot_create(ozayn_om_service_t *svc, uint64_t *out_snapshot_id);

int ozayn_om_snapshot_get(const ozayn_om_service_t *svc,
                          uint64_t snapshot_id,
                          const ozayn_om_snapshot_t **out_snapshot);

int ozayn_om_snapshot_get_latest(const ozayn_om_service_t *svc,
                                 const ozayn_om_snapshot_t **out_snapshot);

int ozayn_om_snapshot_collect(ozayn_om_service_t *svc, uint64_t *out_snapshot_id);

int ozayn_om_collect_all(ozayn_om_service_t *svc);

int ozayn_om_collect_operation_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_queue_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_scheduler_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_workflow_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_pipeline_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_execution_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_failure_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_resource_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_event_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_admission_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_enforcement_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_diagnostic_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_recovery_metrics(ozayn_om_service_t *svc);

int ozayn_om_collect_health_metrics(ozayn_om_service_t *svc);

ozayn_om_stats_t ozayn_om_get_stats(const ozayn_om_service_t *svc);

int64_t ozayn_om_metric_count(const ozayn_om_service_t *svc);

int64_t ozayn_om_snapshot_count(const ozayn_om_service_t *svc);

int ozayn_om_shutdown_drain(ozayn_om_service_t *svc,
                            uint64_t *out_pending_metrics,
                            uint64_t *out_pending_snapshots);

#endif
