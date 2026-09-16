#include "operational_metrics.h"
#include "operation_queue.h"
#include "operation_history.h"
#include "pipeline_scheduler.h"
#include "workflow_orchestrator.h"
#include "pipeline.h"
#include "execution_result.h"
#include "runtime_admission_gate.h"
#include "runtime_enforcement.h"
#include "operational_timeline.h"
#include "resource.h"
#include "diagnostics.h"
#include "workflow_recovery.h"
#include <string.h>
#include <stdio.h>

static ozayn_om_metric_def_t *find_metric_def(ozayn_om_service_t *svc, uint64_t id) {
    for (uint64_t i = 0; i < svc->metric_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->metrics[i].active && svc->metrics[i].metric_id == id)
            return &svc->metrics[i];
    }
    return 0;
}

static const ozayn_om_metric_def_t *find_metric_def_const(const ozayn_om_service_t *svc, uint64_t id) {
    for (uint64_t i = 0; i < svc->metric_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->metrics[i].active && svc->metrics[i].metric_id == id)
            return &svc->metrics[i];
    }
    return 0;
}

static int find_metric_by_name_index(const ozayn_om_service_t *svc, const char *name) {
    for (uint64_t i = 0; i < svc->metric_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->metrics[i].active && strcmp(svc->metrics[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

static int find_counter_index(const ozayn_om_service_t *svc, uint64_t metric_id) {
    for (uint64_t i = 0; i < svc->counter_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->counters[i].metric_id == metric_id)
            return (int)i;
    }
    return -1;
}

static int find_gauge_index(const ozayn_om_service_t *svc, uint64_t metric_id) {
    for (uint64_t i = 0; i < svc->gauge_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->gauges[i].metric_id == metric_id)
            return (int)i;
    }
    return -1;
}

static int find_histogram_index(const ozayn_om_service_t *svc, uint64_t metric_id) {
    for (uint64_t i = 0; i < svc->histogram_count && i < OZAYN_OM_MAX_HISTOGRAMS; i++) {
        if (svc->histograms[i].metric_id == metric_id)
            return (int)i;
    }
    return -1;
}

static int find_duration_index(const ozayn_om_service_t *svc, uint64_t metric_id) {
    for (uint64_t i = 0; i < svc->duration_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->durations[i].metric_id == metric_id)
            return (int)i;
    }
    return -1;
}

static int find_rate_index(const ozayn_om_service_t *svc, uint64_t metric_id) {
    for (uint64_t i = 0; i < svc->rate_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->rates[i].metric_id == metric_id)
            return (int)i;
    }
    return -1;
}

static int find_ratio_index(const ozayn_om_service_t *svc, uint64_t metric_id) {
    for (uint64_t i = 0; i < svc->ratio_count && i < OZAYN_OM_MAX_METRICS; i++) {
        if (svc->ratios[i].metric_id == metric_id)
            return (int)i;
    }
    return -1;
}

static int register_counter(ozayn_om_service_t *svc, uint64_t metric_id) {
    if (svc->counter_count >= OZAYN_OM_MAX_METRICS) return -1;
    ozayn_om_counter_t *c = &svc->counters[svc->counter_count];
    memset(c, 0, sizeof(*c));
    c->metric_id = metric_id;
    c->timestamp = time(0);
    svc->counter_count++;
    return 0;
}

static int register_gauge(ozayn_om_service_t *svc, uint64_t metric_id) {
    if (svc->gauge_count >= OZAYN_OM_MAX_METRICS) return -1;
    ozayn_om_gauge_t *g = &svc->gauges[svc->gauge_count];
    memset(g, 0, sizeof(*g));
    g->metric_id = metric_id;
    g->min_value = INT64_MAX;
    g->max_value = INT64_MIN;
    g->timestamp = time(0);
    svc->gauge_count++;
    return 0;
}

static int register_duration(ozayn_om_service_t *svc, uint64_t metric_id) {
    if (svc->duration_count >= OZAYN_OM_MAX_METRICS) return -1;
    ozayn_om_duration_t *d = &svc->durations[svc->duration_count];
    memset(d, 0, sizeof(*d));
    d->metric_id = metric_id;
    d->min_value = INT64_MAX;
    d->max_value = INT64_MIN;
    d->timestamp = time(0);
    svc->duration_count++;
    return 0;
}

static int register_rate(ozayn_om_service_t *svc, uint64_t metric_id) {
    if (svc->rate_count >= OZAYN_OM_MAX_METRICS) return -1;
    ozayn_om_rate_t *r = &svc->rates[svc->rate_count];
    memset(r, 0, sizeof(*r));
    r->metric_id = metric_id;
    r->timestamp = time(0);
    svc->rate_count++;
    return 0;
}

static int register_ratio(ozayn_om_service_t *svc, uint64_t metric_id) {
    if (svc->ratio_count >= OZAYN_OM_MAX_METRICS) return -1;
    ozayn_om_ratio_t *r = &svc->ratios[svc->ratio_count];
    memset(r, 0, sizeof(*r));
    r->metric_id = metric_id;
    r->timestamp = time(0);
    svc->ratio_count++;
    return 0;
}

const char *ozayn_om_err_name(ozayn_om_err_t e) {
    switch (e) {
        case OZAYN_OM_ERR_OK: return "OK";
        case OZAYN_OM_ERR_NULL_PTR: return "NULL_PTR";
        case OZAYN_OM_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_OM_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_OM_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_OM_ERR_FULL: return "FULL";
        case OZAYN_OM_ERR_DUPLICATE: return "DUPLICATE";
        case OZAYN_OM_ERR_INVALID_TYPE: return "INVALID_TYPE";
        case OZAYN_OM_ERR_INVALID_VALUE: return "INVALID_VALUE";
        case OZAYN_OM_ERR_OVERFLOW: return "OVERFLOW";
        case OZAYN_OM_ERR_STORAGE_ERROR: return "STORAGE_ERROR";
        case OZAYN_OM_ERR_QUERY_INVALID: return "QUERY_INVALID";
        case OZAYN_OM_ERR_QUERY_LIMIT: return "QUERY_LIMIT";
        case OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE: return "SUBSYSTEM_UNAVAILABLE";
        case OZAYN_OM_ERR_CONCURRENCY_ERROR: return "CONCURRENCY_ERROR";
        case OZAYN_OM_ERR_INTERNAL: return "INTERNAL";
    }
    return "UNKNOWN";
}

const char *ozayn_om_metric_type_name(ozayn_om_metric_type_t t) {
    switch (t) {
        case OZAYN_OM_TYPE_COUNTER: return "COUNTER";
        case OZAYN_OM_TYPE_GAUGE: return "GAUGE";
        case OZAYN_OM_TYPE_HISTOGRAM: return "HISTOGRAM";
        case OZAYN_OM_TYPE_DURATION: return "DURATION";
        case OZAYN_OM_TYPE_RATE: return "RATE";
        case OZAYN_OM_TYPE_RATIO: return "RATIO";
    }
    return "UNKNOWN";
}

const char *ozayn_om_category_name(ozayn_om_category_t c) {
    switch (c) {
        case OZAYN_OM_CAT_SYSTEM: return "SYSTEM";
        case OZAYN_OM_CAT_CORE: return "CORE";
        case OZAYN_OM_CAT_COMPONENT: return "COMPONENT";
        case OZAYN_OM_CAT_OPERATION: return "OPERATION";
        case OZAYN_OM_CAT_QUEUE: return "QUEUE";
        case OZAYN_OM_CAT_SCHEDULER: return "SCHEDULER";
        case OZAYN_OM_CAT_WORKFLOW: return "WORKFLOW";
        case OZAYN_OM_CAT_PIPELINE: return "PIPELINE";
        case OZAYN_OM_CAT_EXECUTION: return "EXECUTION";
        case OZAYN_OM_CAT_RESOURCE: return "RESOURCE";
        case OZAYN_OM_CAT_DEVICE: return "DEVICE";
        case OZAYN_OM_CAT_IO: return "IO";
        case OZAYN_OM_CAT_SECURITY: return "SECURITY";
        case OZAYN_OM_CAT_DIAGNOSTIC: return "DIAGNOSTIC";
        case OZAYN_OM_CAT_RECOVERY: return "RECOVERY";
        case OZAYN_OM_CAT_EVENT: return "EVENT";
        case OZAYN_OM_CAT_ERROR: return "ERROR";
        case OZAYN_OM_CAT_STARTUP: return "STARTUP";
        case OZAYN_OM_CAT_SHUTDOWN: return "SHUTDOWN";
    }
    return "UNKNOWN";
}

const char *ozayn_om_unit_name(ozayn_om_unit_t u) {
    switch (u) {
        case OZAYN_OM_UNIT_NONE: return "NONE";
        case OZAYN_OM_UNIT_COUNT: return "COUNT";
        case OZAYN_OM_UNIT_BYTES: return "BYTES";
        case OZAYN_OM_UNIT_US: return "US";
        case OZAYN_OM_UNIT_MS: return "MS";
        case OZAYN_OM_UNIT_SECONDS: return "SECONDS";
        case OZAYN_OM_UNIT_PERCENT: return "PERCENT";
        case OZAYN_OM_UNIT_RATE_PER_SEC: return "RATE_PER_SEC";
    }
    return "UNKNOWN";
}

const char *ozayn_om_scope_name(ozayn_om_scope_t s) {
    switch (s) {
        case OZAYN_OM_SCOPE_GLOBAL: return "GLOBAL";
        case OZAYN_OM_SCOPE_COMPONENT: return "COMPONENT";
        case OZAYN_OM_SCOPE_OPERATION: return "OPERATION";
        case OZAYN_OM_SCOPE_WORKFLOW: return "WORKFLOW";
        case OZAYN_OM_SCOPE_PIPELINE: return "PIPELINE";
    }
    return "UNKNOWN";
}

const char *ozayn_om_collection_status_name(ozayn_om_collection_status_t s) {
    switch (s) {
        case OZAYN_OM_COLLECTED: return "COLLECTED";
        case OZAYN_OM_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_OM_UNSUPPORTED: return "UNSUPPORTED";
        case OZAYN_OM_ERROR: return "ERROR";
    }
    return "UNKNOWN";
}

const char *ozayn_om_threshold_state_name(ozayn_om_threshold_state_t s) {
    switch (s) {
        case OZAYN_OM_THRESH_NORMAL: return "NORMAL";
        case OZAYN_OM_THRESH_ELEVATED: return "ELEVATED";
        case OZAYN_OM_THRESH_HIGH: return "HIGH";
        case OZAYN_OM_THRESH_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

const char *ozayn_om_threshold_type_name(ozayn_om_threshold_type_t t) {
    switch (t) {
        case OZAYN_OM_THRESH_CAPACITY_WARNING: return "CAPACITY_WARNING";
        case OZAYN_OM_THRESH_CAPACITY_CRITICAL: return "CAPACITY_CRITICAL";
        case OZAYN_OM_THRESH_LATENCY_WARNING: return "LATENCY_WARNING";
        case OZAYN_OM_THRESH_LATENCY_CRITICAL: return "LATENCY_CRITICAL";
        case OZAYN_OM_THRESH_EVENT_BACKLOG: return "EVENT_BACKLOG";
        case OZAYN_OM_THRESH_ERROR_RATE: return "ERROR_RATE";
    }
    return "UNKNOWN";
}

const char *ozayn_om_emit_type_name(ozayn_om_emit_type_t t) {
    switch (t) {
        case OZAYN_OM_EMIT_THRESHOLD_REACHED: return "THRESHOLD_REACHED";
        case OZAYN_OM_EMIT_THRESHOLD_CLEARED: return "THRESHOLD_CLEARED";
        case OZAYN_OM_EMIT_CAPACITY_WARNING: return "CAPACITY_WARNING";
        case OZAYN_OM_EMIT_CAPACITY_CRITICAL: return "CAPACITY_CRITICAL";
        case OZAYN_OM_EMIT_LATENCY_WARNING: return "LATENCY_WARNING";
        case OZAYN_OM_EMIT_EVENT_BACKLOG: return "EVENT_BACKLOG";
    }
    return "UNKNOWN";
}

int ozayn_om_init(ozayn_om_service_t *svc) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (svc->initialized) return OZAYN_OM_ERR_ALREADY_INITIALIZED;
    memset(svc, 0, sizeof(*svc));
    svc->initialized = 1;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_shutdown(ozayn_om_service_t *svc) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    svc->initialized = 0;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_is_initialized(const ozayn_om_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

int ozayn_om_bind_subsystems(ozayn_om_service_t *svc, const ozayn_om_subsystem_bind_t *bind) {
    if (!svc || !bind) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    svc->bind = *bind;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_register_metric(ozayn_om_service_t *svc,
                             const char *name,
                             ozayn_om_metric_type_t type,
                             ozayn_om_category_t category,
                             ozayn_om_unit_t unit,
                             ozayn_om_scope_t scope,
                             const char *source_component,
                             uint64_t *out_metric_id) {
    if (!svc || !name) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (svc->metric_count >= OZAYN_OM_MAX_METRICS) return OZAYN_OM_ERR_FULL;

    for (uint64_t i = 0; i < svc->metric_count; i++) {
        if (svc->metrics[i].active && strcmp(svc->metrics[i].name, name) == 0)
            return OZAYN_OM_ERR_DUPLICATE;
    }

    uint64_t id = ++svc->sequence;
    ozayn_om_metric_def_t *def = &svc->metrics[svc->metric_count];
    memset(def, 0, sizeof(*def));
    def->metric_id = id;
    strncpy(def->name, name, OZAYN_OM_MAX_METRIC_NAME - 1);
    def->type = type;
    def->category = category;
    def->unit = unit;
    def->scope = scope;
    def->status = OZAYN_OM_COLLECTED;
    if (source_component) strncpy(def->source_component, source_component, OZAYN_OM_MAX_SOURCE_LEN - 1);
    def->active = 1;
    svc->metric_count++;

    int slot = -1;
    switch (type) {
        case OZAYN_OM_TYPE_COUNTER:
            slot = register_counter(svc, id);
            break;
        case OZAYN_OM_TYPE_GAUGE:
            slot = register_gauge(svc, id);
            break;
        case OZAYN_OM_TYPE_HISTOGRAM:
            if (svc->histogram_count >= OZAYN_OM_MAX_HISTOGRAMS) return OZAYN_OM_ERR_FULL;
            {
                ozayn_om_histogram_t *h = &svc->histograms[svc->histogram_count];
                memset(h, 0, sizeof(*h));
                h->metric_id = id;
                h->min_value = INT64_MAX;
                h->max_value = INT64_MIN;
                h->timestamp = time(0);
                svc->histogram_count++;
                slot = 0;
            }
            break;
        case OZAYN_OM_TYPE_DURATION:
            slot = register_duration(svc, id);
            break;
        case OZAYN_OM_TYPE_RATE:
            slot = register_rate(svc, id);
            break;
        case OZAYN_OM_TYPE_RATIO:
            slot = register_ratio(svc, id);
            break;
    }

    if (slot < 0 && type != OZAYN_OM_TYPE_HISTOGRAM) return OZAYN_OM_ERR_FULL;

    svc->stats.total_metrics_registered++;
    svc->stats.current_metrics = (uint32_t)svc->metric_count;
    if (out_metric_id) *out_metric_id = id;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_unregister_metric(ozayn_om_service_t *svc, uint64_t metric_id) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    ozayn_om_metric_def_t *def = find_metric_def(svc, metric_id);
    if (!def) return OZAYN_OM_ERR_NOT_FOUND;
    def->active = 0;
    svc->stats.current_metrics = (uint32_t)svc->metric_count;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_get_metric_def(const ozayn_om_service_t *svc,
                            uint64_t metric_id,
                            const ozayn_om_metric_def_t **out_def) {
    if (!svc || !out_def) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    const ozayn_om_metric_def_t *def = find_metric_def_const(svc, metric_id);
    if (!def) return OZAYN_OM_ERR_NOT_FOUND;
    *out_def = def;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_get_metric_by_name(const ozayn_om_service_t *svc,
                                const char *name,
                                const ozayn_om_metric_def_t **out_def) {
    if (!svc || !name || !out_def) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_metric_by_name_index(svc, name);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    *out_def = &svc->metrics[idx];
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_counter_increment(ozayn_om_service_t *svc, uint64_t metric_id, int64_t delta) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_counter_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_counter_t *c = &svc->counters[idx];
    c->prev_value = c->value;
    c->value += delta;
    if (c->value < 0) c->value = 0;
    c->timestamp = time(0);
    c->update_count++;
    svc->stats.total_counter_updates++;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_counter_get(const ozayn_om_service_t *svc, uint64_t metric_id, int64_t *out_value) {
    if (!svc || !out_value) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_counter_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    *out_value = svc->counters[idx].value;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_gauge_set(ozayn_om_service_t *svc, uint64_t metric_id, int64_t value) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_gauge_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_gauge_t *g = &svc->gauges[idx];
    g->value = value;
    if (value < g->min_value) g->min_value = value;
    if (value > g->max_value) g->max_value = value;
    g->timestamp = time(0);
    g->update_count++;
    svc->stats.total_gauge_updates++;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_gauge_update(ozayn_om_service_t *svc, uint64_t metric_id, int64_t delta) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_gauge_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_gauge_t *g = &svc->gauges[idx];
    g->value += delta;
    if (g->value < g->min_value) g->min_value = g->value;
    if (g->value > g->max_value) g->max_value = g->value;
    g->timestamp = time(0);
    g->update_count++;
    svc->stats.total_gauge_updates++;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_gauge_get(const ozayn_om_service_t *svc, uint64_t metric_id, int64_t *out_value) {
    if (!svc || !out_value) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_gauge_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    *out_value = svc->gauges[idx].value;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_histogram_create(ozayn_om_service_t *svc,
                              uint64_t metric_id,
                              const int64_t *boundaries,
                              int boundary_count) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (boundary_count <= 0 || boundary_count > OZAYN_OM_MAX_HISTOGRAM_BUCKETS)
        return OZAYN_OM_ERR_INVALID_VALUE;
    int idx = find_histogram_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_histogram_t *h = &svc->histograms[idx];
    h->bucket_count = boundary_count;
    for (int i = 0; i < boundary_count; i++)
        h->boundaries[i] = boundaries[i];
    h->min_value = INT64_MAX;
    h->max_value = INT64_MIN;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_histogram_record(ozayn_om_service_t *svc, uint64_t metric_id, int64_t value) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_histogram_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_histogram_t *h = &svc->histograms[idx];
    if (h->bucket_count == 0) return OZAYN_OM_ERR_INVALID_VALUE;
    int placed = 0;
    for (int i = 0; i < h->bucket_count; i++) {
        if (value <= h->boundaries[i]) {
            h->bucket_counts[i]++;
            placed = 1;
            break;
        }
    }
    if (!placed) h->bucket_counts[h->bucket_count - 1]++;
    h->total_count++;
    h->total_sum += value;
    if (value < h->min_value) h->min_value = value;
    if (value > h->max_value) h->max_value = value;
    h->timestamp = time(0);
    svc->stats.total_histogram_updates++;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_histogram_get(const ozayn_om_service_t *svc,
                           uint64_t metric_id,
                           const uint64_t **out_bucket_counts,
                           int *out_bucket_count,
                           uint64_t *out_total_count,
                           int64_t *out_total_sum) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_histogram_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    const ozayn_om_histogram_t *h = &svc->histograms[idx];
    if (out_bucket_counts) *out_bucket_counts = h->bucket_counts;
    if (out_bucket_count) *out_bucket_count = h->bucket_count;
    if (out_total_count) *out_total_count = h->total_count;
    if (out_total_sum) *out_total_sum = h->total_sum;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_duration_record(ozayn_om_service_t *svc, uint64_t metric_id, int64_t duration_us) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (duration_us < 0) return OZAYN_OM_ERR_INVALID_VALUE;
    int idx = find_duration_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_duration_t *d = &svc->durations[idx];
    d->last_value = d->value;
    d->value = duration_us;
    if (duration_us < d->min_value) d->min_value = duration_us;
    if (duration_us > d->max_value) d->max_value = duration_us;
    d->sample_count++;
    d->timestamp = time(0);
    svc->stats.total_duration_records++;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_duration_get(const ozayn_om_service_t *svc, uint64_t metric_id,
                          int64_t *out_min, int64_t *out_max, uint64_t *out_count) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_duration_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    const ozayn_om_duration_t *d = &svc->durations[idx];
    if (out_min) *out_min = d->min_value;
    if (out_max) *out_max = d->max_value;
    if (out_count) *out_count = d->sample_count;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_rate_update(ozayn_om_service_t *svc, uint64_t metric_id,
                         int64_t numerator, int64_t denominator) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_rate_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_rate_t *r = &svc->rates[idx];
    r->numerator = numerator;
    r->denominator = denominator;
    r->value = denominator > 0 ? (double)numerator / (double)denominator : 0.0;
    r->timestamp = time(0);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_rate_get(const ozayn_om_service_t *svc, uint64_t metric_id, double *out_rate) {
    if (!svc || !out_rate) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_rate_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    *out_rate = svc->rates[idx].value;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_ratio_update(ozayn_om_service_t *svc, uint64_t metric_id,
                          int64_t numerator, int64_t denominator) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_ratio_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    ozayn_om_ratio_t *r = &svc->ratios[idx];
    r->numerator = numerator;
    r->denominator = denominator;
    r->value = denominator > 0 ? (double)numerator / (double)denominator : 0.0;
    r->timestamp = time(0);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_ratio_get(const ozayn_om_service_t *svc, uint64_t metric_id, double *out_ratio) {
    if (!svc || !out_ratio) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    int idx = find_ratio_index(svc, metric_id);
    if (idx < 0) return OZAYN_OM_ERR_NOT_FOUND;
    *out_ratio = svc->ratios[idx].value;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_threshold_register(ozayn_om_service_t *svc,
                                const char *metric_name,
                                ozayn_om_threshold_type_t type,
                                ozayn_om_category_t category,
                                int64_t warning_threshold,
                                int64_t critical_threshold) {
    if (!svc || !metric_name) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (svc->threshold_count >= OZAYN_OM_MAX_THRESHOLDS) return OZAYN_OM_ERR_FULL;

    for (uint64_t i = 0; i < svc->threshold_count; i++) {
        if (svc->thresholds[i].active && strcmp(svc->thresholds[i].name, metric_name) == 0)
            return OZAYN_OM_ERR_DUPLICATE;
    }

    ozayn_om_threshold_t *t = &svc->thresholds[svc->threshold_count];
    memset(t, 0, sizeof(*t));
    strncpy(t->name, metric_name, OZAYN_OM_MAX_METRIC_NAME - 1);
    t->type = type;
    t->category = category;
    t->warning_threshold = warning_threshold;
    t->critical_threshold = critical_threshold;
    t->current_state = OZAYN_OM_THRESH_NORMAL;
    t->active = 1;
    svc->threshold_count++;
    svc->stats.current_thresholds = (uint32_t)svc->threshold_count;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_threshold_evaluate(ozayn_om_service_t *svc,
                                const char *metric_name,
                                int64_t current_value,
                                ozayn_om_threshold_state_t *out_state) {
    if (!svc || !metric_name || !out_state) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;

    ozayn_om_threshold_t *t = 0;
    for (uint64_t i = 0; i < svc->threshold_count; i++) {
        if (svc->thresholds[i].active && strcmp(svc->thresholds[i].name, metric_name) == 0) {
            t = &svc->thresholds[i];
            break;
        }
    }
    if (!t) return OZAYN_OM_ERR_NOT_FOUND;

    ozayn_om_threshold_state_t prev = t->current_state;

    if (current_value >= t->critical_threshold)
        t->current_state = OZAYN_OM_THRESH_CRITICAL;
    else if (current_value >= t->warning_threshold)
        t->current_state = OZAYN_OM_THRESH_HIGH;
    else if (current_value > 0)
        t->current_state = OZAYN_OM_THRESH_ELEVATED;
    else
        t->current_state = OZAYN_OM_THRESH_NORMAL;

    *out_state = t->current_state;
    svc->stats.total_threshold_checks++;

    if (t->current_state != OZAYN_OM_THRESH_NORMAL && prev == OZAYN_OM_THRESH_NORMAL) {
        svc->stats.total_threshold_breaches++;
        uint64_t alert_id = ++svc->sequence;
        ozayn_om_alert_t *alert = &svc->alerts[svc->alert_head % OZAYN_OM_MAX_METRICS];
        memset(alert, 0, sizeof(*alert));
        alert->event_id = alert_id;
        alert->type = t->current_state >= OZAYN_OM_THRESH_CRITICAL ?
            OZAYN_OM_EMIT_CAPACITY_CRITICAL : OZAYN_OM_EMIT_LATENCY_WARNING;
        strncpy(alert->metric_name, metric_name, OZAYN_OM_MAX_METRIC_NAME - 1);
        alert->threshold_state = t->current_state;
        alert->current_value = current_value;
        alert->threshold_value = t->current_state >= OZAYN_OM_THRESH_CRITICAL ?
            t->critical_threshold : t->warning_threshold;
        alert->timestamp = time(0);
        alert->active = 1;
        svc->alert_head++;
        svc->alert_count++;
        svc->stats.total_alerts_emitted++;
        svc->stats.current_alerts = (uint32_t)(svc->alert_count < OZAYN_OM_MAX_METRICS ?
            svc->alert_count : OZAYN_OM_MAX_METRICS);
    } else if (t->current_state == OZAYN_OM_THRESH_NORMAL && prev != OZAYN_OM_THRESH_NORMAL) {
        uint64_t alert_id = ++svc->sequence;
        ozayn_om_alert_t *alert = &svc->alerts[svc->alert_head % OZAYN_OM_MAX_METRICS];
        memset(alert, 0, sizeof(*alert));
        alert->event_id = alert_id;
        alert->type = OZAYN_OM_EMIT_THRESHOLD_CLEARED;
        strncpy(alert->metric_name, metric_name, OZAYN_OM_MAX_METRIC_NAME - 1);
        alert->threshold_state = OZAYN_OM_THRESH_NORMAL;
        alert->current_value = current_value;
        alert->timestamp = time(0);
        alert->active = 1;
        svc->alert_head++;
        svc->alert_count++;
        svc->stats.total_alerts_emitted++;
    }

    return OZAYN_OM_ERR_OK;
}

int ozayn_om_threshold_get_state(const ozayn_om_service_t *svc,
                                 const char *metric_name,
                                 ozayn_om_threshold_state_t *out_state) {
    if (!svc || !metric_name || !out_state) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    for (uint64_t i = 0; i < svc->threshold_count; i++) {
        if (svc->thresholds[i].active && strcmp(svc->thresholds[i].name, metric_name) == 0) {
            *out_state = svc->thresholds[i].current_state;
            return OZAYN_OM_ERR_OK;
        }
    }
    return OZAYN_OM_ERR_NOT_FOUND;
}

int ozayn_om_alert_get(const ozayn_om_service_t *svc,
                       uint64_t event_id,
                       const ozayn_om_alert_t **out_alert) {
    if (!svc || !out_alert) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    uint64_t count = svc->alert_count < OZAYN_OM_MAX_METRICS ? svc->alert_count : OZAYN_OM_MAX_METRICS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->alert_head - 1 - i + OZAYN_OM_MAX_METRICS) % OZAYN_OM_MAX_METRICS;
        if (svc->alerts[idx].active && svc->alerts[idx].event_id == event_id) {
            *out_alert = &svc->alerts[idx];
            return OZAYN_OM_ERR_OK;
        }
    }
    return OZAYN_OM_ERR_NOT_FOUND;
}

int ozayn_om_alert_get_recent(const ozayn_om_service_t *svc,
                              uint64_t count,
                              const ozayn_om_alert_t **out_alerts,
                              uint64_t *out_count) {
    if (!svc || !out_alerts || !out_count) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    uint64_t cnt = 0;
    uint64_t avail = svc->alert_count < OZAYN_OM_MAX_METRICS ? svc->alert_count : OZAYN_OM_MAX_METRICS;
    uint64_t limit = count < avail ? count : avail;
    for (uint64_t i = 0; i < limit; i++) {
        uint64_t idx = (svc->alert_head - 1 - i + OZAYN_OM_MAX_METRICS) % OZAYN_OM_MAX_METRICS;
        if (svc->alerts[idx].active)
            out_alerts[cnt++] = &svc->alerts[idx];
    }
    *out_count = cnt;
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_snapshot_create(ozayn_om_service_t *svc, uint64_t *out_snapshot_id) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (svc->snapshot_count >= OZAYN_OM_MAX_SNAPSHOTS) {
        svc->snapshot_head++;
    } else {
        svc->snapshot_count++;
    }
    uint64_t pos = svc->snapshot_head % OZAYN_OM_MAX_SNAPSHOTS;
    ozayn_om_snapshot_t *snap = &svc->snapshots[pos];
    memset(snap, 0, sizeof(*snap));
    snap->snapshot_id = ++svc->sequence;
    snap->timestamp = time(0);
    snap->active = 1;
    if (out_snapshot_id) *out_snapshot_id = snap->snapshot_id;
    svc->snapshot_head++;
    svc->stats.total_snapshots_created++;
    svc->stats.current_snapshots = (uint32_t)(svc->snapshot_count < OZAYN_OM_MAX_SNAPSHOTS ?
        svc->snapshot_count : OZAYN_OM_MAX_SNAPSHOTS);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_snapshot_get(const ozayn_om_service_t *svc,
                          uint64_t snapshot_id,
                          const ozayn_om_snapshot_t **out_snapshot) {
    if (!svc || !out_snapshot) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    uint64_t count = svc->snapshot_count < OZAYN_OM_MAX_SNAPSHOTS ? svc->snapshot_count : OZAYN_OM_MAX_SNAPSHOTS;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t idx = (svc->snapshot_head - 1 - i + OZAYN_OM_MAX_SNAPSHOTS) % OZAYN_OM_MAX_SNAPSHOTS;
        if (svc->snapshots[idx].active && svc->snapshots[idx].snapshot_id == snapshot_id) {
            *out_snapshot = &svc->snapshots[idx];
            return OZAYN_OM_ERR_OK;
        }
    }
    return OZAYN_OM_ERR_NOT_FOUND;
}

int ozayn_om_snapshot_get_latest(const ozayn_om_service_t *svc,
                                 const ozayn_om_snapshot_t **out_snapshot) {
    if (!svc || !out_snapshot) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (svc->snapshot_count == 0) return OZAYN_OM_ERR_NOT_FOUND;
    uint64_t idx = (svc->snapshot_head - 1 + OZAYN_OM_MAX_SNAPSHOTS) % OZAYN_OM_MAX_SNAPSHOTS;
    *out_snapshot = &svc->snapshots[idx];
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_snapshot_collect(ozayn_om_service_t *svc, uint64_t *out_snapshot_id) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    uint64_t snap_id = 0;
    int rc = ozayn_om_snapshot_create(svc, &snap_id);
    if (rc != OZAYN_OM_ERR_OK) return rc;
    ozayn_om_snapshot_t *snap = 0;
    for (uint64_t i = 0; i < svc->snapshot_count; i++) {
        uint64_t idx = (svc->snapshot_head - 1 - i + OZAYN_OM_MAX_SNAPSHOTS) % OZAYN_OM_MAX_SNAPSHOTS;
        if (svc->snapshots[idx].active && svc->snapshots[idx].snapshot_id == snap_id) {
            snap = &svc->snapshots[idx];
            break;
        }
    }
    if (!snap) return OZAYN_OM_ERR_INTERNAL;
    ozayn_om_collect_all(svc);
    if (svc->bind.operation_queue) {
        ozayn_oq_service_t *q = (ozayn_oq_service_t *)svc->bind.operation_queue;
        snap->queued_operations = (uint32_t)ozayn_oq_total_submitted(q) -
            (uint32_t)(ozayn_oq_total_succeeded(q) + ozayn_oq_total_failed(q) +
             ozayn_oq_total_cancelled(q) + ozayn_oq_total_timeouts(q));
    }
    if (out_snapshot_id) *out_snapshot_id = snap_id;
    return OZAYN_OM_ERR_OK;
}

static int64_t get_counter_val(const ozayn_om_service_t *svc, const char *name) {
    int idx = find_metric_by_name_index(svc, name);
    if (idx < 0) return 0;
    int cidx = find_counter_index(svc, svc->metrics[idx].metric_id);
    if (cidx < 0) return 0;
    return svc->counters[cidx].value;
}

int ozayn_om_collect_all(ozayn_om_service_t *svc) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    ozayn_om_collect_operation_metrics(svc);
    ozayn_om_collect_queue_metrics(svc);
    ozayn_om_collect_scheduler_metrics(svc);
    ozayn_om_collect_workflow_metrics(svc);
    ozayn_om_collect_pipeline_metrics(svc);
    ozayn_om_collect_execution_metrics(svc);
    ozayn_om_collect_failure_metrics(svc);
    ozayn_om_collect_resource_metrics(svc);
    ozayn_om_collect_event_metrics(svc);
    ozayn_om_collect_admission_metrics(svc);
    ozayn_om_collect_enforcement_metrics(svc);
    ozayn_om_collect_diagnostic_metrics(svc);
    ozayn_om_collect_recovery_metrics(svc);
    ozayn_om_collect_health_metrics(svc);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_operation_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.operation_history) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_oh_service_t *oh = (ozayn_oh_service_t *)svc->bind.operation_history;
    ozayn_oh_stats_t st;
    if (ozayn_oh_get_stats(oh, &st) != OZAYN_OH_OK) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "ops_received", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_recorded - get_counter_val(svc, "ops_received"));
    if (ozayn_om_get_metric_by_name(svc, "ops_succeeded", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_succeeded - get_counter_val(svc, "ops_succeeded"));
    if (ozayn_om_get_metric_by_name(svc, "ops_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_failed - get_counter_val(svc, "ops_failed"));
    if (ozayn_om_get_metric_by_name(svc, "ops_cancelled", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_cancelled - get_counter_val(svc, "ops_cancelled"));
    if (ozayn_om_get_metric_by_name(svc, "ops_timeout", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_timeout - get_counter_val(svc, "ops_timeout"));
    if (ozayn_om_get_metric_by_name(svc, "ops_rejected", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_rejected - get_counter_val(svc, "ops_rejected"));
    if (ozayn_om_get_metric_by_name(svc, "ops_expired", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_expired - get_counter_val(svc, "ops_expired"));
    if (ozayn_om_get_metric_by_name(svc, "ops_retries", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_retries - get_counter_val(svc, "ops_retries"));
    if (ozayn_om_get_metric_by_name(svc, "ops_current", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_count);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_queue_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.operation_queue) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_oq_service_t *q = (ozayn_oq_service_t *)svc->bind.operation_queue;
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "queue_submitted", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_submitted(q) - get_counter_val(svc, "queue_submitted"));
    if (ozayn_om_get_metric_by_name(svc, "queue_succeeded", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_succeeded(q) - get_counter_val(svc, "queue_succeeded"));
    if (ozayn_om_get_metric_by_name(svc, "queue_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_failed(q) - get_counter_val(svc, "queue_failed"));
    if (ozayn_om_get_metric_by_name(svc, "queue_rejected", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_rejected(q) - get_counter_val(svc, "queue_rejected"));
    if (ozayn_om_get_metric_by_name(svc, "queue_cancelled", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_cancelled(q) - get_counter_val(svc, "queue_cancelled"));
    if (ozayn_om_get_metric_by_name(svc, "queue_timeouts", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_timeouts(q) - get_counter_val(svc, "queue_timeouts"));
    if (ozayn_om_get_metric_by_name(svc, "queue_expired", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_expired(q) - get_counter_val(svc, "queue_expired"));
    if (ozayn_om_get_metric_by_name(svc, "queue_duplicates", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)ozayn_oq_total_duplicates(q) - get_counter_val(svc, "queue_duplicates"));
    if (ozayn_om_get_metric_by_name(svc, "queue_conflicts", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)q->total_conflicts - get_counter_val(svc, "queue_conflicts"));
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_scheduler_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.pipeline_scheduler) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_spa_service_t *sp = (ozayn_spa_service_t *)svc->bind.pipeline_scheduler;
    ozayn_spa_stats_t st = ozayn_spa_get_stats(sp);
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "sched_submitted", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_submitted - get_counter_val(svc, "sched_submitted"));
    if (ozayn_om_get_metric_by_name(svc, "sched_scheduled", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_scheduled - get_counter_val(svc, "sched_scheduled"));
    if (ozayn_om_get_metric_by_name(svc, "sched_completed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_completed - get_counter_val(svc, "sched_completed"));
    if (ozayn_om_get_metric_by_name(svc, "sched_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_failed - get_counter_val(svc, "sched_failed"));
    if (ozayn_om_get_metric_by_name(svc, "sched_deferred", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_deferred - get_counter_val(svc, "sched_deferred"));
    if (ozayn_om_get_metric_by_name(svc, "sched_rejected", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_rejected - get_counter_val(svc, "sched_rejected"));
    if (ozayn_om_get_metric_by_name(svc, "sched_resource_conflicts", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_resource_conflicts - get_counter_val(svc, "sched_resource_conflicts"));
    if (ozayn_om_get_metric_by_name(svc, "sched_pipeline_conflicts", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_pipeline_conflicts - get_counter_val(svc, "sched_pipeline_conflicts"));
    if (ozayn_om_get_metric_by_name(svc, "sched_dependency_waits", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_dependency_waits - get_counter_val(svc, "sched_dependency_waits"));
    if (ozayn_om_get_metric_by_name(svc, "sched_queue_depth", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_queued);
    if (ozayn_om_get_metric_by_name(svc, "sched_running", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_running);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_workflow_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.workflow_orchestrator) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_wof_service_t *wf = (ozayn_wof_service_t *)svc->bind.workflow_orchestrator;
    const ozayn_wof_stats_t *st = ozayn_wof_get_stats(wf);
    if (!st) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "wf_created", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_workflows_created - get_counter_val(svc, "wf_created"));
    if (ozayn_om_get_metric_by_name(svc, "wf_succeeded", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_workflows_succeeded - get_counter_val(svc, "wf_succeeded"));
    if (ozayn_om_get_metric_by_name(svc, "wf_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_workflows_failed - get_counter_val(svc, "wf_failed"));
    if (ozayn_om_get_metric_by_name(svc, "wf_cancelled", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_workflows_cancelled - get_counter_val(svc, "wf_cancelled"));
    if (ozayn_om_get_metric_by_name(svc, "wf_expired", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_workflows_expired - get_counter_val(svc, "wf_expired"));
    if (ozayn_om_get_metric_by_name(svc, "wf_active", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st->active_workflows);
    if (ozayn_om_get_metric_by_name(svc, "wf_stages_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_stages_failed - get_counter_val(svc, "wf_stages_failed"));
    if (ozayn_om_get_metric_by_name(svc, "wf_dependency_cycles", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_dependency_cycles_detected - get_counter_val(svc, "wf_dependency_cycles"));
    if (ozayn_om_get_metric_by_name(svc, "wf_retries", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_retries - get_counter_val(svc, "wf_retries"));
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_pipeline_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.pipeline_coordinator) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_pco_service_t *pc = (ozayn_pco_service_t *)svc->bind.pipeline_coordinator;
    ozayn_pco_stats_t st;
    if (ozayn_pco_get_stats(pc, &st) != OZAYN_PCO_OK) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "pipe_created", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_pipelines_created - get_counter_val(svc, "pipe_created"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_started", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_pipelines_started - get_counter_val(svc, "pipe_started"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_pipelines_failed - get_counter_val(svc, "pipe_failed"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_stopped", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_pipelines_stopped - get_counter_val(svc, "pipe_stopped"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_expired", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_pipelines_expired - get_counter_val(svc, "pipe_expired"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_backpressure", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_backpressure_events - get_counter_val(svc, "pipe_backpressure"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_stages_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_stages_failed - get_counter_val(svc, "pipe_stages_failed"));
    if (ozayn_om_get_metric_by_name(svc, "pipe_active", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_active_pipelines);
    if (ozayn_om_get_metric_by_name(svc, "pipe_stages_active", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_stages_active);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_execution_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.execution_result) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_xr_service_t *xr = (ozayn_xr_service_t *)svc->bind.execution_result;
    ozayn_xr_stats_t st;
    if (ozayn_xr_stats_get(xr, &st) != OZAYN_XR_ERR_OK) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "exec_received", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_results_received - get_counter_val(svc, "exec_received"));
    if (ozayn_om_get_metric_by_name(svc, "exec_succeeded", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_succeeded - get_counter_val(svc, "exec_succeeded"));
    if (ozayn_om_get_metric_by_name(svc, "exec_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_failed - get_counter_val(svc, "exec_failed"));
    if (ozayn_om_get_metric_by_name(svc, "exec_partial", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_partial - get_counter_val(svc, "exec_partial"));
    if (ozayn_om_get_metric_by_name(svc, "exec_cancelled", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_cancelled - get_counter_val(svc, "exec_cancelled"));
    if (ozayn_om_get_metric_by_name(svc, "exec_timeout", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_timeout - get_counter_val(svc, "exec_timeout"));
    if (ozayn_om_get_metric_by_name(svc, "exec_reconciliations", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_reconciliations - get_counter_val(svc, "exec_reconciliations"));
    if (ozayn_om_get_metric_by_name(svc, "exec_consistent", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_consistent - get_counter_val(svc, "exec_consistent"));
    if (ozayn_om_get_metric_by_name(svc, "exec_inconsistent", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_inconsistent - get_counter_val(svc, "exec_inconsistent"));
    if (ozayn_om_get_metric_by_name(svc, "exec_pending", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_pending);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_failure_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.workflow_recovery) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_wfr_service_t *wfr = (ozayn_wfr_service_t *)svc->bind.workflow_recovery;
    const ozayn_wfr_stats_t *st = ozayn_wfr_get_stats(wfr);
    if (!st) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "fail_detected", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_failures_detected - get_counter_val(svc, "fail_detected"));
    if (ozayn_om_get_metric_by_name(svc, "fail_classified", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_failures_classified - get_counter_val(svc, "fail_classified"));
    if (ozayn_om_get_metric_by_name(svc, "fail_contained", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_failures_contained - get_counter_val(svc, "fail_contained"));
    if (ozayn_om_get_metric_by_name(svc, "fail_recovered", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_failures_recovered - get_counter_val(svc, "fail_recovered"));
    if (ozayn_om_get_metric_by_name(svc, "fail_escalated", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_failures_escalated - get_counter_val(svc, "fail_escalated"));
    if (ozayn_om_get_metric_by_name(svc, "fail_unrecoverable", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_failures_unrecoverable - get_counter_val(svc, "fail_unrecoverable"));
    if (ozayn_om_get_metric_by_name(svc, "fail_retries", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_retries - get_counter_val(svc, "fail_retries"));
    if (ozayn_om_get_metric_by_name(svc, "fail_active", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st->active_failures);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_resource_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.resource_manager) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_rcm_service_t *rm = (ozayn_rcm_service_t *)svc->bind.resource_manager;
    ozayn_rcm_stats_t st;
    if (ozayn_rcm_get_stats(rm, &st) != OZAYN_RCM_OK) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "res_registered", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_resources_registered - get_counter_val(svc, "res_registered"));
    if (ozayn_om_get_metric_by_name(svc, "res_available", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_available - get_counter_val(svc, "res_available"));
    if (ozayn_om_get_metric_by_name(svc, "res_insufficient", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_insufficient - get_counter_val(svc, "res_insufficient"));
    if (ozayn_om_get_metric_by_name(svc, "res_unavailable", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_unavailable - get_counter_val(svc, "res_unavailable"));
    if (ozayn_om_get_metric_by_name(svc, "res_reservations", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_reservations_created - get_counter_val(svc, "res_reservations"));
    if (ozayn_om_get_metric_by_name(svc, "res_reservation_fails", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_reservations_failed - get_counter_val(svc, "res_reservation_fails"));
    if (ozayn_om_get_metric_by_name(svc, "res_active", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_active_reservations);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_event_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.operational_timeline) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_otl_service_t *otl = (ozayn_otl_service_t *)svc->bind.operational_timeline;
    ozayn_otl_stats_t st;
    if (ozayn_otl_stats_get(otl, &st) != OZAYN_OTL_ERR_OK) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "evt_ingested", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_events_ingested - get_counter_val(svc, "evt_ingested"));
    if (ozayn_om_get_metric_by_name(svc, "evt_correlated", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_correlations_formed - get_counter_val(svc, "evt_correlated"));
    if (ozayn_om_get_metric_by_name(svc, "evt_duplicates", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_duplicates_detected - get_counter_val(svc, "evt_duplicates"));
    if (ozayn_om_get_metric_by_name(svc, "evt_out_of_order", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_out_of_order - get_counter_val(svc, "evt_out_of_order"));
    if (ozayn_om_get_metric_by_name(svc, "evt_late", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_late_arrivals - get_counter_val(svc, "evt_late"));
    if (ozayn_om_get_metric_by_name(svc, "evt_stored", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_events_stored);
    if (ozayn_om_get_metric_by_name(svc, "evt_active_timelines", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_active_timelines);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_admission_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.runtime_admission_gate) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_rag_service_t *rag = (ozayn_rag_service_t *)svc->bind.runtime_admission_gate;
    const ozayn_rag_stats_t *st = ozayn_rag_get_stats(rag);
    if (!st) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "adm_requests", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_requests - get_counter_val(svc, "adm_requests"));
    if (ozayn_om_get_metric_by_name(svc, "adm_accepted", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_accepted - get_counter_val(svc, "adm_accepted"));
    if (ozayn_om_get_metric_by_name(svc, "adm_queued", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_queued - get_counter_val(svc, "adm_queued"));
    if (ozayn_om_get_metric_by_name(svc, "adm_deferred", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_deferred - get_counter_val(svc, "adm_deferred"));
    if (ozayn_om_get_metric_by_name(svc, "adm_denied", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_denied - get_counter_val(svc, "adm_denied"));
    if (ozayn_om_get_metric_by_name(svc, "adm_blocked", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_blocked - get_counter_val(svc, "adm_blocked"));
    if (ozayn_om_get_metric_by_name(svc, "adm_expired", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_expired - get_counter_val(svc, "adm_expired"));
    if (ozayn_om_get_metric_by_name(svc, "adm_reassessments", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_reassessments - get_counter_val(svc, "adm_reassessments"));
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_enforcement_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.runtime_enforcement) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_roe_service_t *roe = (ozayn_roe_service_t *)svc->bind.runtime_enforcement;
    const ozayn_roe_stats_t *st = ozayn_roe_get_stats(roe);
    if (!st) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "enf_requests", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_requests - get_counter_val(svc, "enf_requests"));
    if (ozayn_om_get_metric_by_name(svc, "enf_approved", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_approved - get_counter_val(svc, "enf_approved"));
    if (ozayn_om_get_metric_by_name(svc, "enf_blocked", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_blocked - get_counter_val(svc, "enf_blocked"));
    if (ozayn_om_get_metric_by_name(svc, "enf_reassessments", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_reassessments - get_counter_val(svc, "enf_reassessments"));
    if (ozayn_om_get_metric_by_name(svc, "enf_duplicates_blocked", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_duplicates_blocked - get_counter_val(svc, "enf_duplicates_blocked"));
    if (ozayn_om_get_metric_by_name(svc, "enf_dispatches", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->total_dispatches - get_counter_val(svc, "enf_dispatches"));
    if (ozayn_om_get_metric_by_name(svc, "enf_mode_blocks", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->mode_blocks - get_counter_val(svc, "enf_mode_blocks"));
    if (ozayn_om_get_metric_by_name(svc, "enf_security_blocks", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->security_blocks - get_counter_val(svc, "enf_security_blocks"));
    if (ozayn_om_get_metric_by_name(svc, "enf_safety_blocks", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->safety_blocks - get_counter_val(svc, "enf_safety_blocks"));
    if (ozayn_om_get_metric_by_name(svc, "enf_resource_blocks", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st->resource_blocks - get_counter_val(svc, "enf_resource_blocks"));
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_diagnostic_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.diagnostics) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    ozayn_dha_service_t *dha = (ozayn_dha_service_t *)svc->bind.diagnostics;
    ozayn_dha_stats_t st;
    if (ozayn_dha_get_stats(dha, &st) != OZAYN_DHA_OK) { svc->stats.total_collection_failures++; return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE; }
    const ozayn_om_metric_def_t *d;
    if (ozayn_om_get_metric_by_name(svc, "diag_requests", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_requests - get_counter_val(svc, "diag_requests"));
    if (ozayn_om_get_metric_by_name(svc, "diag_succeeded", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_succeeded - get_counter_val(svc, "diag_succeeded"));
    if (ozayn_om_get_metric_by_name(svc, "diag_failed", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_failed - get_counter_val(svc, "diag_failed"));
    if (ozayn_om_get_metric_by_name(svc, "diag_health_changes", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_counter_increment(svc, d->metric_id, (int64_t)st.total_health_changed - get_counter_val(svc, "diag_health_changes"));
    if (ozayn_om_get_metric_by_name(svc, "diag_active", &d) == OZAYN_OM_ERR_OK)
        ozayn_om_gauge_set(svc, d->metric_id, (int64_t)st.current_requests);
    return OZAYN_OM_ERR_OK;
}

int ozayn_om_collect_recovery_metrics(ozayn_om_service_t *svc) {
    return ozayn_om_collect_failure_metrics(svc);
}

int ozayn_om_collect_health_metrics(ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->bind.diagnostics) return OZAYN_OM_ERR_SUBSYSTEM_UNAVAILABLE;
    return OZAYN_OM_ERR_OK;
}

ozayn_om_stats_t ozayn_om_get_stats(const ozayn_om_service_t *svc) {
    if (!svc) { ozayn_om_stats_t z; memset(&z, 0, sizeof(z)); return z; }
    return svc->stats;
}

int64_t ozayn_om_metric_count(const ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->metric_count;
}

int64_t ozayn_om_snapshot_count(const ozayn_om_service_t *svc) {
    if (!svc || !svc->initialized) return -1;
    return (int64_t)svc->snapshot_count;
}

int ozayn_om_shutdown_drain(ozayn_om_service_t *svc,
                            uint64_t *out_pending_metrics,
                            uint64_t *out_pending_snapshots) {
    if (!svc) return OZAYN_OM_ERR_NULL_PTR;
    if (!svc->initialized) return OZAYN_OM_ERR_NOT_INITIALIZED;
    if (out_pending_metrics) *out_pending_metrics = svc->metric_count;
    if (out_pending_snapshots) *out_pending_snapshots = svc->snapshot_count;
    return OZAYN_OM_ERR_OK;
}
