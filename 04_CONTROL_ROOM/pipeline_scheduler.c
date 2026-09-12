#include "pipeline_scheduler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * STATIC GLOBAL
 * ============================================================ */

static ozayn_spa_service_t _global_svc;

/* ============================================================
 * TRANSITION MATRIX
 * ============================================================ */

static const int _transitions[OZAYN_SPA_SCHED_STATE_COUNT][OZAYN_SPA_SCHED_STATE_COUNT] = {
/*                         CR  QU  WA  EL  SC  RS  ST  RU  PA  DR  CO  FA  CA  EX  RE  UN */
/* CREATED           */ {  0,  1,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  0,  1,  0 },
/* QUEUED            */ {  0,  0,  1,  1,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  0,  0 },
/* WAITING           */ {  0,  0,  0,  1,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  0,  0 },
/* ELIGIBLE          */ {  0,  0,  1,  0,  1,  0,  0,  0,  0,  0,  0,  1,  1,  1,  0,  0 },
/* SCHEDULED         */ {  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0 },
/* RESERVED          */ {  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  0,  1,  1,  0,  0,  0 },
/* STARTING          */ {  0,  0,  0,  0,  0,  0,  0,  1,  0,  0,  0,  1,  0,  0,  0,  0 },
/* RUNNING           */ {  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  1,  0,  0,  0,  0 },
/* PAUSED            */ {  0,  0,  0,  0,  0,  0,  0,  1,  0,  1,  1,  1,  0,  0,  0,  0 },
/* DRAINING          */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  0,  0,  0,  0 },
/* COMPLETED         */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
/* FAILED            */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
/* CANCELLED         */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
/* EXPIRED           */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
/* REJECTED          */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
/* UNAVAILABLE       */ {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
};

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static ozayn_spa_entry_t *_find_entry(ozayn_spa_service_t *svc, const char *entry_id) {
    if (!svc || !entry_id) return NULL;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active &&
            strcmp(svc->entries[i].entry_id, entry_id) == 0) {
            return &svc->entries[i];
        }
    }
    return NULL;
}

static ozayn_spa_entry_t *_find_entry_by_pipeline(ozayn_spa_service_t *svc,
                                                   const char *pipeline_id) {
    if (!svc || !pipeline_id) return NULL;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active &&
            strcmp(svc->entries[i].pipeline_id, pipeline_id) == 0) {
            return &svc->entries[i];
        }
    }
    return NULL;
}

static int _find_free_slot(const ozayn_spa_service_t *svc) {
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (!svc->entries[i].active) return i;
    }
    return -1;
}

static int _find_free_event_slot(const ozayn_spa_service_t *svc) {
    if (svc->event_count < OZAYN_SPA_MAX_EVENTS) {
        return (svc->event_head + svc->event_count) % OZAYN_SPA_MAX_EVENTS;
    }
    return svc->event_head;
}

static int _find_free_decision_slot(const ozayn_spa_service_t *svc) {
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (!svc->decisions[i].active) return i;
    }
    return -1;
}

static void _emit_event(ozayn_spa_service_t *svc,
                        ozayn_spa_event_type_t type,
                        const char *entry_id,
                        const char *pipeline_id,
                        const char *message) {
    if (!svc) return;
    int idx = _find_free_event_slot(svc);
    if (svc->event_count >= OZAYN_SPA_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_SPA_MAX_EVENTS;
    } else {
        svc->event_count++;
    }
    memset(&svc->events[idx], 0, sizeof(ozayn_spa_event_t));
    svc->events[idx].type = type;
    svc->events[idx].timestamp = time(NULL);
    svc->events[idx].sequence = svc->event_sequence++;
    if (entry_id)
        strncpy(svc->events[idx].entry_id, entry_id, OZAYN_SPA_MAX_ID_LEN - 1);
    if (pipeline_id)
        strncpy(svc->events[idx].pipeline_id, pipeline_id, OZAYN_SPA_MAX_ID_LEN - 1);
    if (message)
        strncpy(svc->events[idx].message, message, OZAYN_SPA_MAX_METADATA_LEN - 1);
}

static void _record_decision(ozayn_spa_service_t *svc,
                             ozayn_spa_entry_t *entry,
                             ozayn_spa_decision_t decision,
                             ozayn_spa_wait_reason_t wait_reason,
                             ozayn_spa_close_reason_t close_reason,
                             const char *reason) {
    if (!svc || !entry) return;
    int idx = _find_free_decision_slot(svc);
    if (idx < 0) return;
    memset(&svc->decisions[idx], 0, sizeof(ozayn_spa_decision_record_t));
    svc->decisions[idx].active = 1;
    svc->decision_count++;
    svc->decisions[idx].decision = decision;
    svc->decisions[idx].priority = entry->priority;
    svc->decisions[idx].wait_reason = wait_reason;
    svc->decisions[idx].close_reason = close_reason;
    svc->decisions[idx].decision_time = time(NULL);
    svc->decisions[idx].eligibility_ok = (decision == OZAYN_SPA_DECISION_SCHEDULE);
    svc->decisions[idx].resource_ok = (decision != OZAYN_SPA_DECISION_UNAVAILABLE);
    svc->decisions[idx].conflict_detected = (wait_reason == OZAYN_SPA_WAIT_CONFLICT);
    svc->decisions[idx].dependency_ok = (wait_reason != OZAYN_SPA_WAIT_DEPENDENCY);
    svc->decisions[idx].authorization_ok = (wait_reason != OZAYN_SPA_WAIT_AUTHORIZATION);
    svc->decisions[idx].safety_ok = (wait_reason != OZAYN_SPA_WAIT_SAFETY);
    strncpy(svc->decisions[idx].entry_id, entry->entry_id, OZAYN_SPA_MAX_ID_LEN - 1);
    strncpy(svc->decisions[idx].pipeline_id, entry->pipeline_id, OZAYN_SPA_MAX_ID_LEN - 1);
    strncpy(svc->decisions[idx].operation_id, entry->operation_id, OZAYN_SPA_MAX_ID_LEN - 1);
    if (reason)
        strncpy(svc->decisions[idx].reject_reason, reason, OZAYN_SPA_MAX_METADATA_LEN - 1);
    char did[OZAYN_SPA_MAX_ID_LEN];
    snprintf(did, sizeof(did), "dec-%lu", (unsigned long)svc->decision_sequence);
    svc->decision_sequence++;
    strncpy(svc->decisions[idx].decision_id, did, OZAYN_SPA_MAX_ID_LEN - 1);
}

static int _is_terminal(ozayn_spa_sched_state_t s) {
    return s == OZAYN_SPA_SCHED_COMPLETED ||
           s == OZAYN_SPA_SCHED_FAILED ||
           s == OZAYN_SPA_SCHED_CANCELLED ||
           s == OZAYN_SPA_SCHED_EXPIRED ||
           s == OZAYN_SPA_SCHED_REJECTED ||
           s == OZAYN_SPA_SCHED_UNAVAILABLE;
}

static int _count_by_state(const ozayn_spa_service_t *svc, ozayn_spa_sched_state_t state) {
    int c = 0;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active && svc->entries[i].state == state) c++;
    }
    return c;
}

static int _count_non_terminal(const ozayn_spa_service_t *svc) {
    int c = 0;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active && !_is_terminal(svc->entries[i].state)) c++;
    }
    return c;
}

static void _update_stats(ozayn_spa_service_t *svc) {
    svc->stats.current_queued = _count_by_state(svc, OZAYN_SPA_SCHED_QUEUED);
    svc->stats.current_waiting = _count_by_state(svc, OZAYN_SPA_SCHED_WAITING);
    svc->stats.current_eligible = _count_by_state(svc, OZAYN_SPA_SCHED_ELIGIBLE);
    svc->stats.current_scheduled = _count_by_state(svc, OZAYN_SPA_SCHED_SCHEDULED);
    svc->stats.current_running = _count_by_state(svc, OZAYN_SPA_SCHED_RUNNING);
    svc->stats.current_paused = _count_by_state(svc, OZAYN_SPA_SCHED_PAUSED);
    int blocked = 0;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active &&
            (svc->entries[i].state == OZAYN_SPA_SCHED_WAITING) &&
            svc->entries[i].wait_reason != OZAYN_SPA_WAIT_NONE) {
            blocked++;
        }
    }
    svc->stats.current_blocked = blocked;
}

static int _deps_satisfied(ozayn_spa_service_t *svc, const ozayn_spa_entry_t *entry) {
    for (int d = 0; d < entry->dependency_count; d++) {
        const ozayn_spa_entry_t *dep = NULL;
        for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
            if (svc->entries[i].active &&
                strcmp(svc->entries[i].entry_id, entry->dependencies[d]) == 0) {
                dep = &svc->entries[i];
                break;
            }
        }
        if (!dep) return 0;
        if (dep->state != OZAYN_SPA_SCHED_COMPLETED &&
            dep->state != OZAYN_SPA_SCHED_RUNNING) {
            return 0;
        }
    }
    return 1;
}

static int _has_cycle(ozayn_spa_service_t *svc, const char *entry_id,
                      const char *dep_id) {
    char visited[OZAYN_SPA_MAX_ENTRIES][OZAYN_SPA_MAX_ID_LEN];
    int vcount = 0;
    char stack[OZAYN_SPA_MAX_ENTRIES][OZAYN_SPA_MAX_ID_LEN];
    int scount = 0;
    strncpy(stack[scount++], dep_id, OZAYN_SPA_MAX_ID_LEN - 1);
    while (scount > 0) {
        char current[OZAYN_SPA_MAX_ID_LEN];
        strncpy(current, stack[--scount], OZAYN_SPA_MAX_ID_LEN - 1);
        if (strcmp(current, entry_id) == 0) return 1;
        int already = 0;
        for (int v = 0; v < vcount; v++) {
            if (strcmp(visited[v], current) == 0) { already = 1; break; }
        }
        if (already) continue;
        if (vcount < OZAYN_SPA_MAX_ENTRIES)
            strncpy(visited[vcount++], current, OZAYN_SPA_MAX_ID_LEN - 1);
        for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
            if (svc->entries[i].active &&
                strcmp(svc->entries[i].entry_id, current) == 0) {
                for (int d = 0; d < svc->entries[i].dependency_count; d++) {
                    if (scount < OZAYN_SPA_MAX_ENTRIES)
                        strncpy(stack[scount++], svc->entries[i].dependencies[d],
                                OZAYN_SPA_MAX_ID_LEN - 1);
                }
                break;
            }
        }
    }
    return 0;
}


/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_service_init(ozayn_spa_service_t *svc,
                                       const ozayn_spa_service_config_t *cfg) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (svc->initialized) return OZAYN_SPA_ERR_ALREADY_INIT;
    memset(svc, 0, sizeof(ozayn_spa_service_t));
    if (cfg) {
        svc->config = *cfg;
        if (cfg->component_registry) svc->component_registry = cfg->component_registry;
        if (cfg->safety_engine) svc->safety_engine = cfg->safety_engine;
        if (cfg->resource_manager) svc->resource_manager = cfg->resource_manager;
        if (cfg->operation_queue) svc->operation_queue = cfg->operation_queue;
        if (cfg->pipeline_coordinator) svc->pipeline_coordinator = cfg->pipeline_coordinator;
        if (cfg->diagnostics) svc->diagnostics = cfg->diagnostics;
        if (cfg->audit) svc->audit = cfg->audit;
    }
    if (svc->config.max_entries <= 0) svc->config.max_entries = OZAYN_SPA_MAX_ENTRIES;
    if (svc->config.max_running <= 0) svc->config.max_running = OZAYN_SPA_DEFAULT_MAX_RUNNING;
    if (svc->config.max_waiting <= 0) svc->config.max_waiting = OZAYN_SPA_DEFAULT_MAX_WAITING;
    if (svc->config.max_scheduled <= 0) svc->config.max_scheduled = OZAYN_SPA_DEFAULT_MAX_SCHEDULED;
    if (svc->config.max_scheduling_attempts <= 0)
        svc->config.max_scheduling_attempts = OZAYN_SPA_DEFAULT_MAX_SCHEDULING_ATTEMPTS;
    if (svc->config.max_priority_boost <= 0)
        svc->config.max_priority_boost = OZAYN_SPA_DEFAULT_MAX_PRIORITY_BOOST;
    if (svc->config.max_wait_time_ms <= 0)
        svc->config.max_wait_time_ms = OZAYN_SPA_DEFAULT_MAX_WAIT_TIME_MS;
    if (svc->config.entry_ttl_ms <= 0)
        svc->config.entry_ttl_ms = OZAYN_SPA_DEFAULT_ENTRY_TTL_MS;
    if (svc->config.tick_interval_ms <= 0)
        svc->config.tick_interval_ms = OZAYN_SPA_DEFAULT_TICK_INTERVAL_MS;
    if (svc->config.aging_interval_s <= 0)
        svc->config.aging_interval_s = OZAYN_SPA_DEFAULT_AGING_INTERVAL_S;
    svc->config.aging_enabled = 1;
    svc->last_aging_time = time(NULL);
    svc->last_tick_time = time(NULL);
    svc->initialized = 1;
    _emit_event(svc, OZAYN_SPA_EVENT_SCHEDULER_STARTED, "", "", "Scheduler initialized");
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_service_shutdown(ozayn_spa_service_t *svc) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    _emit_event(svc, OZAYN_SPA_EVENT_SCHEDULER_STOPPED, "", "", "Scheduler shutting down");
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active && !_is_terminal(svc->entries[i].state)) {
            svc->entries[i].state = OZAYN_SPA_SCHED_CANCELLED;
            svc->entries[i].close_reason = OZAYN_SPA_CLOSE_SHUTDOWN;
        }
    }
    svc->initialized = 0;
    return OZAYN_SPA_OK;
}

int ozayn_spa_service_is_initialized(const ozayn_spa_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_spa_service_t *ozayn_spa_get_global(void) {
    return &_global_svc;
}

/* ============================================================
 * SECTION 16 — SCHEDULING ENTRY MANAGEMENT
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_submit(ozayn_spa_service_t *svc,
                                 const char *pipeline_id,
                                 const char *operation_id,
                                 const char *request_id,
                                 ozayn_spa_priority_t priority,
                                 const char *metadata) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!pipeline_id || !pipeline_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (!operation_id || !operation_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (priority < OZAYN_SPA_PRIORITY_LOW || priority > OZAYN_SPA_PRIORITY_CRITICAL)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (_find_entry_by_pipeline(svc, pipeline_id))
        return OZAYN_SPA_ERR_DUPLICATE;
    int slot = _find_free_slot(svc);
    if (slot < 0) return OZAYN_SPA_ERR_LIMIT_REACHED;
    int running = _count_by_state(svc, OZAYN_SPA_SCHED_RUNNING) +
                  _count_by_state(svc, OZAYN_SPA_SCHED_STARTING);
    if (running >= svc->config.max_running) {
        int waiting = _count_by_state(svc, OZAYN_SPA_SCHED_WAITING) +
                      _count_by_state(svc, OZAYN_SPA_SCHED_QUEUED);
        if (waiting >= svc->config.max_waiting) return OZAYN_SPA_ERR_QUEUE_FULL;
    }
    memset(&svc->entries[slot], 0, sizeof(ozayn_spa_entry_t));
    svc->entries[slot].active = 1;
    svc->entries[slot].state = OZAYN_SPA_SCHED_CREATED;
    svc->entries[slot].priority = priority;
    svc->entries[slot].effective_priority = priority;
    svc->entries[slot].age_boost = 0;
    svc->entries[slot].submitted_at = time(NULL);
    svc->entries[slot].max_wait_time_ms = svc->config.max_wait_time_ms;
    svc->entries[slot].entry_ttl_ms = svc->config.entry_ttl_ms;
    svc->entries[slot].expiration_time = svc->entries[slot].submitted_at +
                                          svc->entries[slot].entry_ttl_ms / 1000;
    svc->entries[slot].max_attempts = svc->config.max_scheduling_attempts;
    svc->entries[slot].attempt_count = 0;
    snprintf(svc->entries[slot].entry_id, OZAYN_SPA_MAX_ID_LEN,
             "spa-%lu", (unsigned long)(svc->entry_sequence++));
    strncpy(svc->entries[slot].pipeline_id, pipeline_id, OZAYN_SPA_MAX_ID_LEN - 1);
    strncpy(svc->entries[slot].operation_id, operation_id, OZAYN_SPA_MAX_ID_LEN - 1);
    if (request_id)
        strncpy(svc->entries[slot].request_id, request_id, OZAYN_SPA_MAX_ID_LEN - 1);
    if (metadata)
        strncpy(svc->entries[slot].safe_metadata, metadata, OZAYN_SPA_MAX_METADATA_LEN - 1);
    svc->entry_count++;
    svc->stats.total_submitted++;
    svc->entries[slot].state = OZAYN_SPA_SCHED_QUEUED;
    _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_SCHEDULED, svc->entries[slot].entry_id,
                pipeline_id, "Pipeline submitted");
    _update_stats(svc);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_cancel(ozayn_spa_service_t *svc,
                                 const char *entry_id,
                                 ozayn_spa_close_reason_t reason) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    if (_is_terminal(e->state)) return OZAYN_SPA_ERR_STATE_INVALID;
    e->close_reason = reason;
    e->state = OZAYN_SPA_SCHED_CANCELLED;
    svc->stats.total_cancelled++;
    _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_CANCELLED, entry_id,
                e->pipeline_id, "Pipeline cancelled");
    _record_decision(svc, e, OZAYN_SPA_DECISION_REJECT, OZAYN_SPA_WAIT_NONE, reason, "Cancelled");
    _update_stats(svc);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_remove(ozayn_spa_service_t *svc,
                                 const char *entry_id) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    if (!_is_terminal(e->state)) return OZAYN_SPA_ERR_STATE_INVALID;
    e->active = 0;
    svc->entry_count--;
    _update_stats(svc);
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 17 — DEPENDENCY MANAGEMENT
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_add_dependency(ozayn_spa_service_t *svc,
                                         const char *entry_id,
                                         const char *dependency_entry_id) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !dependency_entry_id) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    if (strcmp(entry_id, dependency_entry_id) == 0) return OZAYN_SPA_ERR_DEPENDENCY_CYCLE;
    ozayn_spa_entry_t *dep = _find_entry(svc, dependency_entry_id);
    if (!dep) return OZAYN_SPA_ERR_NOT_FOUND;
    if (_has_cycle(svc, entry_id, dependency_entry_id))
        return OZAYN_SPA_ERR_DEPENDENCY_CYCLE;
    if (e->dependency_count >= OZAYN_SPA_MAX_DEPENDENCIES)
        return OZAYN_SPA_ERR_LIMIT_REACHED;
    strncpy(e->dependencies[e->dependency_count], dependency_entry_id,
            OZAYN_SPA_MAX_ID_LEN - 1);
    e->dependency_count++;
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 18 — RESOURCE REQUIREMENTS
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_set_required_resources(ozayn_spa_service_t *svc,
                                                 const char *entry_id,
                                                 const char resource_ids[][OZAYN_SPA_MAX_ID_LEN],
                                                 int count) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (count < 0 || count > OZAYN_SPA_MAX_REQUIRED_RESOURCES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    e->required_resource_count = count;
    for (int i = 0; i < count; i++)
        strncpy(e->required_resources[i], resource_ids[i], OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_set_required_devices(ozayn_spa_service_t *svc,
                                               const char *entry_id,
                                               const char device_ids[][OZAYN_SPA_MAX_ID_LEN],
                                               int count) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (count < 0 || count > OZAYN_SPA_MAX_REQUIRED_DEVICES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    e->required_device_count = count;
    for (int i = 0; i < count; i++)
        strncpy(e->required_devices[i], device_ids[i], OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_set_required_streams(ozayn_spa_service_t *svc,
                                               const char *entry_id,
                                               const char stream_ids[][OZAYN_SPA_MAX_ID_LEN],
                                               int count) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (count < 0 || count > OZAYN_SPA_MAX_REQUIRED_STREAMS)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    e->required_stream_count = count;
    for (int i = 0; i < count; i++)
        strncpy(e->required_streams[i], stream_ids[i], OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_set_required_routes(ozayn_spa_service_t *svc,
                                              const char *entry_id,
                                              const char route_ids[][OZAYN_SPA_MAX_ID_LEN],
                                              int count) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (count < 0 || count > OZAYN_SPA_MAX_REQUIRED_ROUTES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    e->required_route_count = count;
    for (int i = 0; i < count; i++)
        strncpy(e->required_routes[i], route_ids[i], OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 19 — DEADLINE / TIMING
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_set_deadline(ozayn_spa_service_t *svc,
                                       const char *entry_id,
                                       time_t deadline_ms) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    e->deadline_ms = deadline_ms;
    if (deadline_ms > 0) {
        time_t now = time(NULL);
        e->expiration_time = now + deadline_ms / 1000;
    }
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_set_max_wait_time(ozayn_spa_service_t *svc,
                                             const char *entry_id,
                                             time_t max_wait_ms) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    e->max_wait_time_ms = max_wait_ms;
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 20 — SECURITY REFERENCES
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_set_security_session(ozayn_spa_service_t *svc,
                                               const char *entry_id,
                                               const char *session_ref) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !session_ref) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    strncpy(e->security_session_ref, session_ref, OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_set_authorization_ref(ozayn_spa_service_t *svc,
                                                const char *entry_id,
                                                const char *auth_ref) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !auth_ref) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    strncpy(e->authorization_ref, auth_ref, OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_set_safety_decision_ref(ozayn_spa_service_t *svc,
                                                   const char *entry_id,
                                                   const char *safety_ref) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !safety_ref) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    strncpy(e->safety_decision_ref, safety_ref, OZAYN_SPA_MAX_ID_LEN - 1);
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 21 — SCHEDULER EVALUATION (TICK)
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_tick(ozayn_spa_service_t *svc) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    time_t now = time(NULL);
    svc->stats.total_ticks++;

    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        ozayn_spa_entry_t *e = &svc->entries[i];
        if (!e->active) continue;
        if (_is_terminal(e->state)) continue;

        if (e->expiration_time > 0 && now >= e->expiration_time) {
            e->state = OZAYN_SPA_SCHED_EXPIRED;
            e->close_reason = OZAYN_SPA_CLOSE_DEADLINE_EXPIRED;
            svc->stats.total_expired++;
            svc->stats.total_deadline_expirations++;
            _emit_event(svc, OZAYN_SPA_EVENT_DEADLINE_EXPIRED, e->entry_id,
                        e->pipeline_id, "Deadline expired");
            _record_decision(svc, e, OZAYN_SPA_DECISION_EXPIRE, OZAYN_SPA_WAIT_NONE,
                             OZAYN_SPA_CLOSE_DEADLINE_EXPIRED, "Deadline expired");
            continue;
        }

        if (e->state == OZAYN_SPA_SCHED_QUEUED || e->state == OZAYN_SPA_SCHED_WAITING) {
            e->attempt_count++;
            if (e->attempt_count > e->max_attempts && e->max_attempts > 0) {
                e->state = OZAYN_SPA_SCHED_EXPIRED;
                e->close_reason = OZAYN_SPA_CLOSE_TIMEOUT;
                svc->stats.total_expired++;
                _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_EXPIRED, e->entry_id,
                            e->pipeline_id, "Max attempts exceeded");
                _record_decision(svc, e, OZAYN_SPA_DECISION_EXPIRE, OZAYN_SPA_WAIT_NONE,
                                 OZAYN_SPA_CLOSE_TIMEOUT, "Max attempts exceeded");
                continue;
            }
        }

        if (svc->config.aging_enabled &&
            (e->state == OZAYN_SPA_SCHED_WAITING || e->state == OZAYN_SPA_SCHED_QUEUED)) {
            if (now - svc->last_aging_time >= svc->config.aging_interval_s) {
                if (e->age_boost < svc->config.max_priority_boost) {
                    int old = (int)e->effective_priority;
                    int boosted = old + 1;
                    if (boosted > (int)OZAYN_SPA_PRIORITY_CRITICAL)
                        boosted = (int)OZAYN_SPA_PRIORITY_CRITICAL;
                    e->effective_priority = (ozayn_spa_priority_t)boosted;
                    e->age_boost++;
                    svc->stats.total_fairness_adjustments++;
                    _emit_event(svc, OZAYN_SPA_EVENT_FAIRNESS_ADJUSTED, e->entry_id,
                                e->pipeline_id, "Priority aged");
                }
            }
        }

        if (e->state == OZAYN_SPA_SCHED_QUEUED) {
            if (e->attempt_count <= 1) {
                e->state = OZAYN_SPA_SCHED_WAITING;
                e->wait_reason = OZAYN_SPA_WAIT_RESOURCE;
                _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_WAITING, e->entry_id,
                            e->pipeline_id, "Waiting for resources");
            }
        }

        if (e->state == OZAYN_SPA_SCHED_WAITING) {
            int deps_ok = _deps_satisfied(svc, e);
            if (!deps_ok) {
                e->wait_reason = OZAYN_SPA_WAIT_DEPENDENCY;
                _emit_event(svc, OZAYN_SPA_EVENT_DEPENDENCY_WAIT, e->entry_id,
                            e->pipeline_id, "Waiting for dependency");
                continue;
            }
            e->state = OZAYN_SPA_SCHED_ELIGIBLE;
            e->eligibility_time = now;
            e->wait_reason = OZAYN_SPA_WAIT_NONE;
            _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_ELIGIBLE, e->entry_id,
                        e->pipeline_id, "Pipeline eligible");
        }
    }

    if (svc->last_aging_time > 0 &&
        now - svc->last_aging_time >= svc->config.aging_interval_s) {
        svc->last_aging_time = now;
    }

    _update_stats(svc);
    _emit_event(svc, OZAYN_SPA_EVENT_TICK_EVALUATED, "", "", "Tick completed");
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 22 — READINESS EVALUATION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_evaluate_entry(ozayn_spa_service_t *svc,
                                         const char *entry_id,
                                         ozayn_spa_decision_record_t *out_decision) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !out_decision) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;

    memset(out_decision, 0, sizeof(ozayn_spa_decision_record_t));
    out_decision->active = 1;
    strncpy(out_decision->entry_id, e->entry_id, OZAYN_SPA_MAX_ID_LEN - 1);
    strncpy(out_decision->pipeline_id, e->pipeline_id, OZAYN_SPA_MAX_ID_LEN - 1);
    strncpy(out_decision->operation_id, e->operation_id, OZAYN_SPA_MAX_ID_LEN - 1);
    out_decision->priority = e->priority;
    out_decision->decision_time = time(NULL);
    out_decision->expiration = e->expiration_time;

    if (_is_terminal(e->state)) {
        out_decision->decision = OZAYN_SPA_DECISION_REJECT;
        out_decision->eligibility_ok = 0;
        strncpy(out_decision->reject_reason, "Entry in terminal state",
                OZAYN_SPA_MAX_METADATA_LEN - 1);
        return OZAYN_SPA_OK;
    }

    out_decision->eligibility_ok = 1;
    out_decision->resource_ok = 1;
    out_decision->conflict_detected = 0;
    out_decision->dependency_ok = _deps_satisfied(svc, e);
    out_decision->authorization_ok = (e->authorization_ref[0] != '\0');
    out_decision->safety_ok = (e->safety_decision_ref[0] != '\0');

    if (!out_decision->dependency_ok) {
        out_decision->decision = OZAYN_SPA_DECISION_WAIT;
        out_decision->wait_reason = OZAYN_SPA_WAIT_DEPENDENCY;
        strncpy(out_decision->reject_reason, "Dependency not satisfied",
                OZAYN_SPA_MAX_METADATA_LEN - 1);
        return OZAYN_SPA_OK;
    }

    if (!out_decision->authorization_ok) {
        out_decision->decision = OZAYN_SPA_DECISION_WAIT;
        out_decision->wait_reason = OZAYN_SPA_WAIT_AUTHORIZATION;
        strncpy(out_decision->reject_reason, "Authorization not set",
                OZAYN_SPA_MAX_METADATA_LEN - 1);
        return OZAYN_SPA_OK;
    }

    if (!out_decision->safety_ok) {
        out_decision->decision = OZAYN_SPA_DECISION_WAIT;
        out_decision->wait_reason = OZAYN_SPA_WAIT_SAFETY;
        strncpy(out_decision->reject_reason, "Safety decision not set",
                OZAYN_SPA_MAX_METADATA_LEN - 1);
        return OZAYN_SPA_OK;
    }

    int running = _count_by_state(svc, OZAYN_SPA_SCHED_RUNNING) +
                  _count_by_state(svc, OZAYN_SPA_SCHED_STARTING);
    if (running >= svc->config.max_running) {
        out_decision->decision = OZAYN_SPA_DECISION_DEFER;
        out_decision->wait_reason = OZAYN_SPA_WAIT_CONCURRENCY;
        strncpy(out_decision->reject_reason, "Concurrency limit reached",
                OZAYN_SPA_MAX_METADATA_LEN - 1);
        return OZAYN_SPA_OK;
    }

    out_decision->decision = OZAYN_SPA_DECISION_SCHEDULE;
    out_decision->wait_reason = OZAYN_SPA_WAIT_NONE;
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 23 — SCHEDULING DECISION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_schedule_next(ozayn_spa_service_t *svc,
                                        char *out_entry_id,
                                        int out_entry_id_len) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!out_entry_id || out_entry_id_len <= 0) return OZAYN_SPA_ERR_INVALID_PARAM;

    int running = _count_by_state(svc, OZAYN_SPA_SCHED_RUNNING) +
                  _count_by_state(svc, OZAYN_SPA_SCHED_STARTING);
    if (running >= svc->config.max_running)
        return OZAYN_SPA_ERR_CONCURRENCY;

    int best_idx = -1;
    int best_prio = -1;
    time_t earliest = 0;

    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        ozayn_spa_entry_t *e = &svc->entries[i];
        if (!e->active) continue;
        if (e->state != OZAYN_SPA_SCHED_ELIGIBLE) continue;

        int dominated = 0;
        for (int d = 0; d < e->dependency_count; d++) {
            ozayn_spa_entry_t *dep = NULL;
            for (int j = 0; j < OZAYN_SPA_MAX_ENTRIES; j++) {
                if (svc->entries[j].active &&
                    strcmp(svc->entries[j].entry_id, e->dependencies[d]) == 0) {
                    dep = &svc->entries[j];
                    break;
                }
            }
            if (dep && dep->state != OZAYN_SPA_SCHED_COMPLETED &&
                dep->state != OZAYN_SPA_SCHED_RUNNING) {
                dominated = 1;
                break;
            }
        }
        if (dominated) continue;

        if ((int)e->effective_priority > (int)best_prio) {
            best_prio = e->effective_priority;
            best_idx = i;
            earliest = e->eligibility_time;
        } else if ((int)e->effective_priority == (int)best_prio) {
            if (e->eligibility_time < earliest) {
                earliest = e->eligibility_time;
                best_idx = i;
            }
        }
    }

    if (best_idx < 0) return OZAYN_SPA_ERR_NOT_FOUND;

    ozayn_spa_entry_t *best = &svc->entries[best_idx];
    best->state = OZAYN_SPA_SCHED_SCHEDULED;
    best->scheduled_at = time(NULL);
    svc->stats.total_scheduled++;
    _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_SCHEDULED, best->entry_id,
                best->pipeline_id, "Pipeline scheduled");
    _record_decision(svc, best, OZAYN_SPA_DECISION_SCHEDULE, OZAYN_SPA_WAIT_NONE,
                     OZAYN_SPA_CLOSE_NONE, "Scheduled");
    strncpy(out_entry_id, best->entry_id, out_entry_id_len - 1);
    _update_stats(svc);
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 24 — RESOURCE ARBITRATION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_check_conflicts(ozayn_spa_service_t *svc,
                                          const char *entry_id,
                                          int *out_has_conflict,
                                          char *out_conflicting_entry,
                                           int out_len) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id || !out_has_conflict) return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;

    *out_has_conflict = 0;
    if (out_conflicting_entry && out_len > 0)
        out_conflicting_entry[0] = '\0';

    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        ozayn_spa_entry_t *other = &svc->entries[i];
        if (!other->active) continue;
        if (strcmp(other->entry_id, entry_id) == 0) continue;
        if (_is_terminal(other->state)) continue;

        for (int d = 0; d < e->required_device_count; d++) {
            for (int dd = 0; dd < other->required_device_count; dd++) {
                if (strcmp(e->required_devices[d], other->required_devices[dd]) == 0) {
                    if (other->state == OZAYN_SPA_SCHED_RUNNING ||
                        other->state == OZAYN_SPA_SCHED_RESERVED ||
                        other->state == OZAYN_SPA_SCHED_SCHEDULED) {
                        *out_has_conflict = 1;
                        svc->stats.total_resource_conflicts++;
                        if (out_conflicting_entry && out_len > 0)
                            strncpy(out_conflicting_entry, other->entry_id, out_len - 1);
                        _emit_event(svc, OZAYN_SPA_EVENT_RESOURCE_CONFLICT, entry_id,
                                    e->pipeline_id, "Resource conflict detected");
                        return OZAYN_SPA_OK;
                    }
                }
            }
        }

        for (int r = 0; r < e->required_route_count; r++) {
            for (int rr = 0; rr < other->required_route_count; rr++) {
                if (strcmp(e->required_routes[r], other->required_routes[rr]) == 0) {
                    if (other->state == OZAYN_SPA_SCHED_RUNNING ||
                        other->state == OZAYN_SPA_SCHED_RESERVED ||
                        other->state == OZAYN_SPA_SCHED_SCHEDULED) {
                        *out_has_conflict = 1;
                        svc->stats.total_pipeline_conflicts++;
                        if (out_conflicting_entry && out_len > 0)
                            strncpy(out_conflicting_entry, other->entry_id, out_len - 1);
                        _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_CONFLICT, entry_id,
                                    e->pipeline_id, "Pipeline conflict detected");
                        return OZAYN_SPA_OK;
                    }
                }
            }
        }

        for (int s = 0; s < e->required_stream_count; s++) {
            for (int ss = 0; ss < other->required_stream_count; ss++) {
                if (strcmp(e->required_streams[s], other->required_streams[ss]) == 0) {
                    if (other->state == OZAYN_SPA_SCHED_RUNNING ||
                        other->state == OZAYN_SPA_SCHED_RESERVED ||
                        other->state == OZAYN_SPA_SCHED_SCHEDULED) {
                        *out_has_conflict = 1;
                        svc->stats.total_pipeline_conflicts++;
                        if (out_conflicting_entry && out_len > 0)
                            strncpy(out_conflicting_entry, other->entry_id, out_len - 1);
                        return OZAYN_SPA_OK;
                    }
                }
            }
        }
    }

    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 25 — STATE TRANSITION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_transition(ozayn_spa_service_t *svc,
                                     const char *entry_id,
                                     ozayn_spa_sched_state_t new_state) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (!entry_id) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (new_state < 0 || new_state >= OZAYN_SPA_SCHED_STATE_COUNT)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    ozayn_spa_entry_t *e = _find_entry(svc, entry_id);
    if (!e) return OZAYN_SPA_ERR_NOT_FOUND;
    if (!_transitions[e->state][new_state]) return OZAYN_SPA_ERR_STATE_INVALID;
    e->state = new_state;
    e->last_evaluated_at = time(NULL);
    if (new_state == OZAYN_SPA_SCHED_COMPLETED) {
        svc->stats.total_completed++;
        _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_COMPLETED, entry_id,
                    e->pipeline_id, "Pipeline completed");
    } else if (new_state == OZAYN_SPA_SCHED_FAILED) {
        svc->stats.total_failed++;
        _emit_event(svc, OZAYN_SPA_EVENT_PIPELINE_FAILED, entry_id,
                    e->pipeline_id, "Pipeline failed");
    }
    _update_stats(svc);
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 26 — QUERY
 * ============================================================ */

const ozayn_spa_entry_t *ozayn_spa_find_entry(const ozayn_spa_service_t *svc,
                                               const char *entry_id) {
    if (!svc || !entry_id) return NULL;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active &&
            strcmp(svc->entries[i].entry_id, entry_id) == 0) {
            return &svc->entries[i];
        }
    }
    return NULL;
}

const ozayn_spa_entry_t *ozayn_spa_find_entry_by_pipeline(const ozayn_spa_service_t *svc,
                                                           const char *pipeline_id) {
    if (!svc || !pipeline_id) return NULL;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active &&
            strcmp(svc->entries[i].pipeline_id, pipeline_id) == 0) {
            return &svc->entries[i];
        }
    }
    return NULL;
}

int ozayn_spa_entry_count(const ozayn_spa_service_t *svc) {
    if (!svc) return 0;
    return svc->entry_count;
}

int ozayn_spa_running_count(const ozayn_spa_service_t *svc) {
    if (!svc) return 0;
    return _count_by_state(svc, OZAYN_SPA_SCHED_RUNNING);
}

int ozayn_spa_waiting_count(const ozayn_spa_service_t *svc) {
    if (!svc) return 0;
    return _count_by_state(svc, OZAYN_SPA_SCHED_WAITING) +
           _count_by_state(svc, OZAYN_SPA_SCHED_QUEUED);
}

int ozayn_spa_eligible_count(const ozayn_spa_service_t *svc) {
    if (!svc) return 0;
    return _count_by_state(svc, OZAYN_SPA_SCHED_ELIGIBLE);
}

int ozayn_spa_queue_full(const ozayn_spa_service_t *svc) {
    if (!svc) return 1;
    return _count_non_terminal(svc) >= svc->config.max_entries;
}

int ozayn_spa_running_limit(const ozayn_spa_service_t *svc) {
    if (!svc) return 1;
    int running = _count_by_state(svc, OZAYN_SPA_SCHED_RUNNING) +
                  _count_by_state(svc, OZAYN_SPA_SCHED_STARTING);
    return running >= svc->config.max_running;
}

/* ============================================================
 * SECTION 27 — EVENTS
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_emit_event(ozayn_spa_service_t *svc,
                                     ozayn_spa_event_type_t type,
                                     const char *entry_id,
                                     const char *pipeline_id,
                                     const char *message) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPA_ERR_NOT_INITIALIZED;
    if (type < 0 || type >= OZAYN_SPA_EVENT_COUNT) return OZAYN_SPA_ERR_INVALID_PARAM;
    _emit_event(svc, type, entry_id ? entry_id : "",
                pipeline_id ? pipeline_id : "", message ? message : "");
    return OZAYN_SPA_OK;
}

const ozayn_spa_event_t *ozayn_spa_get_event(const ozayn_spa_service_t *svc,
                                              int index) {
    if (!svc) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int idx = (svc->event_head + index) % OZAYN_SPA_MAX_EVENTS;
    return &svc->events[idx];
}

int ozayn_spa_event_count(const ozayn_spa_service_t *svc) {
    if (!svc) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 28 — CLEANUP
 * ============================================================ */

int ozayn_spa_cleanup_expired(ozayn_spa_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        ozayn_spa_entry_t *e = &svc->entries[i];
        if (!e->active) continue;
        if (_is_terminal(e->state)) {
            if (e->expiration_time > 0 && now >= e->expiration_time) {
                e->active = 0;
                svc->entry_count--;
                cleaned++;
            }
        }
    }
    _update_stats(svc);
    return cleaned;
}

int ozayn_spa_cleanup_terminal(ozayn_spa_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int cleaned = 0;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active && _is_terminal(svc->entries[i].state)) {
            svc->entries[i].active = 0;
            svc->entry_count--;
            cleaned++;
        }
    }
    _update_stats(svc);
    return cleaned;
}

int ozayn_spa_cleanup_all(ozayn_spa_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    int cleaned = 0;
    for (int i = 0; i < OZAYN_SPA_MAX_ENTRIES; i++) {
        if (svc->entries[i].active) {
            svc->entries[i].active = 0;
            cleaned++;
        }
    }
    svc->entry_count = 0;
    _update_stats(svc);
    return cleaned;
}

/* ============================================================
 * SECTION 29 — STATISTICS
 * ============================================================ */

ozayn_spa_stats_t ozayn_spa_get_stats(const ozayn_spa_service_t *svc) {
    if (!svc) {
        ozayn_spa_stats_t zero;
        memset(&zero, 0, sizeof(zero));
        return zero;
    }
    return svc->stats;
}

/* ============================================================
 * SECTION 30 — VALIDATION
 * ============================================================ */

ozayn_spa_err_t ozayn_spa_validate_entry(const ozayn_spa_service_t *svc,
                                         const ozayn_spa_entry_t *entry) {
    if (!svc) return OZAYN_SPA_ERR_NULL;
    if (!entry) return OZAYN_SPA_ERR_NULL;
    if (!entry->active) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (!entry->pipeline_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (!entry->operation_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (!entry->entry_id[0]) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->priority < OZAYN_SPA_PRIORITY_LOW ||
        entry->priority > OZAYN_SPA_PRIORITY_CRITICAL)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->state < 0 || entry->state >= OZAYN_SPA_SCHED_STATE_COUNT)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->dependency_count > OZAYN_SPA_MAX_DEPENDENCIES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->required_resource_count > OZAYN_SPA_MAX_REQUIRED_RESOURCES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->required_device_count > OZAYN_SPA_MAX_REQUIRED_DEVICES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->required_stream_count > OZAYN_SPA_MAX_REQUIRED_STREAMS)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (entry->required_route_count > OZAYN_SPA_MAX_REQUIRED_ROUTES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    return OZAYN_SPA_OK;
}

ozayn_spa_err_t ozayn_spa_validate_config(const ozayn_spa_service_config_t *cfg) {
    if (!cfg) return OZAYN_SPA_ERR_NULL;
    if (cfg->max_entries < 0 || cfg->max_entries > OZAYN_SPA_MAX_ENTRIES)
        return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->max_running < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->max_waiting < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->max_scheduled < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->max_scheduling_attempts < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->max_priority_boost < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->max_wait_time_ms < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    if (cfg->entry_ttl_ms < 0) return OZAYN_SPA_ERR_INVALID_PARAM;
    return OZAYN_SPA_OK;
}

/* ============================================================
 * SECTION 31 — NAME HELPERS
 * ============================================================ */

const char *ozayn_spa_err_name(ozayn_spa_err_t err) {
    switch (err) {
        case OZAYN_SPA_OK:                      return "OK";
        case OZAYN_SPA_ERR_NULL:                return "NULL";
        case OZAYN_SPA_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
        case OZAYN_SPA_ERR_ALREADY_INIT:        return "ALREADY_INIT";
        case OZAYN_SPA_ERR_INVALID_PARAM:       return "INVALID_PARAM";
        case OZAYN_SPA_ERR_LIMIT_REACHED:       return "LIMIT_REACHED";
        case OZAYN_SPA_ERR_NOT_FOUND:           return "NOT_FOUND";
        case OZAYN_SPA_ERR_DUPLICATE:           return "DUPLICATE";
        case OZAYN_SPA_ERR_STATE_INVALID:       return "STATE_INVALID";
        case OZAYN_SPA_ERR_AUTH_FAILED:         return "AUTH_FAILED";
        case OZAYN_SPA_ERR_PERMISSION_DENIED:   return "PERMISSION_DENIED";
        case OZAYN_SPA_ERR_UNAVAILABLE:         return "UNAVAILABLE";
        case OZAYN_SPA_ERR_PIPELINE_INVALID:    return "PIPELINE_INVALID";
        case OZAYN_SPA_ERR_PIPELINE_NOT_FOUND:  return "PIPELINE_NOT_FOUND";
        case OZAYN_SPA_ERR_PIPELINE_CONFLICT:   return "PIPELINE_CONFLICT";
        case OZAYN_SPA_ERR_PIPELINE_UNAVAILABLE:return "PIPELINE_UNAVAILABLE";
        case OZAYN_SPA_ERR_RESOURCE_UNAVAILABLE:return "RESOURCE_UNAVAILABLE";
        case OZAYN_SPA_ERR_RESOURCE_CONFLICT:   return "RESOURCE_CONFLICT";
        case OZAYN_SPA_ERR_RESERVATION_FAILED:  return "RESERVATION_FAILED";
        case OZAYN_SPA_ERR_RESERVATION_EXPIRED: return "RESERVATION_EXPIRED";
        case OZAYN_SPA_ERR_DEPENDENCY_FAILED:   return "DEPENDENCY_FAILED";
        case OZAYN_SPA_ERR_DEPENDENCY_CYCLE:    return "DEPENDENCY_CYCLE";
        case OZAYN_SPA_ERR_DEPENDENCY_TIMEOUT:  return "DEPENDENCY_TIMEOUT";
        case OZAYN_SPA_ERR_SAFETY_CHECK_FAILED: return "SAFETY_CHECK_FAILED";
        case OZAYN_SPA_ERR_SAFETY_RECHECK_FAILED: return "SAFETY_RECHECK_FAILED";
        case OZAYN_SPA_ERR_POLICY_DENIED:       return "POLICY_DENIED";
        case OZAYN_SPA_ERR_DEADLINE_EXPIRED:    return "DEADLINE_EXPIRED";
        case OZAYN_SPA_ERR_CANCELLED:           return "CANCELLED";
        case OZAYN_SPA_ERR_TIMEOUT:             return "TIMEOUT";
        case OZAYN_SPA_ERR_CONCURRENCY:         return "CONCURRENCY";
        case OZAYN_SPA_ERR_CONFIGURATION:       return "CONFIGURATION";
        case OZAYN_SPA_ERR_EVENT_ERROR:         return "EVENT_ERROR";
        case OZAYN_SPA_ERR_HISTORY_ERROR:       return "HISTORY_ERROR";
        case OZAYN_SPA_ERR_RESOURCE_MANAGER:    return "RESOURCE_MANAGER";
        case OZAYN_SPA_ERR_PIPELINE_MANAGER:    return "PIPELINE_MANAGER";
        case OZAYN_SPA_ERR_QUEUE_FULL:          return "QUEUE_FULL";
        case OZAYN_SPA_ERR_CAPACITY_LIMIT:      return "CAPACITY_LIMIT";
        case OZAYN_SPA_ERR_EXPIRED:             return "EXPIRED";
        case OZAYN_SPA_ERR_REJECTED:            return "REJECTED";
        default:                                return "UNKNOWN";
    }
}

const char *ozayn_spa_sched_state_name(ozayn_spa_sched_state_t state) {
    switch (state) {
        case OZAYN_SPA_SCHED_CREATED:    return "CREATED";
        case OZAYN_SPA_SCHED_QUEUED:     return "QUEUED";
        case OZAYN_SPA_SCHED_WAITING:    return "WAITING";
        case OZAYN_SPA_SCHED_ELIGIBLE:   return "ELIGIBLE";
        case OZAYN_SPA_SCHED_SCHEDULED:  return "SCHEDULED";
        case OZAYN_SPA_SCHED_RESERVED:   return "RESERVED";
        case OZAYN_SPA_SCHED_STARTING:   return "STARTING";
        case OZAYN_SPA_SCHED_RUNNING:    return "RUNNING";
        case OZAYN_SPA_SCHED_PAUSED:     return "PAUSED";
        case OZAYN_SPA_SCHED_DRAINING:   return "DRAINING";
        case OZAYN_SPA_SCHED_COMPLETED:  return "COMPLETED";
        case OZAYN_SPA_SCHED_FAILED:     return "FAILED";
        case OZAYN_SPA_SCHED_CANCELLED:  return "CANCELLED";
        case OZAYN_SPA_SCHED_EXPIRED:    return "EXPIRED";
        case OZAYN_SPA_SCHED_REJECTED:   return "REJECTED";
        case OZAYN_SPA_SCHED_UNAVAILABLE:return "UNAVAILABLE";
        default:                         return "UNKNOWN";
    }
}

const char *ozayn_spa_priority_name(ozayn_spa_priority_t priority) {
    switch (priority) {
        case OZAYN_SPA_PRIORITY_LOW:      return "LOW";
        case OZAYN_SPA_PRIORITY_NORMAL:   return "NORMAL";
        case OZAYN_SPA_PRIORITY_HIGH:     return "HIGH";
        case OZAYN_SPA_PRIORITY_CRITICAL: return "CRITICAL";
        default:                          return "UNKNOWN";
    }
}

const char *ozayn_spa_decision_name(ozayn_spa_decision_t decision) {
    switch (decision) {
        case OZAYN_SPA_DECISION_SCHEDULE:    return "SCHEDULE";
        case OZAYN_SPA_DECISION_WAIT:        return "WAIT";
        case OZAYN_SPA_DECISION_DEFER:       return "DEFER";
        case OZAYN_SPA_DECISION_REJECT:      return "REJECT";
        case OZAYN_SPA_DECISION_EXPIRE:      return "EXPIRE";
        case OZAYN_SPA_DECISION_UNAVAILABLE: return "UNAVAILABLE";
        default:                             return "UNKNOWN";
    }
}

const char *ozayn_spa_wait_reason_name(ozayn_spa_wait_reason_t reason) {
    switch (reason) {
        case OZAYN_SPA_WAIT_NONE:          return "NONE";
        case OZAYN_SPA_WAIT_RESOURCE:      return "RESOURCE";
        case OZAYN_SPA_WAIT_DEVICE:        return "DEVICE";
        case OZAYN_SPA_WAIT_STREAM:        return "STREAM";
        case OZAYN_SPA_WAIT_ROUTE:         return "ROUTE";
        case OZAYN_SPA_WAIT_DEPENDENCY:    return "DEPENDENCY";
        case OZAYN_SPA_WAIT_AUTHORIZATION: return "AUTHORIZATION";
        case OZAYN_SPA_WAIT_SAFETY:        return "SAFETY";
        case OZAYN_SPA_WAIT_CONCURRENCY:   return "CONCURRENCY";
        case OZAYN_SPA_WAIT_CONFLICT:      return "CONFLICT";
        case OZAYN_SPA_WAIT_DEADLINE:      return "DEADLINE";
        default:                           return "UNKNOWN";
    }
}

const char *ozayn_spa_event_type_name(ozayn_spa_event_type_t type) {
    switch (type) {
        case OZAYN_SPA_EVENT_SCHEDULER_STARTED:       return "SCHEDULER_STARTED";
        case OZAYN_SPA_EVENT_SCHEDULER_STOPPED:       return "SCHEDULER_STOPPED";
        case OZAYN_SPA_EVENT_PIPELINE_SCHEDULED:      return "PIPELINE_SCHEDULED";
        case OZAYN_SPA_EVENT_PIPELINE_WAITING:        return "PIPELINE_WAITING";
        case OZAYN_SPA_EVENT_PIPELINE_ELIGIBLE:       return "PIPELINE_ELIGIBLE";
        case OZAYN_SPA_EVENT_PIPELINE_DEFERRED:       return "PIPELINE_DEFERRED";
        case OZAYN_SPA_EVENT_PIPELINE_REJECTED:       return "PIPELINE_REJECTED";
        case OZAYN_SPA_EVENT_PIPELINE_EXPIRED:        return "PIPELINE_EXPIRED";
        case OZAYN_SPA_EVENT_PIPELINE_CANCELLED:      return "PIPELINE_CANCELLED";
        case OZAYN_SPA_EVENT_PIPELINE_COMPLETED:      return "PIPELINE_COMPLETED";
        case OZAYN_SPA_EVENT_PIPELINE_FAILED:         return "PIPELINE_FAILED";
        case OZAYN_SPA_EVENT_RESOURCE_CONFLICT:       return "RESOURCE_CONFLICT";
        case OZAYN_SPA_EVENT_PIPELINE_CONFLICT:       return "PIPELINE_CONFLICT";
        case OZAYN_SPA_EVENT_DEPENDENCY_WAIT:         return "DEPENDENCY_WAIT";
        case OZAYN_SPA_EVENT_DEPENDENCY_READY:        return "DEPENDENCY_READY";
        case OZAYN_SPA_EVENT_RESERVATION_REQUESTED:   return "RESERVATION_REQUESTED";
        case OZAYN_SPA_EVENT_RESERVATION_GRANTED:     return "RESERVATION_GRANTED";
        case OZAYN_SPA_EVENT_RESERVATION_FAILED:      return "RESERVATION_FAILED";
        case OZAYN_SPA_EVENT_RESERVATION_RELEASED:    return "RESERVATION_RELEASED";
        case OZAYN_SPA_EVENT_AUTHORIZATION_FAILED:    return "AUTHORIZATION_FAILED";
        case OZAYN_SPA_EVENT_POLICY_DENIED:           return "POLICY_DENIED";
        case OZAYN_SPA_EVENT_SAFETY_RECHECK_FAILED:   return "SAFETY_RECHECK_FAILED";
        case OZAYN_SPA_EVENT_CAPACITY_REACHED:        return "CAPACITY_REACHED";
        case OZAYN_SPA_EVENT_DEADLINE_EXPIRED:        return "DEADLINE_EXPIRED";
        case OZAYN_SPA_EVENT_FAIRNESS_ADJUSTED:       return "FAIRNESS_ADJUSTED";
        case OZAYN_SPA_EVENT_TICK_EVALUATED:          return "TICK_EVALUATED";
        default:                                       return "UNKNOWN";
    }
}

const char *ozayn_spa_close_reason_name(ozayn_spa_close_reason_t reason) {
    switch (reason) {
        case OZAYN_SPA_CLOSE_NONE:                  return "NONE";
        case OZAYN_SPA_CLOSE_MANUAL_CANCEL:         return "MANUAL_CANCEL";
        case OZAYN_SPA_CLOSE_DEADLINE_EXPIRED:      return "DEADLINE_EXPIRED";
        case OZAYN_SPA_CLOSE_RESOURCE_EXHAUSTED:    return "RESOURCE_EXHAUSTED";
        case OZAYN_SPA_CLOSE_DEVICE_UNAVAILABLE:    return "DEVICE_UNAVAILABLE";
        case OZAYN_SPA_CLOSE_STREAM_FAILED:         return "STREAM_FAILED";
        case OZAYN_SPA_CLOSE_ROUTE_FAILED:          return "ROUTE_FAILED";
        case OZAYN_SPA_CLOSE_AUTHORIZATION_FAILED:  return "AUTHORIZATION_FAILED";
        case OZAYN_SPA_CLOSE_SAFETY_DENIED:         return "SAFETY_DENIED";
        case OZAYN_SPA_CLOSE_POLICY_DENIED:         return "POLICY_DENIED";
        case OZAYN_SPA_CLOSE_DEPENDENCY_FAILED:     return "DEPENDENCY_FAILED";
        case OZAYN_SPA_CLOSE_DEPENDENCY_CYCLE:      return "DEPENDENCY_CYCLE";
        case OZAYN_SPA_CLOSE_CONFLICT:              return "CONFLICT";
        case OZAYN_SPA_CLOSE_CONCURRENCY_LIMIT:     return "CONCURRENCY_LIMIT";
        case OZAYN_SPA_CLOSE_TIMEOUT:               return "TIMEOUT";
        case OZAYN_SPA_CLOSE_SHUTDOWN:              return "SHUTDOWN";
        default:                                    return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 32 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_spa_is_valid_transition(ozayn_spa_sched_state_t from,
                                  ozayn_spa_sched_state_t to) {
    if (from < 0 || from >= OZAYN_SPA_SCHED_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_SPA_SCHED_STATE_COUNT) return 0;
    return _transitions[from][to];
}

int ozayn_spa_is_terminal_state(ozayn_spa_sched_state_t state) {
    return _is_terminal(state);
}
