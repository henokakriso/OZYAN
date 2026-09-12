#include "pipeline.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — INTERNAL HELPERS
 * ============================================================ */

static ozayn_pco_service_t _svc;

static int _find_pipeline(const ozayn_pco_service_t *svc,
                           const char *pipeline_id)
{
    if (!svc || !pipeline_id) return -1;
    for (int i = 0; i < svc->config.max_pipelines; i++) {
        if (svc->pipelines[i].active &&
            strncmp(svc->pipelines[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_pipeline_slot(const ozayn_pco_service_t *svc)
{
    for (int i = 0; i < svc->config.max_pipelines; i++) {
        if (!svc->pipelines[i].active) return i;
    }
    return -1;
}

static int _find_stage(const ozayn_pco_service_t *svc,
                        const char *pipeline_id,
                        const char *stage_id)
{
    if (!svc || !pipeline_id || !stage_id) return -1;
    int total = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            strncmp(svc->stages[i].stage_id, stage_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_stage_slot(const ozayn_pco_service_t *svc)
{
    int total = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (!svc->stages[i].active) return i;
    }
    return -1;
}

static int _find_edge(const ozayn_pco_service_t *svc,
                       const char *pipeline_id,
                       const char *edge_id)
{
    if (!svc || !pipeline_id || !edge_id) return -1;
    int total = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            strncmp(svc->edges[i].edge_id, edge_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0)
            return i;
    }
    return -1;
}

static int _find_edge_slot(const ozayn_pco_service_t *svc)
{
    int total = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (!svc->edges[i].active) return i;
    }
    return -1;
}

static void _emit_event(ozayn_pco_service_t *svc,
                          ozayn_pco_event_type_t type,
                          const char *pipeline_id,
                          const char *stage_id,
                          const char *route_id,
                          const char *stream_id,
                          const char *message)
{
    if (!svc) return;
    int idx = (svc->event_head + svc->event_count) %
              OZAYN_PCO_MAX_EVENTS;
    if (svc->event_count >= OZAYN_PCO_MAX_EVENTS) {
        svc->event_head = (svc->event_head + 1) % OZAYN_PCO_MAX_EVENTS;
    } else {
        svc->event_count++;
    }
    svc->events[idx].type = type;
    strncpy(svc->events[idx].pipeline_id, pipeline_id ? pipeline_id : "",
            OZAYN_PCO_MAX_ID_LEN - 1);
    svc->events[idx].pipeline_id[OZAYN_PCO_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].stage_id, stage_id ? stage_id : "",
            OZAYN_PCO_MAX_ID_LEN - 1);
    svc->events[idx].stage_id[OZAYN_PCO_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].route_id, route_id ? route_id : "",
            OZAYN_PCO_MAX_ID_LEN - 1);
    svc->events[idx].route_id[OZAYN_PCO_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].stream_id, stream_id ? stream_id : "",
            OZAYN_PCO_MAX_ID_LEN - 1);
    svc->events[idx].stream_id[OZAYN_PCO_MAX_ID_LEN - 1] = '\0';
    strncpy(svc->events[idx].message, message ? message : "",
            OZAYN_PCO_MAX_DESCRIPTION_LEN - 1);
    svc->events[idx].message[OZAYN_PCO_MAX_DESCRIPTION_LEN - 1] = '\0';
    svc->events[idx].timestamp = time(NULL);
    svc->event_sequence++;
}

/* ============================================================
 * SECTION 2 — STATE MACHINES
 * ============================================================ */

static const int _pipeline_transitions
    [OZAYN_PCO_PIPELINE_STATE_COUNT][OZAYN_PCO_PIPELINE_STATE_COUNT] = {
    /* CREATED -> */
    {   0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    /* VALIDATING -> */
    {   0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* AUTHORIZED -> */
    {   0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0 },
    /* READY -> */
    {   0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1 },
    /* STARTING -> */
    {   0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1 },
    /* ACTIVE -> */
    {   0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1 },
    /* PAUSING -> */
    {   0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1 },
    /* PAUSED -> */
    {   0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1 },
    /* RESUMING -> */
    {   0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1 },
    /* DRAINING -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1 },
    /* STOPPING -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0 },
    /* STOPPED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* FAILED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* DEGRADED -> */
    {   0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1 },
    /* EXPIRED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* REVOKED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* UNAVAILABLE -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* CANCELLED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static const int _stage_transitions
    [OZAYN_PCO_STAGE_STATE_COUNT][OZAYN_PCO_STAGE_STATE_COUNT] = {
    /* CREATED -> */
    {   0, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* VALIDATING -> */
    {   0, 0, 1, 0, 0, 0, 0, 0, 1, 1 },
    /* READY -> */
    {   0, 0, 0, 1, 0, 0, 0, 0, 1, 0 },
    /* STARTING -> */
    {   0, 0, 0, 0, 1, 0, 0, 0, 1, 1 },
    /* ACTIVE -> */
    {   0, 0, 0, 0, 0, 1, 1, 1, 1, 1 },
    /* PAUSED -> */
    {   0, 0, 0, 0, 1, 0, 1, 1, 1, 1 },
    /* DRAINING -> */
    {   0, 0, 0, 0, 0, 0, 0, 1, 1, 1 },
    /* COMPLETED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* FAILED -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    /* UNAVAILABLE -> */
    {   0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

static int _pipeline_transition(ozayn_pco_service_t *svc,
                                 ozayn_pco_pipeline_t *p,
                                 ozayn_pco_pipeline_state_t new_state)
{
    if (!_pipeline_transitions[p->state][new_state]) {
        svc->stats.total_validation_failures++;
        return 0;
    }
    p->state = new_state;
    svc->stats.total_state_transitions++;
    return 1;
}

static int _stage_transition(ozayn_pco_service_t *svc,
                              ozayn_pco_stage_t *s,
                              ozayn_pco_stage_state_t new_state)
{
    if (!_stage_transitions[s->state][new_state]) {
        svc->stats.total_validation_failures++;
        return 0;
    }
    s->state = new_state;
    svc->stats.total_state_transitions++;
    return 1;
}

static int _is_pipeline_terminal(ozayn_pco_pipeline_state_t state)
{
    return state == OZAYN_PCO_PIPELINE_STOPPED ||
           state == OZAYN_PCO_PIPELINE_FAILED ||
           state == OZAYN_PCO_PIPELINE_EXPIRED ||
           state == OZAYN_PCO_PIPELINE_REVOKED ||
           state == OZAYN_PCO_PIPELINE_UNAVAILABLE ||
           state == OZAYN_PCO_PIPELINE_CANCELLED;
}

static int _is_stage_terminal(ozayn_pco_stage_state_t state)
{
    return state == OZAYN_PCO_STAGE_COMPLETED ||
           state == OZAYN_PCO_STAGE_FAILED ||
           state == OZAYN_PCO_STAGE_UNAVAILABLE;
}

static int _has_cycle_dfs(const ozayn_pco_service_t *svc,
                           const char *pipeline_id,
                           const char *current,
                           const char *visited,
                           int visited_count,
                           int max_depth)
{
    if (max_depth <= 0) return 1;
    if (!current || current[0] == '\0') return 0;

    for (int i = 0; i < visited_count; i++) {
        if (strncmp(&visited[i * OZAYN_PCO_MAX_ID_LEN], current,
                    OZAYN_PCO_MAX_ID_LEN) == 0)
            return 1;
    }

    char new_visited[OZAYN_PCO_MAX_DEP_REFS][OZAYN_PCO_MAX_ID_LEN];
    if (visited_count >= OZAYN_PCO_MAX_DEP_REFS) return 1;
    memcpy(new_visited, visited, visited_count * OZAYN_PCO_MAX_ID_LEN);
    strncpy(new_visited[visited_count], current, OZAYN_PCO_MAX_ID_LEN - 1);
    new_visited[visited_count][OZAYN_PCO_MAX_ID_LEN - 1] = '\0';
    visited_count++;

    int total = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            strncmp(svc->edges[i].source_stage_id, current,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (_has_cycle_dfs(svc, pipeline_id,
                               svc->edges[i].destination_stage_id,
                               (const char *)new_visited,
                               visited_count, max_depth - 1))
                return 1;
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_service_init(ozayn_pco_service_t *svc,
                                        const ozayn_pco_service_config_t *cfg)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!cfg) return OZAYN_PCO_ERR_NULL;
    if (svc->initialized) return OZAYN_PCO_ERR_ALREADY_INIT;

    memset(svc, 0, sizeof(*svc));
    svc->config = *cfg;

    if (svc->config.max_pipelines <= 0)
        svc->config.max_pipelines = OZAYN_PCO_MAX_PIPELINES;
    if (svc->config.max_stages <= 0)
        svc->config.max_stages = OZAYN_PCO_MAX_STAGES;
    if (svc->config.max_edges <= 0)
        svc->config.max_edges = OZAYN_PCO_MAX_EDGES;
    if (svc->config.max_fan_out <= 0)
        svc->config.max_fan_out = OZAYN_PCO_MAX_FAN_OUT;
    if (svc->config.max_fan_in <= 0)
        svc->config.max_fan_in = OZAYN_PCO_MAX_FAN_IN;
    if (svc->config.pipeline_ttl_ms <= 0)
        svc->config.pipeline_ttl_ms = OZAYN_PCO_DEFAULT_PIPELINE_TTL_MS;
    if (svc->config.drain_timeout_ms <= 0)
        svc->config.drain_timeout_ms = OZAYN_PCO_DEFAULT_DRAIN_TIMEOUT_MS;
    if (svc->config.sync_timeout_ms <= 0)
        svc->config.sync_timeout_ms = OZAYN_PCO_DEFAULT_SYNC_TIMEOUT_MS;
    if (svc->config.max_runtime_ms <= 0)
        svc->config.max_runtime_ms = OZAYN_PCO_DEFAULT_MAX_RUNTIME_MS;
    if (svc->config.max_concurrent_pipelines <= 0)
        svc->config.max_concurrent_pipelines = OZAYN_PCO_MAX_CONCURRENT_PIPELINES;

    svc->initialized = 1;
    return OZAYN_PCO_OK;
}

void ozayn_pco_service_shutdown(ozayn_pco_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_pco_service_is_initialized(const ozayn_pco_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

ozayn_pco_service_t *ozayn_pco_get_global(void)
{
    return &_svc;
}

/* ============================================================
 * SECTION 4 — PIPELINE OPERATIONS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_pipeline_create(ozayn_pco_service_t *svc,
                                           const ozayn_pco_pipeline_request_t *req,
                                           ozayn_pco_pipeline_t **out_pipeline)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!req) return OZAYN_PCO_ERR_NULL;
    if (!out_pipeline) return OZAYN_PCO_ERR_NULL;
    if (!req->requester_ref[0]) return OZAYN_PCO_ERR_INVALID_PARAM;
    if (req->type < 0 || req->type >= OZAYN_PCO_PIPELINE_TYPE_COUNT)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    if (req->name[0]) {
        for (int i = 0; i < svc->config.max_pipelines; i++) {
            if (svc->pipelines[i].active &&
                strncmp(svc->pipelines[i].name, req->name,
                        OZAYN_PCO_MAX_NAME_LEN) == 0)
                return OZAYN_PCO_ERR_DUPLICATE;
        }
    }

    if (svc->pipeline_count >= svc->config.max_concurrent_pipelines)
        return OZAYN_PCO_ERR_LIMIT_REACHED;

    int slot = _find_pipeline_slot(svc);
    if (slot < 0) return OZAYN_PCO_ERR_LIMIT_REACHED;

    svc->pipeline_sequence++;
    ozayn_pco_pipeline_t *p = &svc->pipelines[slot];
    memset(p, 0, sizeof(*p));

    snprintf(p->pipeline_id, OZAYN_PCO_MAX_ID_LEN, "PCO-%u",
             svc->pipeline_sequence);
    p->version = 1;
    if (req->name[0])
        strncpy(p->name, req->name, OZAYN_PCO_MAX_NAME_LEN - 1);
    if (req->description[0])
        strncpy(p->description, req->description,
                OZAYN_PCO_MAX_DESCRIPTION_LEN - 1);
    p->type = req->type;
    strncpy(p->requester_ref, req->requester_ref, OZAYN_PCO_MAX_ID_LEN - 1);
    if (req->owner_ref[0])
        strncpy(p->owner_ref, req->owner_ref, OZAYN_PCO_MAX_ID_LEN - 1);
    if (req->security_session_ref[0])
        strncpy(p->security_session_ref, req->security_session_ref,
                OZAYN_PCO_MAX_ID_LEN - 1);
    if (req->authorization_ref[0])
        strncpy(p->authorization_ref, req->authorization_ref,
                OZAYN_PCO_MAX_ID_LEN - 1);
    if (req->safety_decision_ref[0])
        strncpy(p->safety_decision_ref, req->safety_decision_ref,
                OZAYN_PCO_MAX_ID_LEN - 1);
    if (req->metadata[0])
        strncpy(p->metadata, req->metadata, OZAYN_PCO_MAX_METADATA_LEN - 1);

    p->state = OZAYN_PCO_PIPELINE_CREATED;
    p->flow_state = OZAYN_PCO_FLOW_NORMAL;
    p->close_reason = OZAYN_PCO_CLOSE_NONE;
    p->created_time = time(NULL);
    p->expiry_time = p->created_time + (svc->config.pipeline_ttl_ms / 1000);
    p->active = 1;

    svc->pipeline_count++;
    svc->stats.total_pipelines_created++;
    svc->stats.current_active_pipelines++;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_CREATED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline created");

    *out_pipeline = p;
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_validate(ozayn_pco_service_t *svc,
                                             const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    time_t now = time(NULL);
    if (p->expiry_time > 0 && now > p->expiry_time) {
        p->state = OZAYN_PCO_PIPELINE_EXPIRED;
        p->close_reason = OZAYN_PCO_CLOSE_TIMEOUT;
        p->closed_time = now;
        p->active = 0;
        svc->pipeline_count--;
        svc->stats.total_pipelines_expired++;
        svc->stats.current_active_pipelines--;
        _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_EXPIRED, p->pipeline_id,
                    NULL, NULL, NULL, "Pipeline expired during validation");
        return OZAYN_PCO_ERR_EXPIRED;
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_VALIDATING)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_STATE_INVALID;
    }

    if (p->stage_count == 0) {
        p->state = OZAYN_PCO_PIPELINE_FAILED;
        p->close_reason = OZAYN_PCO_CLOSE_GRAPH_ERROR;
        p->active = 0;
        svc->pipeline_count--;
        svc->stats.total_pipelines_failed++;
        svc->stats.current_active_pipelines--;
        _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_FAILED, p->pipeline_id,
                    NULL, NULL, NULL, "No stages defined");
        return OZAYN_PCO_ERR_GRAPH_INVALID;
    }

    ozayn_pco_err_t graph_err = ozayn_pco_graph_validate(svc, pipeline_id);
    if (graph_err != OZAYN_PCO_OK) {
        p->state = OZAYN_PCO_PIPELINE_FAILED;
        p->close_reason = OZAYN_PCO_CLOSE_GRAPH_ERROR;
        p->active = 0;
        svc->pipeline_count--;
        svc->stats.total_pipelines_failed++;
        svc->stats.current_active_pipelines--;
        _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_FAILED, p->pipeline_id,
                    NULL, NULL, NULL, "Graph validation failed");
        return graph_err;
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_AUTHORIZED)) {
        p->state = OZAYN_PCO_PIPELINE_FAILED;
        p->close_reason = OZAYN_PCO_CLOSE_CONCURRENT_ERROR;
        p->active = 0;
        svc->pipeline_count--;
        svc->stats.total_pipelines_failed++;
        svc->stats.current_active_pipelines--;
        return OZAYN_PCO_ERR_STATE_INVALID;
    }

    svc->stats.total_pipelines_authorized++;
    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_AUTHORIZED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline authorized");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_authorize(ozayn_pco_service_t *svc,
                                              const char *pipeline_id)
{
    return ozayn_pco_pipeline_validate(svc, pipeline_id);
}

ozayn_pco_err_t ozayn_pco_pipeline_start(ozayn_pco_service_t *svc,
                                          const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (p->state == OZAYN_PCO_PIPELINE_AUTHORIZED) {
        if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_READY))
            return OZAYN_PCO_ERR_STATE_INVALID;
    }

    if (p->state == OZAYN_PCO_PIPELINE_VALIDATING) {
        if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_AUTHORIZED))
            return OZAYN_PCO_ERR_STATE_INVALID;
        if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_READY))
            return OZAYN_PCO_ERR_STATE_INVALID;
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_STARTING)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_START_FAILED;
    }

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_STARTING, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline starting");

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (svc->stages[i].state == OZAYN_PCO_STAGE_READY) {
                _stage_transition(svc, &svc->stages[i],
                                  OZAYN_PCO_STAGE_STARTING);
                _stage_transition(svc, &svc->stages[i],
                                  OZAYN_PCO_STAGE_ACTIVE);
                svc->stats.current_stages_active++;
                _emit_event(svc, OZAYN_PCO_EVENT_STAGE_STARTED,
                            p->pipeline_id, svc->stages[i].stage_id,
                            NULL, NULL, "Stage started");
            }
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_ACTIVE)) {
        _pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_FAILED);
        p->close_reason = OZAYN_PCO_CLOSE_STAGE_FAILURE;
        p->active = 0;
        svc->pipeline_count--;
        svc->stats.total_pipelines_failed++;
        svc->stats.current_active_pipelines--;
        return OZAYN_PCO_ERR_START_FAILED;
    }

    p->activation_time = time(NULL);
    p->last_update_time = p->activation_time;
    svc->stats.total_pipelines_started++;
    svc->stats.total_pipelines_active++;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_ACTIVE, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline active");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_pause(ozayn_pco_service_t *svc,
                                          const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_PAUSING)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_PAUSE_FAILED;
    }

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_PAUSING, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline pausing");

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            svc->stages[i].state == OZAYN_PCO_STAGE_ACTIVE) {
            _stage_transition(svc, &svc->stages[i],
                              OZAYN_PCO_STAGE_PAUSED);
            svc->stats.current_stages_active--;
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_PAUSED)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_PAUSE_FAILED;
    }

    svc->stats.total_pipelines_paused++;
    svc->stats.current_paused_pipelines++;
    p->last_update_time = time(NULL);

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_PAUSED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline paused");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_resume(ozayn_pco_service_t *svc,
                                           const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (p->flow_state == OZAYN_PCO_FLOW_FAILED ||
        p->flow_state == OZAYN_PCO_FLOW_BLOCKED) {
        return OZAYN_PCO_ERR_RESUME_FAILED;
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_RESUMING)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_RESUME_FAILED;
    }

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_RESUMING, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline resuming");

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            svc->stages[i].state == OZAYN_PCO_STAGE_PAUSED) {
            _stage_transition(svc, &svc->stages[i],
                              OZAYN_PCO_STAGE_ACTIVE);
            svc->stats.current_stages_active++;
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_ACTIVE)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_RESUME_FAILED;
    }

    svc->stats.current_paused_pipelines--;
    p->flow_state = OZAYN_PCO_FLOW_NORMAL;
    p->last_update_time = time(NULL);

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_ACTIVE, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline resumed");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_drain(ozayn_pco_service_t *svc,
                                          const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_DRAINING)) {
        svc->stats.total_errors++;
        return OZAYN_PCO_ERR_DRAIN_FAILED;
    }

    p->flow_state = OZAYN_PCO_FLOW_DRAINING;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_DRAINING, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline draining");

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            svc->stages[i].state == OZAYN_PCO_STAGE_ACTIVE) {
            _stage_transition(svc, &svc->stages[i],
                              OZAYN_PCO_STAGE_DRAINING);
        }
    }

    p->last_update_time = time(NULL);
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_stop(ozayn_pco_service_t *svc,
                                         const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (_is_pipeline_terminal(p->state))
        return OZAYN_PCO_ERR_STATE_INVALID;

    int was_paused = (p->state == OZAYN_PCO_PIPELINE_PAUSED);
    int was_active = (p->state == OZAYN_PCO_PIPELINE_ACTIVE);

    if (was_active || was_paused) {
        svc->stats.current_paused_pipelines -= was_paused ? 1 : 0;
    }

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_STOPPING, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline stopping");

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (!_is_stage_terminal(svc->stages[i].state)) {
                if (svc->stages[i].state == OZAYN_PCO_STAGE_ACTIVE ||
                    svc->stages[i].state == OZAYN_PCO_STAGE_PAUSED) {
                    svc->stats.current_stages_active--;
                }
                svc->stages[i].state = OZAYN_PCO_STAGE_COMPLETED;
                svc->stages[i].active = 0;
                svc->stats.total_stages_completed++;
            }
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_STOPPING)) {
        p->state = OZAYN_PCO_PIPELINE_STOPPING;
    }
    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_STOPPED)) {
        p->state = OZAYN_PCO_PIPELINE_STOPPED;
    }

    p->close_reason = OZAYN_PCO_CLOSE_MANUAL_STOP;
    p->closed_time = time(NULL);
    p->active = 0;
    svc->pipeline_count--;
    svc->stats.total_pipelines_stopped++;
    svc->stats.current_active_pipelines--;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_STOPPED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline stopped");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_cancel(ozayn_pco_service_t *svc,
                                           const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (_is_pipeline_terminal(p->state))
        return OZAYN_PCO_ERR_STATE_INVALID;

    if (p->state == OZAYN_PCO_PIPELINE_PAUSED)
        svc->stats.current_paused_pipelines--;

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (!_is_stage_terminal(svc->stages[i].state)) {
                if (svc->stages[i].state == OZAYN_PCO_STAGE_ACTIVE ||
                    svc->stages[i].state == OZAYN_PCO_STAGE_PAUSED) {
                    svc->stats.current_stages_active--;
                }
                svc->stages[i].state = OZAYN_PCO_STAGE_FAILED;
                svc->stages[i].active = 0;
                svc->stats.total_stages_failed++;
            }
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_CANCELLED)) {
        p->state = OZAYN_PCO_PIPELINE_CANCELLED;
    }

    p->close_reason = OZAYN_PCO_CLOSE_MANUAL_STOP;
    p->closed_time = time(NULL);
    p->active = 0;
    svc->pipeline_count--;
    svc->stats.total_pipelines_cancelled++;
    svc->stats.current_active_pipelines--;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_CANCELLED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline cancelled");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_close(ozayn_pco_service_t *svc,
                                          const char *pipeline_id,
                                          ozayn_pco_close_reason_t reason)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (_is_pipeline_terminal(p->state))
        return OZAYN_PCO_ERR_STATE_INVALID;

    if (p->state == OZAYN_PCO_PIPELINE_PAUSED)
        svc->stats.current_paused_pipelines--;

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (!_is_stage_terminal(svc->stages[i].state)) {
                if (svc->stages[i].state == OZAYN_PCO_STAGE_ACTIVE ||
                    svc->stages[i].state == OZAYN_PCO_STAGE_PAUSED) {
                    svc->stats.current_stages_active--;
                }
                svc->stages[i].state = OZAYN_PCO_STAGE_COMPLETED;
                svc->stages[i].active = 0;
                svc->stats.total_stages_completed++;
            }
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_STOPPING))
        p->state = OZAYN_PCO_PIPELINE_STOPPING;
    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_STOPPED))
        p->state = OZAYN_PCO_PIPELINE_STOPPED;

    p->close_reason = reason;
    p->closed_time = time(NULL);
    p->active = 0;
    svc->pipeline_count--;
    svc->stats.total_pipelines_stopped++;
    svc->stats.current_active_pipelines--;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_STOPPED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline closed");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_revoke(ozayn_pco_service_t *svc,
                                           const char *pipeline_id,
                                           ozayn_pco_close_reason_t reason)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (_is_pipeline_terminal(p->state))
        return OZAYN_PCO_ERR_STATE_INVALID;

    if (p->state == OZAYN_PCO_PIPELINE_PAUSED)
        svc->stats.current_paused_pipelines--;

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (!_is_stage_terminal(svc->stages[i].state)) {
                if (svc->stages[i].state == OZAYN_PCO_STAGE_ACTIVE ||
                    svc->stages[i].state == OZAYN_PCO_STAGE_PAUSED) {
                    svc->stats.current_stages_active--;
                }
                svc->stages[i].state = OZAYN_PCO_STAGE_FAILED;
                svc->stages[i].active = 0;
                svc->stats.total_stages_failed++;
            }
        }
    }

    if (!_pipeline_transition(svc, p, OZAYN_PCO_PIPELINE_REVOKED))
        p->state = OZAYN_PCO_PIPELINE_REVOKED;

    p->close_reason = reason;
    p->closed_time = time(NULL);
    p->active = 0;
    svc->pipeline_count--;
    svc->stats.total_pipelines_revoked++;
    svc->stats.current_active_pipelines--;

    _emit_event(svc, OZAYN_PCO_EVENT_PIPELINE_REVOKED, p->pipeline_id,
                NULL, NULL, NULL, "Pipeline revoked");
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_pipeline_remove(ozayn_pco_service_t *svc,
                                           const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int total_edges = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total_edges; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            svc->edges[i].active = 0;
            svc->edge_count--;
        }
    }

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            svc->stages[i].active = 0;
            svc->stage_count--;
        }
    }

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx >= 0) {
        memset(&svc->pipelines[idx], 0, sizeof(ozayn_pco_pipeline_t));
    }
    return OZAYN_PCO_OK;
}

/* ============================================================
 * SECTION 5 — STAGE OPERATIONS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_stage_add(ozayn_pco_service_t *svc,
                                     const char *pipeline_id,
                                     const ozayn_pco_stage_t *stage_def,
                                     ozayn_pco_stage_t **out_stage)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;
    if (!stage_def) return OZAYN_PCO_ERR_NULL;
    if (!out_stage) return OZAYN_PCO_ERR_NULL;
    if (stage_def->type < 0 || stage_def->type >= OZAYN_PCO_STAGE_COUNT)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int pidx = _find_pipeline(svc, pipeline_id);
    if (pidx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[pidx];
    if (p->stage_count >= svc->config.max_stages)
        return OZAYN_PCO_ERR_LIMIT_REACHED;

    if (_find_stage(svc, pipeline_id, stage_def->stage_id) >= 0)
        return OZAYN_PCO_ERR_DUPLICATE;

    int slot = _find_stage_slot(svc);
    if (slot < 0) return OZAYN_PCO_ERR_LIMIT_REACHED;

    ozayn_pco_stage_t *s = &svc->stages[slot];
    memcpy(s, stage_def, sizeof(ozayn_pco_stage_t));
    s->active = 1;
    s->state = OZAYN_PCO_STAGE_CREATED;
    s->created_time = time(NULL);
    strncpy(s->pipeline_id, pipeline_id, OZAYN_PCO_MAX_ID_LEN - 1);

    p->stage_count++;
    svc->stage_count++;
    svc->stats.total_stages_created++;

    _emit_event(svc, OZAYN_PCO_EVENT_STAGE_READY, p->pipeline_id,
                s->stage_id, NULL, NULL, "Stage added");

    *out_stage = s;
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_stage_get(const ozayn_pco_service_t *svc,
                                     const char *pipeline_id,
                                     const char *stage_id,
                                     const ozayn_pco_stage_t **out_stage)
{
    if (!svc || !svc->initialized) return OZAYN_PCO_ERR_NULL;
    if (!pipeline_id || !stage_id || !out_stage)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_stage(svc, pipeline_id, stage_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    *out_stage = &svc->stages[idx];
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_stage_remove(ozayn_pco_service_t *svc,
                                        const char *pipeline_id,
                                        const char *stage_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || !stage_id)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int pidx = _find_pipeline(svc, pipeline_id);
    if (pidx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    int idx = _find_stage(svc, pipeline_id, stage_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_stage_t *s = &svc->stages[idx];
    if (s->state == OZAYN_PCO_STAGE_ACTIVE)
        return OZAYN_PCO_ERR_STATE_INVALID;

    int total_edges = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total_edges; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0 &&
            (strncmp(svc->edges[i].source_stage_id, stage_id,
                     OZAYN_PCO_MAX_ID_LEN) == 0 ||
             strncmp(svc->edges[i].destination_stage_id, stage_id,
                     OZAYN_PCO_MAX_ID_LEN) == 0)) {
            svc->edges[i].active = 0;
            svc->edge_count--;
        }
    }

    svc->pipelines[pidx].stage_count--;
    svc->stage_count--;
    memset(s, 0, sizeof(ozayn_pco_stage_t));
    return OZAYN_PCO_OK;
}

int ozayn_pco_stage_count(const ozayn_pco_service_t *svc,
                           const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return 0;
    int count = 0;
    int total = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

int ozayn_pco_stages_for_pipeline(ozayn_pco_service_t *svc,
                                   const char *pipeline_id,
                                   ozayn_pco_stage_t **out_stages,
                                   int max_out)
{
    if (!svc || !svc->initialized || !pipeline_id || !out_stages)
        return 0;
    int count = 0;
    int total = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total && count < max_out; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            out_stages[count++] = &svc->stages[i];
        }
    }
    return count;
}

/* ============================================================
 * SECTION 6 — GRAPH EDGE OPERATIONS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_edge_add(ozayn_pco_service_t *svc,
                                    const char *pipeline_id,
                                    const ozayn_pco_edge_t *edge_def,
                                    ozayn_pco_edge_t **out_edge)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;
    if (!edge_def) return OZAYN_PCO_ERR_NULL;
    if (!out_edge) return OZAYN_PCO_ERR_NULL;
    if (!edge_def->source_stage_id[0] || !edge_def->destination_stage_id[0])
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int pidx = _find_pipeline(svc, pipeline_id);
    if (pidx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[pidx];
    if (p->edge_count >= svc->config.max_edges)
        return OZAYN_PCO_ERR_LIMIT_REACHED;

    if (_find_edge(svc, pipeline_id, edge_def->edge_id) >= 0)
        return OZAYN_PCO_ERR_DUPLICATE;

    if (_find_stage(svc, pipeline_id, edge_def->source_stage_id) < 0)
        return OZAYN_PCO_ERR_STAGE_NOT_FOUND;
    if (_find_stage(svc, pipeline_id, edge_def->destination_stage_id) < 0)
        return OZAYN_PCO_ERR_STAGE_NOT_FOUND;

    if (strncmp(edge_def->source_stage_id, edge_def->destination_stage_id,
                OZAYN_PCO_MAX_ID_LEN) == 0)
        return OZAYN_PCO_ERR_GRAPH_INVALID;

    int out_count = 0;
    int in_count = 0;
    int total = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (strncmp(svc->edges[i].source_stage_id,
                        edge_def->source_stage_id,
                        OZAYN_PCO_MAX_ID_LEN) == 0)
                out_count++;
            if (strncmp(svc->edges[i].destination_stage_id,
                        edge_def->destination_stage_id,
                        OZAYN_PCO_MAX_ID_LEN) == 0)
                in_count++;
        }
    }

    if (out_count >= svc->config.max_fan_out)
        return OZAYN_PCO_ERR_LIMIT_REACHED;
    if (in_count >= svc->config.max_fan_in)
        return OZAYN_PCO_ERR_LIMIT_REACHED;

    int slot = _find_edge_slot(svc);
    if (slot < 0) return OZAYN_PCO_ERR_LIMIT_REACHED;

    ozayn_pco_edge_t *e = &svc->edges[slot];
    memcpy(e, edge_def, sizeof(ozayn_pco_edge_t));
    e->active = 1;
    e->created_time = time(NULL);
    strncpy(e->pipeline_id, pipeline_id, OZAYN_PCO_MAX_ID_LEN - 1);

    p->edge_count++;
    svc->edge_count++;
    svc->stats.total_edges_created++;

    *out_edge = e;
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_edge_get(const ozayn_pco_service_t *svc,
                                    const char *pipeline_id,
                                    const char *edge_id,
                                    const ozayn_pco_edge_t **out_edge)
{
    if (!svc || !svc->initialized) return OZAYN_PCO_ERR_NULL;
    if (!pipeline_id || !edge_id || !out_edge)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_edge(svc, pipeline_id, edge_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    *out_edge = &svc->edges[idx];
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_edge_remove(ozayn_pco_service_t *svc,
                                       const char *pipeline_id,
                                       const char *edge_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || !edge_id)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int pidx = _find_pipeline(svc, pipeline_id);
    if (pidx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    int idx = _find_edge(svc, pipeline_id, edge_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    svc->pipelines[pidx].edge_count--;
    svc->edge_count--;
    memset(&svc->edges[idx], 0, sizeof(ozayn_pco_edge_t));
    return OZAYN_PCO_OK;
}

int ozayn_pco_edge_count(const ozayn_pco_service_t *svc,
                          const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return 0;
    int count = 0;
    int total = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0)
            count++;
    }
    return count;
}

ozayn_pco_err_t ozayn_pco_graph_validate(const ozayn_pco_service_t *svc,
                                          const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int pidx = _find_pipeline(svc, pipeline_id);
    if (pidx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_err_t cycle_err = ozayn_pco_graph_check_cycle(svc, pipeline_id);
    if (cycle_err != OZAYN_PCO_OK) return cycle_err;

    int total_edges = svc->config.max_edges * svc->config.max_pipelines;
    for (int i = 0; i < total_edges; i++) {
        if (svc->edges[i].active &&
            strncmp(svc->edges[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (!svc->edges[i].source_stage_id[0])
                return OZAYN_PCO_ERR_GRAPH_INVALID;
            if (!svc->edges[i].destination_stage_id[0])
                return OZAYN_PCO_ERR_GRAPH_INVALID;
        }
    }

    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_graph_check_cycle(const ozayn_pco_service_t *svc,
                                             const char *pipeline_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int total_stages = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total_stages; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            char visited[OZAYN_PCO_MAX_DEP_REFS][OZAYN_PCO_MAX_ID_LEN];
            memset(visited, 0, sizeof(visited));
            if (_has_cycle_dfs(svc, pipeline_id,
                               svc->stages[i].stage_id,
                               (const char *)visited, 0,
                               svc->config.max_stages))
                return OZAYN_PCO_ERR_GRAPH_CYCLE;
        }
    }
    return OZAYN_PCO_OK;
}

/* ============================================================
 * SECTION 7 — FLOW CONTROL
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_flow_get_state(const ozayn_pco_service_t *svc,
                                          const char *pipeline_id,
                                          ozayn_pco_flow_state_t *out_state)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || !out_state) return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    *out_state = svc->pipelines[idx].flow_state;
    return OZAYN_PCO_OK;
}

ozayn_pco_err_t ozayn_pco_flow_set_state(ozayn_pco_service_t *svc,
                                          const char *pipeline_id,
                                          ozayn_pco_flow_state_t new_state)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    if (!pipeline_id || pipeline_id[0] == '\0')
        return OZAYN_PCO_ERR_INVALID_PARAM;
    if (new_state < 0 || new_state >= OZAYN_PCO_FLOW_COUNT)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_pipeline_t *p = &svc->pipelines[idx];

    if (new_state == OZAYN_PCO_FLOW_BACKPRESSURED &&
        p->flow_state != OZAYN_PCO_FLOW_BACKPRESSURED) {
        svc->stats.total_backpressure_events++;
        _emit_event(svc, OZAYN_PCO_EVENT_BACKPRESSURED, p->pipeline_id,
                    NULL, NULL, NULL, "Pipeline backpressured");
    }

    p->flow_state = new_state;
    return OZAYN_PCO_OK;
}

int ozayn_pco_flow_is_blocked(const ozayn_pco_service_t *svc,
                               const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return 0;
    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return 0;
    return svc->pipelines[idx].flow_state == OZAYN_PCO_FLOW_BLOCKED;
}

int ozayn_pco_flow_is_backpressured(const ozayn_pco_service_t *svc,
                                     const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return 0;
    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return 0;
    return svc->pipelines[idx].flow_state == OZAYN_PCO_FLOW_BACKPRESSURED;
}

/* ============================================================
 * SECTION 8 — SYNCHRONIZATION
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_sync_check_stage(const ozayn_pco_service_t *svc,
                                            const char *pipeline_id,
                                            const char *stage_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!pipeline_id || !stage_id) return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_stage(svc, pipeline_id, stage_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    const ozayn_pco_stage_t *s = &svc->stages[idx];
    for (int d = 0; d < s->dependency_count; d++) {
        if (s->dependency_stage_ids[d][0] == '\0') continue;
        int didx = _find_stage(svc, pipeline_id,
                                s->dependency_stage_ids[d]);
        if (didx < 0) return OZAYN_PCO_ERR_DEPENDENCY_FAILED;
        if (svc->stages[didx].state != OZAYN_PCO_STAGE_ACTIVE &&
            svc->stages[didx].state != OZAYN_PCO_STAGE_COMPLETED)
            return OZAYN_PCO_ERR_SYNC_FAILED;
    }
    return OZAYN_PCO_OK;
}

int ozayn_pco_sync_all_stages_ready(const ozayn_pco_service_t *svc,
                                     const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return 0;
    int total = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (svc->stages[i].state != OZAYN_PCO_STAGE_ACTIVE &&
                svc->stages[i].state != OZAYN_PCO_STAGE_COMPLETED)
                return 0;
        }
    }
    return 1;
}

ozayn_pco_err_t ozayn_pco_sync_advance_stage(ozayn_pco_service_t *svc,
                                              const char *pipeline_id,
                                              const char *stage_id)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!pipeline_id || !stage_id) return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_stage(svc, pipeline_id, stage_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    ozayn_pco_stage_t *s = &svc->stages[idx];
    s->sequence_number++;
    s->last_update_time = time(NULL);
    return OZAYN_PCO_OK;
}

/* ============================================================
 * SECTION 9 — QUERY
 * ============================================================ */

const ozayn_pco_pipeline_t *ozayn_pco_pipeline_get(
    const ozayn_pco_service_t *svc, const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return NULL;
    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return NULL;
    return &svc->pipelines[idx];
}

const ozayn_pco_pipeline_t *ozayn_pco_pipeline_get_by_name(
    const ozayn_pco_service_t *svc, const char *name)
{
    if (!svc || !svc->initialized || !name) return NULL;
    for (int i = 0; i < svc->config.max_pipelines; i++) {
        if (svc->pipelines[i].active &&
            strncmp(svc->pipelines[i].name, name,
                    OZAYN_PCO_MAX_NAME_LEN) == 0)
            return &svc->pipelines[i];
    }
    return NULL;
}

int ozayn_pco_pipeline_count(const ozayn_pco_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->pipeline_count;
}

int ozayn_pco_pipeline_count_by_state(const ozayn_pco_service_t *svc,
                                       ozayn_pco_pipeline_state_t state)
{
    if (!svc || !svc->initialized) return 0;
    int count = 0;
    for (int i = 0; i < svc->config.max_pipelines; i++) {
        if (svc->pipelines[i].active && svc->pipelines[i].state == state)
            count++;
    }
    return count;
}

int ozayn_pco_pipeline_is_active(const ozayn_pco_service_t *svc,
                                  const char *pipeline_id)
{
    if (!svc || !svc->initialized || !pipeline_id) return 0;
    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return 0;
    return svc->pipelines[idx].state == OZAYN_PCO_PIPELINE_ACTIVE;
}

ozayn_pco_err_t ozayn_pco_health_get(const ozayn_pco_service_t *svc,
                                      const char *pipeline_id,
                                      int *out_healthy,
                                      int *out_degraded,
                                      int *out_failed)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!pipeline_id) return OZAYN_PCO_ERR_INVALID_PARAM;
    if (!out_healthy || !out_degraded || !out_failed)
        return OZAYN_PCO_ERR_INVALID_PARAM;

    int idx = _find_pipeline(svc, pipeline_id);
    if (idx < 0) return OZAYN_PCO_ERR_NOT_FOUND;

    *out_healthy = 0;
    *out_degraded = 0;
    *out_failed = 0;

    int total = svc->config.max_stages * svc->config.max_pipelines;
    for (int i = 0; i < total; i++) {
        if (svc->stages[i].active &&
            strncmp(svc->stages[i].pipeline_id, pipeline_id,
                    OZAYN_PCO_MAX_ID_LEN) == 0) {
            if (svc->stages[i].is_optional) {
                if (svc->stages[i].state == OZAYN_PCO_STAGE_FAILED ||
                    svc->stages[i].state == OZAYN_PCO_STAGE_UNAVAILABLE)
                    (*out_degraded)++;
                else
                    (*out_healthy)++;
            } else {
                if (svc->stages[i].state == OZAYN_PCO_STAGE_FAILED ||
                    svc->stages[i].state == OZAYN_PCO_STAGE_UNAVAILABLE)
                    (*out_failed)++;
                else
                    (*out_healthy)++;
            }
        }
    }
    return OZAYN_PCO_OK;
}

/* ============================================================
 * SECTION 10 — EVENTS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_emit_event(ozayn_pco_service_t *svc,
                                      ozayn_pco_event_type_t type,
                                      const char *pipeline_id,
                                      const char *stage_id,
                                      const char *route_id,
                                      const char *stream_id,
                                      const char *message)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!svc->initialized) return OZAYN_PCO_ERR_NOT_INITIALIZED;
    _emit_event(svc, type, pipeline_id, stage_id, route_id, stream_id,
                message);
    return OZAYN_PCO_OK;
}

const ozayn_pco_event_t *ozayn_pco_event_get(const ozayn_pco_service_t *svc,
                                              int index)
{
    if (!svc || !svc->initialized) return NULL;
    if (index < 0 || index >= svc->event_count) return NULL;
    int idx = (svc->event_head + index) % OZAYN_PCO_MAX_EVENTS;
    return &svc->events[idx];
}

int ozayn_pco_event_count(const ozayn_pco_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 11 — CLEANUP
 * ============================================================ */

int ozayn_pco_cleanup_expired_pipelines(ozayn_pco_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->config.max_pipelines; i++) {
        if (svc->pipelines[i].active &&
            svc->pipelines[i].expiry_time > 0 &&
            now > svc->pipelines[i].expiry_time) {
            svc->pipelines[i].state = OZAYN_PCO_PIPELINE_EXPIRED;
            svc->pipelines[i].close_reason = OZAYN_PCO_CLOSE_TIMEOUT;
            svc->pipelines[i].closed_time = now;
            svc->pipelines[i].active = 0;
            svc->stats.total_pipelines_expired++;
            svc->stats.current_active_pipelines--;
            cleaned++;
        }
    }
    svc->pipeline_count -= cleaned;
    return cleaned;
}

int ozayn_pco_cleanup_stopped_pipelines(ozayn_pco_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    for (int i = 0; i < svc->config.max_pipelines; i++) {
        if (!svc->pipelines[i].active &&
            _is_pipeline_terminal(svc->pipelines[i].state)) {
            memset(&svc->pipelines[i], 0, sizeof(ozayn_pco_pipeline_t));
            cleaned++;
        }
    }
    return cleaned;
}

int ozayn_pco_cleanup_all(ozayn_pco_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    cleaned += ozayn_pco_cleanup_expired_pipelines(svc);
    cleaned += ozayn_pco_cleanup_stopped_pipelines(svc);
    return cleaned;
}

/* ============================================================
 * SECTION 12 — STATISTICS
 * ============================================================ */

ozayn_pco_err_t ozayn_pco_get_stats(const ozayn_pco_service_t *svc,
                                     ozayn_pco_stats_t *out_stats)
{
    if (!svc) return OZAYN_PCO_ERR_NULL;
    if (!out_stats) return OZAYN_PCO_ERR_NULL;
    *out_stats = svc->stats;
    return OZAYN_PCO_OK;
}

/* ============================================================
 * SECTION 13 — VALIDATION
 * ============================================================ */

int ozayn_pco_pipeline_validate_fields(const ozayn_pco_pipeline_t *pipeline)
{
    if (!pipeline) return 0;
    if (pipeline->pipeline_id[0] == '\0') return 0;
    if (pipeline->state < 0 || pipeline->state >= OZAYN_PCO_PIPELINE_STATE_COUNT)
        return 0;
    if (pipeline->created_time <= 0) return 0;
    return 1;
}

int ozayn_pco_pipeline_request_validate(const ozayn_pco_pipeline_request_t *req)
{
    if (!req) return 0;
    if (!req->requester_ref[0]) return 0;
    if (req->type < 0 || req->type >= OZAYN_PCO_PIPELINE_TYPE_COUNT) return 0;
    return 1;
}

int ozayn_pco_stage_validate(const ozayn_pco_stage_t *stage)
{
    if (!stage) return 0;
    if (stage->stage_id[0] == '\0') return 0;
    if (stage->type < 0 || stage->type >= OZAYN_PCO_STAGE_COUNT) return 0;
    if (stage->state < 0 || stage->state >= OZAYN_PCO_STAGE_STATE_COUNT) return 0;
    return 1;
}

int ozayn_pco_edge_validate(const ozayn_pco_edge_t *edge)
{
    if (!edge) return 0;
    if (edge->edge_id[0] == '\0') return 0;
    if (!edge->source_stage_id[0]) return 0;
    if (!edge->destination_stage_id[0]) return 0;
    return 1;
}

int ozayn_pco_pipeline_state_transition_valid(ozayn_pco_pipeline_state_t from,
                                               ozayn_pco_pipeline_state_t to)
{
    if (from < 0 || from >= OZAYN_PCO_PIPELINE_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_PCO_PIPELINE_STATE_COUNT) return 0;
    return _pipeline_transitions[from][to];
}

int ozayn_pco_stage_state_transition_valid(ozayn_pco_stage_state_t from,
                                            ozayn_pco_stage_state_t to)
{
    if (from < 0 || from >= OZAYN_PCO_STAGE_STATE_COUNT) return 0;
    if (to < 0 || to >= OZAYN_PCO_STAGE_STATE_COUNT) return 0;
    return _stage_transitions[from][to];
}

/* ============================================================
 * SECTION 14 — NAME HELPERS
 * ============================================================ */

const char *ozayn_pco_err_name(ozayn_pco_err_t err)
{
    switch (err) {
    case OZAYN_PCO_OK:                          return "OK";
    case OZAYN_PCO_ERR_NULL:                    return "NULL";
    case OZAYN_PCO_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
    case OZAYN_PCO_ERR_ALREADY_INIT:            return "ALREADY_INIT";
    case OZAYN_PCO_ERR_INVALID_PARAM:           return "INVALID_PARAM";
    case OZAYN_PCO_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
    case OZAYN_PCO_ERR_NOT_FOUND:               return "NOT_FOUND";
    case OZAYN_PCO_ERR_DUPLICATE:               return "DUPLICATE";
    case OZAYN_PCO_ERR_STATE_INVALID:           return "STATE_INVALID";
    case OZAYN_PCO_ERR_AUTH_FAILED:             return "AUTH_FAILED";
    case OZAYN_PCO_ERR_PERMISSION_DENIED:       return "PERMISSION_DENIED";
    case OZAYN_PCO_ERR_UNAVAILABLE:             return "UNAVAILABLE";
    case OZAYN_PCO_ERR_GRAPH_INVALID:           return "GRAPH_INVALID";
    case OZAYN_PCO_ERR_GRAPH_CYCLE:             return "GRAPH_CYCLE";
    case OZAYN_PCO_ERR_DEPENDENCY_FAILED:       return "DEPENDENCY_FAILED";
    case OZAYN_PCO_ERR_ROUTE_INVALID:           return "ROUTE_INVALID";
    case OZAYN_PCO_ERR_ROUTE_NOT_FOUND:         return "ROUTE_NOT_FOUND";
    case OZAYN_PCO_ERR_STREAM_INVALID:          return "STREAM_INVALID";
    case OZAYN_PCO_ERR_STREAM_NOT_FOUND:        return "STREAM_NOT_FOUND";
    case OZAYN_PCO_ERR_STAGE_NOT_FOUND:         return "STAGE_NOT_FOUND";
    case OZAYN_PCO_ERR_ENDPOINT_UNAVAILABLE:    return "ENDPOINT_UNAVAILABLE";
    case OZAYN_PCO_ERR_DEVICE_DISCONNECTED:     return "DEVICE_DISCONNECTED";
    case OZAYN_PCO_ERR_RESOURCE_UNAVAILABLE:    return "RESOURCE_UNAVAILABLE";
    case OZAYN_PCO_ERR_RESOURCE_LIMIT:          return "RESOURCE_LIMIT";
    case OZAYN_PCO_ERR_RESERVATION_FAILED:      return "RESERVATION_FAILED";
    case OZAYN_PCO_ERR_POLICY_DENIED:           return "POLICY_DENIED";
    case OZAYN_PCO_ERR_SAFETY_CHECK_FAILED:     return "SAFETY_CHECK_FAILED";
    case OZAYN_PCO_ERR_SYNC_FAILED:             return "SYNC_FAILED";
    case OZAYN_PCO_ERR_SYNC_TIMEOUT:            return "SYNC_TIMEOUT";
    case OZAYN_PCO_ERR_ORDER_ERROR:             return "ORDER_ERROR";
    case OZAYN_PCO_ERR_BACKPRESSURE:            return "BACKPRESSURE";
    case OZAYN_PCO_ERR_BUFFER_LIMIT:            return "BUFFER_LIMIT";
    case OZAYN_PCO_ERR_RATE_LIMIT:              return "RATE_LIMIT";
    case OZAYN_PCO_ERR_START_FAILED:            return "START_FAILED";
    case OZAYN_PCO_ERR_PAUSE_FAILED:            return "PAUSE_FAILED";
    case OZAYN_PCO_ERR_RESUME_FAILED:           return "RESUME_FAILED";
    case OZAYN_PCO_ERR_DRAIN_FAILED:            return "DRAIN_FAILED";
    case OZAYN_PCO_ERR_DRAIN_TIMEOUT:           return "DRAIN_TIMEOUT";
    case OZAYN_PCO_ERR_STOP_FAILED:             return "STOP_FAILED";
    case OZAYN_PCO_ERR_TIMEOUT:                 return "TIMEOUT";
    case OZAYN_PCO_ERR_EXPIRED:                 return "EXPIRED";
    case OZAYN_PCO_ERR_REVOKED:                 return "REVOKED";
    case OZAYN_PCO_ERR_CANCELLED:               return "CANCELLED";
    case OZAYN_PCO_ERR_CONCURRENCY:             return "CONCURRENCY";
    case OZAYN_PCO_ERR_CONFIGURATION:           return "CONFIGURATION";
    case OZAYN_PCO_ERR_EVENT_ERROR:             return "EVENT_ERROR";
    case OZAYN_PCO_ERR_HISTORY_ERROR:           return "HISTORY_ERROR";
    case OZAYN_PCO_ERR_EXECUTION:               return "EXECUTION";
    default:                                    return "UNKNOWN";
    }
}

const char *ozayn_pco_pipeline_state_name(ozayn_pco_pipeline_state_t state)
{
    switch (state) {
    case OZAYN_PCO_PIPELINE_CREATED:      return "CREATED";
    case OZAYN_PCO_PIPELINE_VALIDATING:   return "VALIDATING";
    case OZAYN_PCO_PIPELINE_AUTHORIZED:   return "AUTHORIZED";
    case OZAYN_PCO_PIPELINE_READY:        return "READY";
    case OZAYN_PCO_PIPELINE_STARTING:     return "STARTING";
    case OZAYN_PCO_PIPELINE_ACTIVE:       return "ACTIVE";
    case OZAYN_PCO_PIPELINE_PAUSING:      return "PAUSING";
    case OZAYN_PCO_PIPELINE_PAUSED:       return "PAUSED";
    case OZAYN_PCO_PIPELINE_RESUMING:     return "RESUMING";
    case OZAYN_PCO_PIPELINE_DRAINING:     return "DRAINING";
    case OZAYN_PCO_PIPELINE_STOPPING:     return "STOPPING";
    case OZAYN_PCO_PIPELINE_STOPPED:      return "STOPPED";
    case OZAYN_PCO_PIPELINE_FAILED:       return "FAILED";
    case OZAYN_PCO_PIPELINE_DEGRADED:     return "DEGRADED";
    case OZAYN_PCO_PIPELINE_EXPIRED:      return "EXPIRED";
    case OZAYN_PCO_PIPELINE_REVOKED:      return "REVOKED";
    case OZAYN_PCO_PIPELINE_UNAVAILABLE:  return "UNAVAILABLE";
    case OZAYN_PCO_PIPELINE_CANCELLED:    return "CANCELLED";
    default:                              return "UNKNOWN";
    }
}

const char *ozayn_pco_pipeline_type_name(ozayn_pco_pipeline_type_t type)
{
    switch (type) {
    case OZAYN_PCO_PIPELINE_TYPE_LINEAR:  return "LINEAR";
    case OZAYN_PCO_PIPELINE_TYPE_FAN_OUT: return "FAN_OUT";
    case OZAYN_PCO_PIPELINE_TYPE_FAN_IN:  return "FAN_IN";
    case OZAYN_PCO_PIPELINE_TYPE_COMPLEX: return "COMPLEX";
    default:                              return "UNKNOWN";
    }
}

const char *ozayn_pco_stage_type_name(ozayn_pco_stage_type_t type)
{
    switch (type) {
    case OZAYN_PCO_STAGE_SOURCE:               return "SOURCE";
    case OZAYN_PCO_STAGE_ROUTE:                return "ROUTE";
    case OZAYN_PCO_STAGE_BUFFER:               return "BUFFER";
    case OZAYN_PCO_STAGE_SYNC:                 return "SYNC";
    case OZAYN_PCO_STAGE_TRANSFORM_BOUNDARY:   return "TRANSFORM_BOUNDARY";
    case OZAYN_PCO_STAGE_DESTINATION:          return "DESTINATION";
    default:                                   return "UNKNOWN";
    }
}

const char *ozayn_pco_stage_state_name(ozayn_pco_stage_state_t state)
{
    switch (state) {
    case OZAYN_PCO_STAGE_CREATED:      return "CREATED";
    case OZAYN_PCO_STAGE_VALIDATING:   return "VALIDATING";
    case OZAYN_PCO_STAGE_READY:        return "READY";
    case OZAYN_PCO_STAGE_STARTING:     return "STARTING";
    case OZAYN_PCO_STAGE_ACTIVE:       return "ACTIVE";
    case OZAYN_PCO_STAGE_PAUSED:       return "PAUSED";
    case OZAYN_PCO_STAGE_DRAINING:     return "DRAINING";
    case OZAYN_PCO_STAGE_COMPLETED:    return "COMPLETED";
    case OZAYN_PCO_STAGE_FAILED:       return "FAILED";
    case OZAYN_PCO_STAGE_UNAVAILABLE:  return "UNAVAILABLE";
    default:                           return "UNKNOWN";
    }
}

const char *ozayn_pco_flow_state_name(ozayn_pco_flow_state_t state)
{
    switch (state) {
    case OZAYN_PCO_FLOW_NORMAL:         return "NORMAL";
    case OZAYN_PCO_FLOW_THROTTLED:      return "THROTTLED";
    case OZAYN_PCO_FLOW_BACKPRESSURED:  return "BACKPRESSURED";
    case OZAYN_PCO_FLOW_DRAINING:       return "DRAINING";
    case OZAYN_PCO_FLOW_BLOCKED:        return "BLOCKED";
    case OZAYN_PCO_FLOW_FAILED:         return "FAILED";
    default:                            return "UNKNOWN";
    }
}

const char *ozayn_pco_event_type_name(ozayn_pco_event_type_t type)
{
    switch (type) {
    case OZAYN_PCO_EVENT_PIPELINE_CREATED:         return "PIPELINE_CREATED";
    case OZAYN_PCO_EVENT_PIPELINE_VALIDATING:      return "PIPELINE_VALIDATING";
    case OZAYN_PCO_EVENT_PIPELINE_AUTHORIZED:      return "PIPELINE_AUTHORIZED";
    case OZAYN_PCO_EVENT_PIPELINE_READY:           return "PIPELINE_READY";
    case OZAYN_PCO_EVENT_PIPELINE_STARTING:        return "PIPELINE_STARTING";
    case OZAYN_PCO_EVENT_PIPELINE_ACTIVE:          return "PIPELINE_ACTIVE";
    case OZAYN_PCO_EVENT_PIPELINE_PAUSING:         return "PIPELINE_PAUSING";
    case OZAYN_PCO_EVENT_PIPELINE_PAUSED:          return "PIPELINE_PAUSED";
    case OZAYN_PCO_EVENT_PIPELINE_RESUMING:        return "PIPELINE_RESUMING";
    case OZAYN_PCO_EVENT_PIPELINE_DRAINING:        return "PIPELINE_DRAINING";
    case OZAYN_PCO_EVENT_PIPELINE_STOPPING:        return "PIPELINE_STOPPING";
    case OZAYN_PCO_EVENT_PIPELINE_STOPPED:         return "PIPELINE_STOPPED";
    case OZAYN_PCO_EVENT_PIPELINE_DEGRADED:        return "PIPELINE_DEGRADED";
    case OZAYN_PCO_EVENT_PIPELINE_FAILED:          return "PIPELINE_FAILED";
    case OZAYN_PCO_EVENT_PIPELINE_EXPIRED:         return "PIPELINE_EXPIRED";
    case OZAYN_PCO_EVENT_PIPELINE_REVOKED:         return "PIPELINE_REVOKED";
    case OZAYN_PCO_EVENT_PIPELINE_CANCELLED:       return "PIPELINE_CANCELLED";
    case OZAYN_PCO_EVENT_STAGE_READY:              return "STAGE_READY";
    case OZAYN_PCO_EVENT_STAGE_STARTED:            return "STAGE_STARTED";
    case OZAYN_PCO_EVENT_STAGE_PAUSED:             return "STAGE_PAUSED";
    case OZAYN_PCO_EVENT_STAGE_COMPLETED:          return "STAGE_COMPLETED";
    case OZAYN_PCO_EVENT_STAGE_FAILED:             return "STAGE_FAILED";
    case OZAYN_PCO_EVENT_BACKPRESSURED:            return "BACKPRESSURED";
    case OZAYN_PCO_EVENT_THROTTLED:                return "THROTTLED";
    case OZAYN_PCO_EVENT_BLOCKED:                  return "BLOCKED";
    case OZAYN_PCO_EVENT_DRAIN_TIMEOUT:            return "DRAIN_TIMEOUT";
    case OZAYN_PCO_EVENT_SYNC_WAIT:                return "SYNC_WAIT";
    case OZAYN_PCO_EVENT_SYNC_READY:               return "SYNC_READY";
    case OZAYN_PCO_EVENT_SYNC_TIMEOUT:             return "SYNC_TIMEOUT";
    case OZAYN_PCO_EVENT_ORDER_ERROR:              return "ORDER_ERROR";
    case OZAYN_PCO_EVENT_RESOURCE_UNAVAILABLE:     return "RESOURCE_UNAVAILABLE";
    case OZAYN_PCO_EVENT_AUTHORIZATION_FAILED:     return "AUTHORIZATION_FAILED";
    case OZAYN_PCO_EVENT_POLICY_DENIED:            return "POLICY_DENIED";
    case OZAYN_PCO_EVENT_DEPENDENCY_FAILED:        return "DEPENDENCY_FAILED";
    case OZAYN_PCO_EVENT_DEVICE_DISCONNECTED:      return "DEVICE_DISCONNECTED";
    case OZAYN_PCO_EVENT_ROUTE_FAILED:             return "ROUTE_FAILED";
    case OZAYN_PCO_EVENT_STREAM_FAILED:            return "STREAM_FAILED";
    default:                                       return "UNKNOWN";
    }
}

const char *ozayn_pco_close_reason_name(ozayn_pco_close_reason_t reason)
{
    switch (reason) {
    case OZAYN_PCO_CLOSE_NONE:                   return "NONE";
    case OZAYN_PCO_CLOSE_MANUAL_STOP:            return "MANUAL_STOP";
    case OZAYN_PCO_CLOSE_DRAIN_COMPLETE:         return "DRAIN_COMPLETE";
    case OZAYN_PCO_CLOSE_DRAIN_TIMEOUT:          return "DRAIN_TIMEOUT";
    case OZAYN_PCO_CLOSE_ROUTE_FAILED:           return "ROUTE_FAILED";
    case OZAYN_PCO_CLOSE_STREAM_FAILED:          return "STREAM_FAILED";
    case OZAYN_PCO_CLOSE_DEVICE_DISCONNECTED:    return "DEVICE_DISCONNECTED";
    case OZAYN_PCO_CLOSE_RESOURCE_EXHAUSTED:     return "RESOURCE_EXHAUSTED";
    case OZAYN_PCO_CLOSE_AUTHORIZATION_EXPIRED:  return "AUTHORIZATION_EXPIRED";
    case OZAYN_PCO_CLOSE_AUTHORIZATION_REVOKED:  return "AUTHORIZATION_REVOKED";
    case OZAYN_PCO_CLOSE_POLICY_CHANGED:         return "POLICY_CHANGED";
    case OZAYN_PCO_CLOSE_SAFETY_REJECTION:       return "SAFETY_REJECTION";
    case OZAYN_PCO_CLOSE_TIMEOUT:                return "TIMEOUT";
    case OZAYN_PCO_CLOSE_EXPIRED:                return "EXPIRED";
    case OZAYN_PCO_CLOSE_SYSTEM_SHUTDOWN:        return "SYSTEM_SHUTDOWN";
    case OZAYN_PCO_CLOSE_STAGE_FAILURE:          return "STAGE_FAILURE";
    case OZAYN_PCO_CLOSE_GRAPH_ERROR:            return "GRAPH_ERROR";
    case OZAYN_PCO_CLOSE_CONCURRENT_ERROR:       return "CONCURRENT_ERROR";
    default:                                     return "UNKNOWN";
    }
}

const char *ozayn_pco_edge_direction_name(ozayn_pco_edge_direction_t dir)
{
    switch (dir) {
    case OZAYN_PCO_EDGE_OUTPUT:        return "OUTPUT";
    case OZAYN_PCO_EDGE_INPUT:         return "INPUT";
    case OZAYN_PCO_EDGE_BIDIRECTIONAL: return "BIDIRECTIONAL";
    default:                           return "UNKNOWN";
    }
}
