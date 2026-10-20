/*
 * operational_status.c — Section 04, Step 29
 * Control Room Integration & Operational Status Consolidation
 */

#include "operational_status.h"
#include "control_room.h"
#include "operational_readiness.h"
#include "diagnostics.h"
#include "operational_metrics.h"
#include "operational_alert.h"
#include "../02_PLATFORM/common/platform_capabilities.h"

#include "runtime.h"
#include "modules.h"
#include "tasks.h"
#include "processes.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static int64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void _copy_str(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    if (!src) src = "";
    snprintf(dst, dst_size, "%s", src);
}

static int _find_component(const ozayn_ost_service_t *svc, const char *id) {
    if (!svc || !id) return -1;
    for (int i = 0; i < svc->component_count; i++) {
        if (strcmp(svc->components[i].id, id) == 0) return i;
    }
    return -1;
}

static void _set_reading(ozayn_ost_reading_t *r,
                         ozayn_ost_state_t state,
                         const char *detail) {
    memset(r, 0, sizeof(*r));
    r->state = state;
    _copy_str(r->detail, sizeof(r->detail), detail);
}

static int _add_component(ozayn_ost_service_t *svc,
                          const char *id,
                          const char *display_name,
                          int required,
                          int builtin,
                          int bound,
                          ozayn_ost_provider_fn provider,
                          void *provider_ctx) {
    if (svc->component_count >= OZAYN_OST_MAX_COMPONENTS) {
        return OZAYN_OST_ERR_FULL;
    }

    ozayn_ost_component_t *c = &svc->components[svc->component_count];
    memset(c, 0, sizeof(*c));
    _copy_str(c->id, sizeof(c->id), id);
    _copy_str(c->display_name, sizeof(c->display_name),
              display_name ? display_name : id);
    c->required = required ? 1 : 0;
    c->builtin = builtin ? 1 : 0;
    c->bound = bound ? 1 : 0;
    c->provider = provider;
    c->provider_ctx = provider_ctx;
    c->state = required ? OZAYN_OST_STATE_UNAVAILABLE : OZAYN_OST_STATE_UNKNOWN;
    _copy_str(c->detail, sizeof(c->detail), "not refreshed");

    svc->component_count++;
    return OZAYN_OST_OK;
}

static void _invalidate_component(ozayn_ost_component_t *c) {
    c->state = c->required ? OZAYN_OST_STATE_UNAVAILABLE : OZAYN_OST_STATE_UNKNOWN;
    _copy_str(c->detail, sizeof(c->detail),
              c->bound ? "binding changed; refresh required"
                       : "source not bound");
    c->last_refresh_ok = 0;
    c->last_success_ms = 0;
}

/* ============================================================
 * BUILT-IN PROVIDERS
 * ============================================================ */

static int _provider_runtime(void *ctx, ozayn_ost_reading_t *r) {
    if (!ctx) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "runtime not bound");
        return 0;
    }

    const ozayn_runtime_t *rt = (const ozayn_runtime_t *)ctx;
    switch (rt->state) {
        case OZAYN_STATE_RUNNING:
            _set_reading(r, OZAYN_OST_STATE_OPERATIONAL, "runtime RUNNING");
            break;
        case OZAYN_STATE_CREATED:
        case OZAYN_STATE_INITIALIZING:
            _set_reading(r, OZAYN_OST_STATE_INITIALIZING, "runtime INITIALIZING");
            break;
        case OZAYN_STATE_STOPPING:
        case OZAYN_STATE_STOPPED:
            _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "runtime STOPPED");
            break;
        case OZAYN_STATE_FAILED:
            _set_reading(r, OZAYN_OST_STATE_ERROR, "runtime FAILED");
            break;
        default:
            _set_reading(r, OZAYN_OST_STATE_UNKNOWN, "runtime state unknown");
            break;
    }
    return 0;
}

static int _provider_modules(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_module_manager_t *mgr = (const ozayn_module_manager_t *)ctx;
    if (!mgr->initialized) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "module manager unavailable");
        return 0;
    }

    int total = ozayn_module_manager_count(mgr);
    int active = ozayn_module_manager_active_count(mgr);
    snprintf(r->detail, sizeof(r->detail), "modules=%d active=%d", total, active);
    r->state = OZAYN_OST_STATE_OPERATIONAL;
    return 0;
}

static int _provider_tasks(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_task_manager_t *mgr = (const ozayn_task_manager_t *)ctx;
    if (!mgr->initialized) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "task manager unavailable");
        return 0;
    }

    snprintf(r->detail, sizeof(r->detail), "active tasks=%d",
             ozayn_task_manager_active_count(mgr));
    r->state = OZAYN_OST_STATE_OPERATIONAL;
    return 0;
}

static int _provider_processes(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_process_manager_t *mgr = (const ozayn_process_manager_t *)ctx;
    if (!mgr->initialized) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "process manager unavailable");
        return 0;
    }

    snprintf(r->detail, sizeof(r->detail), "active processes=%d",
             ozayn_process_manager_active_count(mgr));
    r->state = OZAYN_OST_STATE_OPERATIONAL;
    return 0;
}

static int _provider_control_room(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_cr_service_t *svc = (const ozayn_cr_service_t *)ctx;
    if (!ozayn_cr_service_is_initialized(svc)) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "control room not initialized");
        return 0;
    }

    ozayn_cr_state_t state;
    if (ozayn_cr_get_state(svc, &state) != OZAYN_CR_OK) {
        return 1;
    }

    if (state.lifecycle == OZAYN_CR_LC_ERROR ||
        state.core_state == OZAYN_CR_CORE_STATE_ERROR) {
        _set_reading(r, OZAYN_OST_STATE_ERROR, "control room ERROR");
        return 0;
    }

    switch (state.lifecycle) {
        case OZAYN_CR_LC_READY:
        case OZAYN_CR_LC_ACTIVE:
            r->state = (state.core_state == OZAYN_CR_CORE_STATE_DEGRADED)
                           ? OZAYN_OST_STATE_DEGRADED
                           : OZAYN_OST_STATE_OPERATIONAL;
            snprintf(r->detail, sizeof(r->detail),
                     "control room %s (%s)",
                     ozayn_cr_lifecycle_name(state.lifecycle),
                     ozayn_cr_core_state_name(state.core_state));
            break;
        case OZAYN_CR_LC_INITIALIZING:
            _set_reading(r, OZAYN_OST_STATE_INITIALIZING, "control room INITIALIZING");
            break;
        case OZAYN_CR_LC_UNINITIALIZED:
        case OZAYN_CR_LC_STOPPING:
        case OZAYN_CR_LC_STOPPED:
            _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "control room STOPPED");
            break;
        case OZAYN_CR_LC_ERROR:
            _set_reading(r, OZAYN_OST_STATE_ERROR, "control room ERROR");
            break;
        default:
            _set_reading(r, OZAYN_OST_STATE_UNKNOWN, "control room state unknown");
            break;
    }
    return 0;
}

static int _provider_readiness(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_ord_service_t *svc = (const ozayn_ord_service_t *)ctx;
    if (!svc->initialized) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "readiness unavailable");
        return 0;
    }

    ozayn_ord_mode_t mode = ozayn_ord_get_mode(svc);

    if (ozayn_ord_is_flapping(svc)) {
        _set_reading(r, OZAYN_OST_STATE_DEGRADED, "readiness FLAPPING");
        return 0;
    }

    switch (mode) {
        case OZAYN_ORD_MODE_READY:
            _set_reading(r, OZAYN_OST_STATE_OPERATIONAL, "readiness READY");
            break;
        case OZAYN_ORD_MODE_READY_DEGRADED:
        case OZAYN_ORD_MODE_RECOVERY:
        case OZAYN_ORD_MODE_MAINTENANCE:
        case OZAYN_ORD_MODE_SAFE_HOLD:
            snprintf(r->detail, sizeof(r->detail), "readiness %s",
                     ozayn_ord_mode_name(mode));
            r->state = OZAYN_OST_STATE_DEGRADED;
            break;
        case OZAYN_ORD_MODE_BLOCKED:
        case OZAYN_ORD_MODE_SHUTTING_DOWN:
            snprintf(r->detail, sizeof(r->detail), "readiness %s",
                     ozayn_ord_mode_name(mode));
            r->state = OZAYN_OST_STATE_UNAVAILABLE;
            break;
        case OZAYN_ORD_MODE_FAILED:
            _set_reading(r, OZAYN_OST_STATE_ERROR, "readiness FAILED");
            break;
        case OZAYN_ORD_MODE_INITIALIZING:
        case OZAYN_ORD_MODE_UNKNOWN:
            _set_reading(r, OZAYN_OST_STATE_INITIALIZING, "readiness not ready");
            break;
        default:
            _set_reading(r, OZAYN_OST_STATE_UNKNOWN, "readiness state unknown");
            break;
    }
    return 0;
}

static int _provider_diagnostics(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_dha_service_t *svc = (const ozayn_dha_service_t *)ctx;
    if (!ozayn_dha_service_is_initialized(svc)) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "diagnostics unavailable");
        return 0;
    }

    ozayn_dha_stats_t stats;
    if (ozayn_dha_get_stats(svc, &stats) != OZAYN_DHA_OK) {
        return 1;
    }

    snprintf(r->detail, sizeof(r->detail),
             "assessments=%d findings=%d failures=%llu",
             stats.current_assessments,
             stats.current_findings,
             (unsigned long long)stats.total_failed);
    r->state = (stats.current_findings > 0)
                   ? OZAYN_OST_STATE_DEGRADED
                   : OZAYN_OST_STATE_OPERATIONAL;
    return 0;
}

static int _provider_metrics(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_om_service_t *svc = (const ozayn_om_service_t *)ctx;
    if (!ozayn_om_is_initialized(svc)) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "metrics unavailable");
        return 0;
    }

    ozayn_om_stats_t stats = ozayn_om_get_stats(svc);
    snprintf(r->detail, sizeof(r->detail),
             "metrics=%u snapshots=%u collection_failures=%llu",
             stats.current_metrics,
             stats.current_snapshots,
             (unsigned long long)stats.total_collection_failures);
    r->state = (stats.total_collection_failures > 0 || stats.current_alerts > 0)
                   ? OZAYN_OST_STATE_DEGRADED
                   : OZAYN_OST_STATE_OPERATIONAL;
    return 0;
}

static int _provider_alerts(void *ctx, ozayn_ost_reading_t *r) {
    const ozayn_oan_service_t *svc = (const ozayn_oan_service_t *)ctx;
    if (!ozayn_oan_is_initialized(svc)) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE, "alerts unavailable");
        return 0;
    }

    ozayn_oan_summary_t summary;
    if (ozayn_oan_summary(svc, &summary) != OZAYN_OAN_ERR_OK) {
        return 1;
    }

    snprintf(r->detail, sizeof(r->detail),
             "active=%u critical=%u high=%u medium=%u",
             summary.active_count,
             summary.critical_count,
             summary.high_count,
             summary.medium_count);

    if (summary.critical_count > 0) {
        r->state = OZAYN_OST_STATE_ERROR;
    } else if (summary.high_count > 0 || summary.medium_count > 0) {
        r->state = OZAYN_OST_STATE_DEGRADED;
    } else {
        r->state = OZAYN_OST_STATE_OPERATIONAL;
    }
    return 0;
}

static int _provider_platform(void *ctx, ozayn_ost_reading_t *r) {
    (void)ctx;
    if (!ozayn_platform_capabilities_is_available()) {
        _set_reading(r, OZAYN_OST_STATE_UNAVAILABLE,
                     "platform capability registry unavailable");
        return 0;
    }

    snprintf(r->detail, sizeof(r->detail),
             "platform capabilities registered=%d",
             ozayn_platform_capabilities_get_count());
    r->state = OZAYN_OST_STATE_OPERATIONAL;
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_ost_err_name(ozayn_ost_err_t err) {
    switch (err) {
        case OZAYN_OST_OK:                      return "OK";
        case OZAYN_OST_ERR_NULL:                return "NULL";
        case OZAYN_OST_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
        case OZAYN_OST_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_OST_ERR_INVALID_PARAM:       return "INVALID_PARAM";
        case OZAYN_OST_ERR_NOT_FOUND:           return "NOT_FOUND";
        case OZAYN_OST_ERR_FULL:                return "FULL";
        case OZAYN_OST_ERR_DUPLICATE:           return "DUPLICATE";
        case OZAYN_OST_ERR_CONCURRENCY:         return "CONCURRENCY";
        case OZAYN_OST_ERR_PROVIDER_FAILED:     return "PROVIDER_FAILED";
        case OZAYN_OST_ERR_REFRESH_PARTIAL:     return "REFRESH_PARTIAL";
        case OZAYN_OST_ERR_REFRESH_FAILED:      return "REFRESH_FAILED";
    }
    return "UNKNOWN";
}

const char *ozayn_ost_state_name(ozayn_ost_state_t state) {
    switch (state) {
        case OZAYN_OST_STATE_UNKNOWN:       return "UNKNOWN";
        case OZAYN_OST_STATE_INITIALIZING:  return "INITIALIZING";
        case OZAYN_OST_STATE_OPERATIONAL:   return "OPERATIONAL";
        case OZAYN_OST_STATE_DEGRADED:      return "DEGRADED";
        case OZAYN_OST_STATE_UNAVAILABLE:   return "UNAVAILABLE";
        case OZAYN_OST_STATE_ERROR:         return "ERROR";
        case OZAYN_OST_STATE_COUNT:         break;
    }
    return "UNKNOWN";
}

const char *ozayn_ost_refresh_result_name(ozayn_ost_refresh_result_t result) {
    switch (result) {
        case OZAYN_OST_REFRESH_NONE:    return "NONE";
        case OZAYN_OST_REFRESH_OK:      return "OK";
        case OZAYN_OST_REFRESH_PARTIAL: return "PARTIAL";
        case OZAYN_OST_REFRESH_FAILED:  return "FAILED";
    }
    return "NONE";
}

/* ============================================================
 * OVERALL DERIVATION
 * ============================================================ */

static void _derive_overall(ozayn_ost_service_t *svc) {
    int required_total = 0;
    int required_operational = 0;
    int required_unavailable = 0;
    int required_initializing = 0;
    int required_error = 0;
    int any_error = 0;
    int any_degraded = 0;
    int any_operational = 0;

    for (int i = 0; i < svc->component_count; i++) {
        const ozayn_ost_component_t *c = &svc->components[i];

        if (c->state == OZAYN_OST_STATE_ERROR) any_error = 1;
        if (c->state == OZAYN_OST_STATE_DEGRADED) any_degraded = 1;
        if (c->state == OZAYN_OST_STATE_OPERATIONAL) any_operational = 1;

        if (!c->required) continue;

        required_total++;
        switch (c->state) {
            case OZAYN_OST_STATE_OPERATIONAL:
                required_operational++;
                break;
            case OZAYN_OST_STATE_INITIALIZING:
                required_initializing = 1;
                break;
            case OZAYN_OST_STATE_UNAVAILABLE:
            case OZAYN_OST_STATE_UNKNOWN:
                required_unavailable = 1;
                break;
            case OZAYN_OST_STATE_ERROR:
                required_error = 1;
                break;
            default:
                required_unavailable = 1;
                break;
        }
    }

    if (required_error) {
        svc->overall_state = OZAYN_OST_STATE_ERROR;
    } else if (required_unavailable) {
        svc->overall_state = OZAYN_OST_STATE_UNAVAILABLE;
    } else if (any_error || any_degraded) {
        svc->overall_state = OZAYN_OST_STATE_DEGRADED;
    } else if (required_initializing) {
        svc->overall_state = OZAYN_OST_STATE_INITIALIZING;
    } else if (required_total == 0) {
        svc->overall_state = any_operational ? OZAYN_OST_STATE_OPERATIONAL
                                             : OZAYN_OST_STATE_UNKNOWN;
    } else if (required_operational == required_total) {
        svc->overall_state = OZAYN_OST_STATE_OPERATIONAL;
    } else {
        svc->overall_state = OZAYN_OST_STATE_UNKNOWN;
    }

    snprintf(svc->overall_detail, sizeof(svc->overall_detail),
             "%s: %d/%d required operational, %d components",
             ozayn_ost_state_name(svc->overall_state),
             required_operational,
             required_total,
             svc->component_count);

    svc->warning_count = 0;
    for (int i = 0; i < svc->component_count; i++) {
        const ozayn_ost_component_t *c = &svc->components[i];

        int warn = c->state == OZAYN_OST_STATE_ERROR ||
                   c->state == OZAYN_OST_STATE_DEGRADED ||
                   (c->required &&
                    (c->state == OZAYN_OST_STATE_UNAVAILABLE ||
                     c->state == OZAYN_OST_STATE_UNKNOWN ||
                     c->state == OZAYN_OST_STATE_INITIALIZING));

        if (!warn) continue;
        if (svc->warning_count >= OZAYN_OST_MAX_WARNINGS) break;

        char *w = svc->warnings[svc->warning_count];
        snprintf(w, OZAYN_OST_MAX_DETAIL_LEN, "%.48s: %.200s",
                 c->id, c->detail[0] ? c->detail
                                     : ozayn_ost_state_name(c->state));
        svc->warning_count++;
    }
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_init(ozayn_ost_service_t *svc,
                               const ozayn_ost_config_t *cfg) {
    if (!svc) return OZAYN_OST_ERR_NULL;
    if (svc->initialized) return OZAYN_OST_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));
    svc->overall_state = OZAYN_OST_STATE_UNKNOWN;
    _copy_str(svc->overall_detail, sizeof(svc->overall_detail),
              "not refreshed");

    if (!cfg) {
        return OZAYN_OST_ERR_INVALID_PARAM;
    }

    int rc = OZAYN_OST_OK;
    rc = _add_component(svc, OZAYN_OST_ID_RUNTIME, "Core Runtime", 1, 1,
                        cfg->runtime != NULL, _provider_runtime, cfg->runtime);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_MODULES, "Module Manager", 0, 1,
                        cfg->module_manager != NULL, _provider_modules,
                        cfg->module_manager);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_TASKS, "Task Manager", 0, 1,
                        cfg->task_manager != NULL, _provider_tasks,
                        cfg->task_manager);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_PROCESSES, "Process Manager", 0, 1,
                        cfg->process_manager != NULL, _provider_processes,
                        cfg->process_manager);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_CONTROL_ROOM, "Control Room", 1, 1,
                        cfg->control_room != NULL, _provider_control_room,
                        cfg->control_room);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_READINESS, "Operational Readiness", 0, 1,
                        cfg->operational_readiness != NULL, _provider_readiness,
                        cfg->operational_readiness);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_DIAGNOSTICS, "Diagnostics", 0, 1,
                        cfg->diagnostics != NULL, _provider_diagnostics,
                        cfg->diagnostics);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_METRICS, "Operational Metrics", 0, 1,
                        cfg->operational_metrics != NULL, _provider_metrics,
                        cfg->operational_metrics);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_ALERTS, "Operational Alerts", 0, 1,
                        cfg->operational_alert != NULL, _provider_alerts,
                        cfg->operational_alert);
    if (rc != OZAYN_OST_OK) return rc;

    rc = _add_component(svc, OZAYN_OST_ID_PLATFORM, "Platform Capabilities", 0, 1,
                        cfg->include_platform != 0, _provider_platform, NULL);
    if (rc != OZAYN_OST_OK) return rc;

    svc->refresh_result = OZAYN_OST_REFRESH_NONE;
    svc->initialized = 1;
    return OZAYN_OST_OK;
}

ozayn_ost_err_t ozayn_ost_shutdown(ozayn_ost_service_t *svc) {
    if (!svc) return OZAYN_OST_ERR_NULL;
    if (!svc->initialized) return OZAYN_OST_ERR_NOT_INITIALIZED;

    memset(svc, 0, sizeof(*svc));
    return OZAYN_OST_OK;
}

int ozayn_ost_is_initialized(const ozayn_ost_service_t *svc) {
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SUBSYSTEM BINDING
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_bind(ozayn_ost_service_t *svc,
                               const ozayn_ost_config_t *cfg) {
    if (!svc || !cfg) return OZAYN_OST_ERR_NULL;
    if (!svc->initialized) return OZAYN_OST_ERR_NOT_INITIALIZED;
    if (svc->refresh_in_progress) return OZAYN_OST_ERR_CONCURRENCY;

    struct {
        const char *id;
        void *ctx;
        int bound;
    } bindings[] = {
        { OZAYN_OST_ID_RUNTIME,      cfg->runtime,              cfg->runtime != NULL },
        { OZAYN_OST_ID_MODULES,      cfg->module_manager,       cfg->module_manager != NULL },
        { OZAYN_OST_ID_TASKS,        cfg->task_manager,         cfg->task_manager != NULL },
        { OZAYN_OST_ID_PROCESSES,    cfg->process_manager,      cfg->process_manager != NULL },
        { OZAYN_OST_ID_CONTROL_ROOM, cfg->control_room,         cfg->control_room != NULL },
        { OZAYN_OST_ID_READINESS,    cfg->operational_readiness, cfg->operational_readiness != NULL },
        { OZAYN_OST_ID_DIAGNOSTICS,  cfg->diagnostics,          cfg->diagnostics != NULL },
        { OZAYN_OST_ID_METRICS,      cfg->operational_metrics,  cfg->operational_metrics != NULL },
        { OZAYN_OST_ID_ALERTS,       cfg->operational_alert,    cfg->operational_alert != NULL },
        { OZAYN_OST_ID_PLATFORM,     NULL,                      cfg->include_platform != 0 }
    };

    int changed = 0;
    for (size_t i = 0; i < sizeof(bindings) / sizeof(bindings[0]); i++) {
        int idx = _find_component(svc, bindings[i].id);
        if (idx < 0) continue;

        ozayn_ost_component_t *c = &svc->components[idx];
        if (c->provider_ctx == bindings[i].ctx && c->bound == bindings[i].bound) {
            continue;
        }

        c->provider_ctx = bindings[i].ctx;
        c->bound = bindings[i].bound;
        _invalidate_component(c);
        changed = 1;
    }

    if (changed) {
        svc->overall_state = OZAYN_OST_STATE_UNKNOWN;
        _copy_str(svc->overall_detail, sizeof(svc->overall_detail),
                  "binding changed; refresh required");
        svc->warning_count = 0;
    }

    return OZAYN_OST_OK;
}

/* ============================================================
 * COMPONENT REGISTRATION
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_register_component(
    ozayn_ost_service_t *svc,
    const char *component_id,
    const char *display_name,
    int required,
    ozayn_ost_provider_fn provider,
    void *provider_ctx) {
    if (!svc || !component_id || !provider) return OZAYN_OST_ERR_NULL;
    if (!svc->initialized) return OZAYN_OST_ERR_NOT_INITIALIZED;
    if (svc->refresh_in_progress) return OZAYN_OST_ERR_CONCURRENCY;
    if (!component_id[0] || strlen(component_id) >= OZAYN_OST_MAX_ID_LEN) {
        return OZAYN_OST_ERR_INVALID_PARAM;
    }
    if (_find_component(svc, component_id) >= 0) {
        return OZAYN_OST_ERR_DUPLICATE;
    }
    if (svc->component_count >= OZAYN_OST_MAX_COMPONENTS) {
        return OZAYN_OST_ERR_FULL;
    }

    ozayn_ost_err_t rc = (ozayn_ost_err_t)_add_component(
        svc, component_id, display_name, required, 0, 1, provider, provider_ctx);
    if (rc == OZAYN_OST_OK) {
        ozayn_ost_component_t *c = &svc->components[svc->component_count - 1];
        c->state = OZAYN_OST_STATE_UNKNOWN;
        _copy_str(c->detail, sizeof(c->detail), "not refreshed");
    }
    return rc;
}

ozayn_ost_err_t ozayn_ost_get_component(
    const ozayn_ost_service_t *svc,
    const char *component_id,
    ozayn_ost_component_status_t *out_status) {
    if (!svc || !component_id || !out_status) return OZAYN_OST_ERR_NULL;
    if (!svc->initialized) return OZAYN_OST_ERR_NOT_INITIALIZED;

    int idx = _find_component(svc, component_id);
    if (idx < 0) return OZAYN_OST_ERR_NOT_FOUND;

    const ozayn_ost_component_t *c = &svc->components[idx];
    memset(out_status, 0, sizeof(*out_status));
    _copy_str(out_status->id, sizeof(out_status->id), c->id);
    _copy_str(out_status->display_name, sizeof(out_status->display_name),
              c->display_name);
    _copy_str(out_status->detail, sizeof(out_status->detail), c->detail);
    out_status->state = c->state;
    out_status->required = c->required;
    out_status->bound = c->bound;
    out_status->last_refresh_ok = c->last_refresh_ok;
    out_status->last_refresh_ms = c->last_refresh_ms;
    out_status->last_success_ms = c->last_success_ms;
    out_status->refresh_attempts = c->refresh_attempts;
    out_status->refresh_failures = c->refresh_failures;
    return OZAYN_OST_OK;
}

int ozayn_ost_component_count(const ozayn_ost_service_t *svc) {
    if (!svc || !svc->initialized) return 0;
    return svc->component_count;
}

/* ============================================================
 * REFRESH
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_refresh(ozayn_ost_service_t *svc) {
    if (!svc) return OZAYN_OST_ERR_NULL;
    if (!svc->initialized) return OZAYN_OST_ERR_NOT_INITIALIZED;
    if (svc->refresh_in_progress) {
        svc->rejected_refresh_count++;
        return OZAYN_OST_ERR_CONCURRENCY;
    }

    svc->refresh_in_progress = 1;

    int64_t now = _now_ms();
    int attempted = 0;
    int failures = 0;

    for (int i = 0; i < svc->component_count; i++) {
        ozayn_ost_component_t *c = &svc->components[i];

        if (c->builtin && !c->bound) {
            c->state = c->required ? OZAYN_OST_STATE_UNAVAILABLE
                                   : OZAYN_OST_STATE_UNKNOWN;
            _copy_str(c->detail, sizeof(c->detail), "source not bound");
            c->last_refresh_ms = now;
            c->last_refresh_ok = 1;
            continue;
        }

        if (!c->provider) continue;

        ozayn_ost_reading_t reading;
        memset(&reading, 0, sizeof(reading));

        c->refresh_attempts++;
        attempted++;

        int provider_rc = c->provider(c->provider_ctx, &reading);
        if (provider_rc != 0 ||
            reading.state < OZAYN_OST_STATE_UNKNOWN ||
            reading.state >= OZAYN_OST_STATE_COUNT) {
            failures++;
            c->refresh_failures++;
            c->last_refresh_ms = now;
            c->last_refresh_ok = 0;
            continue;
        }

        reading.detail[sizeof(reading.detail) - 1] = '\0';
        c->state = reading.state;
        _copy_str(c->detail, sizeof(c->detail), reading.detail);
        c->last_refresh_ms = now;
        c->last_success_ms = now;
        c->last_refresh_ok = 1;
    }

    _derive_overall(svc);

    svc->generation++;
    svc->refresh_count++;
    svc->last_refresh_ms = now;

    if (failures == 0) {
        svc->refresh_result = OZAYN_OST_REFRESH_OK;
        svc->last_successful_refresh_ms = now;
    } else if (attempted > 0 && failures == attempted) {
        svc->refresh_result = OZAYN_OST_REFRESH_FAILED;
        svc->failed_refresh_count++;
    } else {
        svc->refresh_result = OZAYN_OST_REFRESH_PARTIAL;
        svc->partial_refresh_count++;
    }

    svc->refresh_in_progress = 0;

    if (svc->refresh_result == OZAYN_OST_REFRESH_FAILED) {
        return OZAYN_OST_ERR_REFRESH_FAILED;
    }
    if (svc->refresh_result == OZAYN_OST_REFRESH_PARTIAL) {
        return OZAYN_OST_ERR_REFRESH_PARTIAL;
    }
    return OZAYN_OST_OK;
}

/* ============================================================
 * SNAPSHOT / QUERY
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_get_snapshot(
    const ozayn_ost_service_t *svc,
    ozayn_ost_snapshot_t *out_snapshot) {
    if (!svc || !out_snapshot) return OZAYN_OST_ERR_NULL;
    if (!svc->initialized) return OZAYN_OST_ERR_NOT_INITIALIZED;

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->overall_state = svc->overall_state;
    _copy_str(out_snapshot->overall_detail,
              sizeof(out_snapshot->overall_detail), svc->overall_detail);
    out_snapshot->generation = svc->generation;
    out_snapshot->refreshed_at_ms = svc->last_refresh_ms;
    out_snapshot->last_successful_refresh_ms = svc->last_successful_refresh_ms;
    out_snapshot->refresh_result = svc->refresh_result;
    out_snapshot->refresh_count = svc->refresh_count;
    out_snapshot->partial_refresh_count = svc->partial_refresh_count;
    out_snapshot->failed_refresh_count = svc->failed_refresh_count;
    out_snapshot->rejected_refresh_count = svc->rejected_refresh_count;
    out_snapshot->component_count = svc->component_count;
    out_snapshot->warning_count = svc->warning_count;

    for (int i = 0; i < svc->component_count; i++) {
        const ozayn_ost_component_t *c = &svc->components[i];
        ozayn_ost_component_status_t *d = &out_snapshot->components[i];

        _copy_str(d->id, sizeof(d->id), c->id);
        _copy_str(d->display_name, sizeof(d->display_name), c->display_name);
        _copy_str(d->detail, sizeof(d->detail), c->detail);
        d->state = c->state;
        d->required = c->required;
        d->bound = c->bound;
        d->last_refresh_ok = c->last_refresh_ok;
        d->last_refresh_ms = c->last_refresh_ms;
        d->last_success_ms = c->last_success_ms;
        d->refresh_attempts = c->refresh_attempts;
        d->refresh_failures = c->refresh_failures;
    }

    for (int i = 0; i < svc->warning_count; i++) {
        _copy_str(out_snapshot->warnings[i],
                  sizeof(out_snapshot->warnings[i]), svc->warnings[i]);
    }

    return OZAYN_OST_OK;
}

ozayn_ost_state_t ozayn_ost_overall_state(const ozayn_ost_service_t *svc) {
    if (!svc || !svc->initialized) return OZAYN_OST_STATE_UNKNOWN;
    return svc->overall_state;
}
