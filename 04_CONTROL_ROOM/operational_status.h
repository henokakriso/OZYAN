/*
 * operational_status.h — Section 04, Step 29
 * Control Room Integration & Operational Status Consolidation
 *
 * Consolidates read-only status from Core, Platform and Control Room
 * subsystems into one bounded operational status snapshot.
 *
 * This module does NOT:
 *   - execute commands or remediation
 *   - create, grant or replace authorization
 *   - modify subsystem state
 *   - expose secrets, tokens, keys or environment data
 *   - perform network telemetry
 */

#ifndef OZAYN_OPERATIONAL_STATUS_H
#define OZAYN_OPERATIONAL_STATUS_H

#include <stdint.h>

/* ============================================================
 * LIMITS
 * ============================================================ */

#define OZAYN_OST_MAX_COMPONENTS      16
#define OZAYN_OST_MAX_ID_LEN          64
#define OZAYN_OST_MAX_NAME_LEN        64
#define OZAYN_OST_MAX_DETAIL_LEN     256
#define OZAYN_OST_MAX_WARNINGS         8

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_OST_OK                        =   0,
    OZAYN_OST_ERR_NULL                  =  -1,
    OZAYN_OST_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_OST_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_OST_ERR_INVALID_PARAM         =  -4,
    OZAYN_OST_ERR_NOT_FOUND             =  -5,
    OZAYN_OST_ERR_FULL                  =  -6,
    OZAYN_OST_ERR_DUPLICATE             =  -7,
    OZAYN_OST_ERR_CONCURRENCY           =  -8,
    OZAYN_OST_ERR_PROVIDER_FAILED       =  -9,
    OZAYN_OST_ERR_REFRESH_PARTIAL       = -10,
    OZAYN_OST_ERR_REFRESH_FAILED        = -11
} ozayn_ost_err_t;

/* ============================================================
 * OPERATIONAL STATES
 * ============================================================ */

typedef enum {
    OZAYN_OST_STATE_UNKNOWN         = 0,
    OZAYN_OST_STATE_INITIALIZING    = 1,
    OZAYN_OST_STATE_OPERATIONAL     = 2,
    OZAYN_OST_STATE_DEGRADED        = 3,
    OZAYN_OST_STATE_UNAVAILABLE     = 4,
    OZAYN_OST_STATE_ERROR           = 5,
    OZAYN_OST_STATE_COUNT
} ozayn_ost_state_t;

/* ============================================================
 * REFRESH RESULT
 * ============================================================ */

typedef enum {
    OZAYN_OST_REFRESH_NONE      = 0,
    OZAYN_OST_REFRESH_OK        = 1,
    OZAYN_OST_REFRESH_PARTIAL   = 2,
    OZAYN_OST_REFRESH_FAILED    = 3
} ozayn_ost_refresh_result_t;

/* ============================================================
 * CANONICAL COMPONENT IDENTIFIERS
 * ============================================================ */

#define OZAYN_OST_ID_RUNTIME        "core.runtime"
#define OZAYN_OST_ID_MODULES        "core.modules"
#define OZAYN_OST_ID_TASKS          "core.tasks"
#define OZAYN_OST_ID_PROCESSES      "core.processes"
#define OZAYN_OST_ID_CONTROL_ROOM   "control.room"
#define OZAYN_OST_ID_READINESS      "control.readiness"
#define OZAYN_OST_ID_DIAGNOSTICS    "control.diagnostics"
#define OZAYN_OST_ID_METRICS        "control.metrics"
#define OZAYN_OST_ID_ALERTS         "control.alerts"
#define OZAYN_OST_ID_PLATFORM       "platform.capabilities"

/* ============================================================
 * PROVIDER INTERFACE
 *
 * Providers are read-only status readers. They return 0 on success.
 * A non-zero return means the reading failed; the last valid reading
 * is preserved by the service.
 * ============================================================ */

typedef struct {
    ozayn_ost_state_t state;
    char detail[OZAYN_OST_MAX_DETAIL_LEN];
} ozayn_ost_reading_t;

typedef int (*ozayn_ost_provider_fn)(void *ctx, ozayn_ost_reading_t *out_reading);

/* ============================================================
 * COMPONENT
 * ============================================================ */

typedef struct {
    char                    id[OZAYN_OST_MAX_ID_LEN];
    char                    display_name[OZAYN_OST_MAX_NAME_LEN];
    int                     required;
    int                     builtin;
    int                     bound;
    ozayn_ost_provider_fn   provider;
    void                   *provider_ctx;

    ozayn_ost_state_t       state;
    char                    detail[OZAYN_OST_MAX_DETAIL_LEN];

    int64_t                 last_refresh_ms;
    int64_t                 last_success_ms;
    int                     last_refresh_ok;
    uint64_t                refresh_attempts;
    uint64_t                refresh_failures;
} ozayn_ost_component_t;

/* ============================================================
 * CONFIGURATION / SUBSYSTEM BINDINGS
 * ============================================================ */

typedef struct {
    void *runtime;
    void *module_manager;
    void *task_manager;
    void *process_manager;
    void *control_room;
    void *operational_readiness;
    void *diagnostics;
    void *operational_metrics;
    void *operational_alert;
    int   include_platform;
} ozayn_ost_config_t;

/* ============================================================
 * COMPONENT STATUS VIEW
 * ============================================================ */

typedef struct {
    char                    id[OZAYN_OST_MAX_ID_LEN];
    char                    display_name[OZAYN_OST_MAX_NAME_LEN];
    ozayn_ost_state_t       state;
    char                    detail[OZAYN_OST_MAX_DETAIL_LEN];
    int                     required;
    int                     bound;
    int                     last_refresh_ok;
    int64_t                 last_refresh_ms;
    int64_t                 last_success_ms;
    uint64_t                refresh_attempts;
    uint64_t                refresh_failures;
} ozayn_ost_component_status_t;

/* ============================================================
 * SNAPSHOT
 * ============================================================ */

typedef struct {
    ozayn_ost_state_t           overall_state;
    char                        overall_detail[OZAYN_OST_MAX_DETAIL_LEN];

    uint64_t                    generation;
    int64_t                     refreshed_at_ms;
    int64_t                     last_successful_refresh_ms;
    ozayn_ost_refresh_result_t  refresh_result;

    int                         component_count;
    ozayn_ost_component_status_t components[OZAYN_OST_MAX_COMPONENTS];

    int                         warning_count;
    char                        warnings[OZAYN_OST_MAX_WARNINGS][OZAYN_OST_MAX_DETAIL_LEN];

    uint64_t                    refresh_count;
    uint64_t                    partial_refresh_count;
    uint64_t                    failed_refresh_count;
    uint64_t                    rejected_refresh_count;
} ozayn_ost_snapshot_t;

/* ============================================================
 * SERVICE
 * ============================================================ */

typedef struct {
    int                         initialized;
    int                         refresh_in_progress;

    uint64_t                    generation;
    uint64_t                    refresh_count;
    uint64_t                    partial_refresh_count;
    uint64_t                    failed_refresh_count;
    uint64_t                    rejected_refresh_count;

    int64_t                     last_refresh_ms;
    int64_t                     last_successful_refresh_ms;
    ozayn_ost_refresh_result_t  refresh_result;

    ozayn_ost_state_t           overall_state;
    char                        overall_detail[OZAYN_OST_MAX_DETAIL_LEN];

    int                         component_count;
    ozayn_ost_component_t       components[OZAYN_OST_MAX_COMPONENTS];

    int                         warning_count;
    char                        warnings[OZAYN_OST_MAX_WARNINGS][OZAYN_OST_MAX_DETAIL_LEN];
} ozayn_ost_service_t;

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_ost_err_name(ozayn_ost_err_t err);
const char *ozayn_ost_state_name(ozayn_ost_state_t state);
const char *ozayn_ost_refresh_result_name(ozayn_ost_refresh_result_t result);

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_init(ozayn_ost_service_t *svc,
                               const ozayn_ost_config_t *cfg);
ozayn_ost_err_t ozayn_ost_shutdown(ozayn_ost_service_t *svc);
int             ozayn_ost_is_initialized(const ozayn_ost_service_t *svc);

/* ============================================================
 * SUBSYSTEM BINDING
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_bind(ozayn_ost_service_t *svc,
                               const ozayn_ost_config_t *cfg);

/* ============================================================
 * COMPONENT REGISTRATION
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_register_component(
    ozayn_ost_service_t *svc,
    const char *component_id,
    const char *display_name,
    int required,
    ozayn_ost_provider_fn provider,
    void *provider_ctx);

ozayn_ost_err_t ozayn_ost_get_component(
    const ozayn_ost_service_t *svc,
    const char *component_id,
    ozayn_ost_component_status_t *out_status);

int ozayn_ost_component_count(const ozayn_ost_service_t *svc);

/* ============================================================
 * REFRESH / QUERY
 * ============================================================ */

ozayn_ost_err_t ozayn_ost_refresh(ozayn_ost_service_t *svc);

ozayn_ost_err_t ozayn_ost_get_snapshot(
    const ozayn_ost_service_t *svc,
    ozayn_ost_snapshot_t *out_snapshot);

ozayn_ost_state_t ozayn_ost_overall_state(const ozayn_ost_service_t *svc);

#endif /* OZAYN_OPERATIONAL_STATUS_H */
