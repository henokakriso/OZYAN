#ifndef OZAYN_SEC_DIAG_H
#define OZAYN_SEC_DIAG_H

#include "sec_health.h"
#include "sec_config.h"
#include "incident.h"
#include "backup.h"
#include "deletion.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * sec_diag.h — Security Diagnostics & Self-Diagnostics Foundation
 *              (Step 28).
 *
 * Provides structured diagnostic evaluation explaining WHY security
 * components are healthy or unhealthy, with dependency graph analysis,
 * cycle detection, result freshness, and resource controls.
 *
 * Naming: All types/functions use ozayn_sdiag_ prefix to avoid
 * collision with existing ozayn_sd_* (secure data) types.
 */

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_OK                              =   0,
    OZAYN_SDIAG_ERR                             =  -1,
    OZAYN_SDIAG_ERR_NULL                        =  -2,
    OZAYN_SDIAG_ERR_NOT_INITIALIZED             =  -3,
    OZAYN_SDIAG_ERR_ALREADY_INITIALIZED         =  -4,
    OZAYN_SDIAG_ERR_INVALID_REQUEST             =  -5,
    OZAYN_SDIAG_ERR_INVALID_COMPONENT           =  -6,
    OZAYN_SDIAG_ERR_INVALID_CHECK               =  -7,
    OZAYN_SDIAG_ERR_NOT_FOUND                   =  -8,
    OZAYN_SDIAG_ERR_UNAVAILABLE                 =  -9,
    OZAYN_SDIAG_ERR_FAILED                      = -10,
    OZAYN_SDIAG_ERR_TIMEOUT                     = -11,
    OZAYN_SDIAG_ERR_UNSUPPORTED                 = -12,
    OZAYN_SDIAG_ERR_POLICY_INVALID              = -13,
    OZAYN_SDIAG_ERR_DEPENDENCY_FAILED           = -14,
    OZAYN_SDIAG_ERR_INTEGRITY_FAILED            = -15,
    OZAYN_SDIAG_ERR_RESOURCE_LIMIT              = -16,
    OZAYN_SDIAG_ERR_CONCURRENCY_CONFLICT        = -17,
    OZAYN_SDIAG_ERR_ACCESS_DENIED               = -18,
    OZAYN_SDIAG_ERR_RESULT_STALE                = -19,
    OZAYN_SDIAG_ERR_RECURSION                   = -20,
    OZAYN_SDIAG_ERR_UNSAFE_OPERATION            = -21
} ozayn_sdiag_err_t;

/* ============================================================
 * SECTION 2 — DIAGNOSTIC RESULT STATES
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_STATE_PASS                      = 0,
    OZAYN_SDIAG_STATE_WARNING                   = 1,
    OZAYN_SDIAG_STATE_FAIL                      = 2,
    OZAYN_SDIAG_STATE_UNAVAILABLE               = 3,
    OZAYN_SDIAG_STATE_NOT_SUPPORTED             = 4,
    OZAYN_SDIAG_STATE_SKIPPED                   = 5,
    OZAYN_SDIAG_STATE_UNKNOWN                   = 6
} ozayn_sdiag_state_t;

/* ============================================================
 * SECTION 3 — DIAGNOSTIC SEVERITY
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_SEV_INFO                        = 0,
    OZAYN_SDIAG_SEV_LOW                         = 1,
    OZAYN_SDIAG_SEV_MEDIUM                      = 2,
    OZAYN_SDIAG_SEV_HIGH                        = 3,
    OZAYN_SDIAG_SEV_CRITICAL                    = 4
} ozayn_sdiag_severity_t;

/* ============================================================
 * SECTION 4 — DIAGNOSTIC CHECK CATEGORIES
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_CAT_CONFIGURATION               =  0,
    OZAYN_SDIAG_CAT_POLICY                      =  1,
    OZAYN_SDIAG_CAT_AVAILABILITY                =  2,
    OZAYN_SDIAG_CAT_DEPENDENCY                  =  3,
    OZAYN_SDIAG_CAT_INTEGRITY                   =  4,
    OZAYN_SDIAG_CAT_STORAGE                     =  5,
    OZAYN_SDIAG_CAT_KEY                         =  6,
    OZAYN_SDIAG_CAT_PROTECTION                  =  7,
    OZAYN_SDIAG_CAT_AUTHENTICATION              =  8,
    OZAYN_SDIAG_CAT_AUTHORIZATION               =  9,
    OZAYN_SDIAG_CAT_AUDIT                       = 10,
    OZAYN_SDIAG_CAT_BACKUP                      = 11,
    OZAYN_SDIAG_CAT_RECOVERY                    = 12,
    OZAYN_SDIAG_CAT_DELETION                    = 13,
    OZAYN_SDIAG_CAT_INCIDENT_RESPONSE           = 14,
    OZAYN_SDIAG_CAT_RESOURCE                    = 15
} ozayn_sdiag_category_t;

/* ============================================================
 * SECTION 5 — DIAGNOSTIC MODES
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_MODE_READ_ONLY                  = 0,
    OZAYN_SDIAG_MODE_STANDARD                   = 1,
    OZAYN_SDIAG_MODE_DEEP                       = 2,
    OZAYN_SDIAG_MODE_TEST                       = 3
} ozayn_sdiag_mode_t;

/* ============================================================
 * SECTION 6 — DIAGNOSTIC COST
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_COST_LOW                        = 0,
    OZAYN_SDIAG_COST_MEDIUM                     = 1,
    OZAYN_SDIAG_COST_HIGH                       = 2
} ozayn_sdiag_cost_t;

/* ============================================================
 * SECTION 7 — RECOMMENDATION CODES
 * ============================================================ */

typedef enum {
    OZAYN_SDIAG_REC_NONE                        = 0,
    OZAYN_SDIAG_REC_RELOAD_CONFIGURATION        = 1,
    OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY       = 2,
    OZAYN_SDIAG_REC_CHECK_PLATFORM_KEY_STORE    = 3,
    OZAYN_SDIAG_REC_VERIFY_STORAGE              = 4,
    OZAYN_SDIAG_REC_ROTATE_COMPROMISED_KEY      = 5,
    OZAYN_SDIAG_REC_RUN_BACKUP_VALIDATION       = 6,
    OZAYN_SDIAG_REC_REVIEW_SECURITY_INCIDENT    = 7,
    OZAYN_SDIAG_REC_CHECK_IDENTITY_SERVICE      = 8,
    OZAYN_SDIAG_REC_REAUTHENTICATE              = 9,
    OZAYN_SDIAG_REC_CHECK_AUDIT_INTEGRITY       = 10,
    OZAYN_SDIAG_REC_CHECK_DELETION_POLICY       = 11,
    OZAYN_SDIAG_REC_VERIFY_PROTECTION           = 12,
    OZAYN_SDIAG_REC_CHECK_KEY_LIFECYCLE         = 13,
    OZAYN_SDIAG_REC_CHECK_SESSION_POLICY        = 14,
    OZAYN_SDIAG_REC_CHECK_VAULT_DEPENDENCIES    = 15
} ozayn_sdiag_recommendation_t;

/* ============================================================
 * SECTION 8 — DIAGNOSTIC CHECK MODEL
 * ============================================================ */

#define OZAYN_SDIAG_MAX_CHECKS             64
#define OZAYN_SDIAG_MAX_CHECK_NAME_LEN     48

typedef struct {
    uint32_t                    check_id;
    char                        check_name[OZAYN_SDIAG_MAX_CHECK_NAME_LEN];
    ozayn_sh_component_id_t     component;
    ozayn_sdiag_category_t      category;
    ozayn_sdiag_severity_t      severity;
    ozayn_sdiag_cost_t          cost;
    ozayn_sdiag_mode_t          required_mode;
    int                         enabled;
} ozayn_sdiag_check_t;

/* ============================================================
 * SECTION 9 — DIAGNOSTIC RESULT MODEL
 * ============================================================ */

#define OZAYN_SDIAG_MAX_RESULTS          256
#define OZAYN_SDIAG_MAX_RESULT_DETAIL    192

typedef struct {
    uint32_t                    result_id;
    uint32_t                    check_id;
    ozayn_sh_component_id_t     component;
    ozayn_sdiag_state_t         state;
    ozayn_sdiag_severity_t      severity;
    time_t                      timestamp;
    int                         failure_code;
    ozayn_sdiag_recommendation_t recommendation;
    char                        detail[OZAYN_SDIAG_MAX_RESULT_DETAIL];
    int                         dependency_count;
    ozayn_sh_component_id_t     dependencies[8];
} ozayn_sdiag_result_t;

/* ============================================================
 * SECTION 10 — DIAGNOSTIC SUMMARY
 * ============================================================ */

typedef struct {
    ozayn_sdiag_state_t         overall_state;
    int                         pass_count;
    int                         warning_count;
    int                         fail_count;
    int                         unavailable_count;
    int                         not_supported_count;
    int                         skipped_count;
    int                         unknown_count;
    int                         critical_count;
    ozayn_sdiag_recommendation_t top_recommendation;
    uint64_t                    evaluation_time_ms;
} ozayn_sdiag_summary_t;

/* ============================================================
 * SECTION 11 — DIAGNOSTIC PROVIDER
 * ============================================================ */

typedef struct {
    int (*run_check)(const void *provider_ctx,
                     const ozayn_sdiag_check_t *check,
                     ozayn_sdiag_result_t *out_result);
    const char *(*get_name)(const void *provider_ctx);
} ozayn_sdiag_provider_vtable_t;

typedef struct {
    const ozayn_sdiag_provider_vtable_t *vtable;
    const void                      *context;
    int                              registered;
} ozayn_sdiag_provider_t;

/* ============================================================
 * SECTION 12 — DEPENDENCY GRAPH
 * ============================================================ */

#define OZAYN_SDIAG_MAX_DEPENDENCIES      64

typedef struct {
    ozayn_sh_component_id_t     from;
    ozayn_sh_component_id_t     to;
} ozayn_sdiag_dependency_edge_t;

typedef struct {
    ozayn_sdiag_dependency_edge_t edges[OZAYN_SDIAG_MAX_DEPENDENCIES];
    int                         edge_count;
    int                         cycle_detected;
    ozayn_sh_component_id_t     cycle_start;
    ozayn_sh_component_id_t     cycle_end;
} ozayn_sdiag_dependency_graph_t;

/* ============================================================
 * SECTION 13 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    int                         max_checks;
    int                         max_results;
    int                         max_concurrent;
    int                         check_timeout_ms;
    ozayn_sh_service_t         *health_service;
    ozayn_sc_service_t         *config_service;
    ozayn_ir_service_t         *incident_service;
    ozayn_audit_service_t      *audit;
} ozayn_sdiag_service_config_t;

/* ============================================================
 * SECTION 14 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                         initialized;
    ozayn_sdiag_mode_t          mode;

    /* Checks */
    ozayn_sdiag_check_t         checks[OZAYN_SDIAG_MAX_CHECKS];
    int                         check_count;

    /* Results (ring buffer) */
    ozayn_sdiag_result_t        results[OZAYN_SDIAG_MAX_RESULTS];
    int                         result_head;
    int                         result_count;
    uint32_t                    result_sequence;

    /* Providers */
    ozayn_sdiag_provider_t      providers[16];
    int                         provider_count;

    /* Dependency graph */
    ozayn_sdiag_dependency_graph_t graph;

    /* Dependencies (not owned) */
    ozayn_sh_service_t         *health_service;
    ozayn_sc_service_t         *config_service;
    ozayn_ir_service_t         *incident_service;
    ozayn_audit_service_t      *audit;

    /* Limits */
    int                         max_concurrent;
    int                         active_diagnostics;

    /* Stats */
    uint64_t                    total_checks_run;
    uint64_t                    total_results;
} ozayn_sdiag_service_t;

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_service_init(
    ozayn_sdiag_service_t *svc,
    const ozayn_sdiag_service_config_t *cfg);

void              ozayn_sdiag_service_shutdown(ozayn_sdiag_service_t *svc);

int               ozayn_sdiag_service_is_initialized(
                      const ozayn_sdiag_service_t *svc);

/* ============================================================
 * SECTION 16 — CHECK REGISTRATION
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_register_check(
    ozayn_sdiag_service_t *svc,
    const ozayn_sdiag_check_t *check);

ozayn_sdiag_err_t ozayn_sdiag_register_provider(
    ozayn_sdiag_service_t *svc,
    const ozayn_sdiag_provider_vtable_t *vtable,
    const void *context);

/* ============================================================
 * SECTION 17 — DEPENDENCY GRAPH
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_add_dependency(
    ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t from,
    ozayn_sh_component_id_t to);

int               ozayn_sdiag_has_cycle(const ozayn_sdiag_service_t *svc);

ozayn_sdiag_err_t ozayn_sdiag_get_cycle(
    const ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t *out_start,
    ozayn_sh_component_id_t *out_end);

/* ============================================================
 * SECTION 18 — CHECK EXECUTION
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_run_check(
    ozayn_sdiag_service_t *svc,
    uint32_t check_id,
    ozayn_sdiag_result_t *out_result);

ozayn_sdiag_err_t ozayn_sdiag_run_component_checks(
    ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t component_id);

ozayn_sdiag_err_t ozayn_sdiag_run_all(ozayn_sdiag_service_t *svc);

/* ============================================================
 * SECTION 19 — RESULT QUERY
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_get_result(
    const ozayn_sdiag_service_t *svc,
    uint32_t result_id,
    ozayn_sdiag_result_t *out_result);

int               ozayn_sdiag_get_result_count(
                      const ozayn_sdiag_service_t *svc);

ozayn_sdiag_err_t ozayn_sdiag_get_latest_result(
    const ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t component,
    ozayn_sdiag_result_t *out_result);

/* ============================================================
 * SECTION 20 — SUMMARY
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_get_summary(
    const ozayn_sdiag_service_t *svc,
    ozayn_sdiag_summary_t *out_summary);

const char *ozayn_sdiag_get_safe_summary(
    const ozayn_sdiag_service_t *svc);

/* ============================================================
 * SECTION 21 — CHECK LISTING
 * ============================================================ */

int ozayn_sdiag_list_checks(
    const ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t filter_component,
    ozayn_sdiag_check_t *out_checks,
    int max_count);

/* ============================================================
 * SECTION 22 — MODE & COST CONTROL
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_set_mode(
    ozayn_sdiag_service_t *svc,
    ozayn_sdiag_mode_t mode);

ozayn_sdiag_mode_t ozayn_sdiag_get_mode(
    const ozayn_sdiag_service_t *svc);

int ozayn_sdiag_check_cost_allowed(
    const ozayn_sdiag_service_t *svc,
    ozayn_sdiag_cost_t cost);

/* ============================================================
 * SECTION 23 — FRESHNESS
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_result_is_fresh(
    const ozayn_sdiag_result_t *res,
    int max_age_seconds,
    int *out_is_fresh);

/* ============================================================
 * SECTION 24 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sdiag_err_name(ozayn_sdiag_err_t r);

const char *ozayn_sdiag_state_name(ozayn_sdiag_state_t s);

const char *ozayn_sdiag_severity_name(ozayn_sdiag_severity_t s);

const char *ozayn_sdiag_category_name(ozayn_sdiag_category_t c);

const char *ozayn_sdiag_mode_name(ozayn_sdiag_mode_t m);

const char *ozayn_sdiag_cost_name(ozayn_sdiag_cost_t c);

const char *ozayn_sdiag_recommendation_name(ozayn_sdiag_recommendation_t r);

/* ============================================================
 * SECTION 25 — GLOBAL SERVICE ACCESSOR
 * ============================================================ */

ozayn_sdiag_service_t *ozayn_sdiag_get_global(void);

#endif /* OZAYN_SEC_DIAG_H */
