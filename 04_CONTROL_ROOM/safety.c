/*
 * safety.c — Safety, Preconditions & Policy Enforcement (Step 08).
 *
 * Ensures operations are validated through structured preconditions,
 * policy evaluation, and safety checks before dispatch.
 */

#include "safety.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/*
 * Safety, Preconditions & Policy Enforcement (Step 08).
 *
 * Authorization integration: uses void * pointer to Section 03 authz service.
 * Actual ozayn_authz_authorize() call is deferred to the integration layer.
 * Foundation: validates pointer is non-NULL and service is initialized.
 *
 * Audit integration: uses void * pointer to Section 03 audit service.
 * Foundation: validated pointer access.
 */

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_spe_service_t _spe_global;

ozayn_spe_service_t *ozayn_spe_get_global(void)
{
    return &_spe_global;
}

/* ============================================================
 * SECTION 2 — INTERNAL HELPERS
 * ============================================================ */

static void _audit_event(ozayn_spe_service_t *svc, const char *ref,
                         const char *action, const char *detail)
{
    (void)ref;
    (void)action;
    (void)detail;
    if (!svc || !svc->audit) return;
    /* Audit integration: validated pointer access to audit service.
     * Foundation: pointer validation only. */
}

static void _emit_event(ozayn_spe_service_t *svc,
                        ozayn_spe_event_type_t event_type,
                        const char *ref, const char *detail)
{
    (void)svc; (void)event_type; (void)ref; (void)detail;
    /* Event engine integration stub — events.h cannot be included in Section 04 headers */
}

static int _find_precondition(const ozayn_spe_service_t *svc, const char *id)
{
    if (!svc || !id || id[0] == '\0') return -1;
    for (int i = 0; i < svc->precondition_count; i++) {
        if (svc->preconditions[i].active &&
            strcmp(svc->preconditions[i].precondition_id, id) == 0)
            return i;
    }
    return -1;
}

static int _find_policy(const ozayn_spe_service_t *svc, const char *id)
{
    if (!svc || !id || id[0] == '\0') return -1;
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].active &&
            strcmp(svc->policies[i].policy_id, id) == 0)
            return i;
    }
    return -1;
}

static int _find_decision(const ozayn_spe_service_t *svc, const char *id)
{
    if (!svc || !id || id[0] == '\0') return -1;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head + i) % svc->max_decisions;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].decision_id, id) == 0)
            return idx;
    }
    return -1;
}

static int _find_decision_by_request(const ozayn_spe_service_t *svc, const char *req_id)
{
    if (!svc || !req_id || req_id[0] == '\0') return -1;
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head + i) % svc->max_decisions;
        if (svc->decisions[idx].active &&
            strcmp(svc->decisions[idx].request_id, req_id) == 0)
            return idx;
    }
    return -1;
}

static ozayn_spe_policy_t *_find_policy_by_match(ozayn_spe_service_t *svc,
                                                   const char *op_type,
                                                   const char *target_type,
                                                   const char *cap)
{
    for (int i = 0; i < svc->policy_count; i++) {
        if (!svc->policies[i].active || !svc->policies[i].enabled) continue;
        if (op_type && svc->policies[i].operation_type[0] != '\0' &&
            strcmp(svc->policies[i].operation_type, op_type) != 0) continue;
        if (target_type && svc->policies[i].target_type[0] != '\0' &&
            strcmp(svc->policies[i].target_type, target_type) != 0) continue;
        if (cap && svc->policies[i].capability[0] != '\0' &&
            strcmp(svc->policies[i].capability, cap) != 0) continue;
        return &svc->policies[i];
    }
    return NULL;
}

static ozayn_spe_policy_t *_find_policy_by_match_any(ozayn_spe_service_t *svc,
                                                       const char *op_type,
                                                       const char *target_type,
                                                       const char *cap)
{
    for (int i = 0; i < svc->policy_count; i++) {
        if (!svc->policies[i].active) continue;
        if (op_type && svc->policies[i].operation_type[0] != '\0' &&
            strcmp(svc->policies[i].operation_type, op_type) != 0) continue;
        if (target_type && svc->policies[i].target_type[0] != '\0' &&
            strcmp(svc->policies[i].target_type, target_type) != 0) continue;
        if (cap && svc->policies[i].capability[0] != '\0' &&
            strcmp(svc->policies[i].capability, cap) != 0) continue;
        return &svc->policies[i];
    }
    return NULL;
}

static int _is_precond_result_terminal(ozayn_spe_precond_result_t r)
{
    return r == OZAYN_SPE_RESULT_SATISFIED ||
           r == OZAYN_SPE_RESULT_FAILED ||
           r == OZAYN_SPE_RESULT_UNAVAILABLE;
}

static int _check_authorization(ozayn_spe_service_t *svc,
                                const char *session_id,
                                const char *permission)
{
    (void)permission;
    if (!session_id || session_id[0] == '\0') return 1;
    if (!svc->authorization) return 0;

    /* Authorization check delegated to Section 03 authz service.
     * Foundation: validates pointer is non-NULL and service is initialized.
     * The actual ozayn_authz_authorize() call is deferred to the
     * integration layer where the full auth pipeline is available. */
    return 1; /* Placeholder: authorization service available */
}

/* ============================================================
 * SECTION 3 — LIFECYCLE
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_service_init(ozayn_spe_service_t *svc,
                                        const ozayn_spe_service_config_t *cfg)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (svc->initialized) return OZAYN_SPE_ERR_ALREADY_INITIALIZED;
    memset(svc, 0, sizeof(*svc));
    if (cfg) {
        svc->component_registry = cfg->component_registry;
        svc->command_router = cfg->command_router;
        svc->operation_queue = cfg->operation_queue;
        svc->operation_history = cfg->operation_history;
        svc->diagnostics = cfg->diagnostics;
        svc->authorization = cfg->authorization;
        svc->audit = cfg->audit;
        svc->event_engine = cfg->event_engine;
        svc->max_preconditions = cfg->max_preconditions > 0 ?
            cfg->max_preconditions : OZAYN_SPE_MAX_PRECONDITIONS;
        svc->max_policies = cfg->max_policies > 0 ?
            cfg->max_policies : OZAYN_SPE_MAX_POLICIES;
        svc->max_decisions = cfg->max_decisions > 0 ?
            cfg->max_decisions : OZAYN_SPE_MAX_DECISIONS;
        svc->decision_ttl_ms = cfg->decision_ttl_ms > 0 ?
            cfg->decision_ttl_ms : 300000;
    } else {
        svc->max_preconditions = OZAYN_SPE_MAX_PRECONDITIONS;
        svc->max_policies = OZAYN_SPE_MAX_POLICIES;
        svc->max_decisions = OZAYN_SPE_MAX_DECISIONS;
        svc->decision_ttl_ms = 300000;
    }
    svc->initialized = 1;
    return OZAYN_SPE_OK;
}

void ozayn_spe_service_shutdown(ozayn_spe_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_spe_service_is_initialized(const ozayn_spe_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 4 — PRECONDITION MANAGEMENT
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_precondition_create(ozayn_spe_service_t *svc,
                                               ozayn_spe_precond_category_t category,
                                               const char *description,
                                               const char *target,
                                               const char *required_state,
                                               int required_available,
                                               int required_health,
                                               const char *required_capability,
                                               const char *required_permission,
                                               int resource_required,
                                               ozayn_spe_precondition_t **out_precond)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (category < 0 || category >= OZAYN_SPE_PRECOND_COUNT)
        return OZAYN_SPE_ERR_INVALID_PARAM;
    if (!description || description[0] == '\0') return OZAYN_SPE_ERR_INVALID_PARAM;
    if (!out_precond) return OZAYN_SPE_ERR_NULL;
    if (svc->precondition_count >= svc->max_preconditions)
        return OZAYN_SPE_ERR_LIMIT_REACHED;

    int idx = svc->precondition_count;
    ozayn_spe_precondition_t *p = &svc->preconditions[idx];
    memset(p, 0, sizeof(*p));

    svc->precondition_sequence++;
    snprintf(p->precondition_id, OZAYN_SPE_MAX_ID_LEN, "SPC-%u",
             svc->precondition_sequence);
    p->version = 1;
    p->category = category;
    strncpy(p->description, description, OZAYN_SPE_MAX_DESC_LEN - 1);
    if (target) strncpy(p->target, target, OZAYN_SPE_MAX_TARGET_LEN - 1);
    if (required_state) strncpy(p->required_state, required_state, OZAYN_SPE_MAX_ID_LEN - 1);
    p->required_available = required_available;
    p->required_health = required_health;
    if (required_capability)
        strncpy(p->required_capability, required_capability, OZAYN_SPE_MAX_ID_LEN - 1);
    if (required_permission)
        strncpy(p->required_permission, required_permission, OZAYN_SPE_MAX_ID_LEN - 1);
    p->resource_required = resource_required;
    p->result = OZAYN_SPE_RESULT_UNKNOWN;
    p->evaluation_time = 0;
    p->active = 1;

    svc->precondition_count++;
    *out_precond = p;
    return OZAYN_SPE_OK;
}

ozayn_spe_err_t ozayn_spe_precondition_evaluate(ozayn_spe_service_t *svc,
                                                 const char *precondition_id,
                                                 ozayn_spe_precond_result_t result)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!precondition_id || precondition_id[0] == '\0')
        return OZAYN_SPE_ERR_INVALID_PARAM;
    if (result < 0 || result >= OZAYN_SPE_RESULT_COUNT)
        return OZAYN_SPE_ERR_INVALID_PARAM;

    int idx = _find_precondition(svc, precondition_id);
    if (idx < 0) return OZAYN_SPE_ERR_NOT_FOUND;

    ozayn_spe_precondition_t *p = &svc->preconditions[idx];
    if (_is_precond_result_terminal(p->result))
        return OZAYN_SPE_ERR_STATE_INVALID;

    p->result = result;
    p->evaluation_time = time(NULL);

    if (result == OZAYN_SPE_RESULT_SATISFIED)
        svc->stats.total_precondition_pass++;
    else if (result == OZAYN_SPE_RESULT_FAILED)
        svc->stats.total_precondition_fail++;

    _emit_event(svc, result == OZAYN_SPE_RESULT_FAILED ?
                OZAYN_SPE_EVENT_PRECOND_FAILED :
                OZAYN_SPE_EVENT_PRECOND_EVALUATED,
                p->precondition_id, p->description);

    return OZAYN_SPE_OK;
}

const ozayn_spe_precondition_t *ozayn_spe_precondition_get(
    const ozayn_spe_service_t *svc, const char *precondition_id)
{
    if (!svc || !precondition_id) return NULL;
    int idx = _find_precondition(svc, precondition_id);
    if (idx < 0) return NULL;
    return &svc->preconditions[idx];
}

int ozayn_spe_precondition_count(const ozayn_spe_service_t *svc)
{
    if (!svc) return 0;
    return svc->precondition_count;
}

ozayn_spe_err_t ozayn_spe_precondition_add_dependency(ozayn_spe_service_t *svc,
                                                       const char *precondition_id,
                                                       const char *dependency_id)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!precondition_id || !dependency_id) return OZAYN_SPE_ERR_INVALID_PARAM;
    int idx = _find_precondition(svc, precondition_id);
    if (idx < 0) return OZAYN_SPE_ERR_NOT_FOUND;
    ozayn_spe_precondition_t *p = &svc->preconditions[idx];
    if (p->dependency_count >= OZAYN_SPE_MAX_DEPENDENCIES)
        return OZAYN_SPE_ERR_LIMIT_REACHED;
    strncpy(p->required_dependencies[p->dependency_count], dependency_id,
            OZAYN_SPE_MAX_ID_LEN - 1);
    p->dependency_count++;
    return OZAYN_SPE_OK;
}

/* ============================================================
 * SECTION 5 — POLICY MANAGEMENT
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_policy_create(ozayn_spe_service_t *svc,
                                         const char *operation_type,
                                         const char *target_type,
                                         const char *capability,
                                         const char *required_permission,
                                         int required_health,
                                         const char *required_state,
                                         int required_available,
                                         int resource_required,
                                         ozayn_spe_safety_level_t safety_level,
                                         int timeout_limit_ms,
                                         int retry_limit,
                                         int cancellable,
                                         ozayn_spe_policy_t **out_policy)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!operation_type || operation_type[0] == '\0')
        return OZAYN_SPE_ERR_INVALID_PARAM;
    if (safety_level < 0 || safety_level >= OZAYN_SPE_LEVEL_COUNT)
        return OZAYN_SPE_ERR_INVALID_PARAM;
    if (!out_policy) return OZAYN_SPE_ERR_NULL;
    if (svc->policy_count >= svc->max_policies)
        return OZAYN_SPE_ERR_LIMIT_REACHED;

    int idx = svc->policy_count;
    ozayn_spe_policy_t *pol = &svc->policies[idx];
    memset(pol, 0, sizeof(*pol));

    svc->policy_sequence++;
    snprintf(pol->policy_id, OZAYN_SPE_MAX_ID_LEN, "SPP-%u",
             svc->policy_sequence);
    pol->version = 1;
    strncpy(pol->operation_type, operation_type, OZAYN_SPE_MAX_ID_LEN - 1);
    if (target_type) strncpy(pol->target_type, target_type, OZAYN_SPE_MAX_ID_LEN - 1);
    if (capability) strncpy(pol->capability, capability, OZAYN_SPE_MAX_ID_LEN - 1);
    if (required_permission)
        strncpy(pol->required_permission, required_permission, OZAYN_SPE_MAX_ID_LEN - 1);
    pol->required_health = required_health;
    if (required_state) strncpy(pol->required_state, required_state, OZAYN_SPE_MAX_ID_LEN - 1);
    pol->required_available = required_available;
    pol->resource_required = resource_required;
    pol->safety_level = safety_level;
    pol->timeout_limit_ms = timeout_limit_ms > 0 ? timeout_limit_ms : 30000;
    pol->retry_limit = retry_limit >= 0 ? retry_limit : 3;
    pol->cancellable = cancellable;
    pol->enabled = 1;
    pol->active = 1;

    svc->policy_count++;
    *out_policy = pol;
    return OZAYN_SPE_OK;
}

ozayn_spe_err_t ozayn_spe_policy_set_enabled(ozayn_spe_service_t *svc,
                                              const char *policy_id,
                                              int enabled)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!policy_id || policy_id[0] == '\0') return OZAYN_SPE_ERR_INVALID_PARAM;
    int idx = _find_policy(svc, policy_id);
    if (idx < 0) return OZAYN_SPE_ERR_NOT_FOUND;
    svc->policies[idx].enabled = enabled ? 1 : 0;
    return OZAYN_SPE_OK;
}

const ozayn_spe_policy_t *ozayn_spe_policy_get(const ozayn_spe_service_t *svc,
                                                const char *policy_id)
{
    if (!svc || !policy_id) return NULL;
    int idx = _find_policy(svc, policy_id);
    if (idx < 0) return NULL;
    return &svc->policies[idx];
}

const ozayn_spe_policy_t *ozayn_spe_policy_find(const ozayn_spe_service_t *svc,
                                                 const char *operation_type,
                                                 const char *target_type,
                                                 const char *capability)
{
    if (!svc) return NULL;
    return _find_policy_by_match((ozayn_spe_service_t *)svc,
                                  operation_type, target_type, capability);
}

int ozayn_spe_policy_count(const ozayn_spe_service_t *svc)
{
    if (!svc) return 0;
    return svc->policy_count;
}

ozayn_spe_err_t ozayn_spe_policy_add_conflict(ozayn_spe_service_t *svc,
                                               const char *policy_id,
                                               const char *conflict_action)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!policy_id || !conflict_action) return OZAYN_SPE_ERR_INVALID_PARAM;
    int idx = _find_policy(svc, policy_id);
    if (idx < 0) return OZAYN_SPE_ERR_NOT_FOUND;
    ozayn_spe_policy_t *pol = &svc->policies[idx];
    if (pol->conflict_action_count >= OZAYN_SPE_MAX_CONFLICT_RULES)
        return OZAYN_SPE_ERR_LIMIT_REACHED;
    strncpy(pol->conflict_actions[pol->conflict_action_count], conflict_action,
            OZAYN_SPE_MAX_ID_LEN - 1);
    pol->conflict_action_count++;
    return OZAYN_SPE_OK;
}

ozayn_spe_err_t ozayn_spe_policy_add_dependency(ozayn_spe_service_t *svc,
                                                 const char *policy_id,
                                                 const char *dependency_id)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!policy_id || !dependency_id) return OZAYN_SPE_ERR_INVALID_PARAM;
    int idx = _find_policy(svc, policy_id);
    if (idx < 0) return OZAYN_SPE_ERR_NOT_FOUND;
    ozayn_spe_policy_t *pol = &svc->policies[idx];
    if (pol->dependency_count >= OZAYN_SPE_MAX_DEPENDENCIES)
        return OZAYN_SPE_ERR_LIMIT_REACHED;
    strncpy(pol->required_dependencies[pol->dependency_count], dependency_id,
            OZAYN_SPE_MAX_ID_LEN - 1);
    pol->dependency_count++;
    return OZAYN_SPE_OK;
}

/* ============================================================
 * SECTION 6 — CONFLICT DETECTION
 * ============================================================ */

int ozayn_spe_has_conflict(const ozayn_spe_service_t *svc,
                            const char *target,
                            const char *action)
{
    if (!svc || !target || !action) return 0;
    for (int i = 0; i < svc->policy_count; i++) {
        const ozayn_spe_policy_t *pol = &svc->policies[i];
        if (!pol->active || !pol->enabled) continue;
        if (pol->target_type[0] != '\0' &&
            strcmp(pol->target_type, target) != 0) continue;
        for (int c = 0; c < pol->conflict_action_count; c++) {
            if (strcmp(pol->conflict_actions[c], action) == 0)
                return 1;
        }
    }
    return 0;
}

ozayn_spe_err_t ozayn_spe_check_conflict(const ozayn_spe_service_t *svc,
                                          const char *target,
                                          const char *action,
                                          int *out_conflict)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!out_conflict) return OZAYN_SPE_ERR_NULL;
    *out_conflict = ozayn_spe_has_conflict(svc, target, action);
    if (*out_conflict)
        ((ozayn_spe_service_t *)svc)->stats.total_conflicts_detected++;
    return OZAYN_SPE_OK;
}

/* ============================================================
 * SECTION 7 — SAFETY EVALUATION
 * ============================================================ */

static int _evaluate_preconditions(ozayn_spe_service_t *svc,
                                    const ozayn_spe_policy_t *pol,
                                    const char *target,
                                    const char *capability,
                                    const char *session_id,
                                    const char *permission,
                                    ozayn_spe_decision_record_t *dec)
{
    (void)capability;
    (void)permission;
    int all_satisfied = 1;

    /* Target state precondition */
    if (pol->required_state[0] != '\0') {
        dec->precondition_count++;
        /* In a full system, we'd query the component registry for actual state.
         * Foundation: record the requirement, mark as satisfied if no registry */
        if (svc->component_registry) {
            /* Placeholder: component_registry check would go here */
            strncpy(dec->warnings[dec->warning_count],
                    "state check deferred to registry integration",
                    OZAYN_SPE_MAX_DESC_LEN - 1);
            dec->warning_count++;
        }
    }

    /* Availability precondition */
    if (pol->required_available > 0) {
        dec->precondition_count++;
        if (svc->component_registry) {
            /* Placeholder: availability check */
            strncpy(dec->warnings[dec->warning_count],
                    "availability check deferred to registry integration",
                    OZAYN_SPE_MAX_DESC_LEN - 1);
            dec->warning_count++;
        }
    }

    /* Health precondition */
    if (pol->required_health >= 0) {
        dec->precondition_count++;
        if (svc->diagnostics) {
            /* Placeholder: diagnostics health query */
            strncpy(dec->warnings[dec->warning_count],
                    "health check deferred to diagnostics integration",
                    OZAYN_SPE_MAX_DESC_LEN - 1);
            dec->warning_count++;
        }
    }

    /* Authorization precondition */
    if (pol->required_permission[0] != '\0') {
        dec->precondition_count++;
        if (!_check_authorization(svc, session_id, pol->required_permission)) {
            strncpy(dec->failed_preconditions[dec->failed_precondition_count],
                    "AUTHORIZATION", OZAYN_SPE_MAX_ID_LEN - 1);
            dec->failed_precondition_count++;
            all_satisfied = 0;
        }
    }

    /* Dependency preconditions */
    for (int d = 0; d < pol->dependency_count; d++) {
        dec->precondition_count++;
        /* Placeholder: dependency availability check */
        strncpy(dec->warnings[dec->warning_count],
                "dependency check deferred to dependency integration",
                OZAYN_SPE_MAX_DESC_LEN - 1);
        dec->warning_count++;
    }

    /* Resource precondition */
    if (pol->resource_required) {
        dec->precondition_count++;
        /* Placeholder: resource availability check */
        strncpy(dec->warnings[dec->warning_count],
                "resource check deferred to resource integration",
                OZAYN_SPE_MAX_DESC_LEN - 1);
        dec->warning_count++;
    }

    /* Conflict check */
    if (ozayn_spe_has_conflict(svc, target, pol->operation_type)) {
        dec->precondition_count++;
        strncpy(dec->failed_preconditions[dec->failed_precondition_count],
                "CONFLICT", OZAYN_SPE_MAX_ID_LEN - 1);
        dec->failed_precondition_count++;
        all_satisfied = 0;
    }

    return all_satisfied;
}

static void _create_decision(ozayn_spe_service_t *svc,
                              const char *request_id,
                              const char *operation_id,
                              ozayn_spe_decision_t decision,
                              const char *policy_id,
                              ozayn_spe_decision_record_t *dec)
{
    /* Save precondition state populated by _evaluate_preconditions */
    int saved_precondition_count = dec->precondition_count;
    int saved_failed_precondition_count = dec->failed_precondition_count;
    int saved_warning_count = dec->warning_count;
    char saved_failed_preconditions[OZAYN_SPE_MAX_PRECONDITIONS][OZAYN_SPE_MAX_ID_LEN];
    char saved_warnings[OZAYN_SPE_MAX_PRECONDITIONS][OZAYN_SPE_MAX_DESC_LEN];
    memcpy(saved_failed_preconditions, dec->failed_preconditions, sizeof(saved_failed_preconditions));
    memcpy(saved_warnings, dec->warnings, sizeof(saved_warnings));

    memset(dec, 0, sizeof(*dec));

    /* Restore precondition state */
    dec->precondition_count = saved_precondition_count;
    dec->failed_precondition_count = saved_failed_precondition_count;
    dec->warning_count = saved_warning_count;
    memcpy(dec->failed_preconditions, saved_failed_preconditions, sizeof(saved_failed_preconditions));
    memcpy(dec->warnings, saved_warnings, sizeof(saved_warnings));

    svc->decision_sequence++;
    snprintf(dec->decision_id, OZAYN_SPE_MAX_ID_LEN, "SPD-%u",
             svc->decision_sequence);
    if (request_id) strncpy(dec->request_id, request_id, OZAYN_SPE_MAX_ID_LEN - 1);
    if (operation_id) strncpy(dec->operation_id, operation_id, OZAYN_SPE_MAX_ID_LEN - 1);
    dec->decision = decision;
    if (policy_id) strncpy(dec->policy_id, policy_id, OZAYN_SPE_MAX_ID_LEN - 1);
    dec->evaluation_time = time(NULL);
    dec->expiry_time = dec->evaluation_time + (svc->decision_ttl_ms / 1000);
    dec->active = 1;

    /* Ring buffer insert */
    int idx = (svc->decision_head + svc->decision_count) % svc->max_decisions;
    memcpy(&svc->decisions[idx], dec, sizeof(*dec));
    if (svc->decision_count < svc->max_decisions)
        svc->decision_count++;
    else
        svc->decision_head = (svc->decision_head + 1) % svc->max_decisions;

    svc->stats.current_active_decisions++;
}

ozayn_spe_err_t ozayn_spe_evaluate(ozayn_spe_service_t *svc,
                                    const char *request_id,
                                    const char *operation_id,
                                    const char *target,
                                    const char *action,
                                    const char *capability,
                                    const char *session_id,
                                    const char *requester_identity,
                                    const char *required_permission,
                                    ozayn_spe_decision_record_t **out_decision)
{
    (void)requester_identity;
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!target || target[0] == '\0') return OZAYN_SPE_ERR_INVALID_PARAM;
    if (!action || action[0] == '\0') return OZAYN_SPE_ERR_INVALID_PARAM;
    if (!out_decision) return OZAYN_SPE_ERR_NULL;

    svc->stats.total_evaluations++;
    _emit_event(svc, OZAYN_SPE_EVENT_SAFETY_CHECK_STARTED,
                request_id ? request_id : "", target);

    /* Find matching policy */
    const ozayn_spe_policy_t *pol = _find_policy_by_match_any(svc, action,
                                                               target, capability);
    if (!pol) {
        /* Default deny when no policy exists */
        ozayn_spe_decision_record_t dec;
        _create_decision(svc, request_id, operation_id,
                         OZAYN_SPE_DECISION_DENY, "", &dec);
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_SPE_EVENT_POLICY_DENIED,
                    request_id ? request_id : "", "no matching policy");
        _audit_event(svc, request_id ? request_id : "",
                     "SAFETY_DENIED", "no matching policy");
        *out_decision = &svc->decisions[(svc->decision_head +
            svc->decision_count - 1) % svc->max_decisions];
        return OZAYN_SPE_OK;
    }

    if (!pol->enabled) {
        ozayn_spe_decision_record_t dec;
        _create_decision(svc, request_id, operation_id,
                         OZAYN_SPE_DECISION_UNAVAILABLE, pol->policy_id, &dec);
        svc->stats.total_unavailable++;
        _emit_event(svc, OZAYN_SPE_EVENT_POLICY_DENIED,
                    request_id ? request_id : "", "policy disabled");
        *out_decision = &svc->decisions[(svc->decision_head +
            svc->decision_count - 1) % svc->max_decisions];
        return OZAYN_SPE_OK;
    }

    /* Evaluate preconditions */
    ozayn_spe_decision_record_t dec;
    int preconditions_met = _evaluate_preconditions(svc, pol, target,
                                                     capability, session_id,
                                                     required_permission, &dec);

    /* Determine decision */
    ozayn_spe_decision_t decision;
    if (preconditions_met) {
        decision = OZAYN_SPE_DECISION_ALLOW;
        svc->stats.total_allowed++;
        _emit_event(svc, OZAYN_SPE_EVENT_POLICY_ALLOWED,
                    request_id ? request_id : "", pol->policy_id);
    } else {
        decision = OZAYN_SPE_DECISION_DENY;
        svc->stats.total_denied++;
        _emit_event(svc, OZAYN_SPE_EVENT_POLICY_DENIED,
                    request_id ? request_id : "", pol->policy_id);
        _audit_event(svc, request_id ? request_id : "",
                     "SAFETY_DENIED", pol->policy_id);
    }

    _create_decision(svc, request_id, operation_id, decision,
                     pol->policy_id, &dec);

    _emit_event(svc, OZAYN_SPE_EVENT_POLICY_EVALUATED,
                request_id ? request_id : "", "");

    *out_decision = &svc->decisions[(svc->decision_head +
        svc->decision_count - 1) % svc->max_decisions];
    return OZAYN_SPE_OK;
}

ozayn_spe_err_t ozayn_spe_recheck(ozayn_spe_service_t *svc,
                                   const char *decision_id,
                                   const char *target,
                                   const char *capability,
                                   const char *session_id)
{
    (void)capability;
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    if (!decision_id || decision_id[0] == '\0')
        return OZAYN_SPE_ERR_INVALID_PARAM;

    int idx = _find_decision(svc, decision_id);
    if (idx < 0) return OZAYN_SPE_ERR_NOT_FOUND;

    ozayn_spe_decision_record_t *dec = &svc->decisions[idx];

    /* Check expiry */
    time_t now = time(NULL);
    if (dec->expiry_time > 0 && now > dec->expiry_time) {
        dec->decision = OZAYN_SPE_DECISION_UNAVAILABLE;
        svc->stats.total_recheck_failures++;
        _emit_event(svc, OZAYN_SPE_EVENT_SAFETY_RECHECK_REQUIRED,
                    decision_id, "decision expired");
        return OZAYN_SPE_ERR_DECISION_EXPIRED;
    }

    svc->stats.total_rechecks++;

    /* Re-evaluate authorization */
    int pol_idx = _find_policy(svc, dec->policy_id);
    const ozayn_spe_policy_t *pol = pol_idx >= 0 ? &svc->policies[pol_idx] : NULL;
    if (pol && pol->required_permission[0] != '\0') {
        if (!_check_authorization(svc, session_id, pol->required_permission)) {
            dec->decision = OZAYN_SPE_DECISION_DENY;
            svc->stats.total_recheck_failures++;
            _emit_event(svc, OZAYN_SPE_EVENT_SAFETY_CHECK_FAILED,
                        decision_id, "authorization recheck failed");
            _audit_event(svc, decision_id, "RECHECK_DENIED",
                         "authorization failed on recheck");
            return OZAYN_SPE_OK;
        }
    }

    /* Re-check conflict */
    if (pol && ozayn_spe_has_conflict(svc, target, pol->operation_type)) {
        dec->decision = OZAYN_SPE_DECISION_DENY;
        svc->stats.total_recheck_failures++;
        _emit_event(svc, OZAYN_SPE_EVENT_CONFLICT_DETECTED,
                    decision_id, "conflict on recheck");
        return OZAYN_SPE_OK;
    }

    /* Re-check availability if required */
    if (pol && pol->required_available > 0 && svc->component_registry) {
        /* Placeholder: availability recheck */
    }

    /* Re-check health if required */
    if (pol && pol->required_health >= 0 && svc->diagnostics) {
        /* Placeholder: health recheck */
    }

    /* All rechecks passed — restore decision if it was deferred */
    if (dec->decision == OZAYN_SPE_DECISION_DEFER) {
        dec->decision = OZAYN_SPE_DECISION_ALLOW;
    }

    _emit_event(svc, OZAYN_SPE_EVENT_SAFETY_CHECK_PASSED,
                decision_id, "recheck passed");
    return OZAYN_SPE_OK;
}

const ozayn_spe_decision_record_t *ozayn_spe_decision_get(
    const ozayn_spe_service_t *svc, const char *decision_id)
{
    if (!svc || !decision_id) return NULL;
    int idx = _find_decision(svc, decision_id);
    if (idx < 0) return NULL;
    return &svc->decisions[idx];
}

const ozayn_spe_decision_record_t *ozayn_spe_decision_get_by_request(
    const ozayn_spe_service_t *svc, const char *request_id)
{
    if (!svc || !request_id) return NULL;
    int idx = _find_decision_by_request(svc, request_id);
    if (idx < 0) return NULL;
    return &svc->decisions[idx];
}

int ozayn_spe_decision_count(const ozayn_spe_service_t *svc)
{
    if (!svc) return 0;
    return svc->decision_count;
}

int ozayn_spe_decision_is_valid(const ozayn_spe_service_t *svc,
                                 const char *decision_id)
{
    if (!svc || !decision_id) return 0;
    int idx = _find_decision(svc, decision_id);
    if (idx < 0) return 0;
    const ozayn_spe_decision_record_t *dec = &svc->decisions[idx];
    if (!dec->active) return 0;
    if (dec->expiry_time > 0 && time(NULL) > dec->expiry_time) return 0;
    return 1;
}

/* ============================================================
 * SECTION 8 — STATISTICS
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_get_stats(const ozayn_spe_service_t *svc,
                                     ozayn_spe_stats_t *out_stats)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!out_stats) return OZAYN_SPE_ERR_NULL;
    if (!svc->initialized) return OZAYN_SPE_ERR_NOT_INITIALIZED;
    *out_stats = svc->stats;
    return OZAYN_SPE_OK;
}

/* ============================================================
 * SECTION 9 — CLEANUP
 * ============================================================ */

int ozayn_spe_cleanup_decisions(ozayn_spe_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->decision_count; i++) {
        int idx = (svc->decision_head + i) % svc->max_decisions;
        if (svc->decisions[idx].active) {
            if (svc->decisions[idx].expiry_time > 0 &&
                now > svc->decisions[idx].expiry_time) {
                svc->decisions[idx].active = 0;
                svc->stats.current_active_decisions--;
                cleaned++;
            }
        }
    }
    svc->decision_count -= cleaned;
    return cleaned;
}

int ozayn_spe_cleanup_all(ozayn_spe_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    /* Clean expired decisions */
    cleaned += ozayn_spe_cleanup_decisions(svc);
    /* Reset preconditions */
    for (int i = 0; i < svc->precondition_count; i++) {
        svc->preconditions[i].active = 0;
    }
    svc->precondition_count = 0;
    cleaned++;
    /* Reset policies */
    for (int i = 0; i < svc->policy_count; i++) {
        svc->policies[i].active = 0;
    }
    svc->policy_count = 0;
    cleaned++;
    /* Reset decisions */
    for (int i = 0; i < svc->decision_count; i++) {
        svc->decisions[i].active = 0;
    }
    svc->decision_count = 0;
    svc->decision_head = 0;
    svc->stats.current_active_decisions = 0;
    cleaned++;
    return cleaned;
}

/* ============================================================
 * SECTION 10 — EVENT & AUDIT STUBS
 * ============================================================ */

ozayn_spe_err_t ozayn_spe_emit_event(ozayn_spe_service_t *svc,
                                      ozayn_spe_event_type_t event_type,
                                      const char *reference_id,
                                      const char *detail)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    _emit_event(svc, event_type, reference_id, detail);
    return OZAYN_SPE_OK;
}

ozayn_spe_err_t ozayn_spe_audit(ozayn_spe_service_t *svc,
                                 const char *reference_id,
                                 const char *action,
                                 const char *detail)
{
    if (!svc) return OZAYN_SPE_ERR_NULL;
    if (!reference_id || !action) return OZAYN_SPE_ERR_INVALID_PARAM;
    _audit_event(svc, reference_id, action, detail);
    return OZAYN_SPE_OK;
}

/* ============================================================
 * SECTION 11 — VALIDATION
 * ============================================================ */

int ozayn_spe_precondition_validate(const ozayn_spe_precondition_t *precond)
{
    if (!precond) return 0;
    if (precond->precondition_id[0] == '\0') return 0;
    if (precond->category < 0 || precond->category >= OZAYN_SPE_PRECOND_COUNT) return 0;
    if (precond->description[0] == '\0') return 0;
    return 1;
}

int ozayn_spe_policy_validate(const ozayn_spe_policy_t *policy)
{
    if (!policy) return 0;
    if (policy->policy_id[0] == '\0') return 0;
    if (policy->operation_type[0] == '\0') return 0;
    if (policy->safety_level < 0 || policy->safety_level >= OZAYN_SPE_LEVEL_COUNT) return 0;
    return 1;
}

int ozayn_spe_decision_validate(const ozayn_spe_decision_record_t *decision)
{
    if (!decision) return 0;
    if (decision->decision_id[0] == '\0') return 0;
    if (decision->decision < 0 || decision->decision >= OZAYN_SPE_DECISION_COUNT) return 0;
    return 1;
}

/* ============================================================
 * SECTION 12 — NAME HELPERS
 * ============================================================ */

const char *ozayn_spe_err_name(ozayn_spe_err_t err)
{
    switch (err) {
        case OZAYN_SPE_OK: return "OK";
        case OZAYN_SPE_ERR_NULL: return "NULL";
        case OZAYN_SPE_ERR_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case OZAYN_SPE_ERR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
        case OZAYN_SPE_ERR_INVALID_PARAM: return "INVALID_PARAM";
        case OZAYN_SPE_ERR_LIMIT_REACHED: return "LIMIT_REACHED";
        case OZAYN_SPE_ERR_NOT_FOUND: return "NOT_FOUND";
        case OZAYN_SPE_ERR_STATE_INVALID: return "STATE_INVALID";
        case OZAYN_SPE_ERR_PRECONDITION_FAILED: return "PRECONDITION_FAILED";
        case OZAYN_SPE_ERR_PRECONDITION_UNKNOWN: return "PRECONDITION_UNKNOWN";
        case OZAYN_SPE_ERR_PRECONDITION_UNAVAILABLE: return "PRECONDITION_UNAVAILABLE";
        case OZAYN_SPE_ERR_POLICY_NOT_FOUND: return "POLICY_NOT_FOUND";
        case OZAYN_SPE_ERR_POLICY_INVALID: return "POLICY_INVALID";
        case OZAYN_SPE_ERR_POLICY_DENIED: return "POLICY_DENIED";
        case OZAYN_SPE_ERR_POLICY_UNAVAILABLE: return "POLICY_UNAVAILABLE";
        case OZAYN_SPE_ERR_STATE_REQUIREMENT: return "STATE_REQUIREMENT";
        case OZAYN_SPE_ERR_AVAILABILITY_REQUIREMENT: return "AVAILABILITY_REQUIREMENT";
        case OZAYN_SPE_ERR_HEALTH_REQUIREMENT: return "HEALTH_REQUIREMENT";
        case OZAYN_SPE_ERR_DEPENDENCY_REQUIREMENT: return "DEPENDENCY_REQUIREMENT";
        case OZAYN_SPE_ERR_AUTHORIZATION_REQUIREMENT: return "AUTHORIZATION_REQUIREMENT";
        case OZAYN_SPE_ERR_SESSION_REQUIREMENT: return "SESSION_REQUIREMENT";
        case OZAYN_SPE_ERR_RESOURCE_REQUIREMENT: return "RESOURCE_REQUIREMENT";
        case OZAYN_SPE_ERR_CONFIGURATION_REQUIREMENT: return "CONFIGURATION_REQUIREMENT";
        case OZAYN_SPE_ERR_SECURITY_REQUIREMENT: return "SECURITY_REQUIREMENT";
        case OZAYN_SPE_ERR_OPERATION_CONFLICT: return "OPERATION_CONFLICT";
        case OZAYN_SPE_ERR_SAFETY_CHECK_FAILED: return "SAFETY_CHECK_FAILED";
        case OZAYN_SPE_ERR_SAFETY_RECHECK_FAILED: return "SAFETY_RECHECK_FAILED";
        case OZAYN_SPE_ERR_DECISION_EXPIRED: return "DECISION_EXPIRED";
        case OZAYN_SPE_ERR_CONCURRENCY_LIMIT: return "CONCURRENCY_LIMIT";
    }
    return "UNKNOWN";
}

const char *ozayn_spe_precond_category_name(ozayn_spe_precond_category_t cat)
{
    switch (cat) {
        case OZAYN_SPE_PRECOND_TARGET_STATE: return "TARGET_STATE";
        case OZAYN_SPE_PRECOND_TARGET_AVAILABILITY: return "TARGET_AVAILABILITY";
        case OZAYN_SPE_PRECOND_TARGET_HEALTH: return "TARGET_HEALTH";
        case OZAYN_SPE_PRECOND_CAPABILITY: return "CAPABILITY";
        case OZAYN_SPE_PRECOND_DEPENDENCY: return "DEPENDENCY";
        case OZAYN_SPE_PRECOND_AUTHORIZATION: return "AUTHORIZATION";
        case OZAYN_SPE_PRECOND_SESSION: return "SESSION";
        case OZAYN_SPE_PRECOND_RESOURCE: return "RESOURCE";
        case OZAYN_SPE_PRECOND_CONFIGURATION: return "CONFIGURATION";
        case OZAYN_SPE_PRECOND_SECURITY: return "SECURITY";
        case OZAYN_SPE_PRECOND_CONFLICT: return "CONFLICT";
        case OZAYN_SPE_PRECOND_LIFECYCLE: return "LIFECYCLE";
        case OZAYN_SPE_PRECOND_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_spe_precond_result_name(ozayn_spe_precond_result_t result)
{
    switch (result) {
        case OZAYN_SPE_RESULT_SATISFIED: return "SATISFIED";
        case OZAYN_SPE_RESULT_FAILED: return "FAILED";
        case OZAYN_SPE_RESULT_UNKNOWN: return "UNKNOWN";
        case OZAYN_SPE_RESULT_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_SPE_RESULT_NOT_APPLICABLE: return "NOT_APPLICABLE";
        case OZAYN_SPE_RESULT_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_spe_safety_level_name(ozayn_spe_safety_level_t level)
{
    switch (level) {
        case OZAYN_SPE_LEVEL_SAFE: return "SAFE";
        case OZAYN_SPE_LEVEL_RESTRICTED: return "RESTRICTED";
        case OZAYN_SPE_LEVEL_SENSITIVE: return "SENSITIVE";
        case OZAYN_SPE_LEVEL_CRITICAL: return "CRITICAL";
        case OZAYN_SPE_LEVEL_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_spe_decision_name(ozayn_spe_decision_t decision)
{
    switch (decision) {
        case OZAYN_SPE_DECISION_ALLOW: return "ALLOW";
        case OZAYN_SPE_DECISION_DENY: return "DENY";
        case OZAYN_SPE_DECISION_DEFER: return "DEFER";
        case OZAYN_SPE_DECISION_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_SPE_DECISION_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_spe_event_type_name(ozayn_spe_event_type_t event)
{
    switch (event) {
        case OZAYN_SPE_EVENT_PRECOND_EVALUATED: return "PRECOND_EVALUATED";
        case OZAYN_SPE_EVENT_PRECOND_FAILED: return "PRECOND_FAILED";
        case OZAYN_SPE_EVENT_POLICY_EVALUATED: return "POLICY_EVALUATED";
        case OZAYN_SPE_EVENT_POLICY_ALLOWED: return "POLICY_ALLOWED";
        case OZAYN_SPE_EVENT_POLICY_DENIED: return "POLICY_DENIED";
        case OZAYN_SPE_EVENT_POLICY_DEFERRED: return "POLICY_DEFERRED";
        case OZAYN_SPE_EVENT_SAFETY_CHECK_STARTED: return "SAFETY_CHECK_STARTED";
        case OZAYN_SPE_EVENT_SAFETY_CHECK_FAILED: return "SAFETY_CHECK_FAILED";
        case OZAYN_SPE_EVENT_SAFETY_CHECK_PASSED: return "SAFETY_CHECK_PASSED";
        case OZAYN_SPE_EVENT_SAFETY_RECHECK_REQUIRED: return "SAFETY_RECHECK_REQUIRED";
        case OZAYN_SPE_EVENT_CONFLICT_DETECTED: return "CONFLICT_DETECTED";
        case OZAYN_SPE_EVENT_OPERATION_BLOCKED: return "OPERATION_BLOCKED";
        case OZAYN_SPE_EVENT_COUNT: return "COUNT";
    }
    return "UNKNOWN";
}
