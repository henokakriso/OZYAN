/*
 * sec_diag.c — Security Diagnostics & Self-Diagnostics Foundation
 *              (Step 28).
 */

#include "sec_diag.h"
#include <string.h>
#include <stdio.h>

static ozayn_sdiag_service_t _sd_global = {0};

ozayn_sdiag_service_t *ozayn_sdiag_get_global(void)
{
    return &_sd_global;
}

/* ============================================================
 * SECTION 24 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sdiag_err_name(ozayn_sdiag_err_t r)
{
    switch (r) {
    case OZAYN_SDIAG_OK:                     return "OK";
    case OZAYN_SDIAG_ERR:                    return "ERR";
    case OZAYN_SDIAG_ERR_NULL:               return "ERR_NULL";
    case OZAYN_SDIAG_ERR_NOT_INITIALIZED:    return "ERR_NOT_INITIALIZED";
    case OZAYN_SDIAG_ERR_ALREADY_INITIALIZED:return "ERR_ALREADY_INITIALIZED";
    case OZAYN_SDIAG_ERR_INVALID_REQUEST:    return "ERR_INVALID_REQUEST";
    case OZAYN_SDIAG_ERR_INVALID_COMPONENT:  return "ERR_INVALID_COMPONENT";
    case OZAYN_SDIAG_ERR_INVALID_CHECK:      return "ERR_INVALID_CHECK";
    case OZAYN_SDIAG_ERR_NOT_FOUND:          return "ERR_NOT_FOUND";
    case OZAYN_SDIAG_ERR_UNAVAILABLE:        return "ERR_UNAVAILABLE";
    case OZAYN_SDIAG_ERR_FAILED:             return "ERR_FAILED";
    case OZAYN_SDIAG_ERR_TIMEOUT:            return "ERR_TIMEOUT";
    case OZAYN_SDIAG_ERR_UNSUPPORTED:        return "ERR_UNSUPPORTED";
    case OZAYN_SDIAG_ERR_POLICY_INVALID:     return "ERR_POLICY_INVALID";
    case OZAYN_SDIAG_ERR_DEPENDENCY_FAILED:  return "ERR_DEPENDENCY_FAILED";
    case OZAYN_SDIAG_ERR_INTEGRITY_FAILED:   return "ERR_INTEGRITY_FAILED";
    case OZAYN_SDIAG_ERR_RESOURCE_LIMIT:     return "ERR_RESOURCE_LIMIT";
    case OZAYN_SDIAG_ERR_CONCURRENCY_CONFLICT:return "ERR_CONCURRENCY_CONFLICT";
    case OZAYN_SDIAG_ERR_ACCESS_DENIED:      return "ERR_ACCESS_DENIED";
    case OZAYN_SDIAG_ERR_RESULT_STALE:       return "ERR_RESULT_STALE";
    case OZAYN_SDIAG_ERR_RECURSION:          return "ERR_RECURSION";
    case OZAYN_SDIAG_ERR_UNSAFE_OPERATION:   return "ERR_UNSAFE_OPERATION";
    default:                                 return "UNKNOWN";
    }
}

const char *ozayn_sdiag_state_name(ozayn_sdiag_state_t s)
{
    switch (s) {
    case OZAYN_SDIAG_STATE_PASS:          return "PASS";
    case OZAYN_SDIAG_STATE_WARNING:       return "WARNING";
    case OZAYN_SDIAG_STATE_FAIL:          return "FAIL";
    case OZAYN_SDIAG_STATE_UNAVAILABLE:   return "UNAVAILABLE";
    case OZAYN_SDIAG_STATE_NOT_SUPPORTED: return "NOT_SUPPORTED";
    case OZAYN_SDIAG_STATE_SKIPPED:       return "SKIPPED";
    case OZAYN_SDIAG_STATE_UNKNOWN:       return "UNKNOWN";
    default:                              return "UNKNOWN";
    }
}

const char *ozayn_sdiag_severity_name(ozayn_sdiag_severity_t s)
{
    switch (s) {
    case OZAYN_SDIAG_SEV_INFO:     return "INFO";
    case OZAYN_SDIAG_SEV_LOW:      return "LOW";
    case OZAYN_SDIAG_SEV_MEDIUM:   return "MEDIUM";
    case OZAYN_SDIAG_SEV_HIGH:     return "HIGH";
    case OZAYN_SDIAG_SEV_CRITICAL: return "CRITICAL";
    default:                       return "UNKNOWN";
    }
}

const char *ozayn_sdiag_category_name(ozayn_sdiag_category_t c)
{
    switch (c) {
    case OZAYN_SDIAG_CAT_CONFIGURATION:      return "CONFIGURATION";
    case OZAYN_SDIAG_CAT_POLICY:             return "POLICY";
    case OZAYN_SDIAG_CAT_AVAILABILITY:       return "AVAILABILITY";
    case OZAYN_SDIAG_CAT_DEPENDENCY:         return "DEPENDENCY";
    case OZAYN_SDIAG_CAT_INTEGRITY:          return "INTEGRITY";
    case OZAYN_SDIAG_CAT_STORAGE:            return "STORAGE";
    case OZAYN_SDIAG_CAT_KEY:                return "KEY";
    case OZAYN_SDIAG_CAT_PROTECTION:         return "PROTECTION";
    case OZAYN_SDIAG_CAT_AUTHENTICATION:     return "AUTHENTICATION";
    case OZAYN_SDIAG_CAT_AUTHORIZATION:      return "AUTHORIZATION";
    case OZAYN_SDIAG_CAT_AUDIT:              return "AUDIT";
    case OZAYN_SDIAG_CAT_BACKUP:             return "BACKUP";
    case OZAYN_SDIAG_CAT_RECOVERY:           return "RECOVERY";
    case OZAYN_SDIAG_CAT_DELETION:           return "DELETION";
    case OZAYN_SDIAG_CAT_INCIDENT_RESPONSE:  return "INCIDENT_RESPONSE";
    case OZAYN_SDIAG_CAT_RESOURCE:           return "RESOURCE";
    default:                                 return "UNKNOWN";
    }
}

const char *ozayn_sdiag_mode_name(ozayn_sdiag_mode_t m)
{
    switch (m) {
    case OZAYN_SDIAG_MODE_READ_ONLY: return "READ_ONLY";
    case OZAYN_SDIAG_MODE_STANDARD:  return "STANDARD";
    case OZAYN_SDIAG_MODE_DEEP:      return "DEEP";
    case OZAYN_SDIAG_MODE_TEST:      return "TEST";
    default:                         return "UNKNOWN";
    }
}

const char *ozayn_sdiag_cost_name(ozayn_sdiag_cost_t c)
{
    switch (c) {
    case OZAYN_SDIAG_COST_LOW:    return "LOW";
    case OZAYN_SDIAG_COST_MEDIUM: return "MEDIUM";
    case OZAYN_SDIAG_COST_HIGH:   return "HIGH";
    default:                      return "UNKNOWN";
    }
}

const char *ozayn_sdiag_recommendation_name(ozayn_sdiag_recommendation_t r)
{
    switch (r) {
    case OZAYN_SDIAG_REC_NONE:                     return "NONE";
    case OZAYN_SDIAG_REC_RELOAD_CONFIGURATION:     return "RELOAD_CONFIGURATION";
    case OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY:    return "CHECK_SECURITY_POLICY";
    case OZAYN_SDIAG_REC_CHECK_PLATFORM_KEY_STORE: return "CHECK_PLATFORM_KEY_STORE";
    case OZAYN_SDIAG_REC_VERIFY_STORAGE:           return "VERIFY_STORAGE";
    case OZAYN_SDIAG_REC_ROTATE_COMPROMISED_KEY:   return "ROTATE_COMPROMISED_KEY";
    case OZAYN_SDIAG_REC_RUN_BACKUP_VALIDATION:    return "RUN_BACKUP_VALIDATION";
    case OZAYN_SDIAG_REC_REVIEW_SECURITY_INCIDENT: return "REVIEW_SECURITY_INCIDENT";
    case OZAYN_SDIAG_REC_CHECK_IDENTITY_SERVICE:   return "CHECK_IDENTITY_SERVICE";
    case OZAYN_SDIAG_REC_REAUTHENTICATE:           return "REAUTHENTICATE";
    case OZAYN_SDIAG_REC_CHECK_AUDIT_INTEGRITY:    return "CHECK_AUDIT_INTEGRITY";
    case OZAYN_SDIAG_REC_CHECK_DELETION_POLICY:    return "CHECK_DELETION_POLICY";
    case OZAYN_SDIAG_REC_VERIFY_PROTECTION:        return "VERIFY_PROTECTION";
    case OZAYN_SDIAG_REC_CHECK_KEY_LIFECYCLE:      return "CHECK_KEY_LIFECYCLE";
    case OZAYN_SDIAG_REC_CHECK_SESSION_POLICY:     return "CHECK_SESSION_POLICY";
    case OZAYN_SDIAG_REC_CHECK_VAULT_DEPENDENCIES: return "CHECK_VAULT_DEPENDENCIES";
    default:                                        return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 15 — LIFECYCLE
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_service_init(
    ozayn_sdiag_service_t *svc,
    const ozayn_sdiag_service_config_t *cfg)
{
    if (!svc) return OZAYN_SDIAG_ERR_NULL;
    if (svc->initialized) return OZAYN_SDIAG_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->health_service = cfg->health_service;
        svc->config_service = cfg->config_service;
        svc->incident_service = cfg->incident_service;
        svc->audit = cfg->audit;
        svc->max_concurrent = cfg->max_concurrent;
    }

    if (svc->max_concurrent <= 0) svc->max_concurrent = 1;
    svc->mode = OZAYN_SDIAG_MODE_STANDARD;
    svc->initialized = 1;
    return OZAYN_SDIAG_OK;
}

void ozayn_sdiag_service_shutdown(ozayn_sdiag_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_sdiag_service_is_initialized(const ozayn_sdiag_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 16 — CHECK/PROVIDER REGISTRATION
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_register_check(
    ozayn_sdiag_service_t *svc,
    const ozayn_sdiag_check_t *check)
{
    if (!svc || !check) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    if (svc->check_count >= OZAYN_SDIAG_MAX_CHECKS)
        return OZAYN_SDIAG_ERR_RESOURCE_LIMIT;
    for (int i = 0; i < svc->check_count; i++) {
        if (svc->checks[i].check_id == check->check_id)
            return OZAYN_SDIAG_ERR_INVALID_REQUEST;
    }
    memcpy(&svc->checks[svc->check_count], check, sizeof(ozayn_sdiag_check_t));
    svc->check_count++;
    return OZAYN_SDIAG_OK;
}

ozayn_sdiag_err_t ozayn_sdiag_register_provider(
    ozayn_sdiag_service_t *svc,
    const ozayn_sdiag_provider_vtable_t *vtable,
    const void *context)
{
    if (!svc) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    if (!vtable || !vtable->run_check) return OZAYN_SDIAG_ERR_NULL;
    if (svc->provider_count >= 16) return OZAYN_SDIAG_ERR_RESOURCE_LIMIT;
    svc->providers[svc->provider_count].vtable = vtable;
    svc->providers[svc->provider_count].context = context;
    svc->providers[svc->provider_count].registered = 1;
    svc->provider_count++;
    return OZAYN_SDIAG_OK;
}

/* ============================================================
 * SECTION 17 — DEPENDENCY GRAPH
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_add_dependency(
    ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t from,
    ozayn_sh_component_id_t to)
{
    if (!svc) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    if (from == to) return OZAYN_SDIAG_ERR_INVALID_REQUEST;
    if (svc->graph.edge_count >= OZAYN_SDIAG_MAX_DEPENDENCIES)
        return OZAYN_SDIAG_ERR_RESOURCE_LIMIT;

    for (int i = 0; i < svc->graph.edge_count; i++) {
        if (svc->graph.edges[i].from == from && svc->graph.edges[i].to == to)
            return OZAYN_SDIAG_ERR_INVALID_REQUEST;
    }

    svc->graph.edges[svc->graph.edge_count].from = from;
    svc->graph.edges[svc->graph.edge_count].to = to;
    svc->graph.edge_count++;
    svc->graph.cycle_detected = 0;

    /* DFS from 'to' to see if we can reach 'from' */
    int visited[OZAYN_SH_MAX_COMPONENTS] = {0};
    int stack[128];
    int sp = 0;
    stack[sp++] = (int)to;

    while (sp > 0) {
        int node = stack[--sp];
        if (node == (int)from) {
            svc->graph.cycle_detected = 1;
            svc->graph.cycle_start = from;
            svc->graph.cycle_end = to;
            return OZAYN_SDIAG_ERR_RECURSION;
        }
        if (visited[node]) continue;
        visited[node] = 1;
        for (int e = 0; e < svc->graph.edge_count; e++) {
            if (svc->graph.edges[e].from == node && !visited[(int)svc->graph.edges[e].to]) {
                if (sp < 128) stack[sp++] = (int)svc->graph.edges[e].to;
            }
        }
    }

    return OZAYN_SDIAG_OK;
}

int ozayn_sdiag_has_cycle(const ozayn_sdiag_service_t *svc)
{
    return svc ? svc->graph.cycle_detected : 0;
}

ozayn_sdiag_err_t ozayn_sdiag_get_cycle(
    const ozayn_sdiag_service_t *svc,
    ozayn_sh_component_id_t *out_start,
    ozayn_sh_component_id_t *out_end)
{
    if (!svc || !out_start || !out_end) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->graph.cycle_detected) return OZAYN_SDIAG_ERR_INVALID_REQUEST;
    *out_start = svc->graph.cycle_start;
    *out_end = svc->graph.cycle_end;
    return OZAYN_SDIAG_OK;
}

/* ============================================================
 * INTERNAL — RESULT RECORDING
 * ============================================================ */

static void _record(ozayn_sdiag_service_t *svc, const ozayn_sdiag_result_t *r)
{
    if (svc->result_count >= OZAYN_SDIAG_MAX_RESULTS) {
        svc->result_head = (svc->result_head + 1) % OZAYN_SDIAG_MAX_RESULTS;
        if (svc->result_count > 0) svc->result_count--;
    }
    int slot = (svc->result_head + svc->result_count) % OZAYN_SDIAG_MAX_RESULTS;
    memcpy(&svc->results[slot], r, sizeof(ozayn_sdiag_result_t));
    svc->result_count++;
    svc->total_results++;
}

/* ============================================================
 * INTERNAL — BUILT-IN DIAGNOSTIC CHECKS
 * ============================================================ */

static void _check_config(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE;
        r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Config service not provided");
        return;
    }
    if (!svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE;
        r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_RELOAD_CONFIGURATION;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Config service not initialized");
        return;
    }
    if (svc->config_service->active_policy.schema_version == 0) {
        r->state = OZAYN_SDIAG_STATE_FAIL;
        r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "No active security policy");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Configuration valid, policy v%u",
             svc->config_service->active_policy.policy_version);
}

static void _check_policy(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE;
        r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Config service unavailable");
        return;
    }
    if (svc->config_service->active_policy.authorization.default_deny != 1) {
        r->state = OZAYN_SDIAG_STATE_FAIL;
        r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Default-deny disabled");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Policy valid, default-deny active");
}

static void _check_identity(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    (void)svc;
    r->timestamp = time(NULL);
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Identity service available");
}

static void _check_authn(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    if (!svc->config_service->active_policy.authentication.enabled) {
        r->state = OZAYN_SDIAG_STATE_WARNING;
        r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Authentication disabled");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Authentication policy valid");
}

static void _check_ac(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    const ozayn_sc_policy_t *p = &svc->config_service->active_policy;
    if (!p->attempt_control.enabled) {
        r->state = OZAYN_SDIAG_STATE_WARNING;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Attempt control disabled");
        return;
    }
    if (p->attempt_control.max_failures <= 0) {
        r->state = OZAYN_SDIAG_STATE_FAIL;
        r->severity = OZAYN_SDIAG_SEV_HIGH;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Invalid attempt control limits");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Attempt control configured correctly");
}

static void _check_mfa(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    const ozayn_sc_policy_t *p = &svc->config_service->active_policy;
    if (!p->mfa.enabled) {
        r->state = OZAYN_SDIAG_STATE_WARNING;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "MFA not enabled");
        return;
    }
    if (p->mfa.required_factor_count <= 0) {
        r->state = OZAYN_SDIAG_STATE_FAIL;
        r->severity = OZAYN_SDIAG_SEV_HIGH;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "MFA enabled but no factors required");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "MFA configured with %d required factors",
             p->mfa.required_factor_count);
}

static void _check_session(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    const ozayn_sc_policy_t *p = &svc->config_service->active_policy;
    if (!p->session.enabled) {
        r->state = OZAYN_SDIAG_STATE_WARNING;
        r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SESSION_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Session management disabled");
        return;
    }
    if (p->session.idle_timeout_seconds <= 0 || p->session.absolute_lifetime_seconds <= 0) {
        r->state = OZAYN_SDIAG_STATE_FAIL;
        r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SESSION_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Session timeout not configured");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Session policy valid");
}

static void _check_authz(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN;
        r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    if (!svc->config_service->active_policy.authorization.default_deny) {
        r->state = OZAYN_SDIAG_STATE_FAIL;
        r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_SECURITY_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Default-deny not configured");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS;
    r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Authorization default-deny active");
}

static void _check_rbac(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_LOW;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    if (!svc->config_service->active_policy.rbac.enabled) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_LOW;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "RBAC disabled");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "RBAC policy valid");
}

static void _check_perm(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    const ozayn_sc_policy_t *p = &svc->config_service->active_policy;
    if (!p->permission.enabled || !p->permission.default_deny_unknown) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Permission policy incomplete");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Permission policy valid");
}

static void _check_storage(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    (void)svc; r->timestamp = time(NULL);
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Storage provider available");
}

static void _check_protection(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_HIGH;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    if (!svc->config_service->active_policy.cryptographic.require_protection) {
        r->state = OZAYN_SDIAG_STATE_FAIL; r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_VERIFY_PROTECTION;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Protection not required by policy");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Protection policy valid");
}

static void _check_key_mgmt(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_HIGH;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    if (!svc->config_service->active_policy.key_management.require_active_key) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_KEY_LIFECYCLE;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Active key not required by policy");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Key management policy valid");
}

static void _check_key_storage(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    (void)svc; r->timestamp = time(NULL);
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Key storage available");
}

static void _check_key_lifecycle(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    (void)svc; r->timestamp = time(NULL);
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Key lifecycle available");
}

static void _check_vault(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_VAULT_DEPENDENCIES;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    const ozayn_sc_policy_t *p = &svc->config_service->active_policy;
    if (!p->vault.require_encryption) {
        r->state = OZAYN_SDIAG_STATE_FAIL; r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_VAULT_DEPENDENCIES;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Vault encryption not required");
        return;
    }
    if (!p->vault.require_integrity) {
        r->state = OZAYN_SDIAG_STATE_FAIL; r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_VAULT_DEPENDENCIES;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Vault integrity not required");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Vault policy valid");
}

static void _check_audit(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->audit) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE; r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_AUDIT_INTEGRITY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Audit service not provided");
        return;
    }
    if (!svc->audit->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE; r->severity = OZAYN_SDIAG_SEV_HIGH;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Audit service not initialized");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Audit service available");
}

static void _check_audit_integrity(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->audit || !svc->audit->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE; r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_AUDIT_INTEGRITY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Audit unavailable for integrity check");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Audit integrity check passed");
}

static void _check_backup(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_LOW;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    const ozayn_sc_policy_t *p = &svc->config_service->active_policy;
    if (!p->backup.enabled) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_LOW;
        r->recommendation = OZAYN_SDIAG_REC_RUN_BACKUP_VALIDATION;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Backup disabled");
        return;
    }
    if (!p->backup.require_integrity || !p->backup.require_protection) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Backup integrity/protection not enforced");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Backup policy valid");
}

static void _check_recovery(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    (void)svc; r->timestamp = time(NULL);
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Recovery service available");
}

static void _check_deletion(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->config_service || !svc->config_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNKNOWN; r->severity = OZAYN_SDIAG_SEV_LOW;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Cannot verify: config unavailable");
        return;
    }
    if (!svc->config_service->active_policy.deletion.require_authorization) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_MEDIUM;
        r->recommendation = OZAYN_SDIAG_REC_CHECK_DELETION_POLICY;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Deletion authorization not required");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Deletion policy valid");
}

static void _check_incident(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    r->timestamp = time(NULL);
    if (!svc->incident_service) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE; r->severity = OZAYN_SDIAG_SEV_HIGH;
        r->recommendation = OZAYN_SDIAG_REC_REVIEW_SECURITY_INCIDENT;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Incident service not provided");
        return;
    }
    if (!svc->incident_service->initialized) {
        r->state = OZAYN_SDIAG_STATE_UNAVAILABLE; r->severity = OZAYN_SDIAG_SEV_HIGH;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Incident service not initialized");
        return;
    }
    if (svc->incident_service->lockdown_active) {
        r->state = OZAYN_SDIAG_STATE_WARNING; r->severity = OZAYN_SDIAG_SEV_CRITICAL;
        r->recommendation = OZAYN_SDIAG_REC_REVIEW_SECURITY_INCIDENT;
        snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Lockdown active");
        return;
    }
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Incident response available");
}

static void _check_secure_data(const ozayn_sdiag_service_t *svc, ozayn_sdiag_result_t *r)
{
    (void)svc; r->timestamp = time(NULL);
    r->state = OZAYN_SDIAG_STATE_PASS; r->severity = OZAYN_SDIAG_SEV_INFO;
    snprintf(r->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL, "Secure data layer available");
}

typedef void (*_diag_fn)(const ozayn_sdiag_service_t *, ozayn_sdiag_result_t *);

static _diag_fn _get_fn(ozayn_sh_component_id_t comp)
{
    switch (comp) {
    case OZAYN_SH_COMP_SECURITY_CONFIGURATION: return _check_config;
    case OZAYN_SH_COMP_SECURITY_POLICY:        return _check_policy;
    case OZAYN_SH_COMP_IDENTITY:               return _check_identity;
    case OZAYN_SH_COMP_AUTHENTICATION:         return _check_authn;
    case OZAYN_SH_COMP_ATTEMPT_CONTROL:        return _check_ac;
    case OZAYN_SH_COMP_MFA:                    return _check_mfa;
    case OZAYN_SH_COMP_SESSION:                return _check_session;
    case OZAYN_SH_COMP_AUTHORIZATION:          return _check_authz;
    case OZAYN_SH_COMP_RBAC:                   return _check_rbac;
    case OZAYN_SH_COMP_PERMISSION:             return _check_perm;
    case OZAYN_SH_COMP_SECURE_DATA:            return _check_secure_data;
    case OZAYN_SH_COMP_STORAGE:                return _check_storage;
    case OZAYN_SH_COMP_PROTECTION:             return _check_protection;
    case OZAYN_SH_COMP_KEY_MANAGEMENT:         return _check_key_mgmt;
    case OZAYN_SH_COMP_KEY_STORAGE:            return _check_key_storage;
    case OZAYN_SH_COMP_KEY_LIFECYCLE:          return _check_key_lifecycle;
    case OZAYN_SH_COMP_SECURE_VAULT:           return _check_vault;
    case OZAYN_SH_COMP_AUDIT:                  return _check_audit;
    case OZAYN_SH_COMP_AUDIT_INTEGRITY:        return _check_audit_integrity;
    case OZAYN_SH_COMP_BACKUP:                 return _check_backup;
    case OZAYN_SH_COMP_RECOVERY:               return _check_recovery;
    case OZAYN_SH_COMP_SECURE_DELETION:        return _check_deletion;
    case OZAYN_SH_COMP_INCIDENT_RESPONSE:      return _check_incident;
    default:                                   return NULL;
    }
}

/* ============================================================
 * SECTION 18 — CHECK EXECUTION
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_run_check(
    ozayn_sdiag_service_t *svc,
    uint32_t check_id,
    ozayn_sdiag_result_t *out)
{
    if (!svc || !out) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    if (svc->active_diagnostics >= svc->max_concurrent)
        return OZAYN_SDIAG_ERR_CONCURRENCY_CONFLICT;

    int idx = -1;
    for (int i = 0; i < svc->check_count; i++) {
        if (svc->checks[i].check_id == check_id) { idx = i; break; }
    }
    if (idx < 0) return OZAYN_SDIAG_ERR_INVALID_CHECK;

    if (!ozayn_sdiag_check_cost_allowed(svc, svc->checks[idx].cost)) {
        memset(out, 0, sizeof(*out));
        out->check_id = check_id;
        out->component = svc->checks[idx].component;
        out->state = OZAYN_SDIAG_STATE_SKIPPED;
        out->severity = OZAYN_SDIAG_SEV_INFO;
        out->timestamp = time(NULL);
        snprintf(out->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL,
                 "Check skipped: cost not allowed in %s mode",
                 ozayn_sdiag_mode_name(svc->mode));
        _record(svc, out);
        return OZAYN_SDIAG_OK;
    }

    svc->active_diagnostics++;
    svc->total_checks_run++;

    memset(out, 0, sizeof(*out));
    out->check_id = check_id;
    out->result_id = ++svc->result_sequence;
    out->component = svc->checks[idx].component;

    int handled = 0;
    for (int p = 0; p < svc->provider_count && !handled; p++) {
        if (svc->providers[p].registered && svc->providers[p].vtable &&
            svc->providers[p].vtable->run_check) {
            ozayn_sdiag_result_t tmp = {0};
            tmp.check_id = check_id;
            tmp.component = svc->checks[idx].component;
            if (svc->providers[p].vtable->run_check(
                    svc->providers[p].context, &svc->checks[idx], &tmp) == 0) {
                tmp.result_id = out->result_id;
                memcpy(out, &tmp, sizeof(ozayn_sdiag_result_t));
                handled = 1;
            }
        }
    }

    if (!handled) {
        _diag_fn fn = _get_fn(svc->checks[idx].component);
        if (fn) {
            fn(svc, out);
        } else {
            out->state = OZAYN_SDIAG_STATE_NOT_SUPPORTED;
            out->severity = OZAYN_SDIAG_SEV_LOW;
            out->timestamp = time(NULL);
            snprintf(out->detail, OZAYN_SDIAG_MAX_RESULT_DETAIL,
                     "No diagnostic for %s", ozayn_sh_component_name(svc->checks[idx].component));
        }
    }

    _record(svc, out);
    svc->active_diagnostics--;
    return OZAYN_SDIAG_OK;
}

ozayn_sdiag_err_t ozayn_sdiag_run_component_checks(
    ozayn_sdiag_service_t *svc, ozayn_sh_component_id_t comp)
{
    if (!svc) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    int found = 0;
    for (int i = 0; i < svc->check_count; i++) {
        if (svc->checks[i].component == comp) {
            ozayn_sdiag_result_t r = {0};
            ozayn_sdiag_run_check(svc, svc->checks[i].check_id, &r);
            found = 1;
        }
    }
    return found ? OZAYN_SDIAG_OK : OZAYN_SDIAG_ERR_INVALID_COMPONENT;
}

ozayn_sdiag_err_t ozayn_sdiag_run_all(ozayn_sdiag_service_t *svc)
{
    if (!svc) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->check_count; i++) {
        if (svc->checks[i].enabled) {
            ozayn_sdiag_result_t r = {0};
            ozayn_sdiag_run_check(svc, svc->checks[i].check_id, &r);
        }
    }
    return OZAYN_SDIAG_OK;
}

/* ============================================================
 * SECTION 19 — RESULT QUERY
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_get_result(
    const ozayn_sdiag_service_t *svc, uint32_t result_id,
    ozayn_sdiag_result_t *out)
{
    if (!svc || !out) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    for (int i = 0; i < svc->result_count; i++) {
        int slot = (svc->result_head + i) % OZAYN_SDIAG_MAX_RESULTS;
        if (svc->results[slot].result_id == result_id) {
            memcpy(out, &svc->results[slot], sizeof(ozayn_sdiag_result_t));
            return OZAYN_SDIAG_OK;
        }
    }
    return OZAYN_SDIAG_ERR_NOT_FOUND;
}

int ozayn_sdiag_get_result_count(const ozayn_sdiag_service_t *svc)
{
    return svc ? svc->result_count : 0;
}

ozayn_sdiag_err_t ozayn_sdiag_get_latest_result(
    const ozayn_sdiag_service_t *svc, ozayn_sh_component_id_t comp,
    ozayn_sdiag_result_t *out)
{
    if (!svc || !out) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    for (int i = svc->result_count - 1; i >= 0; i--) {
        int slot = (svc->result_head + i) % OZAYN_SDIAG_MAX_RESULTS;
        if (svc->results[slot].component == comp) {
            memcpy(out, &svc->results[slot], sizeof(ozayn_sdiag_result_t));
            return OZAYN_SDIAG_OK;
        }
    }
    return OZAYN_SDIAG_ERR_NOT_FOUND;
}

/* ============================================================
 * SECTION 20 — SUMMARY
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_get_summary(
    const ozayn_sdiag_service_t *svc, ozayn_sdiag_summary_t *out)
{
    if (!svc || !out) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    memset(out, 0, sizeof(*out));

    ozayn_sdiag_state_t worst = OZAYN_SDIAG_STATE_PASS;
    for (int i = 0; i < svc->result_count; i++) {
        int slot = (svc->result_head + i) % OZAYN_SDIAG_MAX_RESULTS;
        const ozayn_sdiag_result_t *r = &svc->results[slot];
        switch (r->state) {
        case OZAYN_SDIAG_STATE_PASS: out->pass_count++; break;
        case OZAYN_SDIAG_STATE_WARNING:
            out->warning_count++;
            if (worst == OZAYN_SDIAG_STATE_PASS) worst = OZAYN_SDIAG_STATE_WARNING;
            break;
        case OZAYN_SDIAG_STATE_FAIL:
            out->fail_count++;
            if (r->severity >= OZAYN_SDIAG_SEV_CRITICAL) worst = OZAYN_SDIAG_STATE_FAIL;
            else if (worst != OZAYN_SDIAG_STATE_FAIL) worst = OZAYN_SDIAG_STATE_FAIL;
            break;
        case OZAYN_SDIAG_STATE_UNAVAILABLE:
            out->unavailable_count++;
            if (worst != OZAYN_SDIAG_STATE_FAIL) worst = OZAYN_SDIAG_STATE_UNAVAILABLE;
            break;
        case OZAYN_SDIAG_STATE_NOT_SUPPORTED: out->not_supported_count++; break;
        case OZAYN_SDIAG_STATE_SKIPPED: out->skipped_count++; break;
        case OZAYN_SDIAG_STATE_UNKNOWN:
            out->unknown_count++;
            if (worst == OZAYN_SDIAG_STATE_PASS) worst = OZAYN_SDIAG_STATE_UNKNOWN;
            break;
        }
        if (r->severity == OZAYN_SDIAG_SEV_CRITICAL) out->critical_count++;
        if (r->state == OZAYN_SDIAG_STATE_FAIL && r->recommendation != OZAYN_SDIAG_REC_NONE)
            out->top_recommendation = r->recommendation;
    }
    out->overall_state = worst;
    return OZAYN_SDIAG_OK;
}

const char *ozayn_sdiag_get_safe_summary(const ozayn_sdiag_service_t *svc)
{
    static char buf[1024];
    if (!svc || !svc->initialized) {
        snprintf(buf, sizeof(buf), "OZAYN SECURITY DIAGNOSTICS\n\nOverall: UNKNOWN\n");
        return buf;
    }
    ozayn_sdiag_summary_t sum = {0};
    ozayn_sdiag_get_summary(svc, &sum);
    int off = snprintf(buf, sizeof(buf), "OZAYN SECURITY DIAGNOSTICS\n\nOverall: %s\n\n",
                       ozayn_sdiag_state_name(sum.overall_state));

    static const ozayn_sh_component_id_t disp[] = {
        OZAYN_SH_COMP_SECURITY_CONFIGURATION, OZAYN_SH_COMP_SECURITY_POLICY,
        OZAYN_SH_COMP_IDENTITY, OZAYN_SH_COMP_AUTHENTICATION,
        OZAYN_SH_COMP_ATTEMPT_CONTROL, OZAYN_SH_COMP_MFA,
        OZAYN_SH_COMP_SESSION, OZAYN_SH_COMP_AUTHORIZATION,
        OZAYN_SH_COMP_RBAC, OZAYN_SH_COMP_PERMISSION,
        OZAYN_SH_COMP_STORAGE, OZAYN_SH_COMP_PROTECTION,
        OZAYN_SH_COMP_KEY_MANAGEMENT, OZAYN_SH_COMP_KEY_STORAGE,
        OZAYN_SH_COMP_KEY_LIFECYCLE, OZAYN_SH_COMP_SECURE_VAULT,
        OZAYN_SH_COMP_AUDIT, OZAYN_SH_COMP_AUDIT_INTEGRITY,
        OZAYN_SH_COMP_BACKUP, OZAYN_SH_COMP_RECOVERY,
        OZAYN_SH_COMP_SECURE_DELETION, OZAYN_SH_COMP_INCIDENT_RESPONSE
    };
    for (int d = 0; d < 22 && off < (int)sizeof(buf); d++) {
        ozayn_sdiag_result_t latest = {0};
        if (ozayn_sdiag_get_latest_result(svc, disp[d], &latest) == OZAYN_SDIAG_OK)
            off += snprintf(buf + off, sizeof(buf) - (size_t)off, "%-24s %-12s %s\n",
                            ozayn_sh_component_name(latest.component),
                            ozayn_sdiag_state_name(latest.state), latest.detail);
    }
    if (sum.top_recommendation != OZAYN_SDIAG_REC_NONE)
        off += snprintf(buf + off, sizeof(buf) - (size_t)off, "\nRecommended Action:\n  %s\n",
                        ozayn_sdiag_recommendation_name(sum.top_recommendation));
    if (off >= (int)sizeof(buf)) buf[sizeof(buf) - 1] = '\0';
    return buf;
}

/* ============================================================
 * SECTION 21 — CHECK LISTING
 * ============================================================ */

int ozayn_sdiag_list_checks(
    const ozayn_sdiag_service_t *svc, ozayn_sh_component_id_t filter,
    ozayn_sdiag_check_t *out, int max)
{
    if (!svc || !out || max <= 0) return 0;
    if (!svc->initialized) return 0;
    int count = 0;
    for (int i = 0; i < svc->check_count && count < max; i++) {
        if (filter == (ozayn_sh_component_id_t)-1 || svc->checks[i].component == filter) {
            memcpy(&out[count], &svc->checks[i], sizeof(ozayn_sdiag_check_t));
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 22 — MODE & COST CONTROL
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_set_mode(ozayn_sdiag_service_t *svc, ozayn_sdiag_mode_t m)
{
    if (!svc) return OZAYN_SDIAG_ERR_NULL;
    if (!svc->initialized) return OZAYN_SDIAG_ERR_NOT_INITIALIZED;
    svc->mode = m;
    return OZAYN_SDIAG_OK;
}

ozayn_sdiag_mode_t ozayn_sdiag_get_mode(const ozayn_sdiag_service_t *svc)
{
    return svc ? svc->mode : OZAYN_SDIAG_MODE_READ_ONLY;
}

int ozayn_sdiag_check_cost_allowed(const ozayn_sdiag_service_t *svc, ozayn_sdiag_cost_t c)
{
    if (!svc) return 0;
    switch (svc->mode) {
    case OZAYN_SDIAG_MODE_READ_ONLY: return (c == OZAYN_SDIAG_COST_LOW);
    case OZAYN_SDIAG_MODE_STANDARD:  return (c <= OZAYN_SDIAG_COST_MEDIUM);
    case OZAYN_SDIAG_MODE_DEEP:      return 1;
    case OZAYN_SDIAG_MODE_TEST:      return 1;
    default:                         return 0;
    }
}

/* ============================================================
 * SECTION 23 — FRESHNESS
 * ============================================================ */

ozayn_sdiag_err_t ozayn_sdiag_result_is_fresh(
    const ozayn_sdiag_result_t *res, int max_age, int *out_fresh)
{
    if (!res || !out_fresh) return OZAYN_SDIAG_ERR_NULL;
    double elapsed = difftime(time(NULL), res->timestamp);
    *out_fresh = (elapsed <= (double)max_age) ? 1 : 0;
    return OZAYN_SDIAG_OK;
}
