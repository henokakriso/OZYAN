/*
 * sec_health.c — Security Health Monitoring & Security Self-Assessment
 *                Foundation (Step 27).
 *
 * Provides deterministic internal evaluation of OZAYN's security
 * infrastructure with dependency-aware aggregation, operation safety
 * checks, health snapshots, and event-driven audit integration.
 */

#include "sec_health.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * STATIC GLOBAL
 * ============================================================ */

static ozayn_sh_service_t _sh_global = {0};

ozayn_sh_service_t *ozayn_sh_get_global(void)
{
    return &_sh_global;
}

/* ============================================================
 * SECTION 20 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sh_result_name(ozayn_sh_result_t r)
{
    switch (r) {
    case OZAYN_SH_OK:                          return "OK";
    case OZAYN_SH_ERR:                         return "ERR";
    case OZAYN_SH_ERR_NULL:                    return "ERR_NULL";
    case OZAYN_SH_ERR_NOT_INITIALIZED:         return "ERR_NOT_INITIALIZED";
    case OZAYN_SH_ERR_ALREADY_INITIALIZED:     return "ERR_ALREADY_INITIALIZED";
    case OZAYN_SH_ERR_INVALID_REQUEST:         return "ERR_INVALID_REQUEST";
    case OZAYN_SH_ERR_INVALID_COMPONENT:       return "ERR_INVALID_COMPONENT";
    case OZAYN_SH_ERR_INVALID_STATE:           return "ERR_INVALID_STATE";
    case OZAYN_SH_ERR_UNAVAILABLE:             return "ERR_UNAVAILABLE";
    case OZAYN_SH_ERR_CHECK_FAILED:            return "ERR_CHECK_FAILED";
    case OZAYN_SH_ERR_CHECK_TIMEOUT:           return "ERR_CHECK_TIMEOUT";
    case OZAYN_SH_ERR_POLICY_INVALID:          return "ERR_POLICY_INVALID";
    case OZAYN_SH_ERR_POLICY_UNAVAILABLE:      return "ERR_POLICY_UNAVAILABLE";
    case OZAYN_SH_ERR_CONFIGURATION_INVALID:   return "ERR_CONFIGURATION_INVALID";
    case OZAYN_SH_ERR_DEPENDENCY_FAILED:       return "ERR_DEPENDENCY_FAILED";
    case OZAYN_SH_ERR_INTEGRITY_FAILED:        return "ERR_INTEGRITY_FAILED";
    case OZAYN_SH_ERR_SNAPSHOT_INVALID:        return "ERR_SNAPSHOT_INVALID";
    case OZAYN_SH_ERR_SNAPSHOT_STALE:          return "ERR_SNAPSHOT_STALE";
    case OZAYN_SH_ERR_RESOURCE_LIMIT:          return "ERR_RESOURCE_LIMIT";
    case OZAYN_SH_ERR_CONCURRENCY_CONFLICT:    return "ERR_CONCURRENCY_CONFLICT";
    case OZAYN_SH_ERR_LOCKDOWN:                return "ERR_LOCKDOWN";
    case OZAYN_SH_ERR_OPERATION_UNSAFE:        return "ERR_OPERATION_UNSAFE";
    default:                                   return "UNKNOWN";
    }
}

const char *ozayn_sh_health_state_name(ozayn_sh_health_state_t s)
{
    switch (s) {
    case OZAYN_SH_HEALTHY:     return "HEALTHY";
    case OZAYN_SH_DEGRADED:    return "DEGRADED";
    case OZAYN_SH_WARNING:     return "WARNING";
    case OZAYN_SH_CRITICAL:    return "CRITICAL";
    case OZAYN_SH_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_SH_UNKNOWN:     return "UNKNOWN";
    case OZAYN_SH_LOCKDOWN:    return "LOCKDOWN";
    default:                   return "UNKNOWN";
    }
}

const char *ozayn_sh_component_name(ozayn_sh_component_id_t c)
{
    switch (c) {
    case OZAYN_SH_COMP_SECURITY_CONFIGURATION: return "SECURITY_CONFIGURATION";
    case OZAYN_SH_COMP_SECURITY_POLICY:        return "SECURITY_POLICY";
    case OZAYN_SH_COMP_IDENTITY:               return "IDENTITY";
    case OZAYN_SH_COMP_AUTHENTICATION:         return "AUTHENTICATION";
    case OZAYN_SH_COMP_ATTEMPT_CONTROL:        return "ATTEMPT_CONTROL";
    case OZAYN_SH_COMP_MFA:                    return "MFA";
    case OZAYN_SH_COMP_SESSION:                return "SESSION";
    case OZAYN_SH_COMP_AUTHORIZATION:          return "AUTHORIZATION";
    case OZAYN_SH_COMP_RBAC:                   return "RBAC";
    case OZAYN_SH_COMP_PERMISSION:             return "PERMISSION";
    case OZAYN_SH_COMP_SECURE_DATA:            return "SECURE_DATA";
    case OZAYN_SH_COMP_STORAGE:                return "STORAGE";
    case OZAYN_SH_COMP_PROTECTION:             return "PROTECTION";
    case OZAYN_SH_COMP_KEY_MANAGEMENT:         return "KEY_MANAGEMENT";
    case OZAYN_SH_COMP_KEY_STORAGE:            return "KEY_STORAGE";
    case OZAYN_SH_COMP_KEY_LIFECYCLE:          return "KEY_LIFECYCLE";
    case OZAYN_SH_COMP_SECURE_VAULT:           return "SECURE_VAULT";
    case OZAYN_SH_COMP_AUDIT:                  return "AUDIT";
    case OZAYN_SH_COMP_AUDIT_INTEGRITY:        return "AUDIT_INTEGRITY";
    case OZAYN_SH_COMP_BACKUP:                 return "BACKUP";
    case OZAYN_SH_COMP_RECOVERY:               return "RECOVERY";
    case OZAYN_SH_COMP_SECURE_DELETION:        return "SECURE_DELETION";
    case OZAYN_SH_COMP_INCIDENT_RESPONSE:      return "INCIDENT_RESPONSE";
    default:                                   return "UNKNOWN_COMPONENT";
    }
}

const char *ozayn_sh_check_type_name(ozayn_sh_check_type_t t)
{
    switch (t) {
    case OZAYN_SH_CHECK_AVAILABILITY:    return "AVAILABILITY";
    case OZAYN_SH_CHECK_CONFIGURATION:   return "CONFIGURATION";
    case OZAYN_SH_CHECK_POLICY:          return "POLICY";
    case OZAYN_SH_CHECK_INTEGRITY:       return "INTEGRITY";
    case OZAYN_SH_CHECK_DEPENDENCY:      return "DEPENDENCY";
    case OZAYN_SH_CHECK_STORAGE:         return "STORAGE";
    case OZAYN_SH_CHECK_KEY_AVAILABILITY:return "KEY_AVAILABILITY";
    case OZAYN_SH_CHECK_AUTHENTICATION:  return "AUTHENTICATION";
    case OZAYN_SH_CHECK_AUTHORIZATION:   return "AUTHORIZATION";
    case OZAYN_SH_CHECK_AUDIT:           return "AUDIT";
    case OZAYN_SH_CHECK_RECOVERY:        return "RECOVERY";
    case OZAYN_SH_CHECK_RESOURCE:        return "RESOURCE";
    default:                             return "UNKNOWN_CHECK";
    }
}

const char *ozayn_sh_integrity_state_name(ozayn_sh_integrity_state_t s)
{
    switch (s) {
    case OZAYN_SH_INTEGRITY_UNKNOWN:       return "UNKNOWN";
    case OZAYN_SH_INTEGRITY_VALID:         return "VALID";
    case OZAYN_SH_INTEGRITY_INVALID:       return "INVALID";
    case OZAYN_SH_INTEGRITY_CHECK_FAILED:  return "CHECK_FAILED";
    default:                               return "UNKNOWN";
    }
}

const char *ozayn_sh_config_state_name(ozayn_sh_config_state_t s)
{
    switch (s) {
    case OZAYN_SH_CONFIG_UNKNOWN:        return "UNKNOWN";
    case OZAYN_SH_CONFIG_VALID:          return "VALID";
    case OZAYN_SH_CONFIG_INVALID:        return "INVALID";
    case OZAYN_SH_CONFIG_MISSING:        return "MISSING";
    case OZAYN_SH_CONFIG_CHECK_FAILED:   return "CHECK_FAILED";
    default:                             return "UNKNOWN";
    }
}

const char *ozayn_sh_policy_state_name(ozayn_sh_policy_state_t s)
{
    switch (s) {
    case OZAYN_SH_POLICY_UNKNOWN:        return "UNKNOWN";
    case OZAYN_SH_POLICY_VALID:          return "VALID";
    case OZAYN_SH_POLICY_INVALID:        return "INVALID";
    case OZAYN_SH_POLICY_MISSING:        return "MISSING";
    case OZAYN_SH_POLICY_CHECK_FAILED:   return "CHECK_FAILED";
    default:                             return "UNKNOWN";
    }
}

const char *ozayn_sh_event_type_name(ozayn_sh_event_type_t e)
{
    switch (e) {
    case OZAYN_SH_EVENT_CHECK_STARTED:          return "CHECK_STARTED";
    case OZAYN_SH_EVENT_CHECK_COMPLETED:        return "CHECK_COMPLETED";
    case OZAYN_SH_EVENT_HEALTH_DEGRADED:        return "HEALTH_DEGRADED";
    case OZAYN_SH_EVENT_HEALTH_WARNING:         return "HEALTH_WARNING";
    case OZAYN_SH_EVENT_HEALTH_CRITICAL:        return "HEALTH_CRITICAL";
    case OZAYN_SH_EVENT_HEALTH_UNKNOWN:         return "HEALTH_UNKNOWN";
    case OZAYN_SH_EVENT_HEALTH_LOCKDOWN:        return "HEALTH_LOCKDOWN";
    case OZAYN_SH_EVENT_COMPONENT_UNAVAILABLE:  return "COMPONENT_UNAVAILABLE";
    case OZAYN_SH_EVENT_COMPONENT_RECOVERED:    return "COMPONENT_RECOVERED";
    case OZAYN_SH_EVENT_INTEGRITY_CHECK_FAILED: return "INTEGRITY_CHECK_FAILED";
    case OZAYN_SH_EVENT_POLICY_HEALTH_FAILED:   return "POLICY_HEALTH_FAILED";
    case OZAYN_SH_EVENT_DEPENDENCY_FAILURE:     return "DEPENDENCY_FAILURE";
    case OZAYN_SH_EVENT_SNAPSHOT_GENERATED:     return "SNAPSHOT_GENERATED";
    case OZAYN_SH_EVENT_OPERATION_UNSAFE:       return "OPERATION_UNSAFE";
    default:                                    return "UNKNOWN_EVENT";
    }
}

const char *ozayn_sh_operation_type_name(ozayn_sh_operation_type_t o)
{
    switch (o) {
    case OZAYN_SH_OP_VAULT_ACCESS:       return "VAULT_ACCESS";
    case OZAYN_SH_OP_KEY_ACCESS:         return "KEY_ACCESS";
    case OZAYN_SH_OP_ENCRYPT:            return "ENCRYPT";
    case OZAYN_SH_OP_DECRYPT:            return "DECRYPT";
    case OZAYN_SH_OP_AUTHENTICATE:       return "AUTHENTICATE";
    case OZAYN_SH_OP_AUTHORIZE:          return "AUTHORIZE";
    case OZAYN_SH_OP_BACKUP:             return "BACKUP";
    case OZAYN_SH_OP_RESTORE:            return "RESTORE";
    case OZAYN_SH_OP_DELETE:             return "DELETE";
    case OZAYN_SH_OP_CONFIG_CHANGE:      return "CONFIG_CHANGE";
    case OZAYN_SH_OP_AUDIT_READ:         return "AUDIT_READ";
    case OZAYN_SH_OP_INCIDENT_REPORT:    return "INCIDENT_REPORT";
    default:                             return "UNKNOWN_OPERATION";
    }
}

const char *ozayn_sh_operation_safety_name(ozayn_sh_operation_safety_t s)
{
    switch (s) {
    case OZAYN_SH_SAFE_ALLOW:    return "ALLOW";
    case OZAYN_SH_SAFE_RESTRICT: return "RESTRICT";
    case OZAYN_SH_SAFE_DENY:     return "DENY";
    default:                     return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 23 — HEALTH STATE AGGREGATION HELPERS
 * ============================================================ */

ozayn_sh_health_state_t ozayn_sh_worse_state(
    ozayn_sh_health_state_t a,
    ozayn_sh_health_state_t b)
{
    /* Severity order: HEALTHY < DEGRADED < WARNING < CRITICAL
     *                 < UNAVAILABLE < UNKNOWN < LOCKDOWN */
    static const int severity[] = {0, 1, 2, 3, 4, 5, 6};
    int sa = (a >= 0 && a <= 6) ? severity[a] : 5;
    int sb = (b >= 0 && b <= 6) ? severity[b] : 5;
    return (sa >= sb) ? a : b;
}

int ozayn_sh_state_is_usable(ozayn_sh_health_state_t s)
{
    return (s == OZAYN_SH_HEALTHY || s == OZAYN_SH_DEGRADED);
}

int ozayn_sh_state_allows_operation(
    ozayn_sh_health_state_t state,
    ozayn_sh_operation_type_t operation)
{
    (void)operation;

    if (state == OZAYN_SH_LOCKDOWN)
        return 0;
    if (state == OZAYN_SH_CRITICAL)
        return 0;
    if (state == OZAYN_SH_UNKNOWN)
        return 0;
    if (state == OZAYN_SH_UNAVAILABLE)
        return 0;
    return 1;
}

/* ============================================================
 * INTERNAL — FIND COMPONENT SLOT
 * ============================================================ */

static int _find_component(const ozayn_sh_service_t *svc,
                            ozayn_sh_component_id_t id)
{
    for (int i = 0; i < svc->component_count; i++) {
        if (svc->components[i].component_id == id)
            return i;
    }
    return -1;
}

/* ============================================================
 * INTERNAL — SET COMPONENT DEFAULTS
 * ============================================================ */

static void _set_component_defaults(ozayn_sh_component_health_t *comp,
                                     ozayn_sh_component_id_t id,
                                     const char *name,
                                     int required,
                                     const ozayn_sh_component_id_t *deps,
                                     int dep_count)
{
    memset(comp, 0, sizeof(*comp));
    comp->component_id = id;
    if (name) {
        size_t len = strlen(name);
        if (len >= OZAYN_SH_MAX_COMPONENT_NAME_LEN)
            len = OZAYN_SH_MAX_COMPONENT_NAME_LEN - 1;
        memcpy(comp->component_name, name, len);
        comp->component_name[len] = '\0';
    }
    comp->health_state = OZAYN_SH_UNKNOWN;
    comp->available = 0;
    comp->integrity_state = OZAYN_SH_INTEGRITY_UNKNOWN;
    comp->config_state = OZAYN_SH_CONFIG_UNKNOWN;
    comp->policy_state = OZAYN_SH_POLICY_UNKNOWN;
    comp->last_check_time = 0;
    comp->check_version = 0;
    comp->failure_code = 0;
    comp->required = required;
    comp->dependency_count = 0;
    if (deps && dep_count > 0) {
        int count = dep_count;
        if (count > 8) count = 8;
        memcpy(comp->dependencies, deps, (size_t)count * sizeof(ozayn_sh_component_id_t));
        comp->dependency_count = count;
    }
    comp->detail[0] = '\0';
}

/* ============================================================
 * SECTION 13 — LIFECYCLE
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_service_init(ozayn_sh_service_t *svc,
                                         const ozayn_sh_service_config_t *cfg)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (svc->initialized) return OZAYN_SH_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->config_service = cfg->config_service;
        svc->incident_service = cfg->incident_service;
        svc->audit = cfg->audit;
        svc->max_concurrent_checks = cfg->max_concurrent_checks;
    }

    if (svc->max_concurrent_checks <= 0)
        svc->max_concurrent_checks = 1;

    svc->check_version = 1;
    svc->initialized = 1;
    return OZAYN_SH_OK;
}

void ozayn_sh_service_shutdown(ozayn_sh_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_sh_service_is_initialized(const ozayn_sh_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 14 — COMPONENT REGISTRATION
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_register_component(
    ozayn_sh_service_t *svc,
    ozayn_sh_component_id_t component_id,
    const char *component_name,
    int required,
    const ozayn_sh_component_id_t *dependencies,
    int dependency_count)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;
    if (component_id < 0 || component_id >= OZAYN_SH_MAX_COMPONENTS)
        return OZAYN_SH_ERR_INVALID_COMPONENT;
    if (svc->component_count >= OZAYN_SH_MAX_COMPONENTS)
        return OZAYN_SH_ERR_RESOURCE_LIMIT;

    /* Check duplicate */
    for (int i = 0; i < svc->component_count; i++) {
        if (svc->components[i].component_id == component_id)
            return OZAYN_SH_ERR_INVALID_REQUEST;
    }

    ozayn_sh_component_health_t *comp = &svc->components[svc->component_count];
    _set_component_defaults(comp, component_id, component_name, required,
                            dependencies, dependency_count);
    svc->component_count++;
    return OZAYN_SH_OK;
}

ozayn_sh_result_t ozayn_sh_register_provider(
    ozayn_sh_service_t *svc,
    const ozayn_sh_provider_vtable_t *vtable,
    const void *context)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;
    if (!vtable || !vtable->check) return OZAYN_SH_ERR_NULL;
    if (svc->provider_count >= OZAYN_SH_MAX_COMPONENTS)
        return OZAYN_SH_ERR_RESOURCE_LIMIT;

    svc->providers[svc->provider_count].vtable = vtable;
    svc->providers[svc->provider_count].context = context;
    svc->providers[svc->provider_count].registered = 1;
    svc->provider_count++;
    return OZAYN_SH_OK;
}

/* ============================================================
 * INTERNAL — BUILT-IN HEALTH CHECKS
 * ============================================================ */

static void _check_security_configuration(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        comp->available = 0;
        comp->config_state = OZAYN_SH_CONFIG_MISSING;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Config service not provided");
        return;
    }

    comp->available = 1;

    if (!svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        comp->config_state = OZAYN_SH_CONFIG_CHECK_FAILED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Config service not initialized");
        return;
    }

    /* Check active policy exists and is valid */
    if (svc->config_service->active_policy.schema_version == 0) {
        comp->health_state = OZAYN_SH_CRITICAL;
        comp->config_state = OZAYN_SH_CONFIG_INVALID;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "No active security policy");
        return;
    }

    comp->config_state = OZAYN_SH_CONFIG_VALID;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_security_policy(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        comp->policy_state = OZAYN_SH_POLICY_MISSING;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Config service unavailable");
        return;
    }

    comp->available = 1;

    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->schema_version == 0) {
        comp->health_state = OZAYN_SH_CRITICAL;
        comp->policy_state = OZAYN_SH_POLICY_MISSING;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "No active policy");
        return;
    }

    /* Verify default-deny is active */
    if (pol->authorization.default_deny != 1) {
        comp->health_state = OZAYN_SH_CRITICAL;
        comp->policy_state = OZAYN_SH_POLICY_INVALID;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Default-deny disabled");
        return;
    }

    comp->policy_state = OZAYN_SH_POLICY_VALID;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_identity(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);
    comp->available = 1;
    comp->health_state = OZAYN_SH_HEALTHY;
    comp->detail[0] = '\0';
}

static void _check_authentication(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Cannot verify: config unavailable");
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->authentication.enabled) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Authentication disabled by policy");
    }
}

static void _check_attempt_control(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Cannot verify: config unavailable");
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->attempt_control.enabled &&
        pol->attempt_control.max_failures > 0) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Attempt control not properly configured");
    }
}

static void _check_mfa(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Cannot verify: config unavailable");
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->mfa.enabled && pol->mfa.required_factor_count > 0) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_WARNING;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "MFA not fully configured");
    }
}

static void _check_session(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Cannot verify: config unavailable");
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->session.enabled &&
        pol->session.idle_timeout_seconds > 0 &&
        pol->session.absolute_lifetime_seconds > 0) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Session policy incomplete");
    }
}

static void _check_authorization(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Cannot verify: config unavailable");
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->authorization.default_deny) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_CRITICAL;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Default-deny not configured");
    }
}

static void _check_rbac(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->rbac.enabled) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "RBAC disabled by policy");
    }
}

static void _check_permission(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->permission.enabled && pol->permission.default_deny_unknown) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Permission policy incomplete");
    }
}

static void _check_secure_data(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    (void)svc;
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);
    comp->available = 1;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_storage(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    (void)svc;
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);
    comp->available = 1;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_protection(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->cryptographic.require_protection) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_CRITICAL;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Protection not required by policy");
    }
}

static void _check_key_management(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->key_management.require_active_key) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Active key not required by policy");
    }
}

static void _check_key_storage(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    (void)svc;
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);
    comp->available = 1;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_key_lifecycle(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);
    comp->available = 1;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_secure_vault(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->vault.require_encryption &&
        pol->vault.require_integrity) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_CRITICAL;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Vault protection incomplete");
    }
}

static void _check_audit(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->audit) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Audit service not provided");
        return;
    }

    comp->available = 1;

    if (!svc->audit->initialized) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Audit service not initialized");
        return;
    }

    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_audit_integrity(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->audit || !svc->audit->initialized) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        comp->available = 0;
        comp->integrity_state = OZAYN_SH_INTEGRITY_CHECK_FAILED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Audit service unavailable for integrity check");
        return;
    }

    comp->available = 1;
    comp->integrity_state = OZAYN_SH_INTEGRITY_VALID;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_backup(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->backup.enabled &&
        pol->backup.require_integrity &&
        pol->backup.require_protection) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_DEGRADED;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Backup policy incomplete");
    }
}

static void _check_recovery(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    (void)svc;
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);
    comp->available = 1;
    comp->health_state = OZAYN_SH_HEALTHY;
}

static void _check_secure_deletion(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->config_service || !svc->config_service->initialized) {
        comp->health_state = OZAYN_SH_UNKNOWN;
        comp->available = 0;
        return;
    }

    comp->available = 1;
    const ozayn_sc_policy_t *pol = &svc->config_service->active_policy;

    if (pol->deletion.require_authorization) {
        comp->health_state = OZAYN_SH_HEALTHY;
    } else {
        comp->health_state = OZAYN_SH_WARNING;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Deletion authorization not required");
    }
}

static void _check_incident_response(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_health_t *comp)
{
    comp->check_version = svc->check_version;
    comp->last_check_time = time(NULL);

    if (!svc->incident_service) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        comp->available = 0;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Incident service not provided");
        return;
    }

    comp->available = 1;

    if (!svc->incident_service->initialized) {
        comp->health_state = OZAYN_SH_UNAVAILABLE;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Incident service not initialized");
        return;
    }

    if (svc->incident_service->lockdown_active) {
        comp->health_state = OZAYN_SH_LOCKDOWN;
        snprintf(comp->detail, OZAYN_SH_MAX_DETAIL_LEN,
                 "Lockdown active");
        return;
    }

    comp->health_state = OZAYN_SH_HEALTHY;
}

/* ============================================================
 * INTERNAL — CHECK DISPATCH
 * ============================================================ */

typedef void (*_sh_check_fn)(const ozayn_sh_service_t *svc,
                              ozayn_sh_component_health_t *comp);

static _sh_check_fn _get_check_fn(ozayn_sh_component_id_t id)
{
    switch (id) {
    case OZAYN_SH_COMP_SECURITY_CONFIGURATION: return _check_security_configuration;
    case OZAYN_SH_COMP_SECURITY_POLICY:        return _check_security_policy;
    case OZAYN_SH_COMP_IDENTITY:               return _check_identity;
    case OZAYN_SH_COMP_AUTHENTICATION:         return _check_authentication;
    case OZAYN_SH_COMP_ATTEMPT_CONTROL:        return _check_attempt_control;
    case OZAYN_SH_COMP_MFA:                    return _check_mfa;
    case OZAYN_SH_COMP_SESSION:                return _check_session;
    case OZAYN_SH_COMP_AUTHORIZATION:          return _check_authorization;
    case OZAYN_SH_COMP_RBAC:                   return _check_rbac;
    case OZAYN_SH_COMP_PERMISSION:             return _check_permission;
    case OZAYN_SH_COMP_SECURE_DATA:            return _check_secure_data;
    case OZAYN_SH_COMP_STORAGE:                return _check_storage;
    case OZAYN_SH_COMP_PROTECTION:             return _check_protection;
    case OZAYN_SH_COMP_KEY_MANAGEMENT:         return _check_key_management;
    case OZAYN_SH_COMP_KEY_STORAGE:            return _check_key_storage;
    case OZAYN_SH_COMP_KEY_LIFECYCLE:          return _check_key_lifecycle;
    case OZAYN_SH_COMP_SECURE_VAULT:           return _check_secure_vault;
    case OZAYN_SH_COMP_AUDIT:                  return _check_audit;
    case OZAYN_SH_COMP_AUDIT_INTEGRITY:        return _check_audit_integrity;
    case OZAYN_SH_COMP_BACKUP:                 return _check_backup;
    case OZAYN_SH_COMP_RECOVERY:               return _check_recovery;
    case OZAYN_SH_COMP_SECURE_DELETION:        return _check_secure_deletion;
    case OZAYN_SH_COMP_INCIDENT_RESPONSE:      return _check_incident_response;
    default:                                   return NULL;
    }
}

/* ============================================================
 * SECTION 15 — HEALTH CHECK
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_check(
    ozayn_sh_service_t *svc,
    ozayn_sh_component_id_t component_id,
    ozayn_sh_component_health_t *out_health)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;
    if (!out_health) return OZAYN_SH_ERR_NULL;

    /* Concurrency limit */
    if (svc->active_checks >= svc->max_concurrent_checks)
        return OZAYN_SH_ERR_CONCURRENCY_CONFLICT;

    int idx = _find_component(svc, component_id);
    if (idx < 0)
        return OZAYN_SH_ERR_INVALID_COMPONENT;

    svc->active_checks++;

    /* Run check via provider if available, otherwise built-in */
    int found_provider = 0;
    for (int i = 0; i < svc->provider_count; i++) {
        if (!svc->providers[i].registered) continue;
        if (!svc->providers[i].vtable) continue;
        if (!svc->providers[i].vtable->check) continue;

        ozayn_sh_component_health_t tmp = {0};
        tmp.component_id = component_id;
        int rc = svc->providers[i].vtable->check(
            svc->providers[i].context, &tmp);
        if (rc == 0) {
            memcpy(&svc->components[idx], &tmp,
                   sizeof(ozayn_sh_component_health_t));
            memcpy(out_health, &tmp, sizeof(ozayn_sh_component_health_t));
            found_provider = 1;
            break;
        }
    }

    if (!found_provider) {
        _sh_check_fn fn = _get_check_fn(component_id);
        if (fn) {
            fn(svc, &svc->components[idx]);
        } else {
            svc->components[idx].health_state = OZAYN_SH_UNKNOWN;
            svc->components[idx].last_check_time = time(NULL);
            svc->components[idx].check_version = svc->check_version;
        }
        memcpy(out_health, &svc->components[idx],
               sizeof(ozayn_sh_component_health_t));
    }

    svc->active_checks--;
    svc->total_checks++;

    /* Record event for state changes */
    if (out_health->health_state == OZAYN_SH_CRITICAL ||
        out_health->health_state == OZAYN_SH_LOCKDOWN) {
        ozayn_sh_record_event(svc, OZAYN_SH_EVENT_HEALTH_CRITICAL,
                              component_id, out_health->health_state,
                              out_health->detail);
    } else if (out_health->health_state == OZAYN_SH_UNAVAILABLE) {
        ozayn_sh_record_event(svc, OZAYN_SH_EVENT_COMPONENT_UNAVAILABLE,
                              component_id, out_health->health_state,
                              out_health->detail);
    }

    return OZAYN_SH_OK;
}

ozayn_sh_result_t ozayn_sh_check_all(ozayn_sh_service_t *svc)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    svc->check_version++;

    for (int i = 0; i < svc->component_count; i++) {
        ozayn_sh_component_health_t tmp = {0};
        ozayn_sh_check(svc, svc->components[i].component_id, &tmp);
    }

    /* Evaluate dependencies */
    ozayn_sh_evaluate_dependencies(svc);

    /* Aggregate */
    memset(&svc->aggregation, 0, sizeof(svc->aggregation));
    svc->aggregation.last_aggregation_time = (uint64_t)time(NULL);
    svc->aggregation.aggregation_version = svc->check_version;

    for (int i = 0; i < svc->component_count; i++) {
        ozayn_sh_health_state_t st = svc->components[i].health_state;
        switch (st) {
        case OZAYN_SH_HEALTHY:     svc->aggregation.healthy_count++; break;
        case OZAYN_SH_DEGRADED:    svc->aggregation.degraded_count++; break;
        case OZAYN_SH_WARNING:     svc->aggregation.warning_count++; break;
        case OZAYN_SH_CRITICAL:    svc->aggregation.critical_count++; break;
        case OZAYN_SH_UNAVAILABLE: svc->aggregation.unavailable_count++; break;
        case OZAYN_SH_UNKNOWN:     svc->aggregation.unknown_count++; break;
        case OZAYN_SH_LOCKDOWN:    svc->aggregation.lockdown_count++; break;
        }

        if (svc->components[i].required) {
            svc->aggregation.required_total_count++;
            if (st == OZAYN_SH_HEALTHY || st == OZAYN_SH_DEGRADED)
                svc->aggregation.required_healthy_count++;
        } else {
            svc->aggregation.optional_total_count++;
            if (st == OZAYN_SH_HEALTHY || st == OZAYN_SH_DEGRADED)
                svc->aggregation.optional_healthy_count++;
        }
    }

    /* Aggregate overall state */
    ozayn_sh_health_state_t overall = OZAYN_SH_HEALTHY;

    if (svc->aggregation.lockdown_count > 0) {
        overall = OZAYN_SH_LOCKDOWN;
    } else if (svc->aggregation.critical_count > 0) {
        overall = OZAYN_SH_CRITICAL;
    } else if (svc->aggregation.unknown_count > 0) {
        overall = OZAYN_SH_UNKNOWN;
    } else if (svc->aggregation.unavailable_count > 0 &&
               svc->aggregation.required_healthy_count <
               svc->aggregation.required_total_count) {
        overall = OZAYN_SH_CRITICAL;
    } else if (svc->aggregation.unavailable_count > 0) {
        overall = OZAYN_SH_DEGRADED;
    } else if (svc->aggregation.warning_count > 0) {
        overall = OZAYN_SH_WARNING;
    } else if (svc->aggregation.degraded_count > 0) {
        overall = OZAYN_SH_DEGRADED;
    }

    /* Fail-closed: if no components, UNKNOWN */
    if (svc->component_count == 0)
        overall = OZAYN_SH_UNKNOWN;

    svc->aggregation.overall_state = overall;

    return OZAYN_SH_OK;
}

/* ============================================================
 * SECTION 19 — DEPENDENCY EVALUATION
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_evaluate_dependencies(
    ozayn_sh_service_t *svc)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    /* Propagate dependency failures */
    int changed = 1;
    int iterations = 0;
    while (changed && iterations < 10) {
        changed = 0;
        iterations++;
        for (int i = 0; i < svc->component_count; i++) {
            ozayn_sh_component_health_t *comp = &svc->components[i];
            if (!comp->required) continue;
            if (comp->health_state == OZAYN_SH_HEALTHY ||
                comp->health_state == OZAYN_SH_DEGRADED)
                continue;

            /* Mark dependents */
            for (int j = 0; j < svc->component_count; j++) {
                if (i == j) continue;
                ozayn_sh_component_health_t *dep = &svc->components[j];
                for (int d = 0; d < dep->dependency_count; d++) {
                    if (dep->dependencies[d] == comp->component_id) {
                        if (dep->health_state == OZAYN_SH_HEALTHY) {
                            dep->health_state = OZAYN_SH_DEGRADED;
                            snprintf(dep->detail, OZAYN_SH_MAX_DETAIL_LEN,
                                     "Dependency %s unhealthy",
                                     ozayn_sh_component_name(
                                         comp->component_id));
                            changed = 1;
                        }
                    }
                }
            }
        }
    }

    return OZAYN_SH_OK;
}

/* ============================================================
 * SECTION 16 — STATUS QUERY
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_get_status(
    const ozayn_sh_service_t *svc,
    ozayn_sh_health_state_t *out_state)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!out_state) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    *out_state = svc->aggregation.overall_state;
    return OZAYN_SH_OK;
}

ozayn_sh_result_t ozayn_sh_get_component_status(
    const ozayn_sh_service_t *svc,
    ozayn_sh_component_id_t component_id,
    ozayn_sh_component_health_t *out_health)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!out_health) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    int idx = _find_component(svc, component_id);
    if (idx < 0)
        return OZAYN_SH_ERR_INVALID_COMPONENT;

    memcpy(out_health, &svc->components[idx],
           sizeof(ozayn_sh_component_health_t));
    return OZAYN_SH_OK;
}

const char *ozayn_sh_get_safe_summary(const ozayn_sh_service_t *svc)
{
    static char _summary_buf[1024];

    if (!svc || !svc->initialized) {
        snprintf(_summary_buf, sizeof(_summary_buf),
                 "OZAYN SECURITY STATUS\n\nOverall: UNKNOWN\n");
        return _summary_buf;
    }

    int off = 0;
    off += snprintf(_summary_buf + off, sizeof(_summary_buf) - (size_t)off,
                    "OZAYN SECURITY STATUS\n\nOverall: %s\n\n",
                    ozayn_sh_health_state_name(svc->aggregation.overall_state));

    static const ozayn_sh_component_id_t display_order[] = {
        OZAYN_SH_COMP_IDENTITY, OZAYN_SH_COMP_AUTHENTICATION,
        OZAYN_SH_COMP_ATTEMPT_CONTROL, OZAYN_SH_COMP_MFA,
        OZAYN_SH_COMP_SESSION, OZAYN_SH_COMP_AUTHORIZATION,
        OZAYN_SH_COMP_RBAC, OZAYN_SH_COMP_PERMISSION,
        OZAYN_SH_COMP_SECURE_VAULT, OZAYN_SH_COMP_KEY_STORAGE,
        OZAYN_SH_COMP_KEY_MANAGEMENT, OZAYN_SH_COMP_PROTECTION,
        OZAYN_SH_COMP_AUDIT, OZAYN_SH_COMP_AUDIT_INTEGRITY,
        OZAYN_SH_COMP_BACKUP, OZAYN_SH_COMP_SECURE_DELETION,
        OZAYN_SH_COMP_INCIDENT_RESPONSE
    };
    int display_count = (int)(sizeof(display_order) /
                              sizeof(display_order[0]));

    for (int d = 0; d < display_count; d++) {
        int idx = _find_component(svc, display_order[d]);
        if (idx < 0) continue;

        const ozayn_sh_component_health_t *c = &svc->components[idx];
        /* Pad name to 22 chars */
        const char *name = ozayn_sh_component_name(c->component_id);
        int name_len = (int)strlen(name);
        off += snprintf(_summary_buf + off,
                        sizeof(_summary_buf) - (size_t)off,
                        "  %-22s %s", name,
                        ozayn_sh_health_state_name(c->health_state));
        if (off < (int)sizeof(_summary_buf))
            _summary_buf[off] = '\n';
        off++;
    }

    if (off >= (int)sizeof(_summary_buf))
        _summary_buf[sizeof(_summary_buf) - 1] = '\0';

    return _summary_buf;
}

/* ============================================================
 * SECTION 17 — OPERATION SAFETY CHECK
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_is_operation_safe(
    const ozayn_sh_service_t *svc,
    ozayn_sh_operation_type_t operation,
    ozayn_sh_operation_safety_t *out_safety)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!out_safety) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    ozayn_sh_health_state_t overall = svc->aggregation.overall_state;

    /* LOCKDOWN -> DENY all */
    if (overall == OZAYN_SH_LOCKDOWN) {
        *out_safety = OZAYN_SH_SAFE_DENY;
        return OZAYN_SH_OK;
    }

    /* UNKNOWN -> DENY (fail-closed) */
    if (overall == OZAYN_SH_UNKNOWN) {
        *out_safety = OZAYN_SH_SAFE_DENY;
        return OZAYN_SH_OK;
    }

    /* CRITICAL -> DENY security-sensitive ops */
    if (overall == OZAYN_SH_CRITICAL) {
        *out_safety = OZAYN_SH_SAFE_DENY;
        return OZAYN_SH_OK;
    }

    /* UNAVAILABLE -> RESTRICT */
    if (overall == OZAYN_SH_UNAVAILABLE) {
        *out_safety = OZAYN_SH_SAFE_RESTRICT;
        return OZAYN_SH_OK;
    }

    /* Check specific component dependencies for operation */
    switch (operation) {
    case OZAYN_SH_OP_VAULT_ACCESS:
    case OZAYN_SH_OP_ENCRYPT:
    case OZAYN_SH_OP_DECRYPT: {
        int idx = _find_component(svc, OZAYN_SH_COMP_SECURE_VAULT);
        if (idx >= 0 &&
            !ozayn_sh_state_is_usable(svc->components[idx].health_state)) {
            *out_safety = OZAYN_SH_SAFE_DENY;
            return OZAYN_SH_OK;
        }
        break;
    }
    case OZAYN_SH_OP_KEY_ACCESS: {
        int idx = _find_component(svc, OZAYN_SH_COMP_KEY_MANAGEMENT);
        if (idx >= 0 &&
            !ozayn_sh_state_is_usable(svc->components[idx].health_state)) {
            *out_safety = OZAYN_SH_SAFE_DENY;
            return OZAYN_SH_OK;
        }
        break;
    }
    case OZAYN_SH_OP_AUTHENTICATE: {
        int idx = _find_component(svc, OZAYN_SH_COMP_AUTHENTICATION);
        if (idx >= 0 &&
            !ozayn_sh_state_is_usable(svc->components[idx].health_state)) {
            *out_safety = OZAYN_SH_SAFE_RESTRICT;
            return OZAYN_SH_OK;
        }
        break;
    }
    case OZAYN_SH_OP_AUTHORIZE: {
        int idx = _find_component(svc, OZAYN_SH_COMP_AUTHORIZATION);
        if (idx >= 0 &&
            !ozayn_sh_state_is_usable(svc->components[idx].health_state)) {
            *out_safety = OZAYN_SH_SAFE_DENY;
            return OZAYN_SH_OK;
        }
        break;
    }
    case OZAYN_SH_OP_BACKUP:
    case OZAYN_SH_OP_RESTORE: {
        int idx = _find_component(svc, OZAYN_SH_COMP_BACKUP);
        if (idx >= 0 &&
            !ozayn_sh_state_is_usable(svc->components[idx].health_state)) {
            *out_safety = OZAYN_SH_SAFE_RESTRICT;
            return OZAYN_SH_OK;
        }
        break;
    }
    case OZAYN_SH_OP_DELETE: {
        int idx = _find_component(svc, OZAYN_SH_COMP_SECURE_DELETION);
        if (idx >= 0 &&
            !ozayn_sh_state_is_usable(svc->components[idx].health_state)) {
            *out_safety = OZAYN_SH_SAFE_RESTRICT;
            return OZAYN_SH_OK;
        }
        break;
    }
    default:
        break;
    }

    if (overall == OZAYN_SH_HEALTHY) {
        *out_safety = OZAYN_SH_SAFE_ALLOW;
    } else if (overall == OZAYN_SH_DEGRADED) {
        *out_safety = OZAYN_SH_SAFE_ALLOW;
    } else if (overall == OZAYN_SH_WARNING) {
        *out_safety = OZAYN_SH_SAFE_RESTRICT;
    } else {
        *out_safety = OZAYN_SH_SAFE_RESTRICT;
    }

    return OZAYN_SH_OK;
}

/* ============================================================
 * SECTION 18 — HEALTH SNAPSHOT
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_generate_snapshot(
    const ozayn_sh_service_t *svc,
    ozayn_sh_snapshot_t *out_snapshot)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!out_snapshot) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    out_snapshot->snapshot_id = svc->check_version;
    out_snapshot->snapshot_version = OZAYN_SH_SNAPSHOT_VERSION;
    out_snapshot->timestamp = time(NULL);
    out_snapshot->overall_state = svc->aggregation.overall_state;
    out_snapshot->component_count = svc->component_count;

    memcpy(out_snapshot->components, svc->components,
           (size_t)svc->component_count *
           sizeof(ozayn_sh_component_health_t));
    memcpy(&out_snapshot->aggregation, &svc->aggregation,
           sizeof(ozayn_sh_aggregation_t));

    if (svc->config_service && svc->config_service->initialized) {
        out_snapshot->policy_version =
            svc->config_service->active_policy.policy_version;
        out_snapshot->config_version =
            svc->config_service->active_policy.config_version;
    }

    out_snapshot->integrity_state = OZAYN_SH_INTEGRITY_VALID;

    if (svc->incident_service && svc->incident_service->initialized) {
        out_snapshot->active_incidents =
            svc->incident_service->incident_count;
        out_snapshot->lockdown_active =
            svc->incident_service->lockdown_active;
    }

    /* Generate safe summary */
    int off = snprintf(out_snapshot->summary,
                       sizeof(out_snapshot->summary),
                       "OZAYN SECURITY STATUS\n\nOverall: %s\n\n",
                       ozayn_sh_health_state_name(
                           out_snapshot->overall_state));

    for (int i = 0; i < out_snapshot->component_count &&
         off < (int)sizeof(out_snapshot->summary); i++) {
        const ozayn_sh_component_health_t *c =
            &out_snapshot->components[i];
        off += snprintf(out_snapshot->summary + off,
                        sizeof(out_snapshot->summary) - (size_t)off,
                        "%-24s %s\n",
                        ozayn_sh_component_name(c->component_id),
                        ozayn_sh_health_state_name(c->health_state));
    }

    return OZAYN_SH_OK;
}

ozayn_sh_result_t ozayn_sh_snapshot_is_fresh(
    const ozayn_sh_snapshot_t *snapshot,
    int max_age_seconds,
    int *out_is_fresh)
{
    if (!snapshot) return OZAYN_SH_ERR_NULL;
    if (!out_is_fresh) return OZAYN_SH_ERR_NULL;

    time_t now = time(NULL);
    double elapsed = difftime(now, snapshot->timestamp);

    *out_is_fresh = (elapsed <= (double)max_age_seconds) ? 1 : 0;
    return OZAYN_SH_OK;
}

/* ============================================================
 * SECTION 21 — HEALTH EVENT LOG
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_record_event(
    ozayn_sh_service_t *svc,
    ozayn_sh_event_type_t event_type,
    ozayn_sh_component_id_t component_id,
    ozayn_sh_health_state_t health_state,
    const char *detail)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    if (svc->event_count >= OZAYN_SH_MAX_EVENTS) {
        /* Ring buffer: overwrite oldest */
        svc->event_head = (svc->event_head + 1) % OZAYN_SH_MAX_EVENTS;
        if (svc->event_count > 0) svc->event_count--;
    }

    int slot = (svc->event_head + svc->event_count) % OZAYN_SH_MAX_EVENTS;
    ozayn_sh_event_t *ev = &svc->events[slot];
    ev->event_type = event_type;
    ev->timestamp = time(NULL);
    ev->component_id = component_id;
    ev->health_state = health_state;
    ev->sequence = ++svc->event_sequence;
    if (detail) {
        size_t len = strlen(detail);
        if (len >= OZAYN_SH_MAX_EVENT_DETAIL)
            len = OZAYN_SH_MAX_EVENT_DETAIL - 1;
        memcpy(ev->detail, detail, len);
        ev->detail[len] = '\0';
    } else {
        ev->detail[0] = '\0';
    }

    svc->event_count++;
    svc->total_events++;
    return OZAYN_SH_OK;
}

int ozayn_sh_get_event_count(const ozayn_sh_service_t *svc)
{
    if (!svc) return 0;
    return svc->event_count;
}

ozayn_sh_result_t ozayn_sh_get_event(
    const ozayn_sh_service_t *svc,
    int index,
    ozayn_sh_event_t *out_event)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!out_event) return OZAYN_SH_ERR_NULL;
    if (index < 0 || index >= svc->event_count)
        return OZAYN_SH_ERR_INVALID_REQUEST;

    int slot = (svc->event_head + index) % OZAYN_SH_MAX_EVENTS;
    memcpy(out_event, &svc->events[slot], sizeof(ozayn_sh_event_t));
    return OZAYN_SH_OK;
}

/* ============================================================
 * SECTION 22 — CHANGE DETECTION
 * ============================================================ */

ozayn_sh_result_t ozayn_sh_detect_changes(
    const ozayn_sh_service_t *svc,
    int *out_changes_detected)
{
    if (!svc) return OZAYN_SH_ERR_NULL;
    if (!out_changes_detected) return OZAYN_SH_ERR_NULL;
    if (!svc->initialized) return OZAYN_SH_ERR_NOT_INITIALIZED;

    int changes = 0;

    /* Check if any component has unexpected state changes */
    for (int i = 0; i < svc->component_count; i++) {
        const ozayn_sh_component_health_t *c = &svc->components[i];
        if (c->health_state == OZAYN_SH_UNKNOWN &&
            c->check_version < svc->check_version) {
            changes++;
        }
    }

    /* Check config/policy version if config service available */
    if (svc->config_service && svc->config_service->initialized) {
        const ozayn_sc_policy_t *pol =
            &svc->config_service->active_policy;
        if (pol->schema_version == 0) {
            changes++;
        }
    }

    *out_changes_detected = changes;
    return OZAYN_SH_OK;
}
