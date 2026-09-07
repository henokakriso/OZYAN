#include "authorization.h"
#include <string.h>
#include <stdlib.h>

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_authz_validate_resource_type(const char *resource_type)
{
    if (!resource_type || resource_type[0] == '\0')
        return -1;
    if (strlen(resource_type) >= OZAYN_AUTHZ_MAX_RESOURCE_TYPE_LEN)
        return -1;
    if (strcmp(resource_type, "core") == 0)        return 0;
    if (strcmp(resource_type, "module") == 0)       return 0;
    if (strcmp(resource_type, "plugin") == 0)       return 0;
    if (strcmp(resource_type, "document") == 0)     return 0;
    if (strcmp(resource_type, "memory") == 0)       return 0;
    if (strcmp(resource_type, "database") == 0)     return 0;
    if (strcmp(resource_type, "device") == 0)       return 0;
    if (strcmp(resource_type, "camera") == 0)       return 0;
    if (strcmp(resource_type, "microphone") == 0)   return 0;
    if (strcmp(resource_type, "system") == 0)       return 0;
    if (strcmp(resource_type, "identity") == 0)     return 0;
    if (strcmp(resource_type, "session") == 0)      return 0;
    if (strcmp(resource_type, "service") == 0)      return 0;
    return -1;
}

int ozayn_authz_validate_action(const char *action)
{
    if (!action || action[0] == '\0')
        return -1;
    if (strlen(action) >= OZAYN_AUTHZ_MAX_ACTION_LEN)
        return -1;
    if (strcmp(action, "read") == 0)      return 0;
    if (strcmp(action, "create") == 0)    return 0;
    if (strcmp(action, "update") == 0)    return 0;
    if (strcmp(action, "delete") == 0)    return 0;
    if (strcmp(action, "execute") == 0)   return 0;
    if (strcmp(action, "control") == 0)   return 0;
    if (strcmp(action, "configure") == 0) return 0;
    if (strcmp(action, "install") == 0)   return 0;
    if (strcmp(action, "uninstall") == 0) return 0;
    return -1;
}

int ozayn_authz_validate_scope(const char *scope)
{
    if (!scope || scope[0] == '\0')
        return -1;
    if (strlen(scope) >= OZAYN_AUTHZ_MAX_SCOPE_LEN)
        return -1;
    if (strcmp(scope, "system") == 0)  return 0;
    if (strcmp(scope, "user") == 0)    return 0;
    if (strcmp(scope, "device") == 0)  return 0;
    if (strcmp(scope, "module") == 0)  return 0;
    if (strcmp(scope, "service") == 0) return 0;
    if (strcmp(scope, "global") == 0)  return 0;
    return -1;
}

int ozayn_authz_validate_request(const ozayn_authz_request_t *request)
{
    if (!request)
        return -1;
    if (request->session_id[0] == '\0')
        return -1;
    if (request->resource_type[0] == '\0')
        return -1;
    if (request->action[0] == '\0')
        return -1;
    if (ozayn_authz_validate_resource_type(request->resource_type) != 0)
        return -1;
    if (ozayn_authz_validate_action(request->action) != 0)
        return -1;
    if (request->scope[0] != '\0' &&
        ozayn_authz_validate_scope(request->scope) != 0)
        return -1;
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_authz_svc_decision_name(ozayn_authz_decision_t decision)
{
    switch (decision) {
        case OZAYN_AUTHZ_DECISION_ALLOW: return "ALLOW";
        case OZAYN_AUTHZ_DECISION_DENY:  return "DENY";
        case OZAYN_AUTHZ_DECISION_ERROR: return "ERROR";
        default:                         return "UNKNOWN";
    }
}

const char *ozayn_authz_deny_reason_name(ozayn_authz_deny_reason_t reason)
{
    switch (reason) {
        case OZAYN_AUTHZ_DENY_NONE:                   return "NONE";
        case OZAYN_AUTHZ_DENY_SESSION_INVALID:         return "SESSION_INVALID";
        case OZAYN_AUTHZ_DENY_SESSION_EXPIRED:         return "SESSION_EXPIRED";
        case OZAYN_AUTHZ_DENY_SESSION_REVOKED:         return "SESSION_REVOKED";
        case OZAYN_AUTHZ_DENY_SESSION_TERMINATED:      return "SESSION_TERMINATED";
        case OZAYN_AUTHZ_DENY_IDENTITY_INVALID:        return "IDENTITY_INVALID";
        case OZAYN_AUTHZ_DENY_IDENTITY_SUSPENDED:      return "IDENTITY_SUSPENDED";
        case OZAYN_AUTHZ_DENY_IDENTITY_REVOKED:        return "IDENTITY_REVOKED";
        case OZAYN_AUTHZ_DENY_IDENTITY_ARCHIVED:       return "IDENTITY_ARCHIVED";
        case OZAYN_AUTHZ_DENY_PERMISSION_MISSING:      return "PERMISSION_MISSING";
        case OZAYN_AUTHZ_DENY_ACTION_NOT_ALLOWED:      return "ACTION_NOT_ALLOWED";
        case OZAYN_AUTHZ_DENY_RESOURCE_NOT_FOUND:      return "RESOURCE_NOT_FOUND";
        case OZAYN_AUTHZ_DENY_SCOPE_MISMATCH:          return "SCOPE_MISMATCH";
        case OZAYN_AUTHZ_DENY_POLICY_REJECTED:         return "POLICY_REJECTED";
        case OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE:      return "POLICY_UNAVAILABLE";
        case OZAYN_AUTHZ_DENY_POLICY_ERROR:            return "POLICY_ERROR";
        case OZAYN_AUTHZ_DENY_DEFAULT:                 return "DEFAULT_DENY";
        default:                                       return "UNKNOWN";
    }
}

const char *ozayn_authz_error_name(ozayn_authz_error_t error)
{
    switch (error) {
        case OZAYN_AUTHZ_OK:                       return "OK";
        case OZAYN_AUTHZ_ERR_NULL:                 return "NULL";
        case OZAYN_AUTHZ_ERR_NOT_INITIALIZED:      return "NOT_INITIALIZED";
        case OZAYN_AUTHZ_ERR_NOT_FOUND:            return "NOT_FOUND";
        case OZAYN_AUTHZ_ERR_INVALID:              return "INVALID";
        case OZAYN_AUTHZ_ERR_SESSION_INVALID:      return "SESSION_INVALID";
        case OZAYN_AUTHZ_ERR_IDENTITY_INVALID:     return "IDENTITY_INVALID";
        case OZAYN_AUTHZ_ERR_PROVIDER_UNAVAILABLE: return "PROVIDER_UNAVAILABLE";
        case OZAYN_AUTHZ_ERR_PROVIDER_FAILED:      return "PROVIDER_FAILED";
        case OZAYN_AUTHZ_ERR_POLICY_INVALID:       return "POLICY_INVALID";
        case OZAYN_AUTHZ_ERR_REQUEST_INVALID:      return "REQUEST_INVALID";
        case OZAYN_AUTHZ_ERR_RESOURCE_INVALID:     return "RESOURCE_INVALID";
        case OZAYN_AUTHZ_ERR_ACTION_INVALID:       return "ACTION_INVALID";
        case OZAYN_AUTHZ_ERR_SCOPE_INVALID:        return "SCOPE_INVALID";
        case OZAYN_AUTHZ_ERR_LIMIT_REACHED:        return "LIMIT_REACHED";
        default:                                   return "UNKNOWN";
    }
}

const char *ozayn_authz_resource_type_name(const char *resource_type)
{
    if (!resource_type) return "UNKNOWN";
    if (strcmp(resource_type, "core") == 0)       return "CORE";
    if (strcmp(resource_type, "module") == 0)     return "MODULE";
    if (strcmp(resource_type, "plugin") == 0)     return "PLUGIN";
    if (strcmp(resource_type, "document") == 0)   return "DOCUMENT";
    if (strcmp(resource_type, "memory") == 0)     return "MEMORY";
    if (strcmp(resource_type, "database") == 0)   return "DATABASE";
    if (strcmp(resource_type, "device") == 0)     return "DEVICE";
    if (strcmp(resource_type, "camera") == 0)     return "CAMERA";
    if (strcmp(resource_type, "microphone") == 0) return "MICROPHONE";
    if (strcmp(resource_type, "system") == 0)     return "SYSTEM";
    if (strcmp(resource_type, "identity") == 0)   return "IDENTITY";
    if (strcmp(resource_type, "session") == 0)    return "SESSION";
    if (strcmp(resource_type, "service") == 0)    return "SERVICE";
    return "UNKNOWN";
}

const char *ozayn_authz_action_name(const char *action)
{
    if (!action) return "UNKNOWN";
    if (strcmp(action, "read") == 0)      return "READ";
    if (strcmp(action, "create") == 0)    return "CREATE";
    if (strcmp(action, "update") == 0)    return "UPDATE";
    if (strcmp(action, "delete") == 0)    return "DELETE";
    if (strcmp(action, "execute") == 0)   return "EXECUTE";
    if (strcmp(action, "control") == 0)   return "CONTROL";
    if (strcmp(action, "configure") == 0) return "CONFIGURE";
    if (strcmp(action, "install") == 0)   return "INSTALL";
    if (strcmp(action, "uninstall") == 0) return "UNINSTALL";
    return "UNKNOWN";
}

const char *ozayn_authz_scope_name_value(const char *scope)
{
    if (!scope) return "UNKNOWN";
    if (strcmp(scope, "system") == 0)  return "SYSTEM";
    if (strcmp(scope, "user") == 0)    return "USER";
    if (strcmp(scope, "device") == 0)  return "DEVICE";
    if (strcmp(scope, "module") == 0)  return "MODULE";
    if (strcmp(scope, "service") == 0) return "SERVICE";
    if (strcmp(scope, "global") == 0)  return "GLOBAL";
    return "UNKNOWN";
}

/* ============================================================
 * RESULT HELPERS
 * ============================================================ */

ozayn_authz_result_t ozayn_authz_make_allow(void)
{
    ozayn_authz_result_t r;
    memset(&r, 0, sizeof(r));
    r.decision = OZAYN_AUTHZ_DECISION_ALLOW;
    r.reason = OZAYN_AUTHZ_DENY_NONE;
    return r;
}

ozayn_authz_result_t ozayn_authz_make_deny(ozayn_authz_deny_reason_t reason)
{
    ozayn_authz_result_t r;
    memset(&r, 0, sizeof(r));
    r.decision = OZAYN_AUTHZ_DECISION_DENY;
    r.reason = reason;
    strncpy(r.reason_detail,
            ozayn_authz_deny_reason_name(reason),
            sizeof(r.reason_detail) - 1);
    return r;
}

ozayn_authz_result_t ozayn_authz_make_error(ozayn_authz_deny_reason_t reason)
{
    ozayn_authz_result_t r;
    memset(&r, 0, sizeof(r));
    r.decision = OZAYN_AUTHZ_DECISION_ERROR;
    r.reason = reason;
    strncpy(r.reason_detail,
            ozayn_authz_deny_reason_name(reason),
            sizeof(r.reason_detail) - 1);
    return r;
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_authz_error_t ozayn_authz_service_init(
    ozayn_authz_service_t *svc,
    const ozayn_authz_service_config_t *config)
{
    if (!svc || !config)
        return OZAYN_AUTHZ_ERR_NULL;
    if (!config->session_service)
        return OZAYN_AUTHZ_ERR_INVALID;
    if (!config->identity_service)
        return OZAYN_AUTHZ_ERR_INVALID;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;
    svc->initialized = 1;

    return OZAYN_AUTHZ_OK;
}

void ozayn_authz_service_shutdown(ozayn_authz_service_t *svc)
{
    if (!svc)
        return;

    svc->provider_count = 0;
    svc->initialized = 0;
}

/* ============================================================
 * PROVIDER MANAGEMENT
 * ============================================================ */

ozayn_authz_error_t ozayn_authz_register_provider(
    ozayn_authz_service_t *svc,
    ozayn_authz_policy_provider_t *provider)
{
    if (!svc || !provider)
        return OZAYN_AUTHZ_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AUTHZ_ERR_NOT_INITIALIZED;
    if (!provider->ops)
        return OZAYN_AUTHZ_ERR_INVALID;
    if (svc->provider_count >= OZAYN_AUTHZ_MAX_PROVIDERS)
        return OZAYN_AUTHZ_ERR_LIMIT_REACHED;

    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i] == provider)
            return OZAYN_AUTHZ_ERR_INVALID;
    }

    if (provider->ops->init) {
        int r = provider->ops->init(provider);
        if (r != 0)
            return OZAYN_AUTHZ_ERR_PROVIDER_FAILED;
    }
    provider->initialized = 1;

    svc->providers[svc->provider_count] = provider;
    svc->provider_count++;

    return OZAYN_AUTHZ_OK;
}

ozayn_authz_error_t ozayn_authz_unregister_provider(
    ozayn_authz_service_t *svc,
    ozayn_authz_policy_provider_t *provider)
{
    if (!svc || !provider)
        return OZAYN_AUTHZ_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AUTHZ_ERR_NOT_INITIALIZED;

    int found = -1;
    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i] == provider) {
            found = i;
            break;
        }
    }
    if (found < 0)
        return OZAYN_AUTHZ_ERR_NOT_FOUND;

    if (provider->ops && provider->ops->shutdown && provider->initialized)
        provider->ops->shutdown(provider);
    provider->initialized = 0;

    for (int i = found; i < svc->provider_count - 1; i++)
        svc->providers[i] = svc->providers[i + 1];
    svc->provider_count--;

    return OZAYN_AUTHZ_OK;
}

/* ============================================================
 * AUTHORIZATION OPERATIONS
 * ============================================================ */

ozayn_authz_result_t ozayn_authz_authorize(
    ozayn_authz_service_t *svc,
    const ozayn_authz_request_t *request)
{
    if (!svc || !request)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_DEFAULT);
    if (!svc->initialized)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_DEFAULT);

    /* Validate request structure */
    if (ozayn_authz_validate_request(request) != 0)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_DEFAULT);

    /* Step 1: Validate session */
    ozayn_sess_t session;
    ozayn_sess_error_t sess_r = ozayn_sess_validate(
        svc->config.session_service,
        request->session_id,
        &session);

    if (sess_r == OZAYN_SESS_ERR_NOT_FOUND)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_SESSION_INVALID);
    if (sess_r == OZAYN_SESS_ERR_EXPIRED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_SESSION_EXPIRED);
    if (sess_r == OZAYN_SESS_ERR_REVOKED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_SESSION_REVOKED);
    if (sess_r == OZAYN_SESS_ERR_TERMINATED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_SESSION_TERMINATED);
    if (sess_r == OZAYN_SESS_ERR_IDENTITY_SUSPENDED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_IDENTITY_SUSPENDED);
    if (sess_r == OZAYN_SESS_ERR_IDENTITY_REVOKED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_IDENTITY_REVOKED);
    if (sess_r != OZAYN_SESS_OK)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_SESSION_INVALID);

    /* Step 2: Validate identity */
    ozayn_identity_t identity;
    ozayn_identity_result_t id_r = ozayn_id_get(
        svc->config.identity_service,
        session.identity_id,
        &identity);

    if (id_r != OZAYN_ID_OK)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_IDENTITY_INVALID);
    if (identity.state == OZAYN_ID_STATE_SUSPENDED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_IDENTITY_SUSPENDED);
    if (identity.state == OZAYN_ID_STATE_REVOKED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_IDENTITY_REVOKED);
    if (identity.state == OZAYN_ID_STATE_ARCHIVED)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_IDENTITY_ARCHIVED);

    /* Step 3: Evaluate policy via provider */
    if (svc->provider_count == 0)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE);

    ozayn_authz_policy_provider_t *provider = svc->providers[0];

    if (!provider || !provider->ops || !provider->ops->evaluate)
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE);

    if (provider->ops->is_available &&
        !provider->ops->is_available(provider))
        return ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_POLICY_UNAVAILABLE);

    /* Create a request with the resolved identity_id from the session */
    ozayn_authz_request_t resolved_req = *request;
    strncpy(resolved_req.session_id, session.identity_id,
            sizeof(resolved_req.session_id) - 1);

    ozayn_authz_result_t result = provider->ops->evaluate(
        provider, &resolved_req, session.identity_id);

    return result;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_authz_service_is_initialized(const ozayn_authz_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

int ozayn_authz_service_provider_count(const ozayn_authz_service_t *svc)
{
    if (!svc || !svc->initialized)
        return 0;
    return svc->provider_count;
}

/* ============================================================
 * TEST POLICY PROVIDER
 * ============================================================ */

typedef struct {
    ozayn_authz_result_t forced_result;
    int                  available;
    int                  version;
} _test_policy_data_t;

static int _test_provider_init(ozayn_authz_policy_provider_t *provider)
{
    if (!provider)
        return -1;
    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    if (!data) {
        data = (_test_policy_data_t *)calloc(1, sizeof(_test_policy_data_t));
        if (!data) return -1;
        provider->impl_data = data;
    }
    data->forced_result = ozayn_authz_make_deny(OZAYN_AUTHZ_DENY_DEFAULT);
    data->available = 1;
    data->version = 1;
    return 0;
}

static void _test_provider_shutdown(ozayn_authz_policy_provider_t *provider)
{
    if (!provider)
        return;
    if (provider->impl_data) {
        free(provider->impl_data);
        provider->impl_data = NULL;
    }
}

static ozayn_authz_result_t _test_provider_evaluate(
    ozayn_authz_policy_provider_t *provider,
    const ozayn_authz_request_t *request,
    const char *identity_id)
{
    (void)request;
    (void)identity_id;
    if (!provider || !provider->impl_data)
        return ozayn_authz_make_error(OZAYN_AUTHZ_DENY_POLICY_ERROR);

    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    return data->forced_result;
}

static int _test_provider_is_available(
    const ozayn_authz_policy_provider_t *provider)
{
    if (!provider || !provider->impl_data)
        return 0;
    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    return data->available;
}

static int _test_provider_get_version(
    const ozayn_authz_policy_provider_t *provider)
{
    if (!provider || !provider->impl_data)
        return 0;
    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    return data->version;
}

static const ozayn_authz_policy_ops_t _test_provider_ops = {
    .init        = _test_provider_init,
    .shutdown    = _test_provider_shutdown,
    .evaluate    = _test_provider_evaluate,
    .is_available = _test_provider_is_available,
    .get_version = _test_provider_get_version
};

ozayn_authz_policy_provider_t *ozayn_authz_test_provider_create(void)
{
    ozayn_authz_policy_provider_t *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    p->name = "test_policy_provider";
    p->ops = &_test_provider_ops;
    p->impl_data = NULL;
    p->initialized = 0;
    return p;
}

void ozayn_authz_test_provider_destroy(ozayn_authz_policy_provider_t *provider)
{
    if (!provider)
        return;
    if (provider->ops && provider->ops->shutdown && provider->initialized)
        provider->ops->shutdown(provider);
    free(provider);
}

void ozayn_authz_test_provider_set_result(ozayn_authz_policy_provider_t *provider,
                                           ozayn_authz_result_t result)
{
    if (!provider || !provider->impl_data)
        return;
    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    data->forced_result = result;
}

void ozayn_authz_test_provider_set_available(ozayn_authz_policy_provider_t *provider,
                                              int available)
{
    if (!provider || !provider->impl_data)
        return;
    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    data->available = available;
}

void ozayn_authz_test_provider_set_version(ozayn_authz_policy_provider_t *provider,
                                            int version)
{
    if (!provider || !provider->impl_data)
        return;
    _test_policy_data_t *data = (_test_policy_data_t *)provider->impl_data;
    data->version = version;
}
