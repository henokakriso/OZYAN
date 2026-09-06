#include "authentication.h"
#include <string.h>
#include <stdio.h>

/*
 * authentication.c — Authentication Architecture & Credential Boundary
 *                     (Section 03, Step 13).
 *
 * Implements the authentication service, provider dispatch, request
 * validation, credential reference operations, and name helpers.
 */

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

static const char *_authn_method_names[] = {
    "UNKNOWN", "PASSWORD", "DEVICE", "BIOMETRIC",
    "VOICE", "FACE", "GESTURE", "MULTI_FACTOR"
};

static const char *_authn_verification_names[] = {
    "NOT_VERIFIED", "PENDING", "VERIFIED", "FAILED",
    "UNAVAILABLE", "ERROR"
};

static const char *_authn_credential_state_names[] = {
    "UNINITIALIZED", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"
};

const char *ozayn_authn_method_name(ozayn_authn_method_t method)
{
    int idx = (int)method;
    if (idx < 0 || idx > 7)
        return "UNKNOWN";
    return _authn_method_names[idx];
}

const char *ozayn_authn_result_name(ozayn_authn_result_t result)
{
    switch (result) {
        case OZAYN_AuthN_RESULT_SUCCESS:     return "SUCCESS";
        case OZAYN_AuthN_RESULT_FAILED:      return "FAILED";
        case OZAYN_AuthN_RESULT_REJECTED:    return "REJECTED";
        case OZAYN_AuthN_RESULT_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_AuthN_RESULT_ERROR:       return "ERROR";
        default:                             return "UNKNOWN";
    }
}

const char *ozayn_authn_verification_name(ozayn_authn_verification_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 5)
        return "UNKNOWN";
    return _authn_verification_names[idx];
}

const char *ozayn_authn_credential_state_name(ozayn_authn_credential_state_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 4)
        return "UNKNOWN";
    return _authn_credential_state_names[idx];
}

const char *ozayn_authn_error_name(ozayn_authn_error_t error)
{
    switch (error) {
        case OZAYN_AuthN_OK:                         return "OK";
        case OZAYN_AuthN_ERR_NULL:                   return "NULL";
        case OZAYN_AuthN_ERR_NOT_INITIALIZED:        return "NOT_INITIALIZED";
        case OZAYN_AuthN_ERR_NOT_FOUND:              return "NOT_FOUND";
        case OZAYN_AuthN_ERR_INVALID:                return "INVALID";
        case OZAYN_AuthN_ERR_METHOD_UNSUPPORTED:     return "METHOD_UNSUPPORTED";
        case OZAYN_AuthN_ERR_IDENTITY_NOT_FOUND:     return "IDENTITY_NOT_FOUND";
        case OZAYN_AuthN_ERR_IDENTITY_REVOKED:       return "IDENTITY_REVOKED";
        case OZAYN_AuthN_ERR_IDENTITY_SUSPENDED:     return "IDENTITY_SUSPENDED";
        case OZAYN_AuthN_ERR_IDENTITY_ARCHIVED:      return "IDENTITY_ARCHIVED";
        case OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE:   return "PROVIDER_UNAVAILABLE";
        case OZAYN_AuthN_ERR_PROVIDER_FAILED:        return "PROVIDER_FAILED";
        case OZAYN_AuthN_ERR_CREDENTIAL_UNAVAILABLE: return "CREDENTIAL_UNAVAILABLE";
        case OZAYN_AuthN_ERR_CREDENTIAL_INVALID:     return "CREDENTIAL_INVALID";
        case OZAYN_AuthN_ERR_VERIFICATION_FAILED:    return "VERIFICATION_FAILED";
        case OZAYN_AuthN_ERR_VAULT_UNAVAILABLE:      return "VAULT_UNAVAILABLE";
        case OZAYN_AuthN_ERR_POLICY_REJECTED:        return "POLICY_REJECTED";
        case OZAYN_AuthN_ERR_CONTEXT_INVALID:        return "CONTEXT_INVALID";
        case OZAYN_AuthN_ERR_MAX_RETRIES:            return "MAX_RETRIES";
        default:                                     return "UNKNOWN";
    }
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_authn_validate_method(ozayn_authn_method_t method)
{
    if (method <= OZAYN_AuthN_METHOD_UNKNOWN ||
        method > OZAYN_AuthN_METHOD_MULTI)
        return -1;
    return 0;
}

int ozayn_authn_validate_request(const ozayn_authn_request_t *request)
{
    if (!request)
        return -1;
    if (request->identity_id[0] == '\0')
        return -1;
    if (ozayn_authn_validate_method(request->method) != 0)
        return -1;
    if (request->timestamp <= 0)
        return -1;
    return 0;
}

int ozayn_authn_validate_credential_state(ozayn_authn_credential_state_t state)
{
    if (state < OZAYN_AuthN_CRED_UNINITIALIZED ||
        state > OZAYN_AuthN_CRED_EXPIRED)
        return -1;
    return 0;
}

/* ============================================================
 * CREDENTIAL REFERENCE OPERATIONS
 * ============================================================ */

int ozayn_authn_credential_ref_init(ozayn_authn_credential_ref_t *ref,
                                     const char *cred_id,
                                     ozayn_authn_method_t method,
                                     const char *provider_id)
{
    if (!ref || !cred_id || !provider_id)
        return -1;
    if (cred_id[0] == '\0' || provider_id[0] == '\0')
        return -1;
    if (ozayn_authn_validate_method(method) != 0)
        return -1;

    memset(ref, 0, sizeof(*ref));
    strncpy(ref->id, cred_id, sizeof(ref->id) - 1);
    ref->method = method;
    ref->state = OZAYN_AuthN_CRED_ACTIVE;
    ref->version = 1;
    strncpy(ref->provider_id, provider_id, sizeof(ref->provider_id) - 1);
    ref->created_at = time(NULL);
    ref->modified_at = ref->created_at;
    ref->in_use = 1;
    return 0;
}

int ozayn_authn_credential_ref_validate(const ozayn_authn_credential_ref_t *ref)
{
    if (!ref)
        return -1;
    if (!ref->in_use)
        return -1;
    if (ref->id[0] == '\0')
        return -1;
    if (ozayn_authn_validate_method(ref->method) != 0)
        return -1;
    if (ozayn_authn_validate_credential_state(ref->state) != 0)
        return -1;
    if (ref->state == OZAYN_AuthN_CRED_UNINITIALIZED)
        return -1;
    if (ref->provider_id[0] == '\0')
        return -1;
    if (ref->version == 0)
        return -1;
    if (ref->created_at <= 0)
        return -1;
    return 0;
}

int ozayn_authn_credential_ref_is_usable(const ozayn_authn_credential_ref_t *ref)
{
    if (!ref)
        return 0;
    if (!ref->in_use)
        return 0;
    if (ref->state != OZAYN_AuthN_CRED_ACTIVE)
        return 0;
    return 1;
}

int ozayn_authn_credential_validate_transition(ozayn_authn_credential_state_t from,
                                                ozayn_authn_credential_state_t to)
{
    if (ozayn_authn_validate_credential_state(from) != 0)
        return -1;
    if (ozayn_authn_validate_credential_state(to) != 0)
        return -1;

    switch (from) {
        case OZAYN_AuthN_CRED_UNINITIALIZED:
            return (to == OZAYN_AuthN_CRED_ACTIVE) ? 0 : -1;

        case OZAYN_AuthN_CRED_ACTIVE:
            return (to == OZAYN_AuthN_CRED_SUSPENDED ||
                    to == OZAYN_AuthN_CRED_REVOKED ||
                    to == OZAYN_AuthN_CRED_EXPIRED) ? 0 : -1;

        case OZAYN_AuthN_CRED_SUSPENDED:
            return (to == OZAYN_AuthN_CRED_ACTIVE ||
                    to == OZAYN_AuthN_CRED_REVOKED) ? 0 : -1;

        case OZAYN_AuthN_CRED_REVOKED:
            return -1;

        case OZAYN_AuthN_CRED_EXPIRED:
            return -1;

        default:
            return -1;
    }
}

/* ============================================================
 * AUTHENTICATION SERVICE LIFECYCLE
 * ============================================================ */

ozayn_authn_error_t ozayn_authn_service_init(ozayn_authn_service_t *svc,
                                              const ozayn_authn_service_config_t *config)
{
    if (!svc || !config)
        return OZAYN_AuthN_ERR_NULL;
    if (!config->identity_service)
        return OZAYN_AuthN_ERR_NULL;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;
    svc->provider_count = 0;
    svc->initialized = 1;
    return OZAYN_AuthN_OK;
}

void ozayn_authn_service_shutdown(ozayn_authn_service_t *svc)
{
    if (!svc)
        return;
    svc->provider_count = 0;
    svc->initialized = 0;
}

/* ============================================================
 * PROVIDER MANAGEMENT
 * ============================================================ */

ozayn_authn_error_t ozayn_authn_register_provider(ozayn_authn_service_t *svc,
                                                    ozayn_authn_provider_t *provider)
{
    if (!svc || !provider)
        return OZAYN_AuthN_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AuthN_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->authenticate)
        return OZAYN_AuthN_ERR_INVALID;
    if (!provider->name)
        return OZAYN_AuthN_ERR_INVALID;

    if (svc->provider_count >= OZAYN_AuthN_MAX_PROVIDERS)
        return OZAYN_AuthN_ERR_INVALID;

    /* Check for duplicate */
    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i] == provider)
            return OZAYN_AuthN_ERR_INVALID;
    }

    /* Initialize provider if init op exists */
    if (provider->ops->init) {
        int r = provider->ops->init(provider);
        if (r != 0)
            return OZAYN_AuthN_ERR_PROVIDER_FAILED;
    }

    svc->providers[svc->provider_count] = provider;
    svc->provider_count++;
    return OZAYN_AuthN_OK;
}

ozayn_authn_error_t ozayn_authn_unregister_provider(ozayn_authn_service_t *svc,
                                                      ozayn_authn_provider_t *provider)
{
    if (!svc || !provider)
        return OZAYN_AuthN_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AuthN_ERR_NOT_INITIALIZED;

    for (int i = 0; i < svc->provider_count; i++) {
        if (svc->providers[i] == provider) {
            /* Shutdown provider if shutdown op exists */
            if (provider->ops && provider->ops->shutdown)
                provider->ops->shutdown(provider);

            /* Shift remaining providers */
            for (int j = i; j < svc->provider_count - 1; j++)
                svc->providers[j] = svc->providers[j + 1];
            svc->providers[svc->provider_count - 1] = NULL;
            svc->provider_count--;
            return OZAYN_AuthN_OK;
        }
    }
    return OZAYN_AuthN_ERR_NOT_FOUND;
}

/* ============================================================
 * INTERNAL: Find provider for a given method
 * ============================================================ */

static ozayn_authn_provider_t *_find_provider(ozayn_authn_service_t *svc,
                                               ozayn_authn_method_t method)
{
    for (int i = 0; i < svc->provider_count; i++) {
        ozayn_authn_provider_t *p = svc->providers[i];
        if (!p || !p->ops)
            continue;
        if (p->ops->get_method) {
            if (p->ops->get_method(p) == method)
                return p;
        }
    }
    return NULL;
}

/* ============================================================
 * AUTHENTICATION OPERATIONS
 * ============================================================ */

ozayn_authn_error_t ozayn_authn_authenticate(ozayn_authn_service_t *svc,
                                               const ozayn_authn_request_t *request,
                                               ozayn_authn_response_t *out)
{
    if (!svc || !request || !out)
        return OZAYN_AuthN_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AuthN_ERR_NOT_INITIALIZED;

    /* Validate request */
    if (ozayn_authn_validate_request(request) != 0)
        return OZAYN_AuthN_ERR_INVALID;

    /* Initialize response */
    memset(out, 0, sizeof(*out));
    strncpy(out->identity_id, request->identity_id, sizeof(out->identity_id) - 1);
    out->method = request->method;
    out->auth_time = time(NULL);
    out->verification = OZAYN_AuthN_VERIFY_NOT_VERIFIED;

    /* Resolve identity through Identity Service */
    ozayn_identity_t identity;
    ozayn_identity_result_t id_r = ozayn_id_get(svc->config.identity_service,
                                                  request->identity_id,
                                                  &identity);
    if (id_r != OZAYN_ID_OK) {
        out->result = OZAYN_AuthN_RESULT_FAILED;
        out->verification = OZAYN_AuthN_VERIFY_FAILED;
        strncpy(out->reason, "Identity not found", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_IDENTITY_NOT_FOUND;
    }

    /* Check identity state — only ACTIVE identities may authenticate */
    if (identity.state == OZAYN_ID_STATE_REVOKED) {
        out->result = OZAYN_AuthN_RESULT_REJECTED;
        out->verification = OZAYN_AuthN_VERIFY_FAILED;
        strncpy(out->reason, "Identity is revoked", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_IDENTITY_REVOKED;
    }
    if (identity.state == OZAYN_ID_STATE_SUSPENDED) {
        out->result = OZAYN_AuthN_RESULT_REJECTED;
        out->verification = OZAYN_AuthN_VERIFY_FAILED;
        strncpy(out->reason, "Identity is suspended", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_IDENTITY_SUSPENDED;
    }
    if (identity.state == OZAYN_ID_STATE_ARCHIVED) {
        out->result = OZAYN_AuthN_RESULT_REJECTED;
        out->verification = OZAYN_AuthN_VERIFY_FAILED;
        strncpy(out->reason, "Identity is archived", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_IDENTITY_ARCHIVED;
    }

    /* Find provider for the requested method */
    ozayn_authn_provider_t *provider = _find_provider(svc, request->method);
    if (!provider) {
        out->result = OZAYN_AuthN_RESULT_UNAVAILABLE;
        out->verification = OZAYN_AuthN_VERIFY_UNAVAILABLE;
        strncpy(out->reason, "No provider for method", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE;
    }

    /* Check provider availability */
    if (provider->ops->is_available && !provider->ops->is_available(provider)) {
        out->result = OZAYN_AuthN_RESULT_UNAVAILABLE;
        out->verification = OZAYN_AuthN_VERIFY_UNAVAILABLE;
        strncpy(out->reason, "Provider not available", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_PROVIDER_UNAVAILABLE;
    }

    /* Delegate to provider for verification */
    ozayn_authn_result_t prot_r = provider->ops->authenticate(provider, request, out);
    if (prot_r != OZAYN_AuthN_RESULT_SUCCESS) {
        out->result = prot_r;
        out->verification = OZAYN_AuthN_VERIFY_FAILED;
        if (out->reason[0] == '\0')
            strncpy(out->reason, "Provider verification failed", sizeof(out->reason) - 1);
        return OZAYN_AuthN_ERR_VERIFICATION_FAILED;
    }

    /* Success */
    out->result = OZAYN_AuthN_RESULT_SUCCESS;
    out->verification = OZAYN_AuthN_VERIFY_VERIFIED;
    return OZAYN_AuthN_OK;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_authn_service_is_initialized(const ozayn_authn_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

int ozayn_authn_service_provider_count(const ozayn_authn_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->provider_count;
}
