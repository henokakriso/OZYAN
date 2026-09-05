#include "protection_provider.h"
#include <string.h>

/*
 * protection_provider.c — Protection Provider Dispatch Layer (Section 03, Step 06).
 *
 * Dispatches protection/unprotection calls through the provider vtable.
 * Validates state machine transitions and input parameters.
 */

/* ---- Result Names ---- */
static const char *_prot_result_names[] = {
    "PROT_OK",
    "PROT_NULL",
    "PROT_NOT_INITIALIZED",
    "PROT_INVALID_REQUEST",
    "PROT_INVALID_DATA",
    "PROT_PROTECTION_FAILED",
    "PROT_UNPROTECTION_FAILED",
    "PROT_AUTH_FAILED",
    "PROT_UNSUPPORTED_FORMAT",
    "PROT_UNSUPPORTED_VERSION",
    "PROT_INTEGRITY",
    "PROT_UNAVAILABLE",
    "PROT_INVALID_PROTECTED"
};

/* ---- State Names ---- */
static const char *_prot_state_names[] = {
    "UNINITIALIZED",
    "INITIALIZED",
    "READY",
    "SHUTTING_DOWN",
    "STOPPED"
};

/* ---- Algorithm Names ---- */
static const char *_prot_algorithm_names[] = {
    "none",
    "aes-256-gcm",
    "chacha20-poly1305"
};

const char *ozayn_prot_result_name(ozayn_prot_result_t result)
{
    int idx = -result;
    if (idx < 0 || idx > 12)
        return "UNKNOWN";
    return _prot_result_names[idx];
}

const char *ozayn_prot_state_name(ozayn_prot_state_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 4)
        return "UNKNOWN";
    return _prot_state_names[idx];
}

const char *ozayn_prot_algorithm_name_enum(ozayn_prot_algorithm_t alg)
{
    int idx = (int)alg;
    if (idx < 0 || idx > 2)
        return "unknown";
    return _prot_algorithm_names[idx];
}

/* ---- Provider Lifecycle ---- */
ozayn_prot_result_t ozayn_prot_init(ozayn_protection_provider_t *provider)
{
    if (!provider)
        return OZAYN_PROT_ERR_NULL;
    if (!provider->ops || !provider->ops->init)
        return OZAYN_PROT_ERR_UNAVAILABLE;

    provider->state = OZAYN_PROT_STATE_INITIALIZED;
    ozayn_prot_result_t r = provider->ops->init(provider);
    if (r != OZAYN_PROT_OK) {
        provider->state = OZAYN_PROT_STATE_UNINITIALIZED;
        return r;
    }
    provider->state = OZAYN_PROT_STATE_READY;
    return OZAYN_PROT_OK;
}

void ozayn_prot_shutdown(ozayn_protection_provider_t *provider)
{
    if (!provider)
        return;
    provider->state = OZAYN_PROT_STATE_SHUTTING_DOWN;
    if (provider->ops && provider->ops->shutdown)
        provider->ops->shutdown(provider);
    provider->state = OZAYN_PROT_STATE_STOPPED;
}

int ozayn_prot_is_ready(const ozayn_protection_provider_t *provider)
{
    if (!provider)
        return 0;
    return provider->state == OZAYN_PROT_STATE_READY;
}

/* ---- Dispatch Operations ---- */
ozayn_prot_result_t ozayn_prot_protect(ozayn_protection_provider_t *provider,
                                         const ozayn_prot_request_t *request,
                                         ozayn_protected_data_t *out_protected)
{
    if (!provider || !request || !out_protected)
        return OZAYN_PROT_ERR_NULL;
    if (provider->state != OZAYN_PROT_STATE_READY)
        return OZAYN_PROT_ERR_NOT_INITIALIZED;
    if (!request->plaintext || request->plaintext_len == 0)
        return OZAYN_PROT_ERR_INVALID_REQUEST;
    if (!request->object_id || request->object_id[0] == '\0')
        return OZAYN_PROT_ERR_INVALID_REQUEST;
    if (!provider->ops || !provider->ops->protect)
        return OZAYN_PROT_ERR_UNAVAILABLE;

    memset(out_protected, 0, sizeof(*out_protected));
    return provider->ops->protect(provider, request, out_protected);
}

ozayn_prot_result_t ozayn_prot_unprotect(ozayn_protection_provider_t *provider,
                                           const ozayn_protected_data_t *protected_data,
                                           ozayn_unprot_result_t *out_result)
{
    if (!provider || !protected_data || !out_result)
        return OZAYN_PROT_ERR_NULL;
    if (provider->state != OZAYN_PROT_STATE_READY)
        return OZAYN_PROT_ERR_NOT_INITIALIZED;
    if (protected_data->format_version == 0)
        return OZAYN_PROT_ERR_INVALID_PROTECTED;
    if (!provider->ops || !provider->ops->unprotect)
        return OZAYN_PROT_ERR_UNAVAILABLE;

    memset(out_result, 0, sizeof(*out_result));
    return provider->ops->unprotect(provider, protected_data, out_result);
}

int ozayn_prot_is_available(const ozayn_protection_provider_t *provider)
{
    if (!provider)
        return 0;
    if (provider->state != OZAYN_PROT_STATE_READY)
        return 0;
    if (!provider->ops || !provider->ops->is_available)
        return 0;
    return provider->ops->is_available(provider);
}

const char *ozayn_prot_algorithm_name(const ozayn_protection_provider_t *provider)
{
    if (!provider)
        return "null";
    if (!provider->ops || !provider->ops->algorithm_name)
        return "unknown";
    return provider->ops->algorithm_name(provider);
}

/* ---- Protected Data Validation ---- */
int ozayn_protected_data_validate(const ozayn_protected_data_t *pd)
{
    if (!pd)
        return 0;
    if (pd->format_version != OZAYN_PROT_CURRENT_VERSION)
        return 0;
    if (pd->algorithm == OZAYN_PROT_ALG_NONE)
        return 0;
    if (pd->ciphertext_len == 0)
        return 0;
    if (pd->ciphertext_len > OZAYN_PROT_MAX_CIPHERTEXT_SIZE)
        return 0;
    if (pd->nonce_len == 0 || pd->nonce_len > OZAYN_PROT_MAX_NONCE_SIZE)
        return 0;
    if (pd->tag_len == 0 || pd->tag_len > OZAYN_PROT_MAX_TAG_SIZE)
        return 0;
    return 1;
}
