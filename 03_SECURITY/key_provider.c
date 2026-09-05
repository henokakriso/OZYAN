#include "key_provider.h"
#include <string.h>

/*
 * key_provider.c — Key Management Foundation Dispatch (Section 03, Step 08).
 *
 * Dispatches key operations through the provider vtable.
 * Handles lifecycle state machine and name helpers.
 */

/* ---- Result Names ---- */
static const char *_key_result_names[] = {
    "KEY_OK",
    "KEY_NULL",
    "KEY_UNAVAILABLE",
    "KEY_INVALID_SIZE",
    "KEY_NOT_INITIALIZED",
    "KEY_NOT_FOUND",
    "KEY_INVALID",
    "KEY_PURPOSE_MISMATCH",
    "KEY_VERSION_UNSUPPORTED",
    "KEY_REVOKED",
    "KEY_RETIRED",
    "KEY_LIFECYCLE_INVALID",
    "KEY_ACCESS_DENIED"
};

/* ---- Purpose Names ---- */
static const char *_key_purpose_names[] = {
    "unknown",
    "data-encryption",
    "data-decryption",
    "auth-encryption",
    "auth-decryption"
};

/* ---- Lifecycle Names ---- */
static const char *_key_lifecycle_names[] = {
    "uninitialized",
    "available",
    "active",
    "retired",
    "revoked",
    "invalid"
};

/* ---- Lifecycle Transition Table ---- */
static const int _valid_transitions[6][6] = {
    /* from\to       UNINIT  AVAIL  ACTIVE  RETIRE  REVOKE  INVALID */
    /* UNINITIALIZED */ { 1,    1,     0,      0,      0,      1 },
    /* AVAILABLE     */ { 0,    1,     1,      0,      1,      1 },
    /* ACTIVE        */ { 0,    0,     1,      1,      1,      1 },
    /* RETIRED       */ { 0,    0,     0,      1,      1,      1 },
    /* REVOKED       */ { 0,    0,     0,      0,      1,      1 },
    /* INVALID       */ { 0,    0,     0,      0,      0,      1 }
};

/* ---- Key ID Helpers ---- */
int ozayn_key_id_equal(const ozayn_key_id_t *a, const ozayn_key_id_t *b)
{
    if (!a || !b)
        return 0;
    if (a->version != b->version)
        return 0;
    if (strcmp(a->name, b->name) != 0)
        return 0;
    if (strcmp(a->context, b->context) != 0)
        return 0;
    return 1;
}

void ozayn_key_id_set(ozayn_key_id_t *id, const char *name, uint32_t version,
                       const char *context)
{
    if (!id)
        return;
    memset(id, 0, sizeof(*id));
    if (name)
        strncpy(id->name, name, sizeof(id->name) - 1);
    id->version = version;
    if (context)
        strncpy(id->context, context, sizeof(id->context) - 1);
}

/* ---- Name Helpers ---- */
const char *ozayn_key_result_name(ozayn_key_result_t result)
{
    int idx = -result;
    if (idx < 0 || idx > 12)
        return "KEY_UNKNOWN";
    return _key_result_names[idx];
}

const char *ozayn_key_purpose_name(ozayn_key_purpose_t purpose)
{
    int idx = (int)purpose;
    if (idx < 0 || idx > 4)
        return "unknown";
    return _key_purpose_names[idx];
}

const char *ozayn_key_lifecycle_name(ozayn_key_lifecycle_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 5)
        return "unknown";
    return _key_lifecycle_names[idx];
}

int ozayn_key_lifecycle_transition_valid(ozayn_key_lifecycle_t from,
                                          ozayn_key_lifecycle_t to)
{
    int f = (int)from;
    int t = (int)to;
    if (f < 0 || f > 5 || t < 0 || t > 5)
        return 0;
    return _valid_transitions[f][t];
}

/* ============================================================
 * DISPATCH LAYER
 * ============================================================ */

ozayn_key_result_t ozayn_key_init(ozayn_key_provider_t *provider)
{
    if (!provider)
        return OZAYN_KEY_ERR_NULL;
    if (!provider->ops || !provider->ops->init)
        return OZAYN_KEY_ERR_UNAVAILABLE;

    provider->state = OZAYN_KEY_STATE_INITIALIZED;
    ozayn_key_result_t r = provider->ops->init(provider);
    if (r != OZAYN_KEY_OK) {
        provider->state = OZAYN_KEY_STATE_UNINITIALIZED;
        return r;
    }
    provider->state = OZAYN_KEY_STATE_READY;
    return OZAYN_KEY_OK;
}

void ozayn_key_shutdown(ozayn_key_provider_t *provider)
{
    if (!provider)
        return;
    if (provider->ops && provider->ops->shutdown)
        provider->ops->shutdown(provider);
    provider->state = OZAYN_KEY_STATE_STOPPED;
}

int ozayn_key_is_ready(const ozayn_key_provider_t *provider)
{
    if (!provider)
        return 0;
    return provider->state == OZAYN_KEY_STATE_READY;
}

ozayn_key_result_t ozayn_key_get(ozayn_key_provider_t *provider,
                                   uint8_t *key_out, size_t key_size)
{
    if (!provider || !key_out)
        return OZAYN_KEY_ERR_NULL;
    if (provider->state != OZAYN_KEY_STATE_READY)
        return OZAYN_KEY_ERR_NOT_INITIALIZED;
    if (key_size == 0 || key_size > OZAYN_KEY_MAX_SIZE)
        return OZAYN_KEY_ERR_INVALID_SIZE;
    if (!provider->ops || !provider->ops->get_key)
        return OZAYN_KEY_ERR_UNAVAILABLE;

    return provider->ops->get_key(provider, key_out, key_size);
}

int ozayn_key_is_available(const ozayn_key_provider_t *provider)
{
    if (!provider)
        return 0;
    if (provider->state != OZAYN_KEY_STATE_READY)
        return 0;
    if (!provider->ops || !provider->ops->is_available)
        return 0;
    return provider->ops->is_available(provider);
}

size_t ozayn_key_length(const ozayn_key_provider_t *provider)
{
    if (!provider)
        return 0;
    if (!provider->ops || !provider->ops->key_length)
        return 0;
    return provider->ops->key_length(provider);
}

/* ---- Extended Operations ---- */

ozayn_key_result_t ozayn_key_get_by_id(ozayn_key_provider_t *provider,
                                         const ozayn_key_id_t *id,
                                         ozayn_key_purpose_t purpose,
                                         uint8_t *key_out, size_t key_size)
{
    if (!provider || !id || !key_out)
        return OZAYN_KEY_ERR_NULL;
    if (provider->state != OZAYN_KEY_STATE_READY)
        return OZAYN_KEY_ERR_NOT_INITIALIZED;
    if (key_size == 0 || key_size > OZAYN_KEY_MAX_SIZE)
        return OZAYN_KEY_ERR_INVALID_SIZE;
    if (purpose == OZAYN_KEY_PURPOSE_UNKNOWN)
        return OZAYN_KEY_ERR_PURPOSE_MISMATCH;
    if (!provider->ops || !provider->ops->get_key_by_id)
        return OZAYN_KEY_ERR_UNAVAILABLE;

    return provider->ops->get_key_by_id(provider, id, purpose, key_out, key_size);
}

ozayn_key_result_t ozayn_key_get_metadata(ozayn_key_provider_t *provider,
                                            const ozayn_key_id_t *id,
                                            ozayn_key_metadata_t *out_metadata)
{
    if (!provider || !id || !out_metadata)
        return OZAYN_KEY_ERR_NULL;
    if (provider->state != OZAYN_KEY_STATE_READY)
        return OZAYN_KEY_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->get_metadata)
        return OZAYN_KEY_ERR_UNAVAILABLE;

    return provider->ops->get_metadata(provider, id, out_metadata);
}

ozayn_key_result_t ozayn_key_transition(ozayn_key_provider_t *provider,
                                          const ozayn_key_id_t *id,
                                          ozayn_key_lifecycle_t target)
{
    if (!provider || !id)
        return OZAYN_KEY_ERR_NULL;
    if (provider->state != OZAYN_KEY_STATE_READY)
        return OZAYN_KEY_ERR_NOT_INITIALIZED;
    if (!provider->ops || !provider->ops->transition)
        return OZAYN_KEY_ERR_UNAVAILABLE;

    return provider->ops->transition(provider, id, target);
}

int ozayn_key_count(const ozayn_key_provider_t *provider)
{
    if (!provider)
        return 0;
    if (provider->state != OZAYN_KEY_STATE_READY)
        return 0;
    if (!provider->ops || !provider->ops->key_count)
        return 0;
    return provider->ops->key_count(provider);
}
