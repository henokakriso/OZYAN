#include "key_provider.h"
#include <string.h>

/*
 * key_provider.c — Key Provider Dispatch Layer (Section 03, Step 07).
 *
 * Dispatches key operations through the provider vtable.
 */

static const char *_key_result_names[] = {
    "KEY_OK",
    "KEY_NULL",
    "KEY_UNAVAILABLE",
    "KEY_INVALID_SIZE",
    "KEY_NOT_INITIALIZED"
};

const char *ozayn_key_result_name(ozayn_key_result_t result)
{
    int idx = -result;
    if (idx < 0 || idx > 4)
        return "KEY_UNKNOWN";
    return _key_result_names[idx];
}

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
