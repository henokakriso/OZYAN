#include "key_provider_test.h"
#include <string.h>

/*
 * key_provider_test.c — Test-Only Key Provider (Section 03, Step 07).
 *
 * Provides a fixed key for deterministic testing.
 * DO NOT use in production.
 */

typedef struct {
    uint8_t  key[OZAYN_KEY_MAX_SIZE];
    size_t   key_len;
    int      available;
} _test_key_impl_t;

static _test_key_impl_t _test_impl;

static ozayn_key_result_t _test_init(ozayn_key_provider_t *provider)
{
    (void)provider;
    _test_impl.available = 1;
    return OZAYN_KEY_OK;
}

static void _test_shutdown(ozayn_key_provider_t *provider)
{
    (void)provider;
    memset(&_test_impl, 0, sizeof(_test_impl));
}

static ozayn_key_result_t _test_get_key(ozayn_key_provider_t *provider,
                                           uint8_t *key_out, size_t key_size)
{
    (void)provider;
    if (!_test_impl.available)
        return OZAYN_KEY_ERR_UNAVAILABLE;
    if (key_size < _test_impl.key_len)
        return OZAYN_KEY_ERR_INVALID_SIZE;
    memcpy(key_out, _test_impl.key, _test_impl.key_len);
    return OZAYN_KEY_OK;
}

static int _test_is_available(const ozayn_key_provider_t *provider)
{
    (void)provider;
    return _test_impl.available;
}

static size_t _test_key_length(const ozayn_key_provider_t *provider)
{
    (void)provider;
    return _test_impl.key_len;
}

static const ozayn_key_ops_t _test_ops = {
    .init        = _test_init,
    .shutdown    = _test_shutdown,
    .get_key     = _test_get_key,
    .is_available = _test_is_available,
    .key_length  = _test_key_length
};

void ozayn_key_test_create(ozayn_key_provider_t *provider,
                            const uint8_t *key, size_t key_len)
{
    if (!provider)
        return;
    memset(provider, 0, sizeof(*provider));
    provider->name = "test-key-provider";
    provider->state = OZAYN_KEY_STATE_UNINITIALIZED;
    provider->ops = &_test_ops;
    provider->impl_data = &_test_impl;

    memset(&_test_impl, 0, sizeof(_test_impl));
    if (key && key_len > 0 && key_len <= OZAYN_KEY_MAX_SIZE) {
        memcpy(_test_impl.key, key, key_len);
        _test_impl.key_len = key_len;
    }
}
