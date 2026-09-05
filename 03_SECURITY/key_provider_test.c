#include "key_provider_test.h"
#include <string.h>
#include <time.h>

/*
 * key_provider_test.c — Test-Only Key Provider (Section 03, Step 08).
 *
 * Provides fixed test keys with full key management support.
 * For managed mode, supports multiple keys with lifecycle tracking.
 * DO NOT use in production.
 */

/* ---- Single Key Mode (backward compatible) ---- */
typedef struct {
    uint8_t  key[OZAYN_KEY_MAX_SIZE];
    size_t   key_len;
    int      available;
} _test_single_impl_t;

static _test_single_impl_t _single_impl;

static ozayn_key_result_t _single_init(ozayn_key_provider_t *provider)
{
    (void)provider;
    _single_impl.available = 1;
    return OZAYN_KEY_OK;
}

static void _single_shutdown(ozayn_key_provider_t *provider)
{
    (void)provider;
    memset(&_single_impl, 0, sizeof(_single_impl));
}

static ozayn_key_result_t _single_get_key(ozayn_key_provider_t *provider,
                                            uint8_t *key_out, size_t key_size)
{
    (void)provider;
    if (!_single_impl.available)
        return OZAYN_KEY_ERR_UNAVAILABLE;
    if (key_size < _single_impl.key_len)
        return OZAYN_KEY_ERR_INVALID_SIZE;
    memcpy(key_out, _single_impl.key, _single_impl.key_len);
    return OZAYN_KEY_OK;
}

static int _single_is_available(const ozayn_key_provider_t *provider)
{
    (void)provider;
    return _single_impl.available;
}

static size_t _single_key_length(const ozayn_key_provider_t *provider)
{
    (void)provider;
    return _single_impl.key_len;
}

static const ozayn_key_ops_t _single_ops = {
    .init          = _single_init,
    .shutdown      = _single_shutdown,
    .get_key       = _single_get_key,
    .get_key_by_id = NULL,
    .get_metadata  = NULL,
    .transition    = NULL,
    .is_available  = _single_is_available,
    .key_length    = _single_key_length,
    .key_count     = NULL
};

void ozayn_key_test_create(ozayn_key_provider_t *provider,
                            const uint8_t *key, size_t key_len)
{
    if (!provider)
        return;
    memset(provider, 0, sizeof(*provider));
    provider->name = "test-key-provider";
    provider->state = OZAYN_KEY_STATE_UNINITIALIZED;
    provider->ops = &_single_ops;
    provider->impl_data = &_single_impl;

    memset(&_single_impl, 0, sizeof(_single_impl));
    if (key && key_len > 0 && key_len <= OZAYN_KEY_MAX_SIZE) {
        memcpy(_single_impl.key, key, key_len);
        _single_impl.key_len = key_len;
    }
}

/* ---- Managed Key Mode (multi-key with lifecycle) ---- */

typedef struct {
    ozayn_key_id_t         id;
    uint8_t                key[OZAYN_KEY_MAX_SIZE];
    size_t                 key_len;
    ozayn_key_lifecycle_t  lifecycle;
    ozayn_key_purpose_t    purpose;
    time_t                 created_at;
    time_t                 activated_at;
    time_t                 retired_at;
    int                    in_use;
} _managed_key_entry_t;

typedef struct {
    _managed_key_entry_t keys[OZAYN_KEY_TEST_MAX_KEYS];
    int                  count;
    int                  available;
} _managed_impl_t;

static _managed_impl_t _managed_impl;

static ozayn_key_result_t _managed_init(ozayn_key_provider_t *provider)
{
    (void)provider;
    _managed_impl.available = 1;

    /* Pre-populate test keys */
    time_t now = time(NULL);

    /* Key 1: ACTIVE data encryption key */
    _managed_key_entry_t *k1 = &_managed_impl.keys[0];
    ozayn_key_id_set(&k1->id, "OZAYN-DATA-PRIMARY", 1, "test");
    const uint8_t key1[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
    };
    memcpy(k1->key, key1, 32);
    k1->key_len = 32;
    k1->lifecycle = OZAYN_KEY_LIFECYCLE_ACTIVE;
    k1->purpose = OZAYN_KEY_PURPOSE_DATA_ENCRYPTION;
    k1->created_at = now;
    k1->activated_at = now;
    k1->in_use = 1;

    /* Key 2: RETIRED key */
    _managed_key_entry_t *k2 = &_managed_impl.keys[1];
    ozayn_key_id_set(&k2->id, "OZAYN-DATA-PRIMARY", 1, "test");
    /* Different version */
    k2->id.version = 0;  /* Old version */
    const uint8_t key2[32] = {
        0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,
        0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,
        0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,
        0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0
    };
    memcpy(k2->key, key2, 32);
    k2->key_len = 32;
    k2->lifecycle = OZAYN_KEY_LIFECYCLE_RETIRED;
    k2->purpose = OZAYN_KEY_PURPOSE_DATA_ENCRYPTION;
    k2->created_at = now - 86400;
    k2->activated_at = now - 86400;
    k2->retired_at = now;
    k2->in_use = 1;

    /* Key 3: REVOKED key */
    _managed_key_entry_t *k3 = &_managed_impl.keys[2];
    ozayn_key_id_set(&k3->id, "OZAYN-DATA-REVOKED", 1, "test");
    const uint8_t key3[32] = {
        0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,
        0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,0xD0,
        0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,
        0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,0xE0
    };
    memcpy(k3->key, key3, 32);
    k3->key_len = 32;
    k3->lifecycle = OZAYN_KEY_LIFECYCLE_REVOKED;
    k3->purpose = OZAYN_KEY_PURPOSE_DATA_ENCRYPTION;
    k3->created_at = now - 172800;
    k3->activated_at = now - 86400;
    k3->in_use = 1;

    /* Key 4: different purpose (auth) */
    _managed_key_entry_t *k4 = &_managed_impl.keys[3];
    ozayn_key_id_set(&k4->id, "OZAYN-AUTH-KEY", 1, "test");
    const uint8_t key4[32] = {
        0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,
        0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0,
        0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,
        0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0x00
    };
    memcpy(k4->key, key4, 32);
    k4->key_len = 32;
    k4->lifecycle = OZAYN_KEY_LIFECYCLE_ACTIVE;
    k4->purpose = OZAYN_KEY_PURPOSE_AUTH_ENCRYPTION;
    k4->created_at = now;
    k4->activated_at = now;
    k4->in_use = 1;

    _managed_impl.count = 4;
    return OZAYN_KEY_OK;
}

static void _managed_shutdown(ozayn_key_provider_t *provider)
{
    (void)provider;
    memset(&_managed_impl, 0, sizeof(_managed_impl));
}

static ozayn_key_result_t _managed_get_key(ozayn_key_provider_t *provider,
                                             uint8_t *key_out, size_t key_size)
{
    (void)provider;
    /* Return the first ACTIVE key with DATA_ENCRYPTION purpose */
    for (int i = 0; i < _managed_impl.count; i++) {
        _managed_key_entry_t *k = &_managed_impl.keys[i];
        if (!k->in_use) continue;
        if (k->lifecycle != OZAYN_KEY_LIFECYCLE_ACTIVE) continue;
        if (k->purpose != OZAYN_KEY_PURPOSE_DATA_ENCRYPTION) continue;
        if (key_size < k->key_len)
            return OZAYN_KEY_ERR_INVALID_SIZE;
        memcpy(key_out, k->key, k->key_len);
        return OZAYN_KEY_OK;
    }
    return OZAYN_KEY_ERR_NOT_FOUND;
}

static ozayn_key_result_t _managed_get_key_by_id(ozayn_key_provider_t *provider,
                                                    const ozayn_key_id_t *id,
                                                    ozayn_key_purpose_t purpose,
                                                    uint8_t *key_out, size_t key_size)
{
    (void)provider;
    if (!id)
        return OZAYN_KEY_ERR_NULL;

    for (int i = 0; i < _managed_impl.count; i++) {
        _managed_key_entry_t *k = &_managed_impl.keys[i];
        if (!k->in_use) continue;
        if (!ozayn_key_id_equal(&k->id, id)) continue;

        /* Purpose must match */
        if (k->purpose != purpose)
            return OZAYN_KEY_ERR_PURPOSE_MISMATCH;

        /* Lifecycle check: only ACTIVE keys for new operations */
        if (k->lifecycle == OZAYN_KEY_LIFECYCLE_REVOKED)
            return OZAYN_KEY_ERR_REVOKED;
        if (k->lifecycle == OZAYN_KEY_LIFECYCLE_RETIRED)
            return OZAYN_KEY_ERR_RETIRED;
        if (k->lifecycle != OZAYN_KEY_LIFECYCLE_ACTIVE)
            return OZAYN_KEY_ERR_INVALID_KEY;
        if (k->lifecycle == OZAYN_KEY_LIFECYCLE_INVALID)
            return OZAYN_KEY_ERR_INVALID_KEY;

        if (key_size < k->key_len)
            return OZAYN_KEY_ERR_INVALID_SIZE;
        memcpy(key_out, k->key, k->key_len);
        return OZAYN_KEY_OK;
    }
    return OZAYN_KEY_ERR_NOT_FOUND;
}

static ozayn_key_result_t _managed_get_metadata(ozayn_key_provider_t *provider,
                                                   const ozayn_key_id_t *id,
                                                   ozayn_key_metadata_t *out)
{
    (void)provider;
    if (!id || !out)
        return OZAYN_KEY_ERR_NULL;

    for (int i = 0; i < _managed_impl.count; i++) {
        _managed_key_entry_t *k = &_managed_impl.keys[i];
        if (!k->in_use) continue;
        if (!ozayn_key_id_equal(&k->id, id)) continue;

        memset(out, 0, sizeof(*out));
        out->id = k->id;
        out->lifecycle = k->lifecycle;
        out->purpose = k->purpose;
        out->key_length = (uint32_t)k->key_len;
        out->algorithm = 1;  /* AES-256 */
        out->created_at = k->created_at;
        out->activated_at = k->activated_at;
        out->retired_at = k->retired_at;
        out->is_valid = 1;
        return OZAYN_KEY_OK;
    }
    return OZAYN_KEY_ERR_NOT_FOUND;
}

static ozayn_key_result_t _managed_transition(ozayn_key_provider_t *provider,
                                                const ozayn_key_id_t *id,
                                                ozayn_key_lifecycle_t target)
{
    (void)provider;
    if (!id)
        return OZAYN_KEY_ERR_NULL;

    for (int i = 0; i < _managed_impl.count; i++) {
        _managed_key_entry_t *k = &_managed_impl.keys[i];
        if (!k->in_use) continue;
        if (!ozayn_key_id_equal(&k->id, id)) continue;

        if (!ozayn_key_lifecycle_transition_valid(k->lifecycle, target))
            return OZAYN_KEY_ERR_LIFECYCLE_INVALID;

        k->lifecycle = target;
        if (target == OZAYN_KEY_LIFECYCLE_RETIRED)
            k->retired_at = time(NULL);
        return OZAYN_KEY_OK;
    }
    return OZAYN_KEY_ERR_NOT_FOUND;
}

static int _managed_is_available(const ozayn_key_provider_t *provider)
{
    (void)provider;
    return _managed_impl.available;
}

static size_t _managed_key_length(const ozayn_key_provider_t *provider)
{
    (void)provider;
    /* Return length of first ACTIVE key */
    for (int i = 0; i < _managed_impl.count; i++) {
        _managed_key_entry_t *k = &_managed_impl.keys[i];
        if (!k->in_use) continue;
        if (k->lifecycle == OZAYN_KEY_LIFECYCLE_ACTIVE &&
            k->purpose == OZAYN_KEY_PURPOSE_DATA_ENCRYPTION)
            return k->key_len;
    }
    return 0;
}

static int _managed_key_count(const ozayn_key_provider_t *provider)
{
    (void)provider;
    return _managed_impl.count;
}

static const ozayn_key_ops_t _managed_ops = {
    .init          = _managed_init,
    .shutdown      = _managed_shutdown,
    .get_key       = _managed_get_key,
    .get_key_by_id = _managed_get_key_by_id,
    .get_metadata  = _managed_get_metadata,
    .transition    = _managed_transition,
    .is_available  = _managed_is_available,
    .key_length    = _managed_key_length,
    .key_count     = _managed_key_count
};

void ozayn_key_test_create_managed(ozayn_key_provider_t *provider)
{
    if (!provider)
        return;
    memset(provider, 0, sizeof(*provider));
    provider->name = "test-managed-key-provider";
    provider->state = OZAYN_KEY_STATE_UNINITIALIZED;
    provider->ops = &_managed_ops;
    provider->impl_data = &_managed_impl;
    memset(&_managed_impl, 0, sizeof(_managed_impl));
}
