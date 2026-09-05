#include "secure_key_storage_test.h"
#include <string.h>
#include <time.h>

/*
 * secure_key_storage_test.c — Test-Only Key Storage Backend (Section 03, Step 09).
 *
 * In-memory key storage for testing the secure key storage architecture.
 * Supports store, load, exists, remove, metadata.
 * DO NOT use in production.
 */

typedef struct {
    ozayn_key_id_t        key_id;
    uint8_t               key_material[OZAYN_KS_MAX_KEY_SIZE];
    size_t                key_length;
    ozayn_key_purpose_t   purpose;
    time_t                created_at;
    time_t                stored_at;
    int                   in_use;
} _ks_test_entry_t;

typedef struct {
    _ks_test_entry_t   entries[OZAYN_KS_TEST_MAX_ENTRIES];
    int                count;
    ozayn_ks_test_config_t *config;
} _ks_test_impl_t;

static _ks_test_impl_t _ks_impl;

/* ---- Find entry by key ID ---- */
static _ks_test_entry_t *_find_entry(const ozayn_key_id_t *id)
{
    for (int i = 0; i < OZAYN_KS_TEST_MAX_ENTRIES; i++) {
        if (_ks_impl.entries[i].in_use &&
            ozayn_key_id_equal(&_ks_impl.entries[i].key_id, id))
            return &_ks_impl.entries[i];
    }
    return NULL;
}

/* ---- Find free slot ---- */
static _ks_test_entry_t *_find_free(void)
{
    for (int i = 0; i < OZAYN_KS_TEST_MAX_ENTRIES; i++) {
        if (!_ks_impl.entries[i].in_use)
            return &_ks_impl.entries[i];
    }
    return NULL;
}

/* ---- Init ---- */
static ozayn_ks_result_t _test_init(ozayn_key_storage_t *storage)
{
    (void)storage;
    ozayn_ks_test_config_t *cfg = _ks_impl.config;
    memset(&_ks_impl, 0, sizeof(_ks_impl));
    _ks_impl.config = cfg;
    _ks_impl.count = 0;
    return OZAYN_KS_OK;
}

/* ---- Shutdown ---- */
static void _test_shutdown(ozayn_key_storage_t *storage)
{
    (void)storage;
    memset(&_ks_impl, 0, sizeof(_ks_impl));
}

/* ---- Store ---- */
static ozayn_ks_result_t _test_store(ozayn_key_storage_t *storage,
                                       const ozayn_ks_request_t *request,
                                       ozayn_ks_result_data_t *out)
{
    (void)storage;
    if (_ks_impl.config && _ks_impl.config->unavailable)
        return OZAYN_KS_ERR_UNAVAILABLE;
    if (_ks_impl.config && _ks_impl.config->access_denied)
        return OZAYN_KS_ERR_ACCESS_DENIED;
    if (_ks_impl.config && _ks_impl.config->fail_store)
        return OZAYN_KS_ERR_STORAGE_FAILED;

    /* Check if key already exists */
    _ks_test_entry_t *existing = _find_entry(&request->key_id);
    if (existing)
        return OZAYN_KS_ERR_ALREADY_EXISTS;

    /* Find free slot */
    _ks_test_entry_t *entry = _find_free();
    if (!entry)
        return OZAYN_KS_ERR_STORAGE_FAILED;

    entry->key_id = request->key_id;
    memcpy(entry->key_material, request->key_material, request->key_length);
    entry->key_length = request->key_length;
    entry->purpose = request->purpose;
    entry->created_at = time(NULL);
    entry->stored_at = time(NULL);
    entry->in_use = 1;
    _ks_impl.count++;

    out->status = OZAYN_KS_OK;
    out->key_id = request->key_id;
    out->key_version = request->key_id.version;
    out->purpose = request->purpose;
    out->stored_at = entry->stored_at;
    return OZAYN_KS_OK;
}

/* ---- Load ---- */
static ozayn_ks_result_t _test_load(ozayn_key_storage_t *storage,
                                      const ozayn_ks_request_t *request,
                                      ozayn_ks_result_data_t *out)
{
    (void)storage;
    if (_ks_impl.config && _ks_impl.config->unavailable)
        return OZAYN_KS_ERR_UNAVAILABLE;
    if (_ks_impl.config && _ks_impl.config->access_denied)
        return OZAYN_KS_ERR_ACCESS_DENIED;
    if (_ks_impl.config && _ks_impl.config->fail_load)
        return OZAYN_KS_ERR_STORAGE_FAILED;

    _ks_test_entry_t *entry = _find_entry(&request->key_id);
    if (!entry)
        return OZAYN_KS_ERR_NOT_FOUND;

    out->status = OZAYN_KS_OK;
    memcpy(out->key_material, entry->key_material, entry->key_length);
    out->key_length = entry->key_length;
    out->key_id = entry->key_id;
    out->purpose = entry->purpose;
    out->key_version = entry->key_id.version;
    out->stored_at = entry->stored_at;
    return OZAYN_KS_OK;
}

/* ---- Exists ---- */
static ozayn_ks_result_t _test_exists(ozayn_key_storage_t *storage,
                                        const ozayn_key_id_t *key_id,
                                        int *out_exists)
{
    (void)storage;
    if (_ks_impl.config && _ks_impl.config->unavailable)
        return OZAYN_KS_ERR_UNAVAILABLE;

    *out_exists = (_find_entry(key_id) != NULL) ? 1 : 0;
    return OZAYN_KS_OK;
}

/* ---- Remove ---- */
static ozayn_ks_result_t _test_remove(ozayn_key_storage_t *storage,
                                        const ozayn_key_id_t *key_id)
{
    (void)storage;
    if (_ks_impl.config && _ks_impl.config->unavailable)
        return OZAYN_KS_ERR_UNAVAILABLE;
    if (_ks_impl.config && _ks_impl.config->access_denied)
        return OZAYN_KS_ERR_ACCESS_DENIED;
    if (_ks_impl.config && _ks_impl.config->fail_remove)
        return OZAYN_KS_ERR_STORAGE_FAILED;

    _ks_test_entry_t *entry = _find_entry(key_id);
    if (!entry)
        return OZAYN_KS_ERR_NOT_FOUND;

    entry->in_use = 0;
    _ks_impl.count--;
    return OZAYN_KS_OK;
}

/* ---- Get Metadata ---- */
static ozayn_ks_result_t _test_get_metadata(ozayn_key_storage_t *storage,
                                              const ozayn_key_id_t *key_id,
                                              ozayn_ks_metadata_t *out)
{
    (void)storage;
    if (_ks_impl.config && _ks_impl.config->unavailable)
        return OZAYN_KS_ERR_UNAVAILABLE;

    _ks_test_entry_t *entry = _find_entry(key_id);
    if (!entry)
        return OZAYN_KS_ERR_NOT_FOUND;

    out->key_id = entry->key_id;
    out->lifecycle = OZAYN_KEY_LIFECYCLE_ACTIVE;
    out->purpose = entry->purpose;
    out->key_version = entry->key_id.version;
    out->key_length = entry->key_length;
    out->created_at = entry->created_at;
    out->stored_at = entry->stored_at;
    strncpy(out->platform_type, "in-memory-test", sizeof(out->platform_type) - 1);
    out->is_valid = 1;
    return OZAYN_KS_OK;
}

/* ---- Query ---- */
static int _test_is_available(const ozayn_key_storage_t *storage)
{
    (void)storage;
    if (_ks_impl.config && _ks_impl.config->unavailable)
        return 0;
    return 1;
}

static const char *_test_platform_name(const ozayn_key_storage_t *storage)
{
    (void)storage;
    return "in-memory-test";
}

/* ---- Ops Table ---- */
static const ozayn_ks_ops_t _test_ops = {
    .init          = _test_init,
    .shutdown      = _test_shutdown,
    .store         = _test_store,
    .load          = _test_load,
    .exists        = _test_exists,
    .remove        = _test_remove,
    .get_metadata  = _test_get_metadata,
    .is_available  = _test_is_available,
    .platform_name = _test_platform_name
};

/* ---- Public API ---- */
void ozayn_ks_test_create(ozayn_key_storage_t *storage,
                           ozayn_ks_test_config_t *config)
{
    if (!storage)
        return;
    memset(storage, 0, sizeof(*storage));
    storage->name = "test-key-storage";
    storage->state = OZAYN_KS_STATE_UNINITIALIZED;
    storage->ops = &_test_ops;
    storage->impl_data = &_ks_impl;

    memset(&_ks_impl, 0, sizeof(_ks_impl));
    _ks_impl.config = config;
}
