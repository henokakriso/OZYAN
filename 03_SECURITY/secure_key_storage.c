#include "secure_key_storage.h"
#include <string.h>

/*
 * secure_key_storage.c — Secure Key Storage Dispatch (Section 03, Step 09).
 *
 * Dispatches key storage operations through the provider vtable.
 */

/* ---- Result Names ---- */
static const char *_ks_result_names[] = {
    "KS_OK",
    "KS_NULL",
    "KS_NOT_INITIALIZED",
    "KS_UNAVAILABLE",
    "KS_NOT_FOUND",
    "KS_ALREADY_EXISTS",
    "KS_INVALID_REQUEST",
    "KS_INVALID_KEY",
    "KS_ACCESS_DENIED",
    "KS_STORAGE_FAILED",
    "KS_PLATFORM_ERROR",
    "KS_UNSUPPORTED",
    "KS_KEY_REMOVED"
};

/* ---- Operation Names ---- */
static const char *_ks_op_names[] = {
    "invalid",
    "store",
    "load",
    "exists",
    "remove",
    "metadata"
};

/* ---- State Names ---- */
static const char *_ks_state_names[] = {
    "uninitialized",
    "initialized",
    "ready",
    "stopped"
};

const char *ozayn_ks_result_name(ozayn_ks_result_t result)
{
    int idx = -result;
    if (idx < 0 || idx > 12)
        return "KS_UNKNOWN";
    return _ks_result_names[idx];
}

const char *ozayn_ks_operation_name(ozayn_ks_operation_t op)
{
    int idx = (int)op;
    if (idx < 0 || idx > 5)
        return "invalid";
    return _ks_op_names[idx];
}

const char *ozayn_ks_state_name(ozayn_ks_state_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 3)
        return "unknown";
    return _ks_state_names[idx];
}

/* ---- Request Helpers ---- */
void ozayn_ks_request_init(ozayn_ks_request_t *req, ozayn_ks_operation_t op,
                            const ozayn_key_id_t *id, ozayn_key_purpose_t purpose)
{
    if (!req)
        return;
    memset(req, 0, sizeof(*req));
    req->operation = op;
    if (id)
        req->key_id = *id;
    req->purpose = purpose;
}

void ozayn_ks_request_set_store(ozayn_ks_request_t *req,
                                 const ozayn_key_id_t *id,
                                 const uint8_t *key, size_t key_len,
                                 ozayn_key_purpose_t purpose)
{
    if (!req)
        return;
    memset(req, 0, sizeof(*req));
    req->operation = OZAYN_KS_OP_STORE;
    if (id)
        req->key_id = *id;
    req->purpose = purpose;
    if (key && key_len > 0 && key_len <= OZAYN_KS_MAX_KEY_SIZE) {
        memcpy(req->key_material, key, key_len);
        req->key_length = key_len;
    }
}

/* ============================================================
 * DISPATCH LAYER
 * ============================================================ */

ozayn_ks_result_t ozayn_ks_init(ozayn_key_storage_t *storage)
{
    if (!storage)
        return OZAYN_KS_ERR_NULL;
    if (!storage->ops || !storage->ops->init)
        return OZAYN_KS_ERR_UNAVAILABLE;

    storage->state = OZAYN_KS_STATE_INITIALIZED;
    ozayn_ks_result_t r = storage->ops->init(storage);
    if (r != OZAYN_KS_OK) {
        storage->state = OZAYN_KS_STATE_UNINITIALIZED;
        return r;
    }
    storage->state = OZAYN_KS_STATE_READY;
    return OZAYN_KS_OK;
}

void ozayn_ks_shutdown(ozayn_key_storage_t *storage)
{
    if (!storage)
        return;
    if (storage->ops && storage->ops->shutdown)
        storage->ops->shutdown(storage);
    storage->state = OZAYN_KS_STATE_STOPPED;
}

int ozayn_ks_is_ready(const ozayn_key_storage_t *storage)
{
    if (!storage)
        return 0;
    return storage->state == OZAYN_KS_STATE_READY;
}

ozayn_ks_result_t ozayn_ks_store(ozayn_key_storage_t *storage,
                                  const ozayn_ks_request_t *request,
                                  ozayn_ks_result_data_t *out)
{
    if (!storage || !request || !out)
        return OZAYN_KS_ERR_NULL;
    if (storage->state != OZAYN_KS_STATE_READY)
        return OZAYN_KS_ERR_NOT_INITIALIZED;
    if (request->operation != OZAYN_KS_OP_STORE)
        return OZAYN_KS_ERR_INVALID_REQUEST;
    if (request->key_length == 0 || request->key_length > OZAYN_KS_MAX_KEY_SIZE)
        return OZAYN_KS_ERR_INVALID_KEY;
    if (request->purpose == OZAYN_KEY_PURPOSE_UNKNOWN)
        return OZAYN_KS_ERR_INVALID_REQUEST;
    if (!storage->ops || !storage->ops->store)
        return OZAYN_KS_ERR_UNAVAILABLE;

    memset(out, 0, sizeof(*out));
    return storage->ops->store(storage, request, out);
}

ozayn_ks_result_t ozayn_ks_load(ozayn_key_storage_t *storage,
                                 const ozayn_ks_request_t *request,
                                 ozayn_ks_result_data_t *out)
{
    if (!storage || !request || !out)
        return OZAYN_KS_ERR_NULL;
    if (storage->state != OZAYN_KS_STATE_READY)
        return OZAYN_KS_ERR_NOT_INITIALIZED;
    if (request->operation != OZAYN_KS_OP_LOAD)
        return OZAYN_KS_ERR_INVALID_REQUEST;
    if (!storage->ops || !storage->ops->load)
        return OZAYN_KS_ERR_UNAVAILABLE;

    memset(out, 0, sizeof(*out));
    return storage->ops->load(storage, request, out);
}

ozayn_ks_result_t ozayn_ks_exists(ozayn_key_storage_t *storage,
                                   const ozayn_key_id_t *key_id,
                                   int *out_exists)
{
    if (!storage || !key_id || !out_exists)
        return OZAYN_KS_ERR_NULL;
    if (storage->state != OZAYN_KS_STATE_READY)
        return OZAYN_KS_ERR_NOT_INITIALIZED;
    if (!storage->ops || !storage->ops->exists)
        return OZAYN_KS_ERR_UNAVAILABLE;

    *out_exists = 0;
    return storage->ops->exists(storage, key_id, out_exists);
}

ozayn_ks_result_t ozayn_ks_remove(ozayn_key_storage_t *storage,
                                   const ozayn_key_id_t *key_id)
{
    if (!storage || !key_id)
        return OZAYN_KS_ERR_NULL;
    if (storage->state != OZAYN_KS_STATE_READY)
        return OZAYN_KS_ERR_NOT_INITIALIZED;
    if (!storage->ops || !storage->ops->remove)
        return OZAYN_KS_ERR_UNAVAILABLE;

    return storage->ops->remove(storage, key_id);
}

ozayn_ks_result_t ozayn_ks_get_metadata(ozayn_key_storage_t *storage,
                                          const ozayn_key_id_t *key_id,
                                          ozayn_ks_metadata_t *out)
{
    if (!storage || !key_id || !out)
        return OZAYN_KS_ERR_NULL;
    if (storage->state != OZAYN_KS_STATE_READY)
        return OZAYN_KS_ERR_NOT_INITIALIZED;
    if (!storage->ops || !storage->ops->get_metadata)
        return OZAYN_KS_ERR_UNAVAILABLE;

    memset(out, 0, sizeof(*out));
    return storage->ops->get_metadata(storage, key_id, out);
}

int ozayn_ks_is_available(const ozayn_key_storage_t *storage)
{
    if (!storage)
        return 0;
    if (storage->state != OZAYN_KS_STATE_READY)
        return 0;
    if (!storage->ops || !storage->ops->is_available)
        return 0;
    return storage->ops->is_available(storage);
}

const char *ozayn_ks_platform_name(const ozayn_key_storage_t *storage)
{
    if (!storage)
        return "null";
    if (!storage->ops || !storage->ops->platform_name)
        return "unknown";
    return storage->ops->platform_name(storage);
}
