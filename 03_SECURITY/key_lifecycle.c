#include "key_lifecycle.h"
#include <string.h>

/*
 * key_lifecycle.c — Key Lifecycle & Rotation (Section 03, Step 10).
 *
 * Manages key versions, lifecycle transitions, active-key selection,
 * controlled rotation, and historical-key lookup.
 */

/* ---- Result Names ---- */
static const char *_kl_result_names[] = {
    "KL_OK",
    "KL_NULL",
    "KL_NOT_INITIALIZED",
    "KL_UNAVAILABLE",
    "KL_NOT_FOUND",
    "KL_INVALID_TRANSITION",
    "KL_ALREADY_ACTIVE",
    "KL_ALREADY_RETIRED",
    "KL_ALREADY_REVOKED",
    "KL_VERSION_CONFLICT",
    "KL_NO_ACTIVE_KEY",
    "KL_ROTATION_FAILED",
    "KL_ROTATION_IN_PROGRESS",
    "KL_KEY_UNAVAILABLE",
    "KL_KEY_INVALID",
    "KL_STORAGE_FAILED",
    "KL_ACTIVATION_FAILED",
    "KL_RETIREMENT_FAILED"
};

const char *ozayn_kl_result_name(ozayn_kl_result_t result)
{
    int idx = -result;
    if (idx < 0 || idx > 17)
        return "KL_UNKNOWN";
    return _kl_result_names[idx];
}

/* ---- Find key entry by name ---- */
static ozayn_kl_key_entry_t *_find_key(ozayn_kl_manager_t *mgr, const char *name)
{
    if (!mgr || !name)
        return NULL;
    for (int i = 0; i < OZAYN_KL_MAX_KEY_NAMES; i++) {
        if (mgr->keys[i].in_use && strcmp(mgr->keys[i].name, name) == 0)
            return &mgr->keys[i];
    }
    return NULL;
}

/* ---- Find free key entry ---- */
static ozayn_kl_key_entry_t *_find_free_key(ozayn_kl_manager_t *mgr)
{
    for (int i = 0; i < OZAYN_KL_MAX_KEY_NAMES; i++) {
        if (!mgr->keys[i].in_use)
            return &mgr->keys[i];
    }
    return NULL;
}

/* ---- Find version entry within a key ---- */
static ozayn_kl_version_t *_find_version(ozayn_kl_key_entry_t *key, uint32_t version)
{
    for (int i = 0; i < OZAYN_KL_MAX_KEY_VERSIONS; i++) {
        if (key->versions[i].in_use && key->versions[i].id.version == version)
            return &key->versions[i];
    }
    return NULL;
}

/* ---- Find free version slot ---- */
static ozayn_kl_version_t *_find_free_version(ozayn_kl_key_entry_t *key)
{
    for (int i = 0; i < OZAYN_KL_MAX_KEY_VERSIONS; i++) {
        if (!key->versions[i].in_use)
            return &key->versions[i];
    }
    return NULL;
}

/* ---- Validate lifecycle transition ---- */
static int _transition_valid(ozayn_key_lifecycle_t from, ozayn_key_lifecycle_t to)
{
    /* Reuse the transition table from key_provider.c */
    static const int table[6][6] = {
        /* from\to       UNINIT  AVAIL  ACTIVE  RETIRE  REVOKE  INVALID */
        /* UNINITIALIZED */ { 1,    1,     0,      0,      0,      1 },
        /* AVAILABLE     */ { 0,    1,     1,      0,      1,      1 },
        /* ACTIVE        */ { 0,    0,     1,      1,      1,      1 },
        /* RETIRED       */ { 0,    0,     0,      1,      1,      1 },
        /* REVOKED       */ { 0,    0,     0,      0,      1,      1 },
        /* INVALID       */ { 0,    0,     0,      0,      0,      1 }
    };
    int f = (int)from;
    int t = (int)to;
    if (f < 0 || f > 5 || t < 0 || t > 5)
        return 0;
    return table[f][t];
}

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_kl_result_t ozayn_kl_init(ozayn_kl_manager_t *mgr)
{
    if (!mgr)
        return OZAYN_KL_ERR_NULL;
    memset(mgr, 0, sizeof(*mgr));
    mgr->initialized = 1;
    return OZAYN_KL_OK;
}

void ozayn_kl_shutdown(ozayn_kl_manager_t *mgr)
{
    if (!mgr)
        return;
    memset(mgr, 0, sizeof(*mgr));
}

/* ============================================================
 * KEY REGISTRATION
 * ============================================================ */

ozayn_kl_result_t ozayn_kl_register_key(ozayn_kl_manager_t *mgr,
                                          const char *name,
                                          ozayn_key_purpose_t purpose)
{
    if (!mgr || !name)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;
    if (purpose == OZAYN_KEY_PURPOSE_UNKNOWN)
        return OZAYN_KL_ERR_KEY_INVALID;

    /* Check if already registered */
    if (_find_key(mgr, name))
        return OZAYN_KL_ERR_VERSION_CONFLICT;

    /* Find free slot */
    ozayn_kl_key_entry_t *entry = _find_free_key(mgr);
    if (!entry)
        return OZAYN_KL_ERR_UNAVAILABLE;

    memset(entry, 0, sizeof(*entry));
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->purpose = purpose;
    entry->version_count = 0;
    entry->active_version_index = -1;
    entry->in_use = 1;
    mgr->key_count++;

    return OZAYN_KL_OK;
}

ozayn_kl_result_t ozayn_kl_add_version(ozayn_kl_manager_t *mgr,
                                         const char *name,
                                         const ozayn_key_id_t *id,
                                         uint32_t key_length)
{
    if (!mgr || !name || !id)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    /* Check version uniqueness */
    if (_find_version(key, id->version))
        return OZAYN_KL_ERR_VERSION_CONFLICT;

    /* Find free version slot */
    ozayn_kl_version_t *ver = _find_free_version(key);
    if (!ver)
        return OZAYN_KL_ERR_UNAVAILABLE;

    memset(ver, 0, sizeof(*ver));
    ver->id = *id;
    ver->lifecycle = OZAYN_KEY_LIFECYCLE_AVAILABLE;
    ver->purpose = key->purpose;
    ver->key_length = key_length;
    ver->created_at = time(NULL);
    ver->in_use = 1;
    key->version_count++;

    return OZAYN_KL_OK;
}

/* ============================================================
 * LIFECYCLE TRANSITIONS
 * ============================================================ */

ozayn_kl_result_t ozayn_kl_transition(ozayn_kl_manager_t *mgr,
                                        const char *name,
                                        uint32_t version,
                                        ozayn_key_lifecycle_t target)
{
    if (!mgr || !name)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return OZAYN_KL_ERR_NOT_FOUND;

    if (!_transition_valid(ver->lifecycle, target))
        return OZAYN_KL_ERR_INVALID_TRANSITION;

    ver->lifecycle = target;

    if (target == OZAYN_KEY_LIFECYCLE_RETIRED)
        ver->retired_at = time(NULL);
    else if (target == OZAYN_KEY_LIFECYCLE_REVOKED)
        ver->revoked_at = time(NULL);

    return OZAYN_KL_OK;
}

ozayn_kl_result_t ozayn_kl_activate(ozayn_kl_manager_t *mgr,
                                      const char *name,
                                      uint32_t version)
{
    if (!mgr || !name)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return OZAYN_KL_ERR_NOT_FOUND;

    if (ver->lifecycle == OZAYN_KEY_LIFECYCLE_ACTIVE)
        return OZAYN_KL_ERR_ALREADY_ACTIVE;
    if (ver->lifecycle == OZAYN_KEY_LIFECYCLE_REVOKED)
        return OZAYN_KL_ERR_ALREADY_REVOKED;
    if (ver->lifecycle != OZAYN_KEY_LIFECYCLE_AVAILABLE)
        return OZAYN_KL_ERR_INVALID_TRANSITION;

    /* Retire current active key if any */
    if (key->active_version_index >= 0) {
        ozayn_kl_version_t *old = &key->versions[key->active_version_index];
        if (old->in_use && old->lifecycle == OZAYN_KEY_LIFECYCLE_ACTIVE) {
            old->lifecycle = OZAYN_KEY_LIFECYCLE_RETIRED;
            old->retired_at = time(NULL);
        }
    }

    ver->lifecycle = OZAYN_KEY_LIFECYCLE_ACTIVE;
    ver->activated_at = time(NULL);

    /* Update active index */
    for (int i = 0; i < OZAYN_KL_MAX_KEY_VERSIONS; i++) {
        if (&key->versions[i] == ver) {
            key->active_version_index = i;
            break;
        }
    }

    return OZAYN_KL_OK;
}

ozayn_kl_result_t ozayn_kl_retire(ozayn_kl_manager_t *mgr,
                                    const char *name,
                                    uint32_t version)
{
    if (!mgr || !name)
        return OZAYN_KL_ERR_NULL;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return OZAYN_KL_ERR_NOT_FOUND;

    if (ver->lifecycle == OZAYN_KEY_LIFECYCLE_RETIRED)
        return OZAYN_KL_ERR_ALREADY_RETIRED;
    if (ver->lifecycle == OZAYN_KEY_LIFECYCLE_REVOKED)
        return OZAYN_KL_ERR_ALREADY_REVOKED;
    if (ver->lifecycle != OZAYN_KEY_LIFECYCLE_ACTIVE)
        return OZAYN_KL_ERR_INVALID_TRANSITION;

    ver->lifecycle = OZAYN_KEY_LIFECYCLE_RETIRED;
    ver->retired_at = time(NULL);

    /* Clear active index if this was the active key */
    if (key->active_version_index >= 0 &&
        &key->versions[key->active_version_index] == ver)
    {
        key->active_version_index = -1;
    }

    return OZAYN_KL_OK;
}

ozayn_kl_result_t ozayn_kl_revoke(ozayn_kl_manager_t *mgr,
                                    const char *name,
                                    uint32_t version)
{
    if (!mgr || !name)
        return OZAYN_KL_ERR_NULL;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return OZAYN_KL_ERR_NOT_FOUND;

    if (ver->lifecycle == OZAYN_KEY_LIFECYCLE_REVOKED)
        return OZAYN_KL_ERR_ALREADY_REVOKED;

    /* Can revoke from ACTIVE or RETIRED or AVAILABLE */
    if (!_transition_valid(ver->lifecycle, OZAYN_KEY_LIFECYCLE_REVOKED))
        return OZAYN_KL_ERR_INVALID_TRANSITION;

    ver->lifecycle = OZAYN_KEY_LIFECYCLE_REVOKED;
    ver->revoked_at = time(NULL);

    /* Clear active index if this was the active key */
    if (key->active_version_index >= 0 &&
        &key->versions[key->active_version_index] == ver)
    {
        key->active_version_index = -1;
    }

    return OZAYN_KL_OK;
}

/* ============================================================
 * KEY ROTATION
 * ============================================================ */

ozayn_kl_result_t ozayn_kl_rotate(ozayn_kl_manager_t *mgr,
                                    const char *name,
                                    const uint8_t *new_key_material,
                                    size_t key_length)
{
    if (!mgr || !name || !new_key_material)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;
    if (key_length == 0 || key_length > OZAYN_KEY_MAX_SIZE)
        return OZAYN_KL_ERR_KEY_INVALID;

    /* Check no rotation already in progress */
    if (mgr->current_rotation.in_progress)
        return OZAYN_KL_ERR_ROTATION_IN_PROGRESS;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    /* Determine new version number */
    uint32_t new_version = 0;
    for (int i = 0; i < OZAYN_KL_MAX_KEY_VERSIONS; i++) {
        if (key->versions[i].in_use) {
            if (key->versions[i].id.version >= new_version)
                new_version = key->versions[i].id.version;
        }
    }
    new_version++;

    /* Start rotation tracking */
    memset(&mgr->current_rotation, 0, sizeof(mgr->current_rotation));
    strncpy(mgr->current_rotation.key_name, name, sizeof(mgr->current_rotation.key_name) - 1);
    mgr->current_rotation.purpose = key->purpose;
    mgr->current_rotation.new_version = new_version;
    mgr->current_rotation.old_version = (key->active_version_index >= 0) ?
        key->versions[key->active_version_index].id.version : 0;
    mgr->current_rotation.in_progress = 1;
    mgr->current_rotation.started_at = time(NULL);

    /* Step 1: Add new version */
    ozayn_key_id_t new_id;
    ozayn_key_id_set(&new_id, name, new_version, "production");
    ozayn_kl_result_t r = ozayn_kl_add_version(mgr, name, &new_id, (uint32_t)key_length);
    if (r != OZAYN_KL_OK) {
        mgr->current_rotation.in_progress = 0;
        return OZAYN_KL_ERR_ROTATION_FAILED;
    }

    /* Step 2: Activate new version (this retires the old active key) */
    r = ozayn_kl_activate(mgr, name, new_version);
    if (r != OZAYN_KL_OK) {
        mgr->current_rotation.in_progress = 0;
        return OZAYN_KL_ERR_ROTATION_FAILED;
    }

    /* Rotation complete */
    mgr->current_rotation.in_progress = 0;
    return OZAYN_KL_OK;
}

/* ============================================================
 * KEY LOOKUP
 * ============================================================ */

ozayn_kl_result_t ozayn_kl_get_active(ozayn_kl_manager_t *mgr,
                                        const char *name,
                                        ozayn_kl_version_t **out_version)
{
    if (!mgr || !name || !out_version)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    if (key->active_version_index < 0)
        return OZAYN_KL_ERR_NO_ACTIVE_KEY;

    *out_version = &key->versions[key->active_version_index];
    return OZAYN_KL_OK;
}

ozayn_kl_result_t ozayn_kl_get_version(ozayn_kl_manager_t *mgr,
                                         const char *name,
                                         uint32_t version,
                                         ozayn_kl_version_t **out_version)
{
    if (!mgr || !name || !out_version)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return OZAYN_KL_ERR_NOT_FOUND;

    *out_version = ver;
    return OZAYN_KL_OK;
}

ozayn_kl_result_t ozayn_kl_get_latest_version(ozayn_kl_manager_t *mgr,
                                                const char *name,
                                                uint32_t *out_version)
{
    if (!mgr || !name || !out_version)
        return OZAYN_KL_ERR_NULL;
    if (!mgr->initialized)
        return OZAYN_KL_ERR_NOT_INITIALIZED;

    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return OZAYN_KL_ERR_NOT_FOUND;

    uint32_t latest = 0;
    for (int i = 0; i < OZAYN_KL_MAX_KEY_VERSIONS; i++) {
        if (key->versions[i].in_use && key->versions[i].id.version > latest)
            latest = key->versions[i].id.version;
    }

    if (latest == 0)
        return OZAYN_KL_ERR_NOT_FOUND;

    *out_version = latest;
    return OZAYN_KL_OK;
}

int ozayn_kl_is_active(ozayn_kl_manager_t *mgr,
                        const char *name,
                        uint32_t version)
{
    if (!mgr || !name)
        return 0;
    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return 0;
    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return 0;
    return ver->lifecycle == OZAYN_KEY_LIFECYCLE_ACTIVE;
}

int ozayn_kl_is_usable(ozayn_kl_manager_t *mgr,
                        const char *name,
                        uint32_t version)
{
    if (!mgr || !name)
        return 0;
    ozayn_kl_key_entry_t *key = _find_key(mgr, name);
    if (!key)
        return 0;
    ozayn_kl_version_t *ver = _find_version(key, version);
    if (!ver)
        return 0;
    return ver->lifecycle == OZAYN_KEY_LIFECYCLE_ACTIVE ||
           ver->lifecycle == OZAYN_KEY_LIFECYCLE_RETIRED ||
           ver->lifecycle == OZAYN_KEY_LIFECYCLE_AVAILABLE;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_kl_key_count(const ozayn_kl_manager_t *mgr)
{
    if (!mgr)
        return 0;
    return mgr->key_count;
}

int ozayn_kl_version_count(const ozayn_kl_manager_t *mgr, const char *name)
{
    if (!mgr || !name)
        return 0;
    const ozayn_kl_key_entry_t *key = NULL;
    for (int i = 0; i < OZAYN_KL_MAX_KEY_NAMES; i++) {
        if (mgr->keys[i].in_use && strcmp(mgr->keys[i].name, name) == 0) {
            key = &mgr->keys[i];
            break;
        }
    }
    if (!key)
        return 0;
    return key->version_count;
}

int ozayn_kl_is_rotation_in_progress(const ozayn_kl_manager_t *mgr)
{
    if (!mgr)
        return 0;
    return mgr->current_rotation.in_progress;
}
