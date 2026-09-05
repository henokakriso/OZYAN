#include "secure_data_object.h"
#include <string.h>
#include <stdio.h>

/*
 * secure_data_object.c — Secure Data Object Implementation (Section 03, Step 03).
 *
 * Implements the formal data model and validation contract for persistent
 * OZAYN data objects. Validates identity, classification consistency,
 * lifecycle state, ownership, and integrity.
 *
 * This step only represents states and validates consistency.
 * Cryptographic integrity, encryption, and authentication are deferred.
 */

/* ---- Data state name lookup ---- */
const char *ozayn_data_state_name(ozayn_data_state_t state)
{
    switch (state) {
        case OZAYN_DATA_STATE_UNINITIALIZED:      return "Uninitialized";
        case OZAYN_DATA_STATE_VALID:              return "Valid";
        case OZAYN_DATA_STATE_INVALID:            return "Invalid";
        case OZAYN_DATA_STATE_MARKED_FOR_DELETION: return "Marked for Deletion";
        default:                                  return "Unknown State";
    }
}

/* ---- Data scope name lookup ---- */
const char *ozayn_data_scope_name(ozayn_data_scope_t scope)
{
    switch (scope) {
        case OZAYN_DATA_SCOPE_UNKNOWN:  return "Unknown";
        case OZAYN_DATA_SCOPE_SYSTEM:   return "System";
        case OZAYN_DATA_SCOPE_USER:     return "User";
        case OZAYN_DATA_SCOPE_SESSION:  return "Session";
        case OZAYN_DATA_SCOPE_MODULE:   return "Module";
        case OZAYN_DATA_SCOPE_GLOBAL:   return "Global";
        default:                        return "Unknown Scope";
    }
}

/* ---- Object initialization ---- */
int ozayn_sdo_init(ozayn_secure_data_object_t *obj,
                   const char *id,
                   ozayn_data_category_t category,
                   const char *owner,
                   ozayn_data_scope_t scope)
{
    if (!obj || !id || !owner)
        return -1;
    if (id[0] == '\0')
        return -1;
    if (category < 0 || category >= OZAYN_DATA_CATEGORY_COUNT)
        return -1;
    if (scope <= OZAYN_DATA_SCOPE_UNKNOWN || scope > OZAYN_DATA_SCOPE_GLOBAL)
        return -1;

    memset(obj, 0, sizeof(*obj));

    strncpy(obj->id, id, OZAYN_SDO_MAX_ID_LEN - 1);
    obj->id[OZAYN_SDO_MAX_ID_LEN - 1] = '\0';

    strncpy(obj->version, "1.0", OZAYN_SDO_MAX_VERSION_LEN - 1);

    obj->category       = category;
    obj->classification = ozayn_data_default_classification(category);

    obj->state          = OZAYN_DATA_STATE_VALID;
    obj->integrity      = OZAYN_DATA_INTEGRITY_UNKNOWN;
    obj->storage_state  = OZAYN_DATA_STORAGE_INACTIVE;

    strncpy(obj->owner, owner, OZAYN_SDO_MAX_OWNER_LEN - 1);
    obj->owner[OZAYN_SDO_MAX_OWNER_LEN - 1] = '\0';
    obj->scope          = scope;

    obj->created_at     = 0;
    obj->modified_at    = 0;
    obj->content_size   = 0;
    obj->checksum       = 0;

    return 0;
}

/* ---- Invalidate object ---- */
int ozayn_sdo_invalidate(ozayn_secure_data_object_t *obj)
{
    if (!obj)
        return -1;
    if (obj->state == OZAYN_DATA_STATE_UNINITIALIZED)
        return -1;
    obj->state = OZAYN_DATA_STATE_INVALID;
    return 0;
}

/* ---- Mark for deletion ---- */
int ozayn_sdo_mark_for_deletion(ozayn_secure_data_object_t *obj)
{
    if (!obj)
        return -1;
    if (obj->state == OZAYN_DATA_STATE_UNINITIALIZED)
        return -1;
    if (obj->state == OZAYN_DATA_STATE_INVALID)
        return -1;
    obj->state = OZAYN_DATA_STATE_MARKED_FOR_DELETION;
    return 0;
}

/* ---- Classification consistency validation ---- */
/*
 * Prevents obviously unsafe combinations:
 *   - AUTH_INFO must never be PUBLIC
 *   - IDENTITY_INFORMATION must never be PUBLIC
 *   - SECURITY_EVENTS must never be PUBLIC
 *
 * Returns 0 if consistent, -1 if the combination is unsafe.
 */
int ozayn_sdo_validate_classification(const ozayn_secure_data_object_t *obj)
{
    if (!obj)
        return -1;

    /* These categories must never be PUBLIC */
    if (obj->category == OZAYN_DATA_CATEGORY_AUTH_INFO &&
        obj->classification == OZAYN_SEC_LEVEL_PUBLIC)
        return -1;

    if (obj->category == OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION &&
        obj->classification == OZAYN_SEC_LEVEL_PUBLIC)
        return -1;

    if (obj->category == OZAYN_DATA_CATEGORY_SECURITY_EVENTS &&
        obj->classification == OZAYN_SEC_LEVEL_PUBLIC)
        return -1;

    return 0;
}

/* ---- Full object validation ---- */
int ozayn_sdo_validate(const ozayn_secure_data_object_t *obj)
{
    if (!obj)
        return -1;

    /* Identity */
    if (obj->id[0] == '\0')
        return -1;

    /* Category */
    if (obj->category < 0 || obj->category >= OZAYN_DATA_CATEGORY_COUNT)
        return -1;

    /* Classification */
    if (obj->classification < 0 || obj->classification > OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE)
        return -1;

    /* State */
    if (obj->state < 0 || obj->state > OZAYN_DATA_STATE_MARKED_FOR_DELETION)
        return -1;
    if (obj->state == OZAYN_DATA_STATE_UNINITIALIZED)
        return -1;
    if (obj->state == OZAYN_DATA_STATE_INVALID)
        return -1;

    /* Integrity */
    if (obj->integrity < 0 || obj->integrity > OZAYN_DATA_INTEGRITY_CORRUPTED)
        return -1;

    /* Storage state */
    if (obj->storage_state < 0 || obj->storage_state > OZAYN_DATA_STORAGE_DELETED)
        return -1;

    /* Ownership */
    if (obj->owner[0] == '\0')
        return -1;
    if (obj->scope <= OZAYN_DATA_SCOPE_UNKNOWN || obj->scope > OZAYN_DATA_SCOPE_GLOBAL)
        return -1;

    /* Timestamps: modification must not precede creation (if both set) */
    if (obj->created_at > 0 && obj->modified_at > 0) {
        if (obj->modified_at < obj->created_at)
            return -1;
    }

    /* Classification consistency */
    if (ozayn_sdo_validate_classification(obj) != 0)
        return -1;

    return 0;
}

/* ---- Security metadata lock check ---- */
/*
 * Indicates whether security-critical metadata should be treated as
 * immutable once the object is in a validated state.
 *
 * Returns 1 if metadata should be locked (immutable), 0 otherwise.
 */
int ozayn_sdo_is_security_metadata_locked(const ozayn_secure_data_object_t *obj)
{
    if (!obj)
        return 0;
    /* Lock security metadata when object is valid or has been persisted */
    return (obj->state == OZAYN_DATA_STATE_VALID ||
            obj->storage_state == OZAYN_DATA_STORAGE_ACTIVE ||
            obj->storage_state == OZAYN_DATA_STORAGE_ARCHIVED);
}
