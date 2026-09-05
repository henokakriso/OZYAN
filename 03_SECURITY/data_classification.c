#include "data_classification.h"
#include <string.h>

/*
 * data_classification.c — Data Classification Implementation (Section 03, Step 02).
 *
 * Provides lookup tables, name helpers, and metadata validation for the
 * Secure Data Layer classification system.
 */

/* ---- Default classification per category ---- */
static const ozayn_security_level_t _default_classifications[OZAYN_DATA_CATEGORY_COUNT] = {
    [OZAYN_DATA_CATEGORY_USER_PREFERENCES]     = OZAYN_SEC_LEVEL_SENSITIVE,
    [OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION] = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE,
    [OZAYN_DATA_CATEGORY_AUTH_INFO]            = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE,
    [OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY] = OZAYN_SEC_LEVEL_SENSITIVE,
    [OZAYN_DATA_CATEGORY_AI_MEMORY]            = OZAYN_SEC_LEVEL_SENSITIVE,
    [OZAYN_DATA_CATEGORY_DOCUMENTS]            = OZAYN_SEC_LEVEL_SENSITIVE,
    [OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION] = OZAYN_SEC_LEVEL_INTERNAL,
    [OZAYN_DATA_CATEGORY_SECURITY_EVENTS]      = OZAYN_SEC_LEVEL_SENSITIVE,
    [OZAYN_DATA_CATEGORY_ARWE_INFORMATION]     = OZAYN_SEC_LEVEL_SENSITIVE,
};

ozayn_security_level_t ozayn_data_default_classification(ozayn_data_category_t category)
{
    if (category < 0 || category >= OZAYN_DATA_CATEGORY_COUNT)
        return OZAYN_SEC_LEVEL_PUBLIC;
    return _default_classifications[category];
}

/* ---- Category name lookup ---- */
static const char *_category_names[OZAYN_DATA_CATEGORY_COUNT] = {
    [OZAYN_DATA_CATEGORY_USER_PREFERENCES]     = "User Preferences",
    [OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION] = "Identity Information",
    [OZAYN_DATA_CATEGORY_AUTH_INFO]            = "Authentication Information",
    [OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY] = "Conversation History",
    [OZAYN_DATA_CATEGORY_AI_MEMORY]            = "AI Memory",
    [OZAYN_DATA_CATEGORY_DOCUMENTS]            = "Documents",
    [OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION] = "System Configuration",
    [OZAYN_DATA_CATEGORY_SECURITY_EVENTS]      = "Security Events",
    [OZAYN_DATA_CATEGORY_ARWE_INFORMATION]     = "ARWE Information",
};

const char *ozayn_data_category_name(ozayn_data_category_t category)
{
    if (category < 0 || category >= OZAYN_DATA_CATEGORY_COUNT)
        return "Unknown Category";
    return _category_names[category];
}

/* ---- Security level name lookup ---- */
static const char *_level_names[] = {
    [OZAYN_SEC_LEVEL_PUBLIC]         = "Public",
    [OZAYN_SEC_LEVEL_INTERNAL]       = "Internal",
    [OZAYN_SEC_LEVEL_SENSITIVE]      = "Sensitive",
    [OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE] = "Highly Sensitive",
};

const char *ozayn_security_level_name(ozayn_security_level_t level)
{
    if (level < 0 || level > OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE)
        return "Unknown Level";
    return _level_names[level];
}

/* ---- Integrity state name lookup ---- */
static const char *_integrity_names[] = {
    [OZAYN_DATA_INTEGRITY_UNKNOWN]   = "Unknown",
    [OZAYN_DATA_INTEGRITY_VALID]     = "Valid",
    [OZAYN_DATA_INTEGRITY_INVALID]   = "Invalid",
    [OZAYN_DATA_INTEGRITY_CORRUPTED] = "Corrupted",
};

const char *ozayn_data_integrity_name(ozayn_data_integrity_t state)
{
    if (state < 0 || state > OZAYN_DATA_INTEGRITY_CORRUPTED)
        return "Unknown Integrity";
    return _integrity_names[state];
}

/* ---- Storage state name lookup ---- */
static const char *_storage_state_names[] = {
    [OZAYN_DATA_STORAGE_UNKNOWN]   = "Unknown",
    [OZAYN_DATA_STORAGE_INACTIVE]  = "Inactive",
    [OZAYN_DATA_STORAGE_ACTIVE]    = "Active",
    [OZAYN_DATA_STORAGE_ARCHIVED]  = "Archived",
    [OZAYN_DATA_STORAGE_DELETED]   = "Deleted",
};

const char *ozayn_data_storage_state_name(ozayn_data_storage_state_t state)
{
    if (state < 0 || state > OZAYN_DATA_STORAGE_DELETED)
        return "Unknown State";
    return _storage_state_names[state];
}

/* ---- Result code name lookup ---- */
const char *ozayn_secure_data_result_name(ozayn_secure_data_result_t result)
{
    switch (result) {
        case OZAYN_SD_OK:                  return "OK";
        case OZAYN_SD_ERR_NOT_FOUND:       return "Not Found";
        case OZAYN_SD_ERR_ACCESS_DENIED:   return "Access Denied";
        case OZAYN_SD_ERR_INVALID_DATA:    return "Invalid Data";
        case OZAYN_SD_ERR_STORAGE_FAILURE: return "Storage Failure";
        case OZAYN_SD_ERR_INTEGRITY:       return "Integrity Failure";
        case OZAYN_SD_ERR_SECURITY:        return "Security Failure";
        case OZAYN_SD_ERR_INVALID_REQUEST: return "Invalid Request";
        case OZAYN_SD_ERR_NULL:            return "Null Pointer";
        case OZAYN_SD_ERR_STATE:           return "Invalid State";
        case OZAYN_SD_ERR_NOT_INITIALIZED: return "Not Initialized";
        default:                           return "Unknown Result";
    }
}

/* ---- Metadata initialization ---- */
int ozayn_data_metadata_init(ozayn_data_metadata_t *meta,
                             const char *id,
                             ozayn_data_category_t category,
                             const char *owner)
{
    if (!meta || !id || !owner)
        return -1;
    if (id[0] == '\0')
        return -1;
    if (category < 0 || category >= OZAYN_DATA_CATEGORY_COUNT)
        return -1;

    memset(meta, 0, sizeof(*meta));
    strncpy(meta->id, id, OZAYN_SD_MAX_ID_LEN - 1);
    meta->id[OZAYN_SD_MAX_ID_LEN - 1] = '\0';
    meta->category     = category;
    meta->classification = ozayn_data_default_classification(category);
    meta->created_at   = 0;  /* Caller may set via time(NULL) */
    meta->modified_at  = 0;
    strncpy(meta->owner, owner, OZAYN_SD_MAX_OWNER_LEN - 1);
    meta->owner[OZAYN_SD_MAX_OWNER_LEN - 1] = '\0';
    meta->integrity     = OZAYN_DATA_INTEGRITY_UNKNOWN;
    meta->storage_state = OZAYN_DATA_STORAGE_INACTIVE;
    return 0;
}

/* ---- Metadata validation ---- */
int ozayn_data_metadata_validate(const ozayn_data_metadata_t *meta)
{
    if (!meta)
        return -1;
    if (meta->id[0] == '\0')
        return -1;
    if (meta->category < 0 || meta->category >= OZAYN_DATA_CATEGORY_COUNT)
        return -1;
    if (meta->classification < 0 || meta->classification > OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE)
        return -1;
    if (meta->integrity < 0 || meta->integrity > OZAYN_DATA_INTEGRITY_CORRUPTED)
        return -1;
    if (meta->storage_state < 0 || meta->storage_state > OZAYN_DATA_STORAGE_DELETED)
        return -1;
    return 0;
}

/* ---- Sensitivity check ---- */
int ozayn_data_metadata_is_sensitive(const ozayn_data_metadata_t *meta)
{
    if (!meta)
        return 0;
    return meta->classification >= OZAYN_SEC_LEVEL_SENSITIVE;
}
