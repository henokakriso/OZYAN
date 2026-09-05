#ifndef OZAYN_DATA_CLASSIFICATION_H
#define OZAYN_DATA_CLASSIFICATION_H

#include <stdint.h>
#include <time.h>

/*
 * data_classification.h — Secure Data Layer Classification (Section 03, Step 02).
 *
 * Defines data categories, security classification levels, metadata model,
 * and error codes for the Secure Data Layer.
 *
 * Every piece of persistent data in OZAYN is assigned a category and a
 * security classification. This information determines how the data must
 * be stored, accessed, and protected.
 */

/* ---- Data Categories ---- */
typedef enum {
    OZAYN_DATA_CATEGORY_USER_PREFERENCES     = 0,
    OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION = 1,
    OZAYN_DATA_CATEGORY_AUTH_INFO            = 2,
    OZAYN_DATA_CATEGORY_CONVERSATION_HISTORY = 3,
    OZAYN_DATA_CATEGORY_AI_MEMORY            = 4,
    OZAYN_DATA_CATEGORY_DOCUMENTS            = 5,
    OZAYN_DATA_CATEGORY_SYSTEM_CONFIGURATION = 6,
    OZAYN_DATA_CATEGORY_SECURITY_EVENTS      = 7,
    OZAYN_DATA_CATEGORY_ARWE_INFORMATION     = 8,
    OZAYN_DATA_CATEGORY_COUNT
} ozayn_data_category_t;

/* ---- Security Classification Levels ---- */
typedef enum {
    OZAYN_SEC_LEVEL_PUBLIC         = 0,  /* No protection required */
    OZAYN_SEC_LEVEL_INTERNAL       = 1,  /* Internal use, no external exposure */
    OZAYN_SEC_LEVEL_SENSITIVE      = 2,  /* Requires access control and protection */
    OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE = 3 /* Maximum protection, strict access control */
} ozayn_security_level_t;

/* ---- Data Integrity State ---- */
typedef enum {
    OZAYN_DATA_INTEGRITY_UNKNOWN   = 0,
    OZAYN_DATA_INTEGRITY_VALID     = 1,
    OZAYN_DATA_INTEGRITY_INVALID   = 2,
    OZAYN_DATA_INTEGRITY_CORRUPTED = 3
} ozayn_data_integrity_t;

/* ---- Data Storage State ---- */
typedef enum {
    OZAYN_DATA_STORAGE_UNKNOWN    = 0,
    OZAYN_DATA_STORAGE_INACTIVE   = 1,  /* Not yet persisted */
    OZAYN_DATA_STORAGE_ACTIVE     = 2,  /* Currently stored */
    OZAYN_DATA_STORAGE_ARCHIVED  = 3,  /* Moved to archive */
    OZAYN_DATA_STORAGE_DELETED    = 4   /* Marked for deletion */
} ozayn_data_storage_state_t;

/* ---- Secure Data Error Codes ---- */
typedef enum {
    OZAYN_SD_OK                  =  0,  /* Operation succeeded */
    OZAYN_SD_ERR_NOT_FOUND       = -1,  /* Data object not found */
    OZAYN_SD_ERR_ACCESS_DENIED   = -2,  /* Caller lacks required permission */
    OZAYN_SD_ERR_INVALID_DATA    = -3,  /* Data content is invalid or corrupted */
    OZAYN_SD_ERR_STORAGE_FAILURE = -4,  /* Underlying storage operation failed */
    OZAYN_SD_ERR_INTEGRITY       = -5,  /* Data integrity check failed */
    OZAYN_SD_ERR_SECURITY        = -6,  /* Security policy violation */
    OZAYN_SD_ERR_INVALID_REQUEST = -7,  /* Malformed or invalid request */
    OZAYN_SD_ERR_NULL            = -8,  /* Null pointer argument */
    OZAYN_SD_ERR_STATE           = -9,  /* Invalid state for operation */
    OZAYN_SD_ERR_NOT_INITIALIZED = -10  /* Secure data layer not initialized */
} ozayn_secure_data_result_t;

/* ---- Data Metadata ---- */
#define OZAYN_SD_MAX_ID_LEN     64
#define OZAYN_SD_MAX_OWNER_LEN  64

typedef struct {
    char                        id[OZAYN_SD_MAX_ID_LEN];     /* Unique data identifier */
    ozayn_data_category_t       category;                     /* Data category */
    ozayn_security_level_t      classification;               /* Security classification */
    time_t                      created_at;                   /* Creation timestamp */
    time_t                      modified_at;                  /* Last modification timestamp */
    char                        owner[OZAYN_SD_MAX_OWNER_LEN]; /* Owner / scope identifier */
    ozayn_data_integrity_t      integrity;                    /* Integrity state */
    ozayn_data_storage_state_t  storage_state;                /* Storage state */
} ozayn_data_metadata_t;

/* ---- Default Classification Lookup ---- */
/* Returns the default security classification for a given data category. */
ozayn_security_level_t ozayn_data_default_classification(ozayn_data_category_t category);

/* ---- Name Helpers ---- */
const char *ozayn_data_category_name(ozayn_data_category_t category);
const char *ozayn_security_level_name(ozayn_security_level_t level);
const char *ozayn_data_integrity_name(ozayn_data_integrity_t state);
const char *ozayn_data_storage_state_name(ozayn_data_storage_state_t state);
const char *ozayn_secure_data_result_name(ozayn_secure_data_result_t result);

/* ---- Metadata Helpers ---- */
int ozayn_data_metadata_init(ozayn_data_metadata_t *meta,
                             const char *id,
                             ozayn_data_category_t category,
                             const char *owner);
int ozayn_data_metadata_validate(const ozayn_data_metadata_t *meta);
int ozayn_data_metadata_is_sensitive(const ozayn_data_metadata_t *meta);

#endif
