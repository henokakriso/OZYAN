#ifndef OZAYN_SECURE_DATA_OBJECT_H
#define OZAYN_SECURE_DATA_OBJECT_H

#include "data_classification.h"

/*
 * secure_data_object.h — Secure Data Object (Section 03, Step 03).
 *
 * Defines the formal internal data model for persistent OZAYN data objects.
 * Every piece of persistent data is represented as a Secure Data Object with
 * complete metadata, lifecycle state, ownership, and validation.
 *
 * Architecture:
 *
 *   OZAYN COMPONENT
 *          |
 *          v
 *   SECURE DATA OBJECT  <-- this layer
 *          |
 *          v
 *   VALIDATION
 *          |
 *          v
 *   SECURE DATA INTERFACE
 *          |
 *          v
 *   STORAGE ABSTRACTION
 */

/* ---- Data Lifecycle State ---- */
typedef enum {
    OZAYN_DATA_STATE_UNINITIALIZED      = 0,
    OZAYN_DATA_STATE_VALID              = 1,
    OZAYN_DATA_STATE_INVALID            = 2,
    OZAYN_DATA_STATE_MARKED_FOR_DELETION = 3
} ozayn_data_state_t;

/* ---- Data Ownership / Scope ---- */
typedef enum {
    OZAYN_DATA_SCOPE_UNKNOWN  = 0,
    OZAYN_DATA_SCOPE_SYSTEM   = 1,  /* Owned by OZAYN core system */
    OZAYN_DATA_SCOPE_USER     = 2,  /* Owned by the current user */
    OZAYN_DATA_SCOPE_SESSION  = 3,  /* Scoped to an active session */
    OZAYN_DATA_SCOPE_MODULE   = 4,  /* Scoped to a specific module */
    OZAYN_DATA_SCOPE_GLOBAL   = 5   /* Shared across all scopes */
} ozayn_data_scope_t;

/* ---- Secure Data Object ---- */
#define OZAYN_SDO_MAX_ID_LEN     64
#define OZAYN_SDO_MAX_OWNER_LEN  64
#define OZAYN_SDO_MAX_VERSION_LEN 32

typedef struct {
    /* Identity */
    char                        id[OZAYN_SDO_MAX_ID_LEN];
    char                        version[OZAYN_SDO_MAX_VERSION_LEN];

    /* Classification */
    ozayn_data_category_t       category;
    ozayn_security_level_t      classification;

    /* State */
    ozayn_data_state_t          state;
    ozayn_data_integrity_t      integrity;
    ozayn_data_storage_state_t  storage_state;

    /* Ownership */
    char                        owner[OZAYN_SDO_MAX_OWNER_LEN];
    ozayn_data_scope_t          scope;

    /* Timestamps */
    time_t                      created_at;
    time_t                      modified_at;

    /* Content metadata */
    uint64_t                    content_size;  /* Size in bytes, 0 if unknown */
    uint32_t                    checksum;      /* Simple checksum, 0 if not computed */
} ozayn_secure_data_object_t;

/* ---- Name Helpers ---- */
const char *ozayn_data_state_name(ozayn_data_state_t state);
const char *ozayn_data_scope_name(ozayn_data_scope_t scope);

/* ---- Object Lifecycle ---- */
int ozayn_sdo_init(ozayn_secure_data_object_t *obj,
                   const char *id,
                   ozayn_data_category_t category,
                   const char *owner,
                   ozayn_data_scope_t scope);

int ozayn_sdo_invalidate(ozayn_secure_data_object_t *obj);
int ozayn_sdo_mark_for_deletion(ozayn_secure_data_object_t *obj);

/* ---- Object Validation ---- */
int ozayn_sdo_validate(const ozayn_secure_data_object_t *obj);

/* ---- Classification Consistency ---- */
int ozayn_sdo_validate_classification(const ozayn_secure_data_object_t *obj);

/* ---- Security Metadata Protection ---- */
int ozayn_sdo_is_security_metadata_locked(const ozayn_secure_data_object_t *obj);

#endif
