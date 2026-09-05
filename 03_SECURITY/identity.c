#include "identity.h"
#include <string.h>
#include <stdio.h>

/*
 * identity.c — Identity Foundation & Identity Data Boundary (Section 03, Step 12).
 *
 * Implements the identity model for OZAYN users, devices, system components,
 * and services. Integrates with the Secure Vault for persistence.
 */

/* ---- Name Helpers ---- */

static const char *_id_type_names[] = {
    "UNKNOWN", "USER", "DEVICE", "SYSTEM", "MODULE", "SERVICE"
};

static const char *_id_state_names[] = {
    "UNINITIALIZED", "ACTIVE", "SUSPENDED", "REVOKED", "ARCHIVED"
};

static const char *_id_scope_names[] = {
    "UNKNOWN", "SYSTEM", "USER", "DEVICE", "MODULE", "SERVICE", "GLOBAL"
};

static const char *_id_result_names[] = {
    "OK", "NULL", "NOT_INITIALIZED", "NOT_FOUND", "ALREADY_EXISTS",
    "INVALID", "ID_INVALID", "TYPE_INVALID", "STATE_INVALID",
    "SCOPE_INVALID", "OWNER_INVALID", "STATE_TRANSITION",
    "SUSPENDED", "REVOKED", "ARCHIVED", "STORAGE_FAILED",
    "VAULT_UNAVAILABLE", "LOAD_FAILED", "SAVE_FAILED",
    "CORRUPTED", "METADATA_INVALID"
};

const char *ozayn_id_type_name(ozayn_id_type_t type)
{
    int idx = (int)type;
    if (idx < 0 || idx > 5)
        return "UNKNOWN";
    return _id_type_names[idx];
}

const char *ozayn_id_state_name(ozayn_id_state_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 4)
        return "UNKNOWN";
    return _id_state_names[idx];
}

const char *ozayn_id_scope_name(ozayn_id_scope_t scope)
{
    int idx = (int)scope;
    if (idx < 0 || idx > 6)
        return "UNKNOWN";
    return _id_scope_names[idx];
}

const char *ozayn_id_result_name(ozayn_identity_result_t result)
{
    int idx = -result;
    if (idx < 0 || idx > 20)
        return "UNKNOWN";
    return _id_result_names[idx];
}

/* ---- Validation Helpers ---- */

int ozayn_id_validate_type(ozayn_id_type_t type)
{
    return (type >= OZAYN_ID_TYPE_USER &&
            type <= OZAYN_ID_TYPE_SERVICE) ? 0 : -1;
}

int ozayn_id_validate_state(ozayn_id_state_t state)
{
    return (state >= OZAYN_ID_STATE_ACTIVE &&
            state <= OZAYN_ID_STATE_ARCHIVED) ? 0 : -1;
}

int ozayn_id_validate_scope(ozayn_id_scope_t scope)
{
    return (scope >= OZAYN_ID_SCOPE_SYSTEM &&
            scope <= OZAYN_ID_SCOPE_GLOBAL) ? 0 : -1;
}

int ozayn_id_validate_state_transition(ozayn_id_state_t from,
                                        ozayn_id_state_t to)
{
    /* Valid transitions:
     *   UNINITIALIZED -> ACTIVE
     *   ACTIVE -> SUSPENDED
     *   ACTIVE -> REVOKED
     *   SUSPENDED -> ACTIVE
     *   SUSPENDED -> REVOKED
     *   REVOKED -> ARCHIVED
     */
    if (from == OZAYN_ID_STATE_UNINITIALIZED &&
        to == OZAYN_ID_STATE_ACTIVE)
        return 0;
    if (from == OZAYN_ID_STATE_ACTIVE &&
        to == OZAYN_ID_STATE_SUSPENDED)
        return 0;
    if (from == OZAYN_ID_STATE_ACTIVE &&
        to == OZAYN_ID_STATE_REVOKED)
        return 0;
    if (from == OZAYN_ID_STATE_SUSPENDED &&
        to == OZAYN_ID_STATE_ACTIVE)
        return 0;
    if (from == OZAYN_ID_STATE_SUSPENDED &&
        to == OZAYN_ID_STATE_REVOKED)
        return 0;
    if (from == OZAYN_ID_STATE_REVOKED &&
        to == OZAYN_ID_STATE_ARCHIVED)
        return 0;
    return -1;
}

int ozayn_id_validate(const ozayn_identity_t *id)
{
    if (!id)
        return -1;

    /* ID must not be empty */
    if (id->id[0] == '\0')
        return -1;

    /* No path traversal */
    if (strstr(id->id, "..") != NULL)
        return -1;
    if (id->id[0] == '/')
        return -1;

    /* Type must be valid */
    if (ozayn_id_validate_type(id->type) != 0)
        return -1;

    /* State must be valid */
    if (ozayn_id_validate_state(id->state) != 0)
        return -1;

    /* Scope must be valid */
    if (ozayn_id_validate_scope(id->scope) != 0)
        return -1;

    /* Owner must not be empty */
    if (id->owner[0] == '\0')
        return -1;

    /* Timestamps must be valid */
    if (id->created_at <= 0)
        return -1;
    if (id->modified_at < id->created_at)
        return -1;

    return 0;
}

/* ---- Find identity by ID ---- */

static ozayn_identity_t *_find_identity(ozayn_identity_service_t *svc, const char *id)
{
    if (!svc || !id)
        return NULL;
    for (int i = 0; i < OZAYN_ID_MAX_IDENTITIES; i++) {
        if (svc->identities[i].id[0] != '\0' &&
            strcmp(svc->identities[i].id, id) == 0)
            return &svc->identities[i];
    }
    return NULL;
}

/* ---- Find free identity slot ---- */

static ozayn_identity_t *_find_free_identity(ozayn_identity_service_t *svc)
{
    for (int i = 0; i < OZAYN_ID_MAX_IDENTITIES; i++) {
        if (svc->identities[i].id[0] == '\0')
            return &svc->identities[i];
    }
    return NULL;
}

/* ---- Map identity scope to data scope ---- */
static ozayn_data_scope_t _map_id_scope_to_data_scope(ozayn_id_scope_t scope)
{
    switch (scope) {
        case OZAYN_ID_SCOPE_UNKNOWN:  return OZAYN_DATA_SCOPE_UNKNOWN;
        case OZAYN_ID_SCOPE_SYSTEM:   return OZAYN_DATA_SCOPE_SYSTEM;
        case OZAYN_ID_SCOPE_USER:     return OZAYN_DATA_SCOPE_USER;
        case OZAYN_ID_SCOPE_DEVICE:   return OZAYN_DATA_SCOPE_USER;
        case OZAYN_ID_SCOPE_MODULE:   return OZAYN_DATA_SCOPE_MODULE;
        case OZAYN_ID_SCOPE_SERVICE:  return OZAYN_DATA_SCOPE_SYSTEM;
        case OZAYN_ID_SCOPE_GLOBAL:   return OZAYN_DATA_SCOPE_GLOBAL;
        default:                      return OZAYN_DATA_SCOPE_UNKNOWN;
    }
}

/* ---- Generate unique ID ---- */

static void _generate_id(char *buf, size_t bufsz, ozayn_id_type_t type)
{
    static int counter = 0;
    counter++;
    snprintf(buf, bufsz, "id-%s-%d-%ld",
             ozayn_id_type_name(type),
             counter, (long)time(NULL));
}

/* ============================================================
 * IDENTITY SERVICE LIFECYCLE
 * ============================================================ */

ozayn_identity_result_t ozayn_id_service_init(ozayn_identity_service_t *svc,
                                               const ozayn_identity_service_config_t *config)
{
    if (!svc || !config)
        return OZAYN_ID_ERR_NULL;
    if (!config->vault)
        return OZAYN_ID_ERR_VAULT_UNAVAILABLE;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;
    svc->initialized = 1;
    return OZAYN_ID_OK;
}

void ozayn_id_service_shutdown(ozayn_identity_service_t *svc)
{
    if (!svc)
        return;
    memset(svc->identities, 0, sizeof(svc->identities));
    svc->identity_count = 0;
    svc->initialized = 0;
}

/* ============================================================
 * IDENTITY CREATE
 * ============================================================ */

ozayn_identity_result_t ozayn_id_create(ozayn_identity_service_t *svc,
                                         ozayn_id_type_t type,
                                         const char *label,
                                         ozayn_id_scope_t scope,
                                         const char *owner,
                                         ozayn_identity_t *out_id)
{
    if (!svc || !label || !owner || !out_id)
        return OZAYN_ID_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_ID_ERR_NOT_INITIALIZED;

    /* Validate inputs */
    if (ozayn_id_validate_type(type) != 0)
        return OZAYN_ID_ERR_TYPE_INVALID;
    if (ozayn_id_validate_scope(scope) != 0)
        return OZAYN_ID_ERR_SCOPE_INVALID;
    if (owner[0] == '\0')
        return OZAYN_ID_ERR_OWNER_INVALID;
    if (label[0] == '\0')
        return OZAYN_ID_ERR_INVALID;

    /* Find free slot */
    ozayn_identity_t *ident = _find_free_identity(svc);
    if (!ident)
        return OZAYN_ID_ERR_ALREADY_EXISTS;

    /* Generate unique ID */
    char new_id[OZAYN_ID_MAX_ID_LEN];
    _generate_id(new_id, sizeof(new_id), type);

    /* Check for duplicate (extremely unlikely but safe) */
    if (_find_identity(svc, new_id))
        return OZAYN_ID_ERR_ALREADY_EXISTS;

    /* Initialize identity */
    memset(ident, 0, sizeof(*ident));
    strncpy(ident->id, new_id, sizeof(ident->id) - 1);
    ident->version = 1;
    ident->type = type;
    ident->state = OZAYN_ID_STATE_ACTIVE;
    strncpy(ident->label, label, sizeof(ident->label) - 1);
    ident->scope = scope;
    strncpy(ident->owner, owner, sizeof(ident->owner) - 1);
    ident->created_at = time(NULL);
    ident->modified_at = ident->created_at;
    ident->credential_count = 0;

    svc->identity_count++;

    /* Store through Secure Vault */
    ozayn_secure_data_object_t sdo;
    ozayn_sdo_init(&sdo, ident->id, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION,
                   owner, _map_id_scope_to_data_scope(scope));
    sdo.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    ozayn_vault_result_t vr = ozayn_vault_store(svc->config.vault, &sdo,
                                                 (const uint8_t *)ident,
                                                 sizeof(*ident));
    if (vr != OZAYN_VAULT_OK) {
        /* Rollback */
        memset(ident, 0, sizeof(*ident));
        svc->identity_count--;
        return OZAYN_ID_ERR_STORAGE_FAILED;
    }

    *out_id = *ident;
    return OZAYN_ID_OK;
}

/* ============================================================
 * IDENTITY GET
 * ============================================================ */

ozayn_identity_result_t ozayn_id_get(ozayn_identity_service_t *svc,
                                      const char *id,
                                      ozayn_identity_t *out_id)
{
    if (!svc || !id || !out_id)
        return OZAYN_ID_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_ID_ERR_NOT_INITIALIZED;

    ozayn_identity_t *ident = _find_identity(svc, id);
    if (!ident)
        return OZAYN_ID_ERR_NOT_FOUND;

    /* Validate the identity before returning */
    if (ozayn_id_validate(ident) != 0)
        return OZAYN_ID_ERR_CORRUPTED;

    *out_id = *ident;
    return OZAYN_ID_OK;
}

/* ============================================================
 * IDENTITY UPDATE
 * ============================================================ */

ozayn_identity_result_t ozayn_id_update(ozayn_identity_service_t *svc,
                                         const char *id,
                                         const char *new_label,
                                         ozayn_id_scope_t new_scope)
{
    if (!svc || !id)
        return OZAYN_ID_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_ID_ERR_NOT_INITIALIZED;

    ozayn_identity_t *ident = _find_identity(svc, id);
    if (!ident)
        return OZAYN_ID_ERR_NOT_FOUND;

    /* Must be active or suspended */
    if (ident->state != OZAYN_ID_STATE_ACTIVE &&
        ident->state != OZAYN_ID_STATE_SUSPENDED)
        return OZAYN_ID_ERR_STATE_INVALID;

    /* Validate new scope */
    if (ozayn_id_validate_scope(new_scope) != 0)
        return OZAYN_ID_ERR_SCOPE_INVALID;

    /* Update label if provided */
    if (new_label && new_label[0] != '\0')
        strncpy(ident->label, new_label, sizeof(ident->label) - 1);

    /* Update scope */
    ident->scope = new_scope;
    ident->modified_at = time(NULL);

    /* Update version */
    ident->version++;

    /* Save through vault */
    ozayn_secure_data_object_t sdo;
    ozayn_sdo_init(&sdo, ident->id, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION,
                   ident->owner, _map_id_scope_to_data_scope(ident->scope));
    sdo.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    ozayn_vault_result_t vr = ozayn_vault_update(svc->config.vault, &sdo,
                                                  (const uint8_t *)ident,
                                                  sizeof(*ident));
    if (vr != OZAYN_VAULT_OK)
        return OZAYN_ID_ERR_SAVE_FAILED;

    return OZAYN_ID_OK;
}

/* ============================================================
 * IDENTITY STATE TRANSITIONS
 * ============================================================ */

static ozayn_identity_result_t _transition_state(ozayn_identity_service_t *svc,
                                                   const char *id,
                                                   ozayn_id_state_t target)
{
    if (!svc || !id)
        return OZAYN_ID_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_ID_ERR_NOT_INITIALIZED;

    ozayn_identity_t *ident = _find_identity(svc, id);
    if (!ident)
        return OZAYN_ID_ERR_NOT_FOUND;

    /* Validate transition */
    if (ozayn_id_validate_state_transition(ident->state, target) != 0)
        return OZAYN_ID_ERR_STATE_TRANSITION;

    ident->state = target;
    ident->modified_at = time(NULL);
    ident->version++;

    /* Save through vault */
    ozayn_secure_data_object_t sdo;
    ozayn_sdo_init(&sdo, ident->id, OZAYN_DATA_CATEGORY_IDENTITY_INFORMATION,
                   ident->owner, _map_id_scope_to_data_scope(ident->scope));
    sdo.classification = OZAYN_SEC_LEVEL_SENSITIVE;

    ozayn_vault_result_t vr = ozayn_vault_update(svc->config.vault, &sdo,
                                                  (const uint8_t *)ident,
                                                  sizeof(*ident));
    if (vr != OZAYN_VAULT_OK)
        return OZAYN_ID_ERR_SAVE_FAILED;

    return OZAYN_ID_OK;
}

ozayn_identity_result_t ozayn_id_suspend(ozayn_identity_service_t *svc,
                                          const char *id)
{
    return _transition_state(svc, id, OZAYN_ID_STATE_SUSPENDED);
}

ozayn_identity_result_t ozayn_id_revoke(ozayn_identity_service_t *svc,
                                         const char *id)
{
    return _transition_state(svc, id, OZAYN_ID_STATE_REVOKED);
}

ozayn_identity_result_t ozayn_id_archive(ozayn_identity_service_t *svc,
                                          const char *id)
{
    return _transition_state(svc, id, OZAYN_ID_STATE_ARCHIVED);
}

ozayn_identity_result_t ozayn_id_reactivate(ozayn_identity_service_t *svc,
                                             const char *id)
{
    return _transition_state(svc, id, OZAYN_ID_STATE_ACTIVE);
}

/* ============================================================
 * IDENTITY REMOVE
 * ============================================================ */

ozayn_identity_result_t ozayn_id_remove(ozayn_identity_service_t *svc,
                                         const char *id)
{
    if (!svc || !id)
        return OZAYN_ID_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_ID_ERR_NOT_INITIALIZED;

    ozayn_identity_t *ident = _find_identity(svc, id);
    if (!ident)
        return OZAYN_ID_ERR_NOT_FOUND;

    /* Remove from vault */
    ozayn_vault_result_t vr = ozayn_vault_remove(svc->config.vault, id);
    if (vr != OZAYN_VAULT_OK)
        return OZAYN_ID_ERR_STORAGE_FAILED;

    /* Clear local entry */
    memset(ident, 0, sizeof(*ident));
    svc->identity_count--;

    return OZAYN_ID_OK;
}

/* ============================================================
 * IDENTITY EXISTS
 * ============================================================ */

int ozayn_id_exists(ozayn_identity_service_t *svc, const char *id)
{
    if (!svc || !id)
        return 0;
    if (!svc->initialized)
        return 0;
    return _find_identity(svc, id) != NULL;
}

/* ============================================================
 * IDENTITY LIST
 * ============================================================ */

int ozayn_id_list(ozayn_identity_service_t *svc,
                   ozayn_id_type_t type,
                   ozayn_identity_t *out_items,
                   int max_count)
{
    if (!svc || !out_items || max_count <= 0)
        return 0;
    if (!svc->initialized)
        return 0;

    int count = 0;
    for (int i = 0; i < OZAYN_ID_MAX_IDENTITIES && count < max_count; i++) {
        if (svc->identities[i].id[0] != '\0' &&
            svc->identities[i].type == type)
        {
            out_items[count] = svc->identities[i];
            count++;
        }
    }
    return count;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_id_service_count(const ozayn_identity_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->identity_count;
}

int ozayn_id_service_is_initialized(const ozayn_identity_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}
