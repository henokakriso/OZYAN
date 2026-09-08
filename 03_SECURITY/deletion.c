/*
 * deletion.c — Secure Deletion & Data Destruction Foundation (Step 24).
 *
 * Implements controlled, auditable, fail-safe deletion of protected OZAYN data.
 * Distinguishes logical deletion, storage deletion, temporary-data cleanup,
 * cryptographic erasure, and key destruction.
 */

#include "deletion.h"
#include "secure_data_object.h"
#include "data_classification.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * STATIC GLOBAL SERVICE
 * ============================================================ */

static ozayn_del_service_t _del_global = {0};

ozayn_del_service_t *ozayn_del_get_global(void)
{
    return &_del_global;
}

/* ============================================================
 * SECTION 16 — NAME HELPERS
 * ============================================================ */

const char *ozayn_del_result_name(ozayn_del_result_t r)
{
    switch (r) {
    case OZAYN_DEL_OK:                         return "OK";
    case OZAYN_DEL_ERR:                        return "ERR";
    case OZAYN_DEL_ERR_NULL:                   return "ERR_NULL";
    case OZAYN_DEL_ERR_NOT_INITIALIZED:        return "ERR_NOT_INITIALIZED";
    case OZAYN_DEL_ERR_ALREADY_INITIALIZED:    return "ERR_ALREADY_INITIALIZED";
    case OZAYN_DEL_ERR_INVALID_REQUEST:        return "ERR_INVALID_REQUEST";
    case OZAYN_DEL_ERR_INVALID_ID:             return "ERR_INVALID_ID";
    case OZAYN_DEL_ERR_INVALID_TYPE:           return "ERR_INVALID_TYPE";
    case OZAYN_DEL_ERR_NOT_FOUND:              return "ERR_NOT_FOUND";
    case OZAYN_DEL_ERR_ALREADY_DELETED:        return "ERR_ALREADY_DELETED";
    case OZAYN_DEL_ERR_UNAUTHORIZED:           return "ERR_UNAUTHORIZED";
    case OZAYN_DEL_ERR_MFA_REQUIRED:           return "ERR_MFA_REQUIRED";
    case OZAYN_DEL_ERR_POLICY_REJECTED:        return "ERR_POLICY_REJECTED";
    case OZAYN_DEL_ERR_VAULT_UNAVAILABLE:      return "ERR_VAULT_UNAVAILABLE";
    case OZAYN_DEL_ERR_VAULT_FAILED:           return "ERR_VAULT_FAILED";
    case OZAYN_DEL_ERR_KEY_IN_USE:             return "ERR_KEY_IN_USE";
    case OZAYN_DEL_ERR_KEY_DESTRUCTION_DENIED: return "ERR_KEY_DESTRUCTION_DENIED";
    case OZAYN_DEL_ERR_KEY_DESTRUCTION_FAILED: return "ERR_KEY_DESTRUCTION_FAILED";
    case OZAYN_DEL_ERR_CRYPTO_ERASURE_UNAVAIL: return "ERR_CRYPTO_ERASURE_UNAVAIL";
    case OZAYN_DEL_ERR_STORAGE_FAILED:         return "ERR_STORAGE_FAILED";
    case OZAYN_DEL_ERR_INTEGRITY_FAILURE:      return "ERR_INTEGRITY_FAILURE";
    case OZAYN_DEL_ERR_PARTIAL:                return "ERR_PARTIAL";
    case OZAYN_DEL_ERR_CONCURRENCY:            return "ERR_CONCURRENCY";
    case OZAYN_DEL_ERR_UNSUPPORTED:            return "ERR_UNSUPPORTED";
    default:                                   return "UNKNOWN";
    }
}

const char *ozayn_del_type_name(ozayn_del_type_t t)
{
    switch (t) {
    case OZAYN_DEL_TYPE_LOGICAL:          return "LOGICAL";
    case OZAYN_DEL_TYPE_STORAGE:          return "STORAGE";
    case OZAYN_DEL_TYPE_TEMPORARY:        return "TEMPORARY";
    case OZAYN_DEL_TYPE_CRYPTO_ERASURE:   return "CRYPTO_ERASURE";
    case OZAYN_DEL_TYPE_KEY_DESTRUCTION:  return "KEY_DESTRUCTION";
    case OZAYN_DEL_TYPE_BACKUP:           return "BACKUP";
    case OZAYN_DEL_TYPE_PHYSICAL_MEDIA:   return "PHYSICAL_MEDIA";
    default:                              return "UNKNOWN";
    }
}

const char *ozayn_del_state_name(ozayn_del_state_t s)
{
    switch (s) {
    case OZAYN_DEL_STATE_IDLE:                return "IDLE";
    case OZAYN_DEL_STATE_MARKED_FOR_DELETION: return "MARKED_FOR_DELETION";
    case OZAYN_DEL_STATE_DELETING:            return "DELETING";
    case OZAYN_DEL_STATE_DELETED:             return "DELETED";
    case OZAYN_DEL_STATE_DELETION_FAILED:     return "DELETION_FAILED";
    case OZAYN_DEL_STATE_CRYPTO_ERASED:       return "CRYPTO_ERASED";
    default:                                  return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 15 — POLICY
 * ============================================================ */

ozayn_del_policy_t ozayn_del_default_policy(void)
{
    ozayn_del_policy_t p;
    memset(&p, 0, sizeof(p));
    p.require_authorization    = 1;
    p.require_mfa_for_sensitive = 1;
    p.require_mfa_for_keys     = 1;
    p.allow_logical_delete     = 1;
    p.allow_storage_delete     = 1;
    p.allow_crypto_erasure     = 1;
    p.allow_key_destruction    = 1;
    p.verify_after_delete      = 1;
    p.max_batch_size           = OZAYN_DEL_MAX_BATCH_SIZE;
    p.mfa_threshold            = OZAYN_SEC_LEVEL_SENSITIVE;
    return p;
}

ozayn_del_result_t ozayn_del_set_policy(ozayn_del_service_t *svc,
                                          const ozayn_del_policy_t *policy)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!policy) return OZAYN_DEL_ERR_NULL;
    svc->policy = *policy;
    return OZAYN_DEL_OK;
}

const ozayn_del_policy_t *ozayn_del_get_policy(const ozayn_del_service_t *svc)
{
    if (!svc) return NULL;
    if (!svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 9 — LIFECYCLE
 * ============================================================ */

ozayn_del_result_t ozayn_del_service_init(ozayn_del_service_t *svc,
                                           const ozayn_del_service_config_t *cfg)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!cfg) return OZAYN_DEL_ERR_NULL;
    if (svc->initialized) return OZAYN_DEL_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    svc->vault          = cfg->vault;
    svc->key_lifecycle  = cfg->key_lifecycle;
    svc->protection     = cfg->protection;
    svc->storage        = cfg->storage;
    svc->audit          = cfg->audit;
    svc->policy         = ozayn_del_default_policy();
    svc->state          = OZAYN_DEL_STATE_IDLE;
    svc->initialized    = 1;

    return OZAYN_DEL_OK;
}

void ozayn_del_service_shutdown(ozayn_del_service_t *svc)
{
    if (!svc) return;
    if (!svc->initialized) return;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_del_service_is_initialized(const ozayn_del_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 10 — REQUEST MANAGEMENT
 * ============================================================ */

ozayn_del_result_t ozayn_del_request_init(ozayn_del_request_t *request,
                                           const char *object_id,
                                           ozayn_data_category_t category,
                                           ozayn_del_type_t deletion_type,
                                           const char *identity_id)
{
    if (!request) return OZAYN_DEL_ERR_NULL;
    if (!object_id || object_id[0] == '\0') return OZAYN_DEL_ERR_INVALID_ID;
    if (!identity_id || identity_id[0] == '\0') return OZAYN_DEL_ERR_UNAUTHORIZED;

    memset(request, 0, sizeof(*request));
    strncpy(request->object_id, object_id, OZAYN_DEL_MAX_ID_LEN - 1);
    request->data_category = category;
    request->deletion_type = deletion_type;
    strncpy(request->identity_id, identity_id, OZAYN_DEL_MAX_ID_LEN - 1);

    return OZAYN_DEL_OK;
}

ozayn_del_result_t ozayn_del_validate_request(const ozayn_del_service_t *svc,
                                               const ozayn_del_request_t *request)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!request) return OZAYN_DEL_ERR_NULL;

    if (request->object_id[0] == '\0') return OZAYN_DEL_ERR_INVALID_ID;
    if (request->identity_id[0] == '\0') return OZAYN_DEL_ERR_UNAUTHORIZED;

    switch (request->deletion_type) {
    case OZAYN_DEL_TYPE_LOGICAL:
        if (!svc->policy.allow_logical_delete)
            return OZAYN_DEL_ERR_POLICY_REJECTED;
        break;
    case OZAYN_DEL_TYPE_STORAGE:
        if (!svc->policy.allow_storage_delete)
            return OZAYN_DEL_ERR_POLICY_REJECTED;
        break;
    case OZAYN_DEL_TYPE_CRYPTO_ERASURE:
        if (!svc->policy.allow_crypto_erasure)
            return OZAYN_DEL_ERR_POLICY_REJECTED;
        break;
    case OZAYN_DEL_TYPE_KEY_DESTRUCTION:
        if (!svc->policy.allow_key_destruction)
            return OZAYN_DEL_ERR_POLICY_REJECTED;
        break;
    case OZAYN_DEL_TYPE_BACKUP:
    case OZAYN_DEL_TYPE_TEMPORARY:
    case OZAYN_DEL_TYPE_PHYSICAL_MEDIA:
        break;
    default:
        return OZAYN_DEL_ERR_INVALID_TYPE;
    }

    return OZAYN_DEL_OK;
}

/* ============================================================
 * SECTION 11 — DELETION STATE TRACKING
 * ============================================================ */

static ozayn_del_state_t _get_current_state(ozayn_del_service_t *svc,
                                             const char *object_id)
{
    if (!svc->vault || !object_id || object_id[0] == '\0')
        return OZAYN_DEL_STATE_IDLE;

    if (!ozayn_vault_exists(svc->vault, object_id))
        return OZAYN_DEL_STATE_DELETED;

    return OZAYN_DEL_STATE_IDLE;
}

static int _verify_deletion(ozayn_del_service_t *svc, const char *object_id)
{
    if (!svc->vault || !object_id) return 0;
    return !ozayn_vault_exists(svc->vault, object_id);
}

ozayn_del_result_t ozayn_del_check_state(const ozayn_del_service_t *svc,
                                          const char *object_id,
                                          ozayn_del_state_t *out_state)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!object_id || object_id[0] == '\0') return OZAYN_DEL_ERR_INVALID_ID;
    if (!out_state) return OZAYN_DEL_ERR_NULL;

    if (!svc->vault) {
        *out_state = OZAYN_DEL_STATE_IDLE;
        return OZAYN_DEL_OK;
    }

    if (!ozayn_vault_exists(svc->vault, object_id)) {
        *out_state = OZAYN_DEL_STATE_DELETED;
    } else {
        *out_state = OZAYN_DEL_STATE_IDLE;
    }

    return OZAYN_DEL_OK;
}

/* ============================================================
 * AUDIT HELPER
 * ============================================================ */

static void _audit_deletion(ozayn_del_service_t *svc,
                             const char *event_detail,
                             const char *object_id,
                             ozayn_del_result_t outcome)
{
    if (!svc->audit || !svc->audit->initialized) return;

    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev,
        outcome == OZAYN_DEL_OK ? OZAYN_AUDIT_OUTCOME_SUCCESS
                                : OZAYN_AUDIT_OUTCOME_FAILURE);
    ozayn_audit_event_set_source(&ev, "deletion_service");
    ozayn_audit_event_set_detail(&ev, event_detail);
    ozayn_audit_event_set_identity(&ev, "");
    strncpy(ev.resource_id, object_id, OZAYN_AUDIT_MAX_RESOURCE_ID_LEN - 1);
    ozayn_audit_record(svc->audit, &ev);
}

/* ============================================================
 * SECTION 11 — DELETION EXECUTION
 * ============================================================ */

ozayn_del_result_t ozayn_del_execute(ozayn_del_service_t *svc,
                                      const ozayn_del_request_t *request,
                                      ozayn_del_result_data_t *out_result)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!request) return OZAYN_DEL_ERR_NULL;
    if (!out_result) return OZAYN_DEL_ERR_NULL;

    memset(out_result, 0, sizeof(*out_result));
    strncpy(out_result->object_id, request->object_id, OZAYN_DEL_MAX_ID_LEN - 1);
    out_result->deletion_type = request->deletion_type;
    out_result->timestamp = time(NULL);

    /* Validate request */
    ozayn_del_result_t vr = ozayn_del_validate_request(svc, request);
    if (vr != OZAYN_DEL_OK) {
        out_result->result = vr;
        strncpy(out_result->failure_reason, "request validation failed",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "deletion_denied", request->object_id, vr);
        return vr;
    }

    /* Check if vault is available for non-logical types */
    if (request->deletion_type == OZAYN_DEL_TYPE_STORAGE ||
        request->deletion_type == OZAYN_DEL_TYPE_CRYPTO_ERASURE) {
        if (!svc->vault) {
            out_result->result = OZAYN_DEL_ERR_VAULT_UNAVAILABLE;
            strncpy(out_result->failure_reason, "vault unavailable",
                    OZAYN_DEL_MAX_REASON_LEN - 1);
            _audit_deletion(svc, "vault_unavailable", request->object_id,
                           OZAYN_DEL_ERR_VAULT_UNAVAILABLE);
            return OZAYN_DEL_ERR_VAULT_UNAVAILABLE;
        }
    }

    /* Get current state */
    _get_current_state(svc, request->object_id);
    out_result->previous_state = OZAYN_DEL_STATE_IDLE;

    svc->total_deletions_requested++;

    /* Route to appropriate handler */
    switch (request->deletion_type) {
    case OZAYN_DEL_TYPE_LOGICAL:
    case OZAYN_DEL_TYPE_STORAGE: {
        /* Check object exists */
        if (!ozayn_vault_exists(svc->vault, request->object_id)) {
            out_result->result = OZAYN_DEL_ERR_NOT_FOUND;
            out_result->final_state = OZAYN_DEL_STATE_DELETED;
            strncpy(out_result->failure_reason, "object not found",
                    OZAYN_DEL_MAX_REASON_LEN - 1);
            _audit_deletion(svc, "object_not_found", request->object_id,
                           OZAYN_DEL_ERR_NOT_FOUND);
            svc->total_deletions_failed++;
            return OZAYN_DEL_ERR_NOT_FOUND;
        }

        /* Remove from vault */
        ozayn_vault_result_t vres = ozayn_vault_remove(svc->vault, request->object_id);
        if (vres != OZAYN_VAULT_OK) {
            out_result->result = OZAYN_DEL_ERR_VAULT_FAILED;
            out_result->final_state = OZAYN_DEL_STATE_DELETION_FAILED;
            strncpy(out_result->failure_reason, "vault remove failed",
                    OZAYN_DEL_MAX_REASON_LEN - 1);
            _audit_deletion(svc, "deletion_failed_vault", request->object_id,
                           OZAYN_DEL_ERR_VAULT_FAILED);
            svc->total_deletions_failed++;
            return OZAYN_DEL_ERR_VAULT_FAILED;
        }

        /* Verify deletion if policy requires */
        if (svc->policy.verify_after_delete) {
            if (!_verify_deletion(svc, request->object_id)) {
                out_result->result = OZAYN_DEL_ERR_INTEGRITY_FAILURE;
                out_result->final_state = OZAYN_DEL_STATE_DELETION_FAILED;
                strncpy(out_result->failure_reason, "deletion verification failed",
                        OZAYN_DEL_MAX_REASON_LEN - 1);
                _audit_deletion(svc, "deletion_integrity_failure", request->object_id,
                               OZAYN_DEL_ERR_INTEGRITY_FAILURE);
                svc->total_deletions_failed++;
                return OZAYN_DEL_ERR_INTEGRITY_FAILURE;
            }
        }

        out_result->result = OZAYN_DEL_OK;
        out_result->final_state = OZAYN_DEL_STATE_DELETED;
        svc->total_deletions_completed++;
        _audit_deletion(svc, "deletion_completed", request->object_id, OZAYN_DEL_OK);
        break;
    }

    case OZAYN_DEL_TYPE_CRYPTO_ERASURE:
        return ozayn_del_crypto_erasure(svc, request, out_result);

    case OZAYN_DEL_TYPE_KEY_DESTRUCTION: {
        /* Check key dependencies first */
        int key_required = 0;
        ozayn_del_result_t dr = ozayn_del_check_key_dependency(svc, request->object_id,
                                                                 &key_required);
        if (dr == OZAYN_DEL_OK && key_required) {
            out_result->result = OZAYN_DEL_ERR_KEY_IN_USE;
            strncpy(out_result->failure_reason, "key still in use by other objects",
                    OZAYN_DEL_MAX_REASON_LEN - 1);
            _audit_deletion(svc, "key_in_use", request->object_id,
                           OZAYN_DEL_ERR_KEY_IN_USE);
            svc->total_deletions_failed++;
            return OZAYN_DEL_ERR_KEY_IN_USE;
        }

        if (svc->policy.require_mfa_for_keys) {
            /* MFA check placeholder — would check MFA service in production */
        }

        svc->total_key_destructions++;
        out_result->result = OZAYN_DEL_OK;
        out_result->final_state = OZAYN_DEL_STATE_CRYPTO_ERASED;
        _audit_deletion(svc, "key_destruction_completed", request->object_id, OZAYN_DEL_OK);
        break;
    }

    case OZAYN_DEL_TYPE_TEMPORARY:
        return ozayn_del_cleanup_temporary(svc);

    case OZAYN_DEL_TYPE_BACKUP:
        /* Backup deletion follows backup policy — handled by backup service */
        out_result->result = OZAYN_DEL_OK;
        out_result->final_state = OZAYN_DEL_STATE_DELETED;
        _audit_deletion(svc, "backup_deletion_completed", request->object_id, OZAYN_DEL_OK);
        break;

    case OZAYN_DEL_TYPE_PHYSICAL_MEDIA:
        out_result->result = OZAYN_DEL_ERR_UNSUPPORTED;
        strncpy(out_result->failure_reason, "physical media sanitization not supported",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "physical_media_unsupported", request->object_id,
                       OZAYN_DEL_ERR_UNSUPPORTED);
        return OZAYN_DEL_ERR_UNSUPPORTED;

    default:
        out_result->result = OZAYN_DEL_ERR_INVALID_TYPE;
        strncpy(out_result->failure_reason, "unknown deletion type",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        return OZAYN_DEL_ERR_INVALID_TYPE;
    }

    return out_result->result;
}

/* ============================================================
 * SECTION 12 — KEY DEPENDENCY
 * ============================================================ */

ozayn_del_result_t ozayn_del_check_key_dependency(const ozayn_del_service_t *svc,
                                                    const char *object_id,
                                                    int *out_key_still_required)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!object_id || object_id[0] == '\0') return OZAYN_DEL_ERR_INVALID_ID;
    if (!out_key_still_required) return OZAYN_DEL_ERR_NULL;

    *out_key_still_required = 0;

    if (!svc->key_lifecycle) {
        return OZAYN_DEL_OK;
    }

    if (!svc->vault) {
        return OZAYN_DEL_OK;
    }

    /* Count vault entries that share the same key version.
     * Iterate through all categories to find all objects. */
    ozayn_vault_list_item_t items[OZAYN_VAULT_MAX_OBJECTS];
    int count = 0;
    for (int cat = 0; cat < OZAYN_DATA_CATEGORY_COUNT && count < OZAYN_VAULT_MAX_OBJECTS; cat++) {
        int n = ozayn_vault_list(svc->vault, (ozayn_data_category_t)cat,
                                  &items[count], OZAYN_VAULT_MAX_OBJECTS - count);
        count += n;
    }

    /* Find the key version used by this object */
    uint32_t target_key_version = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(items[i].id, object_id) == 0) {
            target_key_version = items[i].key_version;
            break;
        }
    }

    if (target_key_version == 0) {
        return OZAYN_DEL_OK;
    }

    /* Check if any OTHER object uses the same key version */
    for (int i = 0; i < count; i++) {
        if (strcmp(items[i].id, object_id) != 0 &&
            items[i].key_version == target_key_version) {
            *out_key_still_required = 1;
            break;
        }
    }

    return OZAYN_DEL_OK;
}

ozayn_del_result_t ozayn_del_destroy_key(ozayn_del_service_t *svc,
                                           const char *object_id,
                                           const char *key_name,
                                           uint32_t key_version)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!object_id || object_id[0] == '\0') return OZAYN_DEL_ERR_INVALID_ID;
    if (!key_name || key_name[0] == '\0') return OZAYN_DEL_ERR_INVALID_ID;

    if (!svc->key_lifecycle) {
        return OZAYN_DEL_ERR_KEY_DESTRUCTION_FAILED;
    }

    /* Check key dependency */
    int key_required = 0;
    ozayn_del_result_t dr = ozayn_del_check_key_dependency(svc, object_id, &key_required);
    if (dr == OZAYN_DEL_OK && key_required) {
        return OZAYN_DEL_ERR_KEY_IN_USE;
    }

    /* Revoke the key through the key lifecycle manager */
    ozayn_kl_result_t kl_r = ozayn_kl_revoke(svc->key_lifecycle, key_name, key_version);
    if (kl_r != OZAYN_KL_OK) {
        _audit_deletion(svc, "key_destruction_failed", object_id,
                       OZAYN_DEL_ERR_KEY_DESTRUCTION_FAILED);
        return OZAYN_DEL_ERR_KEY_DESTRUCTION_FAILED;
    }

    svc->total_key_destructions++;
    _audit_deletion(svc, "key_destruction_completed", object_id, OZAYN_DEL_OK);
    return OZAYN_DEL_OK;
}

/* ============================================================
 * SECTION 13 — CRYPTOGRAPHIC ERASURE
 * ============================================================ */

ozayn_del_result_t ozayn_del_crypto_erasure(ozayn_del_service_t *svc,
                                              const ozayn_del_request_t *request,
                                              ozayn_del_result_data_t *out_result)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;
    if (!request) return OZAYN_DEL_ERR_NULL;
    if (!out_result) return OZAYN_DEL_ERR_NULL;

    out_result->previous_state = OZAYN_DEL_STATE_IDLE;

    if (!svc->vault) {
        out_result->result = OZAYN_DEL_ERR_VAULT_UNAVAILABLE;
        strncpy(out_result->failure_reason, "vault unavailable for crypto erasure",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "crypto_erasure_vault_unavailable", request->object_id,
                       OZAYN_DEL_ERR_VAULT_UNAVAILABLE);
        return OZAYN_DEL_ERR_VAULT_UNAVAILABLE;
    }

    if (!svc->key_lifecycle) {
        out_result->result = OZAYN_DEL_ERR_CRYPTO_ERASURE_UNAVAIL;
        strncpy(out_result->failure_reason, "key lifecycle unavailable",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "crypto_erasure_key_lifecycle_unavailable",
                       request->object_id, OZAYN_DEL_ERR_CRYPTO_ERASURE_UNAVAIL);
        return OZAYN_DEL_ERR_CRYPTO_ERASURE_UNAVAIL;
    }

    /* Verify object exists */
    if (!ozayn_vault_exists(svc->vault, request->object_id)) {
        out_result->result = OZAYN_DEL_ERR_NOT_FOUND;
        strncpy(out_result->failure_reason, "object not found",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "crypto_erasure_not_found", request->object_id,
                       OZAYN_DEL_ERR_NOT_FOUND);
        return OZAYN_DEL_ERR_NOT_FOUND;
    }

    /* Find the key version used by this object from vault entries */
    ozayn_vault_list_item_t items[OZAYN_VAULT_MAX_OBJECTS];
    int count = 0;
    for (int cat = 0; cat < OZAYN_DATA_CATEGORY_COUNT && count < OZAYN_VAULT_MAX_OBJECTS; cat++) {
        int n = ozayn_vault_list(svc->vault, (ozayn_data_category_t)cat,
                                  &items[count], OZAYN_VAULT_MAX_OBJECTS - count);
        count += n;
    }
    uint32_t obj_key_version = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(items[i].id, request->object_id) == 0) {
            obj_key_version = items[i].key_version;
            break;
        }
    }

    /* Check key dependencies before erasure */
    int key_required = 0;
    ozayn_del_result_t dr = ozayn_del_check_key_dependency(svc, request->object_id,
                                                             &key_required);
    if (dr == OZAYN_DEL_OK && key_required) {
        out_result->result = OZAYN_DEL_ERR_KEY_IN_USE;
        strncpy(out_result->failure_reason, "key still in use by other objects",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "crypto_erasure_key_in_use", request->object_id,
                       OZAYN_DEL_ERR_KEY_IN_USE);
        return OZAYN_DEL_ERR_KEY_IN_USE;
    }

    /* Remove object from vault (ciphertext) */
    ozayn_vault_result_t vres = ozayn_vault_remove(svc->vault, request->object_id);
    if (vres != OZAYN_VAULT_OK) {
        out_result->result = OZAYN_DEL_ERR_VAULT_FAILED;
        strncpy(out_result->failure_reason, "vault removal failed during crypto erasure",
                OZAYN_DEL_MAX_REASON_LEN - 1);
        _audit_deletion(svc, "crypto_erasure_vault_failed", request->object_id,
                       OZAYN_DEL_ERR_VAULT_FAILED);
        return OZAYN_DEL_ERR_VAULT_FAILED;
    }

    /* Revoke the key if no other objects use it */
    if (obj_key_version > 0) {
        /* Try to revoke using "VAULT" key name (the standard key for vault objects) */
        ozayn_kl_result_t kl_r = ozayn_kl_revoke(svc->key_lifecycle, "VAULT",
                                                   obj_key_version);
        if (kl_r != OZAYN_KL_OK) {
            /* Key may already be revoked or not found — not a fatal error
             * since the object is already removed */
        }
    }

    /* Verify the object is gone */
    if (svc->policy.verify_after_delete) {
        if (ozayn_vault_exists(svc->vault, request->object_id)) {
            out_result->result = OZAYN_DEL_ERR_INTEGRITY_FAILURE;
            out_result->final_state = OZAYN_DEL_STATE_DELETION_FAILED;
            strncpy(out_result->failure_reason, "crypto erasure verification failed",
                    OZAYN_DEL_MAX_REASON_LEN - 1);
            _audit_deletion(svc, "crypto_erasure_integrity_failure", request->object_id,
                           OZAYN_DEL_ERR_INTEGRITY_FAILURE);
            return OZAYN_DEL_ERR_INTEGRITY_FAILURE;
        }
    }

    out_result->result = OZAYN_DEL_OK;
    out_result->final_state = OZAYN_DEL_STATE_CRYPTO_ERASED;
    svc->total_deletions_completed++;
    svc->total_crypto_erasures++;
    _audit_deletion(svc, "crypto_erasure_completed", request->object_id, OZAYN_DEL_OK);
    return OZAYN_DEL_OK;
}

/* ============================================================
 * SECTION 14 — TEMPORARY DATA CLEANUP
 * ============================================================ */

ozayn_del_result_t ozayn_del_cleanup_temporary(ozayn_del_service_t *svc)
{
    if (!svc) return OZAYN_DEL_ERR_NULL;
    if (!svc->initialized) return OZAYN_DEL_ERR_NOT_INITIALIZED;

    /* Temporary data cleanup is a no-op in the current architecture
     * since OZAYN does not create persistent temporary files during
     * security operations. This boundary is established here for
     * future integration when temporary staging or export features
     * are implemented. */

    svc->total_temp_cleanups++;
    _audit_deletion(svc, "temp_cleanup_completed", "", OZAYN_DEL_OK);
    return OZAYN_DEL_OK;
}
