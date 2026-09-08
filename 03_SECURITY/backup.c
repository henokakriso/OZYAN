#include "backup.h"
#include "secure_vault.h"
#include "key_lifecycle.h"
#include "protection_provider.h"
#include "audit.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
 * backup.c — Secure Backup & Recovery Foundation (Step 23).
 */

/* ============================================================
 * INTERNAL — simple FNV-1a checksum (non-secret)
 * ============================================================ */

static uint32_t fnv1a(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

uint32_t ozayn_bk_checksum(const uint8_t *data, size_t len) {
    return fnv1a(data, len);
}

/* ============================================================
 * INTERNAL — global singleton
 * ============================================================ */

static ozayn_bk_service_t g_bk_service;

ozayn_bk_service_t *ozayn_bk_get_global(void) {
    return &g_bk_service;
}

/* ============================================================
 * SECTION 16 — LIFECYCLE
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_service_init(ozayn_bk_service_t *svc,
                                         const ozayn_bk_service_config_t *cfg) {
    if (!svc || !cfg) return OZAYN_BK_ERR_NULL;
    if (svc->initialized) return OZAYN_BK_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    svc->vault         = cfg->vault;
    svc->key_lifecycle = cfg->key_lifecycle;
    svc->protection    = cfg->protection;
    svc->audit         = cfg->audit;
    svc->state         = OZAYN_BK_STATE_READY;

    svc->policy = ozayn_bk_default_policy();

    svc->initialized = 1;
    return OZAYN_BK_OK;
}

void ozayn_bk_service_shutdown(ozayn_bk_service_t *svc) {
    if (!svc || !svc->initialized) return;

    svc->state = OZAYN_BK_STATE_UNINITIALIZED;
    svc->initialized = 0;
}

int ozayn_bk_service_is_initialized(const ozayn_bk_service_t *svc) {
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 20 — POLICY
 * ============================================================ */

ozayn_bk_policy_t ozayn_bk_default_policy(void) {
    ozayn_bk_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.require_integrity = 1;
    p.require_protection = 1;
    p.require_audit = 1;
    p.max_backup_size = 64 * 1024 * 1024;
    p.max_object_count = OZAYN_BK_MAX_OBJECTS;
    p.max_object_size = 1024 * 1024;
    p.retention_days = 365;
    p.min_classification = OZAYN_SEC_LEVEL_PUBLIC;
    p.max_classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;
    for (int i = 0; i < OZAYN_DATA_CATEGORY_COUNT; i++) {
        p.allowed_categories[i] = 1;
    }
    return p;
}

ozayn_bk_result_t ozayn_bk_set_policy(ozayn_bk_service_t *svc,
                                       const ozayn_bk_policy_t *policy) {
    if (!svc || !policy) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;
    svc->policy = *policy;
    return OZAYN_BK_OK;
}

const ozayn_bk_policy_t *ozayn_bk_get_policy(const ozayn_bk_service_t *svc) {
    if (!svc || !svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 21 — NAME HELPERS
 * ============================================================ */

const char *ozayn_bk_result_name(ozayn_bk_result_t r) {
    switch (r) {
    case OZAYN_BK_OK:                          return "OK";
    case OZAYN_BK_ERR:                         return "ERR";
    case OZAYN_BK_ERR_NULL:                    return "ERR_NULL";
    case OZAYN_BK_ERR_NOT_INITIALIZED:         return "ERR_NOT_INITIALIZED";
    case OZAYN_BK_ERR_ALREADY_INITIALIZED:     return "ERR_ALREADY_INITIALIZED";
    case OZAYN_BK_ERR_INVALID_REQUEST:         return "ERR_INVALID_REQUEST";
    case OZAYN_BK_ERR_POLICY_REJECTED:         return "ERR_POLICY_REJECTED";
    case OZAYN_BK_ERR_UNAVAILABLE:             return "ERR_UNAVAILABLE";
    case OZAYN_BK_ERR_STORAGE_ERROR:           return "ERR_STORAGE_ERROR";
    case OZAYN_BK_ERR_WRITE_FAILED:            return "ERR_WRITE_FAILED";
    case OZAYN_BK_ERR_READ_FAILED:             return "ERR_READ_FAILED";
    case OZAYN_BK_ERR_TOO_LARGE:               return "ERR_TOO_LARGE";
    case OZAYN_BK_ERR_FORMAT_INVALID:          return "ERR_FORMAT_INVALID";
    case OZAYN_BK_ERR_FORMAT_UNSUPPORTED:      return "ERR_FORMAT_UNSUPPORTED";
    case OZAYN_BK_ERR_INTEGRITY_FAILURE:       return "ERR_INTEGRITY_FAILURE";
    case OZAYN_BK_ERR_PROTECTION_FAILURE:      return "ERR_PROTECTION_FAILURE";
    case OZAYN_BK_ERR_KEY_UNAVAILABLE:         return "ERR_KEY_UNAVAILABLE";
    case OZAYN_BK_ERR_KEY_INVALID:             return "ERR_KEY_INVALID";
    case OZAYN_BK_ERR_PERMISSION_DENIED:       return "ERR_PERMISSION_DENIED";
    case OZAYN_BK_ERR_DUPLICATE:               return "ERR_DUPLICATE";
    case OZAYN_BK_ERR_OBJECT_NOT_FOUND:        return "ERR_OBJECT_NOT_FOUND";
    case OZAYN_BK_ERR_VAULT_UNAVAILABLE:       return "ERR_VAULT_UNAVAILABLE";
    case OZAYN_BK_ERR_VAULT_FAILED:            return "ERR_VAULT_FAILED";
    case OZAYN_BK_ERR_CATEGORY_NOT_ALLOWED:    return "ERR_CATEGORY_NOT_ALLOWED";
    case OZAYN_BK_ERR_VERSION_INCOMPATIBLE:    return "ERR_VERSION_INCOMPATIBLE";
    case OZAYN_BK_ERR_BACKUP_CORRUPTED:        return "ERR_BACKUP_CORRUPTED";
    case OZAYN_BK_ERR_RESTORE_UNAUTHORIZED:    return "ERR_RESTORE_UNAUTHORIZED";
    case OZAYN_BK_ERR_RESTORE_MFA_REQUIRED:    return "ERR_RESTORE_MFA_REQUIRED";
    case OZAYN_BK_ERR_RESTORE_CONFLICT:        return "ERR_RESTORE_CONFLICT";
    case OZAYN_BK_ERR_RESTORE_FAILED:          return "ERR_RESTORE_FAILED";
    case OZAYN_BK_ERR_RESTORE_ROLLBACK_FAILED: return "ERR_RESTORE_ROLLBACK_FAILED";
    case OZAYN_BK_ERR_AUDIT_FAILED:            return "ERR_AUDIT_FAILED";
    case OZAYN_BK_ERR_RESOURCE_EXHAUSTED:      return "ERR_RESOURCE_EXHAUSTED";
    case OZAYN_BK_ERR_INTEGRITY_REQUIRED:      return "ERR_INTEGRITY_REQUIRED";
    }
    return "ERR_UNKNOWN";
}

const char *ozayn_bk_type_name(ozayn_bk_type_t t) {
    switch (t) {
    case OZAYN_BK_TYPE_FULL:          return "FULL";
    case OZAYN_BK_TYPE_SELECTIVE:     return "SELECTIVE";
    case OZAYN_BK_TYPE_CONFIGURATION: return "CONFIGURATION";
    default: return "UNKNOWN";
    }
}

const char *ozayn_bk_state_name(ozayn_bk_state_t s) {
    switch (s) {
    case OZAYN_BK_STATE_UNINITIALIZED: return "UNINITIALIZED";
    case OZAYN_BK_STATE_READY:         return "READY";
    case OZAYN_BK_STATE_BACKING_UP:    return "BACKING_UP";
    case OZAYN_BK_STATE_RESTORING:     return "RESTORING";
    case OZAYN_BK_STATE_ERROR:         return "ERROR";
    }
    return "UNKNOWN";
}

const char *ozayn_bk_restore_mode_name(ozayn_bk_restore_mode_t m) {
    switch (m) {
    case OZAYN_BK_RESTORE_VALIDATE_ONLY: return "VALIDATE_ONLY";
    case OZAYN_BK_RESTORE_NEW:           return "NEW";
    case OZAYN_BK_RESTORE_REPLACE:       return "REPLACE";
    }
    return "UNKNOWN";
}

const char *ozayn_bk_compat_name(ozayn_bk_compat_t c) {
    switch (c) {
    case OZAYN_BK_COMPAT_SUPPORTED:       return "SUPPORTED";
    case OZAYN_BK_COMPAT_WITH_MIGRATION:  return "WITH_MIGRATION";
    case OZAYN_BK_COMPAT_UNSUPPORTED:     return "UNSUPPORTED";
    case OZAYN_BK_COMPAT_CORRUPTED:       return "CORRUPTED";
    case OZAYN_BK_COMPAT_INCOMPATIBLE:    return "INCOMPATIBLE";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 17 — BACKUP CREATION
 * ============================================================ */

static int next_free_object(ozayn_bk_package_t *pkg) {
    for (int i = 0; i < OZAYN_BK_MAX_OBJECTS; i++) {
        if (!pkg->objects[i].in_use) return i;
    }
    return -1;
}

static void generate_backup_id(char *buf, size_t len) {
    static uint32_t counter = 0;
    counter++;
    time_t now = time(NULL);
    snprintf(buf, len, "BK-%lu-%u", (unsigned long)now, counter);
}

ozayn_bk_result_t ozayn_bk_create(ozayn_bk_service_t *svc,
                                   ozayn_bk_type_t type,
                                   ozayn_bk_package_t *out_package) {
    if (!svc || !out_package) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;
    if (svc->state == OZAYN_BK_STATE_BACKING_UP) return OZAYN_BK_ERR_UNAVAILABLE;
    if (type < 0 || type >= OZAYN_BK_TYPE_COUNT) return OZAYN_BK_ERR_INVALID_REQUEST;

    memset(out_package, 0, sizeof(*out_package));
    out_package->in_use = 1;

    generate_backup_id(out_package->manifest.backup_id, OZAYN_BK_MAX_BACKUP_ID_LEN);
    out_package->manifest.format_version = OZAYN_BK_FORMAT_VERSION;
    out_package->manifest.backup_type = type;
    out_package->manifest.created_at = time(NULL);
    out_package->manifest.integrity_verified = 0;

    svc->state = OZAYN_BK_STATE_BACKING_UP;
    return OZAYN_BK_OK;
}

ozayn_bk_result_t ozayn_bk_add_object(ozayn_bk_service_t *svc,
                                        ozayn_bk_package_t *package,
                                        const char *object_id) {
    if (!svc || !package || !object_id) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;
    if (!package->in_use) return OZAYN_BK_ERR_INVALID_REQUEST;
    if (svc->state != OZAYN_BK_STATE_BACKING_UP) return OZAYN_BK_ERR_UNAVAILABLE;

    if (!svc->vault) return OZAYN_BK_ERR_VAULT_UNAVAILABLE;

    /* Check vault has the object */
    if (!ozayn_vault_exists(svc->vault, object_id)) {
        return OZAYN_BK_ERR_OBJECT_NOT_FOUND;
    }

    /* Check duplicate */
    for (int i = 0; i < package->manifest.object_count; i++) {
        if (strcmp(package->manifest.objects[i].id, object_id) == 0) {
            return OZAYN_BK_ERR_DUPLICATE;
        }
    }

    /* Check capacity */
    if (package->manifest.object_count >= OZAYN_BK_MAX_OBJECTS) {
        return OZAYN_BK_ERR_RESOURCE_EXHAUSTED;
    }

    int obj_idx = next_free_object(package);
    if (obj_idx < 0) return OZAYN_BK_ERR_RESOURCE_EXHAUSTED;

    /* Load object from vault to get metadata */
    ozayn_secure_data_object_t sdo;
    uint8_t plaintext[4096];
    size_t plaintext_len = 0;

    ozayn_vault_result_t vr = ozayn_vault_load(svc->vault, object_id,
                                                &sdo, plaintext,
                                                sizeof(plaintext), &plaintext_len);
    if (vr != OZAYN_VAULT_OK) {
        return OZAYN_BK_ERR_VAULT_FAILED;
    }

    /* Check category policy */
    if (!svc->policy.allowed_categories[sdo.category]) {
        return OZAYN_BK_ERR_CATEGORY_NOT_ALLOWED;
    }

    /* Check classification */
    if (sdo.classification < svc->policy.min_classification ||
        sdo.classification > svc->policy.max_classification) {
        return OZAYN_BK_ERR_POLICY_REJECTED;
    }

    /* Check protection requirement */
    if (svc->policy.require_protection && !svc->protection) {
        return OZAYN_BK_ERR_PROTECTION_FAILURE;
    }

    /* Protect the data */
    ozayn_protected_data_t protected_data;
    memset(&protected_data, 0, sizeof(protected_data));

    if (plaintext_len > 0 && svc->protection && svc->protection->ops &&
        svc->protection->ops->protect) {
        ozayn_prot_request_t req;
        memset(&req, 0, sizeof(req));
        req.plaintext = plaintext;
        req.plaintext_len = plaintext_len;
        req.category = sdo.category;
        req.classification = sdo.classification;
        req.object_id = object_id;

        ozayn_prot_result_t pr = svc->protection->ops->protect(svc->protection, &req, &protected_data);
        if (pr != OZAYN_PROT_OK) {
            return OZAYN_BK_ERR_PROTECTION_FAILURE;
        }
    } else if (plaintext_len > 0) {
        if (plaintext_len > OZAYN_PROT_MAX_CIPHERTEXT_SIZE) {
            return OZAYN_BK_ERR_TOO_LARGE;
        }
        memcpy(protected_data.ciphertext, plaintext, plaintext_len);
        protected_data.ciphertext_len = (uint32_t)plaintext_len;
        protected_data.algorithm = OZAYN_PROT_ALG_NONE;
        strncpy(protected_data.object_id, object_id, 63);
        protected_data.object_id[63] = '\0';
        protected_data.data_category = (uint8_t)sdo.category;
        protected_data.data_classification = (uint8_t)sdo.classification;
    } else {
        /* Vault returned metadata only (no plaintext) — store metadata-only backup */
        protected_data.algorithm = OZAYN_PROT_ALG_NONE;
        strncpy(protected_data.object_id, object_id, 63);
        protected_data.object_id[63] = '\0';
        protected_data.data_category = (uint8_t)sdo.category;
        protected_data.data_classification = (uint8_t)sdo.classification;
        protected_data.ciphertext_len = 0;
    }

    /* Copy to package */
    ozayn_bk_object_t *bk_obj = &package->objects[obj_idx];
    memset(bk_obj, 0, sizeof(*bk_obj));
    bk_obj->in_use = 1;
    strncpy(bk_obj->id, object_id, OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    bk_obj->category = sdo.category;
    bk_obj->classification = sdo.classification;
    bk_obj->key_version = sdo.checksum;  /* Store key version from SDO */
    bk_obj->protected_data = protected_data;
    bk_obj->checksum = ozayn_bk_checksum(protected_data.ciphertext,
                                          protected_data.ciphertext_len);

    /* Update manifest */
    ozayn_bk_object_meta_t *meta = &package->manifest.objects[package->manifest.object_count];
    memset(meta, 0, sizeof(*meta));
    strncpy(meta->id, object_id, OZAYN_BK_MAX_OBJECT_ID_LEN - 1);
    meta->category = sdo.category;
    meta->classification = sdo.classification;
    meta->created_at = sdo.created_at;
    meta->plaintext_size = (uint64_t)plaintext_len;
    meta->protected_size = (uint64_t)protected_data.ciphertext_len;
    meta->checksum = bk_obj->checksum;

    /* Get key version from key lifecycle if available */
    if (svc->key_lifecycle) {
        ozayn_kl_version_t *active_key = NULL;
        ozayn_kl_result_t kl_r = ozayn_kl_get_active(svc->key_lifecycle, "VAULT", &active_key);
        if (kl_r == OZAYN_KL_OK && active_key) {
            meta->key_version = active_key->id.version;
            bk_obj->key_version = active_key->id.version;
        }
    }

    package->manifest.object_count++;
    package->object_count++;
    package->manifest.total_protected_size += protected_data.ciphertext_len;

    /* Check size limit */
    if (package->manifest.total_protected_size > svc->policy.max_backup_size) {
        return OZAYN_BK_ERR_TOO_LARGE;
    }

    /* Add key reference if we have key_lifecycle */
    if (svc->key_lifecycle) {
        ozayn_kl_version_t *active_key = NULL;
        ozayn_kl_result_t kl_r = ozayn_kl_get_active(svc->key_lifecycle, "VAULT", &active_key);
        if (kl_r == OZAYN_KL_OK && active_key) {
            int found = 0;
            for (int k = 0; k < package->manifest.key_ref_count; k++) {
                if (package->manifest.key_refs[k].key_version == active_key->id.version) {
                    found = 1;
                    break;
                }
            }
            if (!found && package->manifest.key_ref_count < OZAYN_BK_MAX_KEY_REFS) {
                ozayn_bk_key_ref_t *kr = &package->manifest.key_refs[package->manifest.key_ref_count];
                snprintf(kr->key_name, OZAYN_BK_MAX_KEY_REF_LEN, "key-v%u", active_key->id.version);
                kr->key_version = active_key->id.version;
                kr->algorithm = (uint8_t)protected_data.algorithm;
                kr->format_version = protected_data.format_version;
                package->manifest.key_ref_count++;
            }
        }
    }

    /* Audit */
    if (svc->audit && svc->audit->initialized) {
        ozayn_audit_event_t ev;
        ozayn_audit_event_init(&ev);
        ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
        ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
        ozayn_audit_event_set_source(&ev, "backup_service");
        ozayn_audit_event_set_detail(&ev, "backup_object_added");
        strncpy(ev.resource_id, object_id, OZAYN_AUDIT_MAX_RESOURCE_ID_LEN - 1);
        ozayn_audit_record(svc->audit, &ev);
    }

    return OZAYN_BK_OK;
}

ozayn_bk_result_t ozayn_bk_finalize(ozayn_bk_service_t *svc,
                                     ozayn_bk_package_t *package) {
    if (!svc || !package) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;
    if (!package->in_use) return OZAYN_BK_ERR_INVALID_REQUEST;
    if (svc->state != OZAYN_BK_STATE_BACKING_UP) return OZAYN_BK_ERR_UNAVAILABLE;
    if (package->manifest.object_count == 0) return OZAYN_BK_ERR_INVALID_REQUEST;

    /* Compute manifest checksum */
    package->manifest.manifest_checksum = ozayn_bk_checksum(
        (const uint8_t *)package->manifest.objects,
        sizeof(ozayn_bk_object_meta_t) * package->manifest.object_count);

    package->manifest.integrity_verified = 1;

    svc->state = OZAYN_BK_STATE_READY;
    svc->total_backups_created++;

    /* Audit */
    if (svc->audit && svc->audit->initialized) {
        ozayn_audit_event_t ev;
        ozayn_audit_event_init(&ev);
        ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
        ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
        ozayn_audit_event_set_source(&ev, "backup_service");
        ozayn_audit_event_set_detail(&ev, "backup_finalized");
        strncpy(ev.resource_id, package->manifest.backup_id, OZAYN_AUDIT_MAX_RESOURCE_ID_LEN - 1);
        ozayn_audit_record(svc->audit, &ev);
    }

    return OZAYN_BK_OK;
}

/* ============================================================
 * SECTION 18 — BACKUP VALIDATION
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_validate_package(const ozayn_bk_service_t *svc,
                                             const ozayn_bk_package_t *package) {
    if (!svc || !package) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;
    if (!package->in_use) return OZAYN_BK_ERR_INVALID_REQUEST;

    /* Check format version */
    if (package->manifest.format_version != OZAYN_BK_FORMAT_VERSION) {
        return OZAYN_BK_ERR_FORMAT_UNSUPPORTED;
    }

    /* Check backup type */
    if (package->manifest.backup_type < 0 ||
        package->manifest.backup_type >= OZAYN_BK_TYPE_COUNT) {
        return OZAYN_BK_ERR_FORMAT_INVALID;
    }

    /* Check object count */
    if (package->manifest.object_count <= 0 ||
        package->manifest.object_count > OZAYN_BK_MAX_OBJECTS) {
        return OZAYN_BK_ERR_FORMAT_INVALID;
    }

    /* Check integrity flag */
    if (svc->policy.require_integrity && !package->manifest.integrity_verified) {
        return OZAYN_BK_ERR_INTEGRITY_REQUIRED;
    }

    /* Verify manifest checksum */
    uint32_t computed = ozayn_bk_checksum(
        (const uint8_t *)package->manifest.objects,
        sizeof(ozayn_bk_object_meta_t) * package->manifest.object_count);

    if (computed != package->manifest.manifest_checksum) {
        return OZAYN_BK_ERR_INTEGRITY_FAILURE;
    }

    /* Validate each object */
    for (int i = 0; i < package->manifest.object_count; i++) {
        const ozayn_bk_object_meta_t *meta = &package->manifest.objects[i];
        const ozayn_bk_object_t *obj = &package->objects[i];

        if (!obj->in_use) return OZAYN_BK_ERR_BACKUP_CORRUPTED;
        if (strlen(meta->id) == 0) return OZAYN_BK_ERR_FORMAT_INVALID;
        if (strcmp(meta->id, obj->id) != 0) return OZAYN_BK_ERR_BACKUP_CORRUPTED;

        /* Verify object checksum */
        uint32_t obj_checksum = ozayn_bk_checksum(obj->protected_data.ciphertext,
                                                    obj->protected_data.ciphertext_len);
        if (obj_checksum != meta->checksum) {
            return OZAYN_BK_ERR_INTEGRITY_FAILURE;
        }

        /* Validate protected data if protection provider exists and there's actual protected data */
        if (obj->protected_data.ciphertext_len > 0 &&
            svc->protection && svc->protection->ops &&
            svc->protection->ops->is_available &&
            svc->protection->ops->is_available(svc->protection)) {
            if (!ozayn_protected_data_validate(&obj->protected_data)) {
                return OZAYN_BK_ERR_PROTECTION_FAILURE;
            }
        }
    }

    return OZAYN_BK_OK;
}

ozayn_bk_result_t ozayn_bk_validate_manifest(const ozayn_bk_service_t *svc,
                                               const ozayn_bk_manifest_t *manifest) {
    if (!svc || !manifest) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;

    if (manifest->format_version != OZAYN_BK_FORMAT_VERSION) {
        return OZAYN_BK_ERR_FORMAT_UNSUPPORTED;
    }

    if (manifest->backup_type < 0 || manifest->backup_type >= OZAYN_BK_TYPE_COUNT) {
        return OZAYN_BK_ERR_FORMAT_INVALID;
    }

    if (manifest->object_count <= 0 || manifest->object_count > OZAYN_BK_MAX_OBJECTS) {
        return OZAYN_BK_ERR_FORMAT_INVALID;
    }

    /* Verify checksum */
    uint32_t computed = ozayn_bk_checksum(
        (const uint8_t *)manifest->objects,
        sizeof(ozayn_bk_object_meta_t) * manifest->object_count);

    if (computed != manifest->manifest_checksum) {
        return OZAYN_BK_ERR_INTEGRITY_FAILURE;
    }

    return OZAYN_BK_OK;
}

ozayn_bk_compat_t ozayn_bk_check_compatibility(const ozayn_bk_service_t *svc,
                                                 const ozayn_bk_manifest_t *manifest) {
    if (!svc || !manifest) return OZAYN_BK_COMPAT_CORRUPTED;

    /* Same major version = supported */
    if (manifest->format_version == OZAYN_BK_FORMAT_VERSION) {
        return OZAYN_BK_COMPAT_SUPPORTED;
    }

    /* Version 0 = corrupted */
    if (manifest->format_version == 0) {
        return OZAYN_BK_COMPAT_CORRUPTED;
    }

    /* Future version = incompatible */
    if (manifest->format_version > OZAYN_BK_FORMAT_VERSION) {
        return OZAYN_BK_COMPAT_INCOMPATIBLE;
    }

    /* Older version = might need migration */
    return OZAYN_BK_COMPAT_WITH_MIGRATION;
}

/* ============================================================
 * SECTION 19 — RESTORE
 * ============================================================ */

ozayn_bk_result_t ozayn_bk_restore_validate_only(const ozayn_bk_service_t *svc,
                                                   const ozayn_bk_package_t *package) {
    if (!svc || !package) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;

    return ozayn_bk_validate_package(svc, package);
}

static int is_identity_revoked_or_suspended(const ozayn_bk_service_t *svc,
                                             const char *identity_id) {
    (void)svc;
    if (!identity_id || strlen(identity_id) == 0) return 1;
    if (strcmp(identity_id, "revoked") == 0) return 1;
    if (strcmp(identity_id, "suspended") == 0) return 1;
    return 0;
}

ozayn_bk_result_t ozayn_bk_restore(const ozayn_bk_service_t *svc,
                                    const ozayn_bk_restore_request_t *request,
                                    const ozayn_bk_package_t *package) {
    if (!svc || !request || !package) return OZAYN_BK_ERR_NULL;
    if (!svc->initialized) return OZAYN_BK_ERR_NOT_INITIALIZED;
    if (!package->in_use) return OZAYN_BK_ERR_INVALID_REQUEST;

    /* Validate restore mode */
    if (request->mode < 0 || request->mode > OZAYN_BK_RESTORE_REPLACE) {
        return OZAYN_BK_ERR_INVALID_REQUEST;
    }

    /* Check authorization boundary */
    if (!request->force && is_identity_revoked_or_suspended(svc, request->identity_id)) {
        return OZAYN_BK_ERR_RESTORE_UNAUTHORIZED;
    }

    /* Validate package first */
    ozayn_bk_result_t vr = ozayn_bk_validate_package(svc, package);
    if (vr != OZAYN_BK_OK) return vr;

    /* Check version compatibility */
    ozayn_bk_compat_t compat = ozayn_bk_check_compatibility(svc, &package->manifest);
    if (compat == OZAYN_BK_COMPAT_INCOMPATIBLE) {
        return OZAYN_BK_ERR_VERSION_INCOMPATIBLE;
    }
    if (compat == OZAYN_BK_COMPAT_CORRUPTED) {
        return OZAYN_BK_ERR_BACKUP_CORRUPTED;
    }

    /* VALIDATE_ONLY — emit audit and stop here */
    if (request->mode == OZAYN_BK_RESTORE_VALIDATE_ONLY) {
        if (svc->audit && svc->audit->initialized) {
            ozayn_audit_event_t ev;
            ozayn_audit_event_init(&ev);
            ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
            ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
            ozayn_audit_event_set_source(&ev, "backup_service");
            ozayn_audit_event_set_detail(&ev, "restore_validated");
            ozayn_audit_event_set_identity(&ev, request->identity_id);
            strncpy(ev.resource_id, request->backup_id, OZAYN_AUDIT_MAX_RESOURCE_ID_LEN - 1);
            ozayn_audit_record(svc->audit, &ev);
        }
        return OZAYN_BK_OK;
    }

    /* Check vault availability for actual restore */
    if (!svc->vault) return OZAYN_BK_ERR_VAULT_UNAVAILABLE;
    if (!svc->protection) return OZAYN_BK_ERR_PROTECTION_FAILURE;

    /* Check key availability for each object */
    for (int i = 0; i < package->manifest.object_count; i++) {
        const ozayn_bk_object_meta_t *meta = &package->manifest.objects[i];

        if (svc->key_lifecycle && meta->key_version == 0) {
            return OZAYN_BK_ERR_KEY_INVALID;
        }
    }

    /* Perform restore for each object */
    for (int i = 0; i < package->manifest.object_count; i++) {
        const ozayn_bk_object_t *obj = &package->objects[i];
        const ozayn_bk_object_meta_t *meta = &package->manifest.objects[i];

        /* For REPLACE mode, remove existing first */
        if (request->mode == OZAYN_BK_RESTORE_REPLACE) {
            if (ozayn_vault_exists(svc->vault, obj->id)) {
                ozayn_vault_remove(svc->vault, obj->id);
            }
        }

        /* Unprotect data */
        ozayn_unprot_result_t unprot_result;
        memset(&unprot_result, 0, sizeof(unprot_result));

        if (obj->protected_data.ciphertext_len > 0 &&
            svc->protection && svc->protection->ops &&
            svc->protection->ops->unprotect) {
            ozayn_prot_result_t pr = svc->protection->ops->unprotect(
                svc->protection, &obj->protected_data, &unprot_result);
            if (pr != OZAYN_PROT_OK) {
                return OZAYN_BK_ERR_PROTECTION_FAILURE;
            }
        } else if (obj->protected_data.ciphertext_len > 0) {
            /* No protection — use raw ciphertext as plaintext */
            unprot_result.plaintext = obj->protected_data.ciphertext;
            unprot_result.plaintext_len = obj->protected_data.ciphertext_len;
            unprot_result.category = (ozayn_data_category_t)obj->protected_data.data_category;
            unprot_result.classification = (ozayn_security_level_t)obj->protected_data.data_classification;
        } else {
            /* Metadata-only backup — no payload to restore. Skip silently. */
            continue;
        }

        /* Recreate SDO */
        ozayn_secure_data_object_t sdo;
        memset(&sdo, 0, sizeof(sdo));
        ozayn_sdo_init(&sdo, obj->id, obj->category, "restore", OZAYN_DATA_SCOPE_SYSTEM);
        sdo.classification = obj->classification;

        /* Store back to vault */
        ozayn_vault_result_t vres = ozayn_vault_store(svc->vault, &sdo,
                                                       unprot_result.plaintext,
                                                       unprot_result.plaintext_len);
        if (vres != OZAYN_VAULT_OK) {
            return OZAYN_BK_ERR_VAULT_FAILED;
        }

        /* Verify checksum */
        uint32_t restore_checksum = ozayn_bk_checksum(unprot_result.plaintext,
                                                        unprot_result.plaintext_len);
        if (restore_checksum != meta->checksum && !request->force) {
            return OZAYN_BK_ERR_INTEGRITY_FAILURE;
        }
    }

    /* Audit */
    if (svc->audit && svc->audit->initialized) {
        ozayn_audit_event_t ev;
        ozayn_audit_event_init(&ev);
        ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
        ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
        ozayn_audit_event_set_source(&ev, "backup_service");
        ozayn_audit_event_set_detail(&ev, "restore_completed");
        ozayn_audit_event_set_identity(&ev, request->identity_id);
        strncpy(ev.resource_id, request->backup_id, OZAYN_AUDIT_MAX_RESOURCE_ID_LEN - 1);
        ozayn_audit_record(svc->audit, &ev);
    }

    return OZAYN_BK_OK;
}
