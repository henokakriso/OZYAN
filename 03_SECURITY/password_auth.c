#include "password_auth.h"
#include "secure_data_object.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

/*
 * password_auth.c — Password Authentication & Credential Protection
 *                    (Section 03, Step 14).
 *
 * Implements password-based authentication using libsodium's Argon2id
 * password hashing. Passwords are hashed with crypto_pwhash_str() for
 * storage and verified with crypto_pwhash_str_verify() for auth.
 *
 * The plaintext password exists only during provisioning/verification,
 * is never written to persistent storage, and is wiped from memory
 * after use.
 */

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

static const char *_pwd_credential_state_names[] = {
    "UNINITIALIZED", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"
};

static const char *_pwd_error_names[] = {
    "OK", "NULL", "NOT_INITIALIZED", "NOT_FOUND", "INVALID",
    "EMPTY_PASSWORD", "PASSWORD_TOO_SHORT", "PASSWORD_TOO_LONG",
    "KDF_FAILED", "VERIFICATION_FAILED", "CREDENTIAL_REVOKED",
    "CREDENTIAL_SUSPENDED", "CREDENTIAL_EXPIRED", "VAULT_FAILED",
    "STORAGE_FAILED", "ALREADY_EXISTS", "IDENTITY_REVOKED",
    "IDENTITY_SUSPENDED", "IDENTITY_ARCHIVED"
};

const char *ozayn_pwd_credential_state_name(ozayn_pwd_credential_state_t state)
{
    int idx = (int)state;
    if (idx < 0 || idx > 4)
        return "UNKNOWN";
    return _pwd_credential_state_names[idx];
}

const char *ozayn_pwd_error_name(ozayn_pwd_error_t error)
{
    int idx = (int)error;
    if (idx < -18 || idx > 0)
        return "UNKNOWN";
    return _pwd_error_names[-idx];
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_pwd_validate_credential_state(ozayn_pwd_credential_state_t state)
{
    if (state < OZAYN_PWD_CRED_UNINITIALIZED || state > OZAYN_PWD_CRED_EXPIRED)
        return -1;
    return 0;
}

int ozayn_pwd_validate_credential_transition(ozayn_pwd_credential_state_t from,
                                              ozayn_pwd_credential_state_t to)
{
    if (ozayn_pwd_validate_credential_state(from) != 0)
        return -1;
    if (ozayn_pwd_validate_credential_state(to) != 0)
        return -1;

    switch (from) {
        case OZAYN_PWD_CRED_UNINITIALIZED:
            return (to == OZAYN_PWD_CRED_ACTIVE) ? 0 : -1;
        case OZAYN_PWD_CRED_ACTIVE:
            return (to == OZAYN_PWD_CRED_SUSPENDED ||
                    to == OZAYN_PWD_CRED_REVOKED ||
                    to == OZAYN_PWD_CRED_EXPIRED) ? 0 : -1;
        case OZAYN_PWD_CRED_SUSPENDED:
            return (to == OZAYN_PWD_CRED_ACTIVE ||
                    to == OZAYN_PWD_CRED_REVOKED) ? 0 : -1;
        case OZAYN_PWD_CRED_REVOKED:
            return -1;
        case OZAYN_PWD_CRED_EXPIRED:
            return -1;
        default:
            return -1;
    }
}

int ozayn_pwd_validate_password(const ozayn_pwd_service_t *svc,
                                 const char *password,
                                 size_t password_len)
{
    if (!password && password_len > 0)
        return -1;
    if (password_len == 0)
        return -1;
    if (!svc || !svc->config.policy.enabled)
        return 0;
    if ((int)password_len < svc->config.policy.min_length)
        return -1;
    if (svc->config.policy.max_length > 0 &&
        (int)password_len > svc->config.policy.max_length)
        return -1;
    return 0;
}

/* ============================================================
 * INTERNAL: Find credential by identity ID
 * ============================================================ */

static ozayn_pwd_credential_t *_find_credential(ozayn_pwd_service_t *svc,
                                                 const char *identity_id)
{
    if (!svc || !identity_id)
        return NULL;
    for (int i = 0; i < OZAYN_PWD_MAX_CREDENTIALS; i++) {
        if (svc->credentials[i].in_use &&
            strcmp(svc->credentials[i].identity_id, identity_id) == 0)
            return &svc->credentials[i];
    }
    return NULL;
}

/* ============================================================
 * INTERNAL: Find free credential slot
 * ============================================================ */

static ozayn_pwd_credential_t *_find_free_credential(ozayn_pwd_service_t *svc)
{
    for (int i = 0; i < OZAYN_PWD_MAX_CREDENTIALS; i++) {
        if (!svc->credentials[i].in_use)
            return &svc->credentials[i];
    }
    return NULL;
}

/* ============================================================
 * INTERNAL: Generate credential ID
 * ============================================================ */

static void _generate_cred_id(char *buf, size_t bufsz, const char *identity_id)
{
    static int counter = 0;
    counter++;
    snprintf(buf, bufsz, "pwd-%s-%d-%ld", identity_id, counter, (long)time(NULL));
}

/* ============================================================
 * INTERNAL: Wipe sensitive memory
 * ============================================================ */

static void _wipe_password(char *buf, size_t len)
{
    if (buf && len > 0)
        sodium_memzero(buf, len);
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_pwd_error_t ozayn_pwd_service_init(ozayn_pwd_service_t *svc,
                                          const ozayn_pwd_service_config_t *config)
{
    if (!svc || !config)
        return OZAYN_PWD_ERR_NULL;
    if (!config->identity_service || !config->vault)
        return OZAYN_PWD_ERR_NULL;

    if (sodium_init() < 0)
        return OZAYN_PWD_ERR_KDF_FAILED;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;

    /* Apply default policy if not configured */
    if (!svc->config.policy.enabled) {
        svc->config.policy.enabled = 1;
        svc->config.policy.min_length = 8;
        svc->config.policy.max_length = 4096;
    }

    svc->initialized = 1;
    return OZAYN_PWD_OK;
}

void ozayn_pwd_service_shutdown(ozayn_pwd_service_t *svc)
{
    if (!svc)
        return;
    /* Wipe all credential hash strings */
    for (int i = 0; i < OZAYN_PWD_MAX_CREDENTIALS; i++) {
        if (svc->credentials[i].in_use)
            sodium_memzero(svc->credentials[i].hash_str,
                           sizeof(svc->credentials[i].hash_str));
    }
    memset(svc->credentials, 0, sizeof(svc->credentials));
    svc->credential_count = 0;
    svc->initialized = 0;
}

/* ============================================================
 * PASSWORD PROVISIONING
 * ============================================================ */

ozayn_pwd_error_t ozayn_pwd_provision(ozayn_pwd_service_t *svc,
                                       const ozayn_pwd_provision_request_t *request,
                                       ozayn_authn_credential_ref_t *out_ref)
{
    if (!svc || !request || !out_ref)
        return OZAYN_PWD_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PWD_ERR_NOT_INITIALIZED;

    /* Validate identity_id */
    if (request->identity_id[0] == '\0')
        return OZAYN_PWD_ERR_INVALID;

    /* Validate password */
    if (request->password_len == 0 || request->password[0] == '\0')
        return OZAYN_PWD_ERR_EMPTY_PASSWORD;

    int pv = ozayn_pwd_validate_password(svc, request->password, request->password_len);
    if (pv != 0) {
        if (request->password_len == 0)
            return OZAYN_PWD_ERR_EMPTY_PASSWORD;
        if (svc->config.policy.enabled &&
            (int)request->password_len < svc->config.policy.min_length)
            return OZAYN_PWD_ERR_PASSWORD_TOO_SHORT;
        if (svc->config.policy.enabled &&
            svc->config.policy.max_length > 0 &&
            (int)request->password_len > svc->config.policy.max_length)
            return OZAYN_PWD_ERR_PASSWORD_TOO_LONG;
        return OZAYN_PWD_ERR_INVALID;
    }

    /* Check identity exists and is active */
    ozayn_identity_t identity;
    ozayn_identity_result_t id_r = ozayn_id_get(svc->config.identity_service,
                                                  request->identity_id,
                                                  &identity);
    if (id_r != OZAYN_ID_OK)
        return OZAYN_PWD_ERR_INVALID;
    if (identity.state == OZAYN_ID_STATE_REVOKED)
        return OZAYN_PWD_ERR_IDENTITY_REVOKED;
    if (identity.state == OZAYN_ID_STATE_SUSPENDED)
        return OZAYN_PWD_ERR_IDENTITY_SUSPENDED;
    if (identity.state == OZAYN_ID_STATE_ARCHIVED)
        return OZAYN_PWD_ERR_IDENTITY_ARCHIVED;

    /* Check no existing credential for this identity */
    if (_find_credential(svc, request->identity_id))
        return OZAYN_PWD_ERR_ALREADY_EXISTS;

    /* Find free slot */
    ozayn_pwd_credential_t *cred = _find_free_credential(svc);
    if (!cred)
        return OZAYN_PWD_ERR_STORAGE_FAILED;

    /* Hash password with Argon2id */
    char hash_str[crypto_pwhash_STRBYTES];
    memset(hash_str, 0, sizeof(hash_str));

    if (crypto_pwhash_str(hash_str,
                          request->password,
                          request->password_len,
                          crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
                          crypto_pwhash_argon2id_MEMLIMIT_MODERATE) != 0) {
        _wipe_password(hash_str, sizeof(hash_str));
        return OZAYN_PWD_ERR_KDF_FAILED;
    }

    /* Store hash through Secure Vault */
    ozayn_secure_data_object_t sdo;
    char cred_id[OZAYN_PWD_MAX_ID_LEN];
    _generate_cred_id(cred_id, sizeof(cred_id), request->identity_id);

    ozayn_sdo_init(&sdo, cred_id, OZAYN_DATA_CATEGORY_AUTH_INFO,
                   request->identity_id, OZAYN_DATA_SCOPE_USER);
    sdo.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;

    ozayn_vault_result_t vr = ozayn_vault_store(svc->config.vault, &sdo,
                                                  (const uint8_t *)hash_str,
                                                  sizeof(hash_str));
    if (vr != OZAYN_VAULT_OK) {
        _wipe_password(hash_str, sizeof(hash_str));
        return OZAYN_PWD_ERR_VAULT_FAILED;
    }

    /* Initialize credential record */
    memset(cred, 0, sizeof(*cred));
    strncpy(cred->id, cred_id, sizeof(cred->id) - 1);
    strncpy(cred->identity_id, request->identity_id, sizeof(cred->identity_id) - 1);
    strncpy(cred->hash_str, hash_str, sizeof(cred->hash_str) - 1);
    cred->state = OZAYN_PWD_CRED_ACTIVE;
    cred->version = 1;
    cred->created_at = time(NULL);
    cred->modified_at = cred->created_at;
    cred->in_use = 1;

    svc->credential_count++;

    /* Wipe local hash copy */
    _wipe_password(hash_str, sizeof(hash_str));

    /* Fill credential reference (non-secret locator) */
    memset(out_ref, 0, sizeof(*out_ref));
    strncpy(out_ref->id, cred_id, sizeof(out_ref->id) - 1);
    out_ref->state = OZAYN_AuthN_CRED_ACTIVE;
    out_ref->method = OZAYN_AuthN_METHOD_PASSWORD;
    out_ref->version = 1;
    strncpy(out_ref->provider_id, "password-provider", sizeof(out_ref->provider_id) - 1);
    out_ref->created_at = cred->created_at;
    out_ref->modified_at = cred->modified_at;
    out_ref->in_use = 1;

    return OZAYN_PWD_OK;
}

/* ============================================================
 * PASSWORD VERIFICATION
 * ============================================================ */

ozayn_pwd_error_t ozayn_pwd_verify(ozayn_pwd_service_t *svc,
                                    const ozayn_pwd_verify_request_t *request,
                                    ozayn_authn_result_t *out_result)
{
    if (!svc || !request || !out_result)
        return OZAYN_PWD_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PWD_ERR_NOT_INITIALIZED;

    *out_result = OZAYN_AuthN_RESULT_FAILED;

    /* Validate input */
    if (request->identity_id[0] == '\0')
        return OZAYN_PWD_ERR_INVALID;
    if (request->password_len == 0 || request->password[0] == '\0')
        return OZAYN_PWD_ERR_EMPTY_PASSWORD;

    /* Check identity exists and is active */
    ozayn_identity_t identity;
    ozayn_identity_result_t id_r = ozayn_id_get(svc->config.identity_service,
                                                  request->identity_id,
                                                  &identity);
    if (id_r != OZAYN_ID_OK)
        return OZAYN_PWD_ERR_INVALID;
    if (identity.state == OZAYN_ID_STATE_REVOKED) {
        *out_result = OZAYN_AuthN_RESULT_REJECTED;
        return OZAYN_PWD_ERR_IDENTITY_REVOKED;
    }
    if (identity.state == OZAYN_ID_STATE_SUSPENDED) {
        *out_result = OZAYN_AuthN_RESULT_REJECTED;
        return OZAYN_PWD_ERR_IDENTITY_SUSPENDED;
    }
    if (identity.state == OZAYN_ID_STATE_ARCHIVED) {
        *out_result = OZAYN_AuthN_RESULT_REJECTED;
        return OZAYN_PWD_ERR_IDENTITY_ARCHIVED;
    }

    /* Find credential */
    ozayn_pwd_credential_t *cred = _find_credential(svc, request->identity_id);
    if (!cred) {
        *out_result = OZAYN_AuthN_RESULT_UNAVAILABLE;
        return OZAYN_PWD_ERR_NOT_FOUND;
    }

    /* Check credential state */
    if (cred->state == OZAYN_PWD_CRED_REVOKED) {
        *out_result = OZAYN_AuthN_RESULT_REJECTED;
        return OZAYN_PWD_ERR_CREDENTIAL_REVOKED;
    }
    if (cred->state == OZAYN_PWD_CRED_SUSPENDED) {
        *out_result = OZAYN_AuthN_RESULT_REJECTED;
        return OZAYN_PWD_ERR_CREDENTIAL_SUSPENDED;
    }
    if (cred->state == OZAYN_PWD_CRED_EXPIRED) {
        *out_result = OZAYN_AuthN_RESULT_REJECTED;
        return OZAYN_PWD_ERR_CREDENTIAL_EXPIRED;
    }

    /* Verify password against stored hash using libsodium's
     * constant-time comparison (crypto_pwhash_str_verify) */
    if (crypto_pwhash_str_verify(cred->hash_str,
                                  request->password,
                                  request->password_len) != 0) {
        *out_result = OZAYN_AuthN_RESULT_FAILED;
        return OZAYN_PWD_ERR_VERIFICATION_FAILED;
    }

    *out_result = OZAYN_AuthN_RESULT_SUCCESS;
    return OZAYN_PWD_OK;
}

/* ============================================================
 * PASSWORD UPDATE
 * ============================================================ */

ozayn_pwd_error_t ozayn_pwd_update(ozayn_pwd_service_t *svc,
                                    const char *identity_id,
                                    const char *new_password,
                                    size_t new_password_len)
{
    if (!svc || !identity_id || !new_password)
        return OZAYN_PWD_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PWD_ERR_NOT_INITIALIZED;
    if (identity_id[0] == '\0')
        return OZAYN_PWD_ERR_INVALID;
    if (new_password_len == 0)
        return OZAYN_PWD_ERR_EMPTY_PASSWORD;

    /* Validate new password */
    int pv = ozayn_pwd_validate_password(svc, new_password, new_password_len);
    if (pv != 0) {
        if ((int)new_password_len < svc->config.policy.min_length)
            return OZAYN_PWD_ERR_PASSWORD_TOO_SHORT;
        if (svc->config.policy.max_length > 0 &&
            (int)new_password_len > svc->config.policy.max_length)
            return OZAYN_PWD_ERR_PASSWORD_TOO_LONG;
        return OZAYN_PWD_ERR_INVALID;
    }

    /* Find existing credential */
    ozayn_pwd_credential_t *cred = _find_credential(svc, identity_id);
    if (!cred)
        return OZAYN_PWD_ERR_NOT_FOUND;

    /* Hash new password */
    char hash_str[crypto_pwhash_STRBYTES];
    memset(hash_str, 0, sizeof(hash_str));

    if (crypto_pwhash_str(hash_str,
                          new_password,
                          new_password_len,
                          crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
                          crypto_pwhash_argon2id_MEMLIMIT_MODERATE) != 0) {
        _wipe_password(hash_str, sizeof(hash_str));
        return OZAYN_PWD_ERR_KDF_FAILED;
    }

    /* Update in vault */
    ozayn_secure_data_object_t sdo;
    ozayn_sdo_init(&sdo, cred->id, OZAYN_DATA_CATEGORY_AUTH_INFO,
                   identity_id, OZAYN_DATA_SCOPE_USER);
    sdo.classification = OZAYN_SEC_LEVEL_HIGHLY_SENSITIVE;

    ozayn_vault_result_t vr = ozayn_vault_update(svc->config.vault, &sdo,
                                                   (const uint8_t *)hash_str,
                                                   sizeof(hash_str));
    if (vr != OZAYN_VAULT_OK) {
        _wipe_password(hash_str, sizeof(hash_str));
        return OZAYN_PWD_ERR_VAULT_FAILED;
    }

    /* Update local credential record */
    sodium_memzero(cred->hash_str, sizeof(cred->hash_str));
    strncpy(cred->hash_str, hash_str, sizeof(cred->hash_str) - 1);
    cred->version++;
    cred->modified_at = time(NULL);

    _wipe_password(hash_str, sizeof(hash_str));
    return OZAYN_PWD_OK;
}

/* ============================================================
 * CREDENTIAL STATE MANAGEMENT
 * ============================================================ */

ozayn_pwd_error_t ozayn_pwd_suspend(ozayn_pwd_service_t *svc,
                                     const char *identity_id)
{
    if (!svc || !identity_id)
        return OZAYN_PWD_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PWD_ERR_NOT_INITIALIZED;

    ozayn_pwd_credential_t *cred = _find_credential(svc, identity_id);
    if (!cred)
        return OZAYN_PWD_ERR_NOT_FOUND;

    if (ozayn_pwd_validate_credential_transition(cred->state,
                                                  OZAYN_PWD_CRED_SUSPENDED) != 0)
        return OZAYN_PWD_ERR_INVALID;

    cred->state = OZAYN_PWD_CRED_SUSPENDED;
    cred->modified_at = time(NULL);
    return OZAYN_PWD_OK;
}

ozayn_pwd_error_t ozayn_pwd_revoke(ozayn_pwd_service_t *svc,
                                    const char *identity_id)
{
    if (!svc || !identity_id)
        return OZAYN_PWD_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_PWD_ERR_NOT_INITIALIZED;

    ozayn_pwd_credential_t *cred = _find_credential(svc, identity_id);
    if (!cred)
        return OZAYN_PWD_ERR_NOT_FOUND;

    if (ozayn_pwd_validate_credential_transition(cred->state,
                                                  OZAYN_PWD_CRED_REVOKED) != 0)
        return OZAYN_PWD_ERR_INVALID;

    cred->state = OZAYN_PWD_CRED_REVOKED;
    cred->modified_at = time(NULL);
    return OZAYN_PWD_OK;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_pwd_service_is_initialized(const ozayn_pwd_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

int ozayn_pwd_service_credential_count(const ozayn_pwd_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->credential_count;
}

int ozayn_pwd_has_credential(const ozayn_pwd_service_t *svc,
                              const char *identity_id)
{
    if (!svc || !identity_id || !svc->initialized)
        return 0;
    return _find_credential((ozayn_pwd_service_t *)svc, identity_id) != NULL ? 1 : 0;
}

/* ============================================================
 * PASSWORD AUTH PROVIDER (implements ozayn_authn_provider_ops_t)
 * ============================================================ */

static int _pwd_provider_init(ozayn_authn_provider_t *provider)
{
    (void)provider;
    return 0;
}

static void _pwd_provider_shutdown(ozayn_authn_provider_t *provider)
{
    (void)provider;
}

static ozayn_authn_result_t _pwd_provider_authenticate(
    ozayn_authn_provider_t *provider,
    const ozayn_authn_request_t *request,
    ozayn_authn_response_t *out)
{
    (void)provider;
    (void)request;

    /* The password provider requires password data in the request.
     * Since Step 13's request struct does not carry password data,
     * this provider cannot directly authenticate through the generic
     * auth service flow. Instead, callers should use ozayn_pwd_verify()
     * directly or extend the auth request struct.
     *
     * For now, return UNAVAILABLE to indicate that the password
     * provider requires a specialized verification path. */
    (void)out;
    return OZAYN_AuthN_RESULT_UNAVAILABLE;
}

static int _pwd_provider_is_available(const ozayn_authn_provider_t *provider)
{
    (void)provider;
    return 1;
}

static ozayn_authn_method_t _pwd_provider_get_method(const ozayn_authn_provider_t *provider)
{
    (void)provider;
    return OZAYN_AuthN_METHOD_PASSWORD;
}

static const ozayn_authn_provider_ops_t _pwd_provider_ops = {
    .init          = _pwd_provider_init,
    .shutdown      = _pwd_provider_shutdown,
    .authenticate  = _pwd_provider_authenticate,
    .is_available  = _pwd_provider_is_available,
    .get_method    = _pwd_provider_get_method
};

void ozayn_pwd_provider_create(ozayn_authn_provider_t *provider,
                                ozayn_pwd_service_t *pwd_svc)
{
    if (!provider)
        return;
    memset(provider, 0, sizeof(*provider));
    provider->name = "password-provider";
    provider->ops = &_pwd_provider_ops;
    provider->impl_data = pwd_svc;
    provider->initialized = 1;
}
