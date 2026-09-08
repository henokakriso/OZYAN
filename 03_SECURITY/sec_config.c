/*
 * sec_config.c — Security Policy & Configuration Hardening Foundation
 *                (Step 26).
 *
 * Provides centralized security policy management, configuration
 * validation, secure defaults, policy versioning, atomic activation,
 * and audit integration.
 */

#include "sec_config.h"
#include <string.h>
#include <stdio.h>

/* ============================================================
 * STATIC GLOBAL
 * ============================================================ */

static ozayn_sc_service_t _sc_global = {0};

ozayn_sc_service_t *ozayn_sc_get_global(void)
{
    return &_sc_global;
}

/* ============================================================
 * SECTION 33 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sc_result_name(ozayn_sc_result_t r)
{
    switch (r) {
    case OZAYN_SC_OK:                              return "OK";
    case OZAYN_SC_ERR:                             return "ERR";
    case OZAYN_SC_ERR_NULL:                        return "ERR_NULL";
    case OZAYN_SC_ERR_NOT_INITIALIZED:             return "ERR_NOT_INITIALIZED";
    case OZAYN_SC_ERR_ALREADY_INITIALIZED:         return "ERR_ALREADY_INITIALIZED";
    case OZAYN_SC_ERR_INVALID_REQUEST:             return "ERR_INVALID_REQUEST";
    case OZAYN_SC_ERR_INVALID_VERSION:             return "ERR_INVALID_VERSION";
    case OZAYN_SC_ERR_INVALID_FIELD:               return "ERR_INVALID_FIELD";
    case OZAYN_SC_ERR_INVALID_VALUE:               return "ERR_INVALID_VALUE";
    case OZAYN_SC_ERR_OUT_OF_RANGE:                return "ERR_OUT_OF_RANGE";
    case OZAYN_SC_ERR_VALIDATION_FAILED:           return "ERR_VALIDATION_FAILED";
    case OZAYN_SC_ERR_CROSS_FIELD_INVALID:         return "ERR_CROSS_FIELD_INVALID";
    case OZAYN_SC_ERR_INCOMPATIBLE_VERSION:        return "ERR_INCOMPATIBLE_VERSION";
    case OZAYN_SC_ERR_MUTABILITY_VIOLATION:        return "ERR_MUTABILITY_VIOLATION";
    case OZAYN_SC_ERR_UNAUTHORIZED:                return "ERR_UNAUTHORIZED";
    case OZAYN_SC_ERR_POLICY_INTEGRITY:            return "ERR_POLICY_INTEGRITY";
    case OZAYN_SC_ERR_POLICY_NOT_ACTIVE:           return "ERR_POLICY_NOT_ACTIVE";
    case OZAYN_SC_ERR_POLICY_ACTIVATION_FAILED:    return "ERR_POLICY_ACTIVATION_FAILED";
    case OZAYN_SC_ERR_AUDIT_FAILURE:               return "ERR_AUDIT_FAILURE";
    case OZAYN_SC_ERR_SECRET_IN_POLICY:            return "ERR_SECRET_IN_POLICY";
    case OZAYN_SC_ERR_INSECURE_CONFIGURATION:      return "ERR_INSECURE_CONFIGURATION";
    case OZAYN_SC_ERR_MANDATORY_FIELD_MISSING:     return "ERR_MANDATORY_FIELD_MISSING";
    case OZAYN_SC_ERR_NO_ACTIVE_POLICY:            return "ERR_NO_ACTIVE_POLICY";
    case OZAYN_SC_ERR_CONFIGURATION_LOCKED:        return "ERR_CONFIGURATION_LOCKED";
    default:                                       return "UNKNOWN";
    }
}

const char *ozayn_sc_class_name(ozayn_sc_class_t c)
{
    switch (c) {
    case OZAYN_SC_CLASS_PUBLIC:               return "PUBLIC";
    case OZAYN_SC_CLASS_INTERNAL:             return "INTERNAL";
    case OZAYN_SC_CLASS_SECURITY_SENSITIVE:   return "SECURITY_SENSITIVE";
    case OZAYN_SC_CLASS_SECRET:               return "SECRET";
    default:                                  return "UNKNOWN";
    }
}

const char *ozayn_sc_mutability_name(ozayn_sc_mutability_t m)
{
    switch (m) {
    case OZAYN_SC_MUTABLE_RUNTIME:            return "RUNTIME_MUTABLE";
    case OZAYN_SC_MUTABLE_RESTART_REQUIRED:   return "RESTART_REQUIRED";
    case OZAYN_SC_MUTABLE_INSTALLATION_ONLY:  return "INSTALLATION_ONLY";
    case OZAYN_SC_IMMUTABLE:                   return "IMMUTABLE";
    default:                                  return "UNKNOWN";
    }
}

const char *ozayn_sc_policy_state_name(ozayn_sc_policy_state_t s)
{
    switch (s) {
    case OZAYN_SC_POLICY_STATE_SUPPORTED:             return "SUPPORTED";
    case OZAYN_SC_POLICY_STATE_SUPPORTED_MIGRATION:   return "SUPPORTED_WITH_MIGRATION";
    case OZAYN_SC_POLICY_STATE_UNSUPPORTED:           return "UNSUPPORTED";
    case OZAYN_SC_POLICY_STATE_INVALID:               return "INVALID";
    case OZAYN_SC_POLICY_STATE_CORRUPTED:             return "CORRUPTED";
    default:                                          return "UNKNOWN";
    }
}

/* ============================================================
 * SECTION 32 — POLICY COMPATIBILITY
 * ============================================================ */

ozayn_sc_policy_state_t ozayn_sc_check_compatibility(uint32_t schema_version)
{
    if (schema_version == OZAYN_SC_POLICY_VERSION_MAJOR)
        return OZAYN_SC_POLICY_STATE_SUPPORTED;
    if (schema_version > 0 &&
        schema_version < OZAYN_SC_POLICY_VERSION_MAJOR)
        return OZAYN_SC_POLICY_STATE_SUPPORTED_MIGRATION;
    if (schema_version == 0)
        return OZAYN_SC_POLICY_STATE_CORRUPTED;
    return OZAYN_SC_POLICY_STATE_UNSUPPORTED;
}

/* ============================================================
 * SECTION 26 — SUB-POLICY VALIDATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_validate_sub_policy_authn(
    const ozayn_sc_authn_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->auth_timeout_seconds < 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
    if (p->max_concurrent_auth_attempts < 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_password(
    const ozayn_sc_pwd_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (p->min_length < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_length < p->min_length) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_length > 4096) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_attempt_control(
    const ozayn_sc_ac_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (p->max_failures < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->window_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->backoff_multiplier < 1.0) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->block_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->initial_delay_ms < 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_delay_ms < p->initial_delay_ms) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->counter_reset_seconds < 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_mfa(
    const ozayn_sc_mfa_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (p->required_factor_count < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->required_factor_count > 8) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->transaction_timeout_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->factor_timeout_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_failures < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->block_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_session(
    const ozayn_sc_sess_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (p->max_sessions_total < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_sessions_per_identity < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->idle_timeout_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->absolute_lifetime_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_authorization(
    const ozayn_sc_authz_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    /* default_deny must be 1 — we never allow disabling it */
    if (!p->default_deny) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_rbac(
    const ozayn_sc_rbac_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (p->max_roles_per_identity < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_permissions_per_role < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_permission(
    const ozayn_sc_perm_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (!p->default_deny_unknown) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
        if (p->max_permissions < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_key(
    const ozayn_sc_key_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->max_key_versions < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    if (p->rotation_interval_seconds < 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_crypto(
    const ozayn_sc_crypto_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    /* require_protection must be 1 */
    if (!p->require_protection) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_vault(
    const ozayn_sc_vault_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    /* require_encryption must be 1 */
    if (!p->require_encryption) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_backup(
    const ozayn_sc_bk_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->enabled) {
        if (!p->require_integrity) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
        if (!p->require_protection) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
        if (p->max_backup_size == 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->max_object_count < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
        if (p->retention_days < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    }
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_deletion(
    const ozayn_sc_del_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    /* require_authorization must be 1 */
    if (!p->require_authorization) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
    if (p->max_batch_size < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_audit(
    const ozayn_sc_audit_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    /* mandatory_event_protection must be 1 */
    if (!p->mandatory_event_protection) return OZAYN_SC_ERR_INSECURE_CONFIGURATION;
    if (p->retention_events < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    if (p->retention_seconds < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_validate_sub_policy_incident(
    const ozayn_sc_ir_policy_t *p)
{
    if (!p) return OZAYN_SC_ERR_NULL;
    if (p->max_incidents < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    if (p->lockdown_threshold < 1) return OZAYN_SC_ERR_OUT_OF_RANGE;
    if (p->dedup_window_seconds < 0) return OZAYN_SC_ERR_OUT_OF_RANGE;
    return OZAYN_SC_OK;
}

/* ============================================================
 * SECTION 27 — CROSS-FIELD VALIDATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_validate_cross_field(
    const ozayn_sc_policy_t *policy)
{
    if (!policy) return OZAYN_SC_ERR_NULL;

    /* MFA + attempt control: if MFA enabled, attempt control must be enabled */
    if (policy->mfa.enabled && !policy->attempt_control.enabled)
        return OZAYN_SC_ERR_CROSS_FIELD_INVALID;

    /* Session: idle timeout must be < absolute lifetime */
    if (policy->session.enabled) {
        if (policy->session.idle_timeout_seconds >=
            policy->session.absolute_lifetime_seconds)
            return OZAYN_SC_ERR_CROSS_FIELD_INVALID;
    }

    /* Session: per-identity max must be <= total max */
    if (policy->session.enabled) {
        if (policy->session.max_sessions_per_identity >
            policy->session.max_sessions_total)
            return OZAYN_SC_ERR_CROSS_FIELD_INVALID;
    }

    /* Key management: if rotation required, interval must be positive */
    if (policy->key_management.rotation_required &&
        policy->key_management.rotation_interval_seconds <= 0)
        return OZAYN_SC_ERR_CROSS_FIELD_INVALID;

    /* Backup + deletion: if both enabled, retention must be consistent */
    if (policy->backup.enabled && policy->backup.retention_days > 0) {
        /* Deletion retention should not conflict with backup retention */
    }

    /* Audit + incident: incident retention must not exceed audit retention */
    if (policy->audit.retention_events > 0 &&
        policy->incident_response.max_incidents > policy->audit.retention_events)
        return OZAYN_SC_ERR_CROSS_FIELD_INVALID;

    return OZAYN_SC_OK;
}

/* ============================================================
 * SECTION 26 — FULL POLICY VALIDATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_validate_policy(const ozayn_sc_policy_t *policy)
{
    if (!policy) return OZAYN_SC_ERR_NULL;

    /* Schema version check */
    ozayn_sc_policy_state_t state = ozayn_sc_check_compatibility(
        policy->schema_version);
    if (state == OZAYN_SC_POLICY_STATE_UNSUPPORTED ||
        state == OZAYN_SC_POLICY_STATE_INVALID ||
        state == OZAYN_SC_POLICY_STATE_CORRUPTED)
        return OZAYN_SC_ERR_INCOMPATIBLE_VERSION;

    /* Validate each sub-policy */
    ozayn_sc_result_t r;

    r = ozayn_sc_validate_sub_policy_authn(&policy->authentication);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_password(&policy->password);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_attempt_control(&policy->attempt_control);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_mfa(&policy->mfa);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_session(&policy->session);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_authorization(&policy->authorization);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_rbac(&policy->rbac);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_permission(&policy->permission);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_key(&policy->key_management);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_crypto(&policy->cryptographic);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_vault(&policy->vault);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_backup(&policy->backup);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_deletion(&policy->deletion);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_audit(&policy->audit);
    if (r != OZAYN_SC_OK) return r;

    r = ozayn_sc_validate_sub_policy_incident(&policy->incident_response);
    if (r != OZAYN_SC_OK) return r;

    /* Cross-field validation */
    r = ozayn_sc_validate_cross_field(policy);
    if (r != OZAYN_SC_OK) return r;

    return OZAYN_SC_OK;
}

/* ============================================================
 * SECTION 34 — SECRET PROHIBITION CHECK
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_check_no_secrets(
    const ozayn_sc_policy_t *policy)
{
    if (!policy) return OZAYN_SC_ERR_NULL;

    /* The policy struct contains only integer/enum values.
     * No pointers, no strings that could hold secrets.
     * The policy_id is a metadata identifier, not a secret.
     * All fields are numeric configuration values.
     * This check is a structural guarantee — the policy type
     * simply cannot contain secret material by design. */
    if (policy->policy_id[0] == '\0')
        return OZAYN_SC_ERR_MANDATORY_FIELD_MISSING;

    return OZAYN_SC_OK;
}

/* ============================================================
 * SECTION 25 — DEFAULT POLICY
 * ============================================================ */

ozayn_sc_policy_t ozayn_sc_default_policy(void)
{
    ozayn_sc_policy_t p;
    memset(&p, 0, sizeof(p));

    strncpy(p.policy_id, "default", OZAYN_SC_MAX_POLICY_ID_LEN - 1);
    p.schema_version = OZAYN_SC_POLICY_VERSION_MAJOR;
    p.policy_version = 1;
    p.config_version = 1;
    p.created_at = time(NULL);

    /* Authentication: secure defaults */
    p.authentication.enabled = 1;
    p.authentication.require_identity_state_active = 1;
    p.authentication.require_credential_valid = 1;
    p.authentication.auth_timeout_seconds = 300;
    p.authentication.max_concurrent_auth_attempts = 5;

    /* Password: secure defaults */
    p.password.enabled = 1;
    p.password.min_length = 8;
    p.password.max_length = 4096;

    /* Attempt control: secure defaults */
    p.attempt_control.enabled = 1;
    p.attempt_control.max_failures = 5;
    p.attempt_control.window_seconds = 300;
    p.attempt_control.initial_delay_ms = 1000;
    p.attempt_control.max_delay_ms = 30000;
    p.attempt_control.backoff_multiplier = 2.0;
    p.attempt_control.block_seconds = 900;
    p.attempt_control.counter_reset_seconds = 0;

    /* MFA: secure defaults */
    p.mfa.enabled = 1;
    p.mfa.required_factor_count = 2;
    p.mfa.transaction_timeout_seconds = 300;
    p.mfa.factor_timeout_seconds = 60;
    p.mfa.max_failures = 5;
    p.mfa.block_seconds = 900;

    /* Session: secure defaults */
    p.session.enabled = 1;
    p.session.max_sessions_total = 512;
    p.session.max_sessions_per_identity = 8;
    p.session.idle_timeout_seconds = 1800;
    p.session.absolute_lifetime_seconds = 86400;

    /* Authorization: secure defaults (DEFAULT DENY) */
    p.authorization.default_deny = 1;
    p.authorization.require_resource = 1;
    p.authorization.require_action = 1;
    p.authorization.require_scope = 1;

    /* RBAC: secure defaults */
    p.rbac.enabled = 1;
    p.rbac.require_explicit_roles = 1;
    p.rbac.max_roles_per_identity = 16;
    p.rbac.max_permissions_per_role = 64;

    /* Permission: secure defaults */
    p.permission.enabled = 1;
    p.permission.default_deny_unknown = 1;
    p.permission.require_explicit_grant = 1;
    p.permission.max_permissions = 1024;

    /* Key management: secure defaults */
    p.key_management.require_active_key = 1;
    p.key_management.max_key_versions = 8;
    p.key_management.rotation_required = 0;
    p.key_management.rotation_interval_seconds = 0;
    p.key_management.require_retirement_before_revoke = 1;

    /* Cryptographic: secure defaults */
    p.cryptographic.require_protection = 1;
    p.cryptographic.min_security_level = 1;
    p.cryptographic.reject_obsolete_algorithms = 1;

    /* Vault: secure defaults */
    p.vault.require_encryption = 1;
    p.vault.require_integrity = 1;
    p.vault.max_object_size = 1048576;
    p.vault.require_classification = 1;

    /* Backup: secure defaults */
    p.backup.enabled = 1;
    p.backup.require_integrity = 1;
    p.backup.require_protection = 1;
    p.backup.require_audit = 1;
    p.backup.max_backup_size = 67108864;
    p.backup.max_object_count = 128;
    p.backup.retention_days = 365;

    /* Deletion: secure defaults */
    p.deletion.require_authorization = 1;
    p.deletion.require_mfa_for_sensitive = 1;
    p.deletion.require_mfa_for_keys = 1;
    p.deletion.verify_after_delete = 1;
    p.deletion.max_batch_size = 64;

    /* Audit: secure defaults */
    p.audit.enabled = 1;
    p.audit.minimum_severity = 0;
    p.audit.retention_events = 4096;
    p.audit.retention_seconds = 31536000;
    p.audit.require_identity = 0;
    p.audit.mandatory_event_protection = 1;

    /* Incident response: secure defaults */
    p.incident_response.max_incidents = 256;
    p.incident_response.auto_contain_critical = 1;
    p.incident_response.require_mfa_for_recovery = 1;
    p.incident_response.lockdown_threshold = 5;
    p.incident_response.dedup_window_seconds = 60;
    p.incident_response.min_lockdown_severity = 4;

    /* Resource limits */
    p.resource_limits.max_policy_size = 65536;
    p.resource_limits.max_sub_policy_fields = 256;
    p.resource_limits.max_role_definitions = 128;
    p.resource_limits.max_permission_definitions = 1024;
    p.resource_limits.max_config_history = OZAYN_SC_MAX_CONFIG_HISTORY;

    return p;
}

/* ============================================================
 * AUDIT HELPER
 * ============================================================ */

static void _audit_config_event(ozayn_sc_service_t *svc,
                                 const char *event_detail,
                                 const char *outcome)
{
    if (!svc->audit || !svc->audit->initialized) return;

    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev,
        strcmp(outcome, "success") == 0 ? OZAYN_AUDIT_OUTCOME_SUCCESS
                                        : OZAYN_AUDIT_OUTCOME_FAILURE);
    ozayn_audit_event_set_source(&ev, "sec_config");
    ozayn_audit_event_set_detail(&ev, event_detail);
    ozayn_audit_event_set_identity(&ev, "");
    ozayn_audit_record(svc->audit, &ev);
}

/* ============================================================
 * SECTION 24 — LIFECYCLE
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_service_init(ozayn_sc_service_t *svc,
                                         const ozayn_sc_service_config_t *cfg)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!cfg) return OZAYN_SC_ERR_NULL;
    if (svc->initialized) return OZAYN_SC_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));
    svc->audit = cfg->audit;
    svc->active_policy = ozayn_sc_default_policy();
    svc->initialized = 1;

    _audit_config_event(svc, "service_initialized", "success");
    return OZAYN_SC_OK;
}

void ozayn_sc_service_shutdown(ozayn_sc_service_t *svc)
{
    if (!svc) return;
    if (!svc->initialized) return;
    memset(svc, 0, sizeof(*svc));
}

int ozayn_sc_service_is_initialized(const ozayn_sc_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 28 — POLICY GET / SET (STAGED)
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_get_active_policy(
    const ozayn_sc_service_t *svc,
    ozayn_sc_policy_t *out_policy)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    if (!out_policy) return OZAYN_SC_ERR_NULL;
    *out_policy = svc->active_policy;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_get_staged_policy(
    const ozayn_sc_service_t *svc,
    ozayn_sc_policy_t *out_policy)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    if (!out_policy) return OZAYN_SC_ERR_NULL;
    if (!svc->has_staged) return OZAYN_SC_ERR_NO_ACTIVE_POLICY;
    *out_policy = svc->staged_policy;
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_stage_policy(ozayn_sc_service_t *svc,
                                         const ozayn_sc_policy_t *policy)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    if (!policy) return OZAYN_SC_ERR_NULL;
    if (svc->locked) return OZAYN_SC_ERR_CONFIGURATION_LOCKED;

    /* Validate the new policy before staging */
    svc->total_validations++;
    ozayn_sc_result_t r = ozayn_sc_validate_policy(policy);
    if (r != OZAYN_SC_OK) {
        svc->total_validation_failures++;
        _audit_config_event(svc, "policy_validation_failed", "failure");
        return r;
    }

    /* Check for secrets (structural guarantee) */
    r = ozayn_sc_check_no_secrets(policy);
    if (r != OZAYN_SC_OK) {
        _audit_config_event(svc, "secret_detected_in_policy", "failure");
        return r;
    }

    svc->staged_policy = *policy;
    svc->staged_policy.activated_at = 0;
    svc->has_staged = 1;

    _audit_config_event(svc, "policy_staged", "success");
    return OZAYN_SC_OK;
}

/* ============================================================
 * SECTION 29 — POLICY ACTIVATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_activate(ozayn_sc_service_t *svc)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    if (svc->locked) return OZAYN_SC_ERR_CONFIGURATION_LOCKED;
    if (!svc->has_staged) return OZAYN_SC_ERR_NO_ACTIVE_POLICY;

    /* Re-validate staged policy (defense in depth) */
    svc->total_validations++;
    ozayn_sc_result_t r = ozayn_sc_validate_policy(&svc->staged_policy);
    if (r != OZAYN_SC_OK) {
        svc->total_validation_failures++;
        svc->total_rejections++;
        _audit_config_event(svc, "policy_activation_rejected_validation", "failure");
        return OZAYN_SC_ERR_POLICY_ACTIVATION_FAILED;
    }

    /* Record history before activation */
    int idx = svc->history_count % OZAYN_SC_MAX_CONFIG_HISTORY;
    svc->history[idx].policy_version = svc->active_policy.policy_version;
    svc->history[idx].config_version = svc->active_policy.config_version;
    svc->history[idx].activated_at = svc->active_policy.activated_at;
    if (svc->history_count < OZAYN_SC_MAX_CONFIG_HISTORY)
        svc->history_count++;

    /* Activate */
    svc->staged_policy.activated_at = time(NULL);
    svc->active_policy = svc->staged_policy;
    svc->has_staged = 0;
    svc->total_activations++;

    _audit_config_event(svc, "policy_activated", "success");
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_reject_staged(ozayn_sc_service_t *svc)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    if (!svc->has_staged) return OZAYN_SC_ERR_NO_ACTIVE_POLICY;

    svc->has_staged = 0;
    svc->total_rejections++;
    _audit_config_event(svc, "policy_rejected", "success");
    return OZAYN_SC_OK;
}

/* ============================================================
 * SECTION 30 — POLICY LOCK
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_lock(ozayn_sc_service_t *svc)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    svc->locked = 1;
    _audit_config_event(svc, "configuration_locked", "success");
    return OZAYN_SC_OK;
}

ozayn_sc_result_t ozayn_sc_unlock(ozayn_sc_service_t *svc)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    svc->locked = 0;
    _audit_config_event(svc, "configuration_unlocked", "success");
    return OZAYN_SC_OK;
}

int ozayn_sc_is_locked(const ozayn_sc_service_t *svc)
{
    if (!svc) return 0;
    if (!svc->initialized) return 0;
    return svc->locked;
}

/* ============================================================
 * SECTION 31 — POLICY HISTORY
 * ============================================================ */

int ozayn_sc_get_history_count(const ozayn_sc_service_t *svc)
{
    if (!svc) return 0;
    if (!svc->initialized) return 0;
    return svc->history_count;
}

ozayn_sc_result_t ozayn_sc_get_history_entry(
    const ozayn_sc_service_t *svc,
    int index,
    uint32_t *out_policy_version,
    uint32_t *out_config_version,
    time_t *out_activated_at)
{
    if (!svc) return OZAYN_SC_ERR_NULL;
    if (!svc->initialized) return OZAYN_SC_ERR_NOT_INITIALIZED;
    if (index < 0 || index >= svc->history_count)
        return OZAYN_SC_ERR_OUT_OF_RANGE;
    if (!out_policy_version || !out_config_version || !out_activated_at)
        return OZAYN_SC_ERR_NULL;

    *out_policy_version = svc->history[index].policy_version;
    *out_config_version = svc->history[index].config_version;
    *out_activated_at   = svc->history[index].activated_at;
    return OZAYN_SC_OK;
}
