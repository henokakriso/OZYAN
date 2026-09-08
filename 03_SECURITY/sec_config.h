#ifndef OZAYN_SEC_CONFIG_H
#define OZAYN_SEC_CONFIG_H

#include "attempt_control.h"
#include "mfa.h"
#include "session_management.h"
#include "authorization.h"
#include "rbac.h"
#include "permission.h"
#include "key_lifecycle.h"
#include "secure_vault.h"
#include "password_auth.h"
#include "backup.h"
#include "deletion.h"
#include "audit.h"
#include "incident.h"
#include "data_classification.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * sec_config.h — Security Policy & Configuration Hardening Foundation
 *                (Step 26).
 *
 * Provides centralized security policy management, configuration
 * validation, secure defaults, policy versioning, atomic activation,
 * and audit integration for all security subsystems.
 *
 * Architecture:
 *   CONFIGURATION SOURCE
 *          ↓
 *      VALIDATE
 *          ↓
 *   SECURITY POLICY
 *          ↓
 *   POLICY CONSUMERS
 *
 * Design principles:
 *   - Centralized policy: single source of truth
 *   - No secrets in policy: secrets belong in vault/key storage
 *   - Fail-closed: invalid config is rejected
 *   - Secure defaults: missing config defaults to safest state
 *   - Atomic activation: validate all, then commit all
 *   - Audit integration: all changes are auditable
 *   - No bypass: no debug switches, no developer overrides
 */

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SC_OK                                 =   0,
    OZAYN_SC_ERR                                =  -1,
    OZAYN_SC_ERR_NULL                           =  -2,
    OZAYN_SC_ERR_NOT_INITIALIZED                =  -3,
    OZAYN_SC_ERR_ALREADY_INITIALIZED            =  -4,
    OZAYN_SC_ERR_INVALID_REQUEST                =  -5,
    OZAYN_SC_ERR_INVALID_VERSION                =  -6,
    OZAYN_SC_ERR_INVALID_FIELD                  =  -7,
    OZAYN_SC_ERR_INVALID_VALUE                  =  -8,
    OZAYN_SC_ERR_OUT_OF_RANGE                   =  -9,
    OZAYN_SC_ERR_VALIDATION_FAILED              = -10,
    OZAYN_SC_ERR_CROSS_FIELD_INVALID            = -11,
    OZAYN_SC_ERR_INCOMPATIBLE_VERSION           = -12,
    OZAYN_SC_ERR_MUTABILITY_VIOLATION           = -13,
    OZAYN_SC_ERR_UNAUTHORIZED                   = -14,
    OZAYN_SC_ERR_POLICY_INTEGRITY               = -15,
    OZAYN_SC_ERR_POLICY_NOT_ACTIVE              = -16,
    OZAYN_SC_ERR_POLICY_ACTIVATION_FAILED       = -17,
    OZAYN_SC_ERR_AUDIT_FAILURE                  = -18,
    OZAYN_SC_ERR_SECRET_IN_POLICY               = -19,
    OZAYN_SC_ERR_INSECURE_CONFIGURATION         = -20,
    OZAYN_SC_ERR_MANDATORY_FIELD_MISSING        = -21,
    OZAYN_SC_ERR_NO_ACTIVE_POLICY               = -22,
    OZAYN_SC_ERR_CONFIGURATION_LOCKED           = -23
} ozayn_sc_result_t;

/* ============================================================
 * SECTION 2 — CONFIGURATION VALUE CLASSIFICATION
 * ============================================================ */

typedef enum {
    OZAYN_SC_CLASS_PUBLIC                       = 0,
    OZAYN_SC_CLASS_INTERNAL                     = 1,
    OZAYN_SC_CLASS_SECURITY_SENSITIVE           = 2,
    OZAYN_SC_CLASS_SECRET                       = 3
} ozayn_sc_class_t;

/* ============================================================
 * SECTION 3 — FIELD MUTABILITY
 * ============================================================ */

typedef enum {
    OZAYN_SC_MUTABLE_RUNTIME                    = 0,
    OZAYN_SC_MUTABLE_RESTART_REQUIRED           = 1,
    OZAYN_SC_MUTABLE_INSTALLATION_ONLY          = 2,
    OZAYN_SC_IMMUTABLE                           = 3
} ozayn_sc_mutability_t;

/* ============================================================
 * SECTION 4 — POLICY VERSION STATE
 * ============================================================ */

typedef enum {
    OZAYN_SC_POLICY_STATE_SUPPORTED             = 0,
    OZAYN_SC_POLICY_STATE_SUPPORTED_MIGRATION   = 1,
    OZAYN_SC_POLICY_STATE_UNSUPPORTED           = 2,
    OZAYN_SC_POLICY_STATE_INVALID               = 3,
    OZAYN_SC_POLICY_STATE_CORRUPTED             = 4
} ozayn_sc_policy_state_t;

/* ============================================================
 * SECTION 5 — AUTHENTICATION POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     require_identity_state_active;
    int     require_credential_valid;
    int     auth_timeout_seconds;
    int     max_concurrent_auth_attempts;
} ozayn_sc_authn_policy_t;

/* ============================================================
 * SECTION 6 — PASSWORD POLICY
 * ============================================================ */

typedef struct {
    int     min_length;
    int     max_length;
    int     enabled;
} ozayn_sc_pwd_policy_t;

/* ============================================================
 * SECTION 7 — ATTEMPT CONTROL POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     max_failures;
    int     window_seconds;
    int     initial_delay_ms;
    int     max_delay_ms;
    double  backoff_multiplier;
    int     block_seconds;
    int     counter_reset_seconds;
} ozayn_sc_ac_policy_t;

/* ============================================================
 * SECTION 8 — MFA POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     required_factor_count;
    int     transaction_timeout_seconds;
    int     factor_timeout_seconds;
    int     max_failures;
    int     block_seconds;
} ozayn_sc_mfa_policy_t;

/* ============================================================
 * SECTION 9 — SESSION POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     max_sessions_total;
    int     max_sessions_per_identity;
    int     idle_timeout_seconds;
    int     absolute_lifetime_seconds;
} ozayn_sc_sess_policy_t;

/* ============================================================
 * SECTION 10 — AUTHORIZATION POLICY
 * ============================================================ */

typedef struct {
    int     default_deny;
    int     require_resource;
    int     require_action;
    int     require_scope;
} ozayn_sc_authz_policy_t;

/* ============================================================
 * SECTION 11 — RBAC POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     require_explicit_roles;
    int     max_roles_per_identity;
    int     max_permissions_per_role;
} ozayn_sc_rbac_policy_t;

/* ============================================================
 * SECTION 12 — PERMISSION POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     default_deny_unknown;
    int     require_explicit_grant;
    int     max_permissions;
} ozayn_sc_perm_policy_t;

/* ============================================================
 * SECTION 13 — KEY MANAGEMENT POLICY
 * ============================================================ */

typedef struct {
    int     require_active_key;
    int     max_key_versions;
    int     rotation_required;
    int     rotation_interval_seconds;
    int     require_retirement_before_revoke;
} ozayn_sc_key_policy_t;

/* ============================================================
 * SECTION 14 — CRYPTOGRAPHIC POLICY
 * ============================================================ */

typedef struct {
    int     require_protection;
    int     min_security_level;
    int     reject_obsolete_algorithms;
} ozayn_sc_crypto_policy_t;

/* ============================================================
 * SECTION 15 — VAULT POLICY
 * ============================================================ */

typedef struct {
    int     require_encryption;
    int     require_integrity;
    int     max_object_size;
    int     require_classification;
} ozayn_sc_vault_policy_t;

/* ============================================================
 * SECTION 16 — BACKUP POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     require_integrity;
    int     require_protection;
    int     require_audit;
    uint64_t max_backup_size;
    int     max_object_count;
    int     retention_days;
} ozayn_sc_bk_policy_t;

/* ============================================================
 * SECTION 17 — DELETION POLICY
 * ============================================================ */

typedef struct {
    int     require_authorization;
    int     require_mfa_for_sensitive;
    int     require_mfa_for_keys;
    int     verify_after_delete;
    int     max_batch_size;
} ozayn_sc_del_policy_t;

/* ============================================================
 * SECTION 18 — AUDIT POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     minimum_severity;
    int     retention_events;
    int     retention_seconds;
    int     require_identity;
    int     mandatory_event_protection;
} ozayn_sc_audit_policy_t;

/* ============================================================
 * SECTION 19 — INCIDENT RESPONSE POLICY
 * ============================================================ */

typedef struct {
    int     max_incidents;
    int     auto_contain_critical;
    int     require_mfa_for_recovery;
    int     lockdown_threshold;
    int     dedup_window_seconds;
    int     min_lockdown_severity;
} ozayn_sc_ir_policy_t;

/* ============================================================
 * SECTION 20 — RESOURCE LIMITS
 * ============================================================ */

typedef struct {
    int     max_policy_size;
    int     max_sub_policy_fields;
    int     max_role_definitions;
    int     max_permission_definitions;
    int     max_config_history;
} ozayn_sc_resource_limits_t;

/* ============================================================
 * SECTION 21 — UNIFIED SECURITY POLICY
 * ============================================================ */

#define OZAYN_SC_POLICY_VERSION_MAJOR    1
#define OZAYN_SC_POLICY_VERSION_MINOR    0
#define OZAYN_SC_POLICY_VERSION_PATCH    0
#define OZAYN_SC_MAX_POLICY_ID_LEN       64
#define OZAYN_SC_MAX_CONFIG_HISTORY      8

typedef struct {
    char                        policy_id[OZAYN_SC_MAX_POLICY_ID_LEN];
    uint32_t                    schema_version;
    uint32_t                    policy_version;
    uint32_t                    config_version;
    time_t                      created_at;
    time_t                      activated_at;

    /* Sub-policies */
    ozayn_sc_authn_policy_t     authentication;
    ozayn_sc_pwd_policy_t       password;
    ozayn_sc_ac_policy_t        attempt_control;
    ozayn_sc_mfa_policy_t       mfa;
    ozayn_sc_sess_policy_t      session;
    ozayn_sc_authz_policy_t     authorization;
    ozayn_sc_rbac_policy_t      rbac;
    ozayn_sc_perm_policy_t      permission;
    ozayn_sc_key_policy_t       key_management;
    ozayn_sc_crypto_policy_t    cryptographic;
    ozayn_sc_vault_policy_t     vault;
    ozayn_sc_bk_policy_t        backup;
    ozayn_sc_del_policy_t       deletion;
    ozayn_sc_audit_policy_t     audit;
    ozayn_sc_ir_policy_t        incident_response;
    ozayn_sc_resource_limits_t  resource_limits;
} ozayn_sc_policy_t;

/* ============================================================
 * SECTION 22 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_audit_service_t      *audit;
} ozayn_sc_service_config_t;

/* ============================================================
 * SECTION 23 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                         initialized;
    ozayn_sc_policy_t           active_policy;
    ozayn_sc_policy_t           staged_policy;
    int                         has_staged;
    int                         locked;

    /* Policy history (metadata only) */
    struct {
        uint32_t    policy_version;
        uint32_t    config_version;
        time_t      activated_at;
    } history[OZAYN_SC_MAX_CONFIG_HISTORY];
    int                         history_count;

    /* Dependencies (not owned) */
    ozayn_audit_service_t      *audit;

    /* Stats */
    uint64_t                    total_activations;
    uint64_t                    total_rejections;
    uint64_t                    total_validations;
    uint64_t                    total_validation_failures;
} ozayn_sc_service_t;

/* ============================================================
 * SECTION 24 — LIFECYCLE
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_service_init(ozayn_sc_service_t *svc,
                                         const ozayn_sc_service_config_t *cfg);

void              ozayn_sc_service_shutdown(ozayn_sc_service_t *svc);

int               ozayn_sc_service_is_initialized(const ozayn_sc_service_t *svc);

/* ============================================================
 * SECTION 25 — DEFAULT POLICY
 * ============================================================ */

ozayn_sc_policy_t ozayn_sc_default_policy(void);

/* ============================================================
 * SECTION 26 — POLICY VALIDATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_validate_policy(const ozayn_sc_policy_t *policy);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_authn(
    const ozayn_sc_authn_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_password(
    const ozayn_sc_pwd_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_attempt_control(
    const ozayn_sc_ac_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_mfa(
    const ozayn_sc_mfa_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_session(
    const ozayn_sc_sess_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_authorization(
    const ozayn_sc_authz_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_rbac(
    const ozayn_sc_rbac_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_permission(
    const ozayn_sc_perm_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_key(
    const ozayn_sc_key_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_crypto(
    const ozayn_sc_crypto_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_vault(
    const ozayn_sc_vault_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_backup(
    const ozayn_sc_bk_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_deletion(
    const ozayn_sc_del_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_audit(
    const ozayn_sc_audit_policy_t *p);

ozayn_sc_result_t ozayn_sc_validate_sub_policy_incident(
    const ozayn_sc_ir_policy_t *p);

/* ============================================================
 * SECTION 27 — CROSS-FIELD VALIDATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_validate_cross_field(
    const ozayn_sc_policy_t *policy);

/* ============================================================
 * SECTION 28 — POLICY GET / SET (STAGED)
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_get_active_policy(
    const ozayn_sc_service_t *svc,
    ozayn_sc_policy_t *out_policy);

ozayn_sc_result_t ozayn_sc_get_staged_policy(
    const ozayn_sc_service_t *svc,
    ozayn_sc_policy_t *out_policy);

ozayn_sc_result_t ozayn_sc_stage_policy(ozayn_sc_service_t *svc,
                                         const ozayn_sc_policy_t *policy);

/* ============================================================
 * SECTION 29 — POLICY ACTIVATION
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_activate(ozayn_sc_service_t *svc);

ozayn_sc_result_t ozayn_sc_reject_staged(ozayn_sc_service_t *svc);

/* ============================================================
 * SECTION 30 — POLICY LOCK
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_lock(ozayn_sc_service_t *svc);

ozayn_sc_result_t ozayn_sc_unlock(ozayn_sc_service_t *svc);

int               ozayn_sc_is_locked(const ozayn_sc_service_t *svc);

/* ============================================================
 * SECTION 31 — POLICY HISTORY
 * ============================================================ */

int ozayn_sc_get_history_count(const ozayn_sc_service_t *svc);

ozayn_sc_result_t ozayn_sc_get_history_entry(
    const ozayn_sc_service_t *svc,
    int index,
    uint32_t *out_policy_version,
    uint32_t *out_config_version,
    time_t *out_activated_at);

/* ============================================================
 * SECTION 32 — POLICY COMPATIBILITY
 * ============================================================ */

ozayn_sc_policy_state_t ozayn_sc_check_compatibility(
    uint32_t schema_version);

/* ============================================================
 * SECTION 33 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sc_result_name(ozayn_sc_result_t r);

const char *ozayn_sc_class_name(ozayn_sc_class_t c);

const char *ozayn_sc_mutability_name(ozayn_sc_mutability_t m);

const char *ozayn_sc_policy_state_name(ozayn_sc_policy_state_t s);

/* ============================================================
 * SECTION 34 — SECRET PROHIBITION CHECK
 * ============================================================ */

ozayn_sc_result_t ozayn_sc_check_no_secrets(
    const ozayn_sc_policy_t *policy);

/* ============================================================
 * SECTION 35 — GLOBAL SERVICE ACCESSOR
 * ============================================================ */

ozayn_sc_service_t *ozayn_sc_get_global(void);

#endif /* OZAYN_SEC_CONFIG_H */
