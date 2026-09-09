/*
 * sec_response.h — Security Orchestration & Controlled Response Foundation (Step 34).
 *
 * Answers: "How do we ensure every security response passes through
 *           policy validation, authorization, assurance, controlled
 *           execution, verification, and audit — without bypassing
 *           any existing security boundary?"
 *
 * Core principle: A recommendation is not an authorization.
 *
 * RECOMMENDATION → RESPONSE PLAN → POLICY VALIDATION → AUTHORIZATION
 * → APPROVAL/ASSURANCE → CONTROLLED EXECUTION → VERIFICATION → AUDIT
 *
 * Deterministic, auditable, bounded, fail-safe.
 * No AI/ML, no autonomous destructive behavior, no arbitrary execution.
 * No bypass of authentication, MFA, session, authorization, RBAC, or policy.
 */

#ifndef OZAYN_SEC_RESPONSE_H
#define OZAYN_SEC_RESPONSE_H

#include "sec_risk.h"
#include "sec_intel.h"
#include "sec_alert.h"
#include "sec_config.h"
#include "incident.h"
#include "audit.h"
#include "authorization.h"
#include "session_management.h"
#include "identity.h"
#include "mfa.h"
#include "rbac.h"
#include "permission.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_OK                              =   0,
    OZAYN_SRESP_ERR_NULL                        =  -1,
    OZAYN_SRESP_ERR_NOT_INITIALIZED             =  -2,
    OZAYN_SRESP_ERR_ALREADY_INITIALIZED         =  -3,
    OZAYN_SRESP_ERR_INVALID_PARAM               =  -4,
    OZAYN_SRESP_ERR_LIMIT_REACHED               =  -5,
    OZAYN_SRESP_ERR_NOT_FOUND                   =  -6,
    OZAYN_SRESP_ERR_STATE_INVALID               =  -7,
    OZAYN_SRESP_ERR_STATE_TRANSITION            =  -8,
    OZAYN_SRESP_ERR_POLICY_DENIED               =  -9,
    OZAYN_SRESP_ERR_POLICY_UNAVAILABLE          = -10,
    OZAYN_SRESP_ERR_AUTHORIZATION_DENIED        = -11,
    OZAYN_SRESP_ERR_AUTHORIZATION_UNAVAILABLE   = -12,
    OZAYN_SRESP_ERR_ASSURANCE_REQUIRED          = -13,
    OZAYN_SRESP_ERR_APPROVAL_REQUIRED           = -14,
    OZAYN_SRESP_ERR_APPROVAL_INVALID            = -15,
    OZAYN_SRESP_ERR_PRECONDITION_FAILED         = -16,
    OZAYN_SRESP_ERR_TARGET_INVALID              = -17,
    OZAYN_SRESP_ERR_TARGET_UNAVAILABLE          = -18,
    OZAYN_SRESP_ERR_ACTION_UNSUPPORTED          = -19,
    OZAYN_SRESP_ERR_ACTION_INVALID              = -20,
    OZAYN_SRESP_ERR_EXECUTION_FAILED            = -21,
    OZAYN_SRESP_ERR_EXECUTION_PARTIAL           = -22,
    OZAYN_SRESP_ERR_EXECUTION_TIMEOUT           = -23,
    OZAYN_SRESP_ERR_VERIFICATION_FAILED         = -24,
    OZAYN_SRESP_ERR_CONCURRENCY_CONFLICT        = -25,
    OZAYN_SRESP_ERR_REPLAY_DETECTED             = -26,
    OZAYN_SRESP_ERR_RESOURCE_LIMIT              = -27,
    OZAYN_SRESP_ERR_EXPIRED                     = -28,
    OZAYN_SRESP_ERR_CANCELLED                   = -29,
    OZAYN_SRESP_ERR_INTEGRITY_FAILURE           = -30,
    OZAYN_SRESP_ERR_INTERNAL                    = -31
} ozayn_sresp_err_t;

/* ============================================================
 * SECTION 2 — RESPONSE ACTION TYPES
 * ============================================================
 *
 * Only explicitly defined, policy-controlled actions.
 * No generic EXECUTE_ANY_COMMAND or RUN_SHELL_COMMAND.
 */

typedef enum {
    OZAYN_SRESP_ACTION_NONE                     =  0,
    OZAYN_SRESP_ACTION_MONITOR                  =  1,
    OZAYN_SRESP_ACTION_INVESTIGATE              =  2,
    OZAYN_SRESP_ACTION_REQUIRE_REAUTH           =  3,
    OZAYN_SRESP_ACTION_REQUIRE_MFA              =  4,
    OZAYN_SRESP_ACTION_REVIEW_SESSION           =  5,
    OZAYN_SRESP_ACTION_REVOKE_SESSION           =  6,
    OZAYN_SRESP_ACTION_REVIEW_IDENTITY          =  7,
    OZAYN_SRESP_ACTION_SUSPEND_IDENTITY         =  8,
    OZAYN_SRESP_ACTION_REVIEW_PERMISSION        =  9,
    OZAYN_SRESP_ACTION_REVIEW_ROLE              = 10,
    OZAYN_SRESP_ACTION_REVIEW_KEY_STATE         = 11,
    OZAYN_SRESP_ACTION_RESTRICT_RESOURCE        = 12,
    OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN        = 13
} ozayn_sresp_action_type_t;

/* ============================================================
 * SECTION 3 — RESPONSE ACTION STATES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_STATE_CREATED                   =  0,
    OZAYN_SRESP_STATE_VALIDATING                =  1,
    OZAYN_SRESP_STATE_VALIDATED                 =  2,
    OZAYN_SRESP_STATE_AWAITING_APPROVAL         =  3,
    OZAYN_SRESP_STATE_APPROVED                  =  4,
    OZAYN_SRESP_STATE_EXECUTING                 =  5,
    OZAYN_SRESP_STATE_VERIFYING                 =  6,
    OZAYN_SRESP_STATE_SUCCEEDED                 =  7,
    OZAYN_SRESP_STATE_VALIDATION_FAILED         =  8,
    OZAYN_SRESP_STATE_REJECTED                  =  9,
    OZAYN_SRESP_STATE_CANCELLED                 = 10,
    OZAYN_SRESP_STATE_EXPIRED                   = 11,
    OZAYN_SRESP_STATE_FAILED                    = 12,
    OZAYN_SRESP_STATE_PARTIAL                   = 13
} ozayn_sresp_state_t;

/* ============================================================
 * SECTION 4 — EXECUTION MODES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_MODE_VALIDATE_ONLY              = 0,
    OZAYN_SRESP_MODE_DRY_RUN                    = 1,
    OZAYN_SRESP_MODE_APPROVED_EXECUTION         = 2
} ozayn_sresp_exec_mode_t;

/* ============================================================
 * SECTION 5 — ASSURANCE LEVELS
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_ASSURANCE_NONE                  = 0,
    OZAYN_SRESP_ASSURANCE_SINGLE                = 1,
    OZAYN_SRESP_ASSURANCE_MULTI                 = 2,
    OZAYN_SRESP_ASSURANCE_HIGH                  = 3
} ozayn_sresp_assurance_t;

/* ============================================================
 * SECTION 6 — ROLLBACK CAPABILITY
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_ROLLBACK_UNKNOWN                = 0,
    OZAYN_SRESP_ROLLBACK_REVERSIBLE             = 1,
    OZAYN_SRESP_ROLLBACK_PARTIALLY_REVERSIBLE   = 2,
    OZAYN_SRESP_ROLLBACK_NOT_REVERSIBLE         = 3
} ozayn_sresp_rollback_t;

/* ============================================================
 * SECTION 7 — VERIFICATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_VERIFY_NOT_REQUIRED             = 0,
    OZAYN_SRESP_VERIFY_PENDING                  = 1,
    OZAYN_SRESP_VERIFY_SUCCEEDED                = 2,
    OZAYN_SRESP_VERIFY_FAILED                   = 3
} ozayn_sresp_verify_state_t;

/* ============================================================
 * SECTION 8 — PLAN STATES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_PLAN_CREATED                    = 0,
    OZAYN_SRESP_PLAN_VALIDATING                 = 1,
    OZAYN_SRESP_PLAN_VALIDATED                  = 2,
    OZAYN_SRESP_PLAN_AWAITING_APPROVAL          = 3,
    OZAYN_SRESP_PLAN_APPROVED                   = 4,
    OZAYN_SRESP_PLAN_EXECUTING                  = 5,
    OZAYN_SRESP_PLAN_COMPLETED                  = 6,
    OZAYN_SRESP_PLAN_PARTIAL                    = 7,
    OZAYN_SRESP_PLAN_FAILED                     = 8,
    OZAYN_SRESP_PLAN_CANCELLED                  = 9,
    OZAYN_SRESP_PLAN_EXPIRED                    = 10
} ozayn_sresp_plan_state_t;

/* ============================================================
 * SECTION 9 — APPROVAL STATES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_APPROVAL_NOT_REQUIRED           = 0,
    OZAYN_SRESP_APPROVAL_PENDING                = 1,
    OZAYN_SRESP_APPROVAL_GRANTED                = 2,
    OZAYN_SRESP_APPROVAL_DENIED                 = 3,
    OZAYN_SRESP_APPROVAL_EXPIRED                = 4
} ozayn_sresp_approval_state_t;

/* ============================================================
 * SECTION 10 — PRECONDITION CHECK RESULTS
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_PRECOND_OK                      = 0,
    OZAYN_SRESP_PRECOND_RESPONSE_NOT_FOUND      = 1,
    OZAYN_SRESP_PRECOND_RESPONSE_EXPIRED        = 2,
    OZAYN_SRESP_PRECOND_INCIDENT_INVALID        = 3,
    OZAYN_SRESP_PRECOND_RISK_INVALID            = 4,
    OZAYN_SRESP_PRECOND_POLICY_INVALID          = 5,
    OZAYN_SRESP_PRECOND_AUTHORIZATION_INVALID   = 6,
    OZAYN_SRESP_PRECOND_ASSURANCE_MISSING       = 7,
    OZAYN_SRESP_PRECOND_TARGET_NOT_FOUND        = 8,
    OZAYN_SRESP_PRECOND_TARGET_STATE_INCOMPATIBLE = 9,
    OZAYN_SRESP_PRECOND_ALREADY_EXECUTED        = 10,
    OZAYN_SRESP_PRECOND_CANCELLED               = 11,
    OZAYN_SRESP_PRECOND_REPLAY_DETECTED         = 12,
    OZAYN_SRESP_PRECOND_DEPENDENCY_UNAVAILABLE  = 13,
    OZAYN_SRESP_PRECOND_LOCKDOWN_INCOMPATIBLE   = 14
} ozayn_sresp_precond_t;

/* ============================================================
 * SECTION 11 — EXPLANATION CODES
 * ============================================================ */

typedef enum {
    OZAYN_SRESP_EXPLAIN_NONE                    =  0,
    OZAYN_SRESP_EXPLAIN_POLICY_ALLOWED          =  1,
    OZAYN_SRESP_EXPLAIN_POLICY_DENIED           =  2,
    OZAYN_SRESP_EXPLAIN_AUTHORIZED              =  3,
    OZAYN_SRESP_EXPLAIN_UNAUTHORIZED            =  4,
    OZAYN_SRESP_EXPLAIN_ASSURANCE_MET           =  5,
    OZAYN_SRESP_EXPLAIN_ASSURANCE_INSUFFICIENT  =  6,
    OZAYN_SRESP_EXPLAIN_APPROVAL_GRANTED        =  7,
    OZAYN_SRESP_EXPLAIN_APPROVAL_DENIED         =  8,
    OZAYN_SRESP_EXPLAIN_APPROVAL_REQUIRED       =  9,
    OZAYN_SRESP_EXPLAIN_PRECONDITION_MET        = 10,
    OZAYN_SRESP_EXPLAIN_PRECONDITION_FAILED     = 11,
    OZAYN_SRESP_EXPLAIN_EXECUTION_SUCCEEDED     = 12,
    OZAYN_SRESP_EXPLAIN_EXECUTION_FAILED        = 13,
    OZAYN_SRESP_EXPLAIN_VERIFICATION_PASSED     = 14,
    OZAYN_SRESP_EXPLAIN_VERIFICATION_FAILED     = 15,
    OZAYN_SRESP_EXPLAIN_CONCURRENCY_CONFLICT    = 16,
    OZAYN_SRESP_EXPLAIN_REPLAY_DETECTED         = 17,
    OZAYN_SRESP_EXPLAIN_RESOURCE_LIMIT          = 18,
    OZAYN_SRESP_EXPLAIN_IDEMPOTENT_SKIP         = 19
} ozayn_sresp_explain_t;

/* ============================================================
 * SECTION 12 — CONSTANTS
 * ============================================================ */

#define OZAYN_SRESP_MAX_ID_LEN                  64
#define OZAYN_SRESP_MAX_META_LEN               256
#define OZAYN_SRESP_MAX_EXPLANATIONS            16
#define OZAYN_SRESP_MAX_ACTIONS_PER_PLAN        16
#define OZAYN_SRESP_MAX_PRECONDITIONS            8
#define OZAYN_SRESP_MAX_RESPONSES              256
#define OZAYN_SRESP_MAX_PLANS                   64
#define OZAYN_SRESP_MAX_EXECUTION_HISTORY      128

/* ============================================================
 * SECTION 13 — RESPONSE ACTION
 * ============================================================ */

typedef struct {
    /* Identity */
    char                     action_id[OZAYN_SRESP_MAX_ID_LEN];
    uint32_t                 action_version;

    /* Type */
    ozayn_sresp_action_type_t action_type;

    /* Source references */
    char                     source_component[OZAYN_SRESP_MAX_ID_LEN];
    char                     incident_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     risk_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     correlation_id[OZAYN_SRESP_MAX_ID_LEN];

    /* Target */
    char                     target_identity_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     target_session_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     target_resource_id[OZAYN_SRESP_MAX_ID_LEN];

    /* Assurance & authorization */
    ozayn_sresp_assurance_t  required_assurance;
    ozayn_sresp_approval_state_t approval_state;

    /* Execution */
    ozayn_sresp_exec_mode_t  execution_mode;
    ozayn_sresp_rollback_t   rollback_capability;
    ozayn_sresp_verify_state_t verification_state;

    /* Preconditions */
    int                      preconditions_met;

    /* State */
    ozayn_sresp_state_t      state;

    /* Explanation */
    int                      explanation_count;
    ozayn_sresp_explain_t    explanations[OZAYN_SRESP_MAX_EXPLANATIONS];

    /* Timing */
    time_t                   created_time;
    time_t                   expiration_time;
    time_t                   execution_time;
    time_t                   completion_time;
    time_t                   updated_time;

    /* Versioning (concurrency control) */
    uint32_t                 expected_version;

    /* Safe metadata */
    char                     safe_metadata[OZAYN_SRESP_MAX_META_LEN];
} ozayn_sresp_action_t;

/* ============================================================
 * SECTION 14 — RESPONSE PLAN
 * ============================================================ */

typedef struct {
    /* Identity */
    char                     plan_id[OZAYN_SRESP_MAX_ID_LEN];
    uint32_t                 plan_version;

    /* Source references */
    char                     incident_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     risk_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     decision_id[OZAYN_SRESP_MAX_ID_LEN];
    char                     correlation_id[OZAYN_SRESP_MAX_ID_LEN];

    /* Actions */
    int                      action_count;
    ozayn_sresp_action_t     actions[OZAYN_SRESP_MAX_ACTIONS_PER_PLAN];

    /* Policy */
    int                      policy_version_valid;
    int                      policy_checksum;

    /* Assurance & approval */
    ozayn_sresp_assurance_t  required_assurance;
    ozayn_sresp_approval_state_t approval_state;
    char                     approver_identity_id[OZAYN_SRESP_MAX_ID_LEN];

    /* Execution */
    ozayn_sresp_exec_mode_t  execution_mode;
    ozayn_sresp_plan_state_t state;

    /* Timing */
    time_t                   created_time;
    time_t                   expiration_time;
    time_t                   updated_time;

    /* Versioning (concurrency control) */
    uint32_t                 expected_version;

    /* Safe metadata */
    char                     safe_metadata[OZAYN_SRESP_MAX_META_LEN];
} ozayn_sresp_plan_t;

/* ============================================================
 * SECTION 15 — RESPONSE POLICY
 * ============================================================ */

typedef struct {
    int                      enabled;
    int                      max_plans;
    int                      max_actions_per_plan;
    int                      max_concurrent_executions;
    int                      max_queued_responses;
    int                      plan_retention_seconds;
    int                      approval_timeout_seconds;
    int                      execution_timeout_seconds;
    int                      max_retries;

    /* Assurance thresholds per action type (0=none, 1=single, 2=multi, 3=high) */
    int                      assurance_requirement[14];

    /* Approval required per action type (0=no, 1=yes) */
    int                      approval_required[14];

    /* Reversible per action type (0=unknown, 1=reversible, 2=partial, 3=not) */
    int                      rollback_capability[14];

    /* Integration toggles */
    int                      incident_integration_enabled;
    int                      alert_integration_enabled;
    int                      audit_integration_enabled;
} ozayn_sresp_policy_t;

/* ============================================================
 * SECTION 16 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_sr_service_t       *risk_service;
    ozayn_sintel_service_t   *intel_service;
    ozayn_ir_service_t       *incident_service;
    ozayn_salert_service_t   *alert_service;
    ozayn_sc_service_t       *config_service;
    ozayn_audit_service_t    *audit;
    ozayn_authz_service_t    *authz_service;
    ozayn_sess_service_t     *session_service;
    ozayn_identity_service_t *identity_service;
    ozayn_mfa_service_t      *mfa_service;
} ozayn_sresp_service_config_t;

/* ============================================================
 * SECTION 17 — EXECUTION HISTORY ENTRY
 * ============================================================ */

typedef struct {
    char                     action_id[OZAYN_SRESP_MAX_ID_LEN];
    ozayn_sresp_action_type_t action_type;
    ozayn_sresp_state_t      final_state;
    time_t                   execution_time;
    time_t                   completion_time;
    int                      result_code;
} ozayn_sresp_history_entry_t;

/* ============================================================
 * SECTION 18 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                      initialized;

    /* Plans */
    ozayn_sresp_plan_t       plans[OZAYN_SRESP_MAX_PLANS];
    int                      plan_head;
    int                      plan_count;
    uint32_t                 plan_sequence;

    /* Execution history */
    ozayn_sresp_history_entry_t history[OZAYN_SRESP_MAX_EXECUTION_HISTORY];
    int                      history_head;
    int                      history_count;

    /* Active execution count */
    int                      active_executions;

    /* Policy */
    ozayn_sresp_policy_t     policy;

    /* Dependencies (not owned) */
    ozayn_sr_service_t       *risk_service;
    ozayn_sintel_service_t   *intel_service;
    ozayn_ir_service_t       *incident_service;
    ozayn_salert_service_t   *alert_service;
    ozayn_sc_service_t       *config_service;
    ozayn_audit_service_t    *audit;
    ozayn_authz_service_t    *authz_service;
    ozayn_sess_service_t     *session_service;
    ozayn_identity_service_t *identity_service;
    ozayn_mfa_service_t      *mfa_service;

    /* Statistics */
    uint64_t                 total_plans_created;
    uint64_t                 total_plans_validated;
    uint64_t                 total_plans_approved;
    uint64_t                 total_plans_executed;
    uint64_t                 total_plans_succeeded;
    uint64_t                 total_plans_failed;
    uint64_t                 total_plans_cancelled;
    uint64_t                 total_plans_expired;
    uint64_t                 total_actions_executed;
    uint64_t                 total_actions_succeeded;
    uint64_t                 total_actions_failed;
    uint64_t                 total_policy_rejections;
    uint64_t                 total_auth_denials;
    uint64_t                 total_approval_requests;
    uint64_t                 total_idempotent_skips;
} ozayn_sresp_service_t;

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sresp_err_name(ozayn_sresp_err_t err);
const char *ozayn_sresp_action_name(ozayn_sresp_action_type_t action);
const char *ozayn_sresp_state_name(ozayn_sresp_state_t state);
const char *ozayn_sresp_exec_mode_name(ozayn_sresp_exec_mode_t mode);
const char *ozayn_sresp_assurance_name(ozayn_sresp_assurance_t a);
const char *ozayn_sresp_rollback_name(ozayn_sresp_rollback_t r);
const char *ozayn_sresp_verify_name(ozayn_sresp_verify_state_t v);
const char *ozayn_sresp_plan_state_name(ozayn_sresp_plan_state_t s);
const char *ozayn_sresp_approval_name(ozayn_sresp_approval_state_t a);
const char *ozayn_sresp_precond_name(ozayn_sresp_precond_t p);
const char *ozayn_sresp_explain_name(ozayn_sresp_explain_t e);

/* ============================================================
 * SECTION 20 — LIFECYCLE
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_service_init(
    ozayn_sresp_service_t *svc,
    const ozayn_sresp_service_config_t *cfg);

void ozayn_sresp_service_shutdown(ozayn_sresp_service_t *svc);

int ozayn_sresp_service_is_initialized(const ozayn_sresp_service_t *svc);

/* ============================================================
 * SECTION 21 — RESPONSE PLAN OPERATIONS
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_create_plan(
    ozayn_sresp_service_t *svc,
    const char *incident_id,
    const char *risk_id,
    const char *correlation_id,
    ozayn_sresp_plan_t **out_plan);

ozayn_sresp_err_t ozayn_sresp_add_action_to_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    ozayn_sresp_action_type_t action_type,
    const char *target_identity_id,
    const char *target_session_id,
    const char *target_resource_id,
    ozayn_sresp_action_t **out_action);

ozayn_sresp_plan_t *ozayn_sresp_get_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id);

int ozayn_sresp_plan_count(const ozayn_sresp_service_t *svc);

int ozayn_sresp_list_plans(
    const ozayn_sresp_service_t *svc,
    int filter_state,
    ozayn_sresp_plan_t **out_plans,
    int max_count);

/* ============================================================
 * SECTION 22 — POLICY VALIDATION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_validate_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id);

ozayn_sresp_err_t ozayn_sresp_validate_action(
    ozayn_sresp_service_t *svc,
    ozayn_sresp_action_t *action);

/* ============================================================
 * SECTION 23 — AUTHORIZATION CHECK
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_check_authorization(
    ozayn_sresp_service_t *svc,
    const char *plan_id);

/* ============================================================
 * SECTION 24 — ASSURANCE & APPROVAL
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_check_assurance(
    ozayn_sresp_service_t *svc,
    const char *plan_id);

ozayn_sresp_err_t ozayn_sresp_approve_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    const char *approver_identity_id);

ozayn_sresp_err_t ozayn_sresp_reject_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    const char *rejector_identity_id);

/* ============================================================
 * SECTION 25 — PRECONDITION CHECK
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_check_preconditions(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    ozayn_sresp_precond_t *out_result);

/* ============================================================
 * SECTION 26 — CONTROLLED EXECUTION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_execute_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    ozayn_sresp_exec_mode_t mode);

ozayn_sresp_err_t ozayn_sresp_execute_action(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    const char *action_id,
    ozayn_sresp_exec_mode_t mode);

/* ============================================================
 * SECTION 27 — VERIFICATION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_verify_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id);

/* ============================================================
 * SECTION 28 — CANCELLATION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_cancel_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id);

/* ============================================================
 * SECTION 29 — IDEMPOTENCY
 * ============================================================ */

int ozayn_sresp_is_duplicate_action(
    const ozayn_sresp_service_t *svc,
    const char *action_type_name,
    const char *target_id,
    const char *incident_id);

/* ============================================================
 * SECTION 30 — CONFLICT DETECTION
 * ============================================================ */

int ozayn_sresp_has_conflicting_action(
    const ozayn_sresp_service_t *svc,
    ozayn_sresp_action_type_t action_type,
    const char *target_id);

/* ============================================================
 * SECTION 31 — HISTORY
 * ============================================================ */

int ozayn_sresp_history_count(const ozayn_sresp_service_t *svc);

int ozayn_sresp_list_history(
    const ozayn_sresp_service_t *svc,
    ozayn_sresp_history_entry_t *out_entries,
    int max_count);

/* ============================================================
 * SECTION 32 — AUDIT
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_audit_event(
    ozayn_sresp_service_t *svc,
    const char *event_type,
    const char *detail);

/* ============================================================
 * SECTION 33 — POLICY
 * ============================================================ */

ozayn_sresp_policy_t ozayn_sresp_default_policy(void);

ozayn_sresp_err_t ozayn_sresp_set_policy(
    ozayn_sresp_service_t *svc,
    const ozayn_sresp_policy_t *policy);

const ozayn_sresp_policy_t *ozayn_sresp_get_policy(
    const ozayn_sresp_service_t *svc);

/* ============================================================
 * SECTION 34 — CLEANUP
 * ============================================================ */

int ozayn_sresp_cleanup_expired_plans(ozayn_sresp_service_t *svc);

/* ============================================================
 * SECTION 35 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sresp_plans_full(const ozayn_sresp_service_t *svc);
int ozayn_sresp_executions_at_limit(const ozayn_sresp_service_t *svc);

/* ============================================================
 * SECTION 36 — GLOBAL ACCESSOR
 * ============================================================ */

ozayn_sresp_service_t *ozayn_sresp_get_global(void);

/* ============================================================
 * SECTION 37 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_sresp_state_transition_valid(ozayn_sresp_state_t from, ozayn_sresp_state_t to);

int ozayn_sresp_plan_state_transition_valid(ozayn_sresp_plan_state_t from, ozayn_sresp_plan_state_t to);

/* ============================================================
 * SECTION 38 — ACTION TYPE VALIDATION
 * ============================================================ */

int ozayn_sresp_is_valid_action_type(int action_type);

int ozayn_sresp_action_requires_target(ozayn_sresp_action_type_t action_type);

#ifdef __cplusplus
}
#endif

#endif /* OZAYN_SEC_RESPONSE_H */
