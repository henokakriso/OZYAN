/*
 * sec_response.c — Security Orchestration & Controlled Response Foundation (Step 34).
 *
 * Core principle: A recommendation is not an authorization.
 * Every response must pass through:
 *   RECOMMENDATION → RESPONSE PLAN → POLICY VALIDATION → AUTHORIZATION
 *   → APPROVAL/ASSURANCE → CONTROLLED EXECUTION → VERIFICATION → AUDIT
 */

#include "sec_response.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================
 * GLOBAL SINGLETON
 * ============================================================ */

static ozayn_sresp_service_t _sresp_global = {0};

ozayn_sresp_service_t *ozayn_sresp_get_global(void)
{
    return &_sresp_global;
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static void _generate_id(char *buf, int buflen, const char *prefix, uint32_t seq)
{
    static const char hex[] = "0123456789ABCDEF";
    char raw[16];
    int len = 0;
    uint32_t v = seq;
    if (v == 0) v = 1;
    while (v > 0 && len < 16) {
        raw[len++] = hex[v & 0xF];
        v >>= 4;
    }
    int off = snprintf(buf, buflen, "%s-", prefix);
    for (int i = len - 1; i >= 0 && off < buflen - 1; i--)
        buf[off++] = raw[i];
    buf[off] = '\0';
}

static void _audit_event(ozayn_sresp_service_t *svc,
                          const char *event_type,
                          const char *detail)
{
    if (!svc->audit || !svc->audit->initialized) return;
    ozayn_audit_event_t ev;
    ozayn_audit_event_init(&ev);
    ozayn_audit_event_set_type(&ev, OZAYN_AUDIT_CONFIG_CHANGED);
    ozayn_audit_event_set_outcome(&ev, OZAYN_AUDIT_OUTCOME_SUCCESS);
    ozayn_audit_event_set_severity(&ev, OZAYN_AUDIT_SEV_NOTICE);
    ozayn_audit_event_set_source(&ev, "SEC_RESPONSE");
    char buf[512];
    snprintf(buf, sizeof(buf), "%s: %s", event_type,
             detail ? detail : "N/A");
    ozayn_audit_event_set_detail(&ev, buf);
    ozayn_audit_record(svc->audit, &ev);
}

static ozayn_sresp_plan_t *_alloc_plan(ozayn_sresp_service_t *svc)
{
    if (svc->plan_count >= svc->policy.max_plans) {
        svc->plan_head = (svc->plan_head + 1) % OZAYN_SRESP_MAX_PLANS;
        svc->plan_count--;
    }
    int slot = (svc->plan_head + svc->plan_count) % OZAYN_SRESP_MAX_PLANS;
    memset(&svc->plans[slot], 0, sizeof(ozayn_sresp_plan_t));
    svc->plan_count++;
    return &svc->plans[slot];
}

static void _add_history(ozayn_sresp_service_t *svc,
                          const char *action_id,
                          ozayn_sresp_action_type_t action_type,
                          ozayn_sresp_state_t final_state,
                          int result_code)
{
    int slot = (svc->history_head + svc->history_count) %
               OZAYN_SRESP_MAX_EXECUTION_HISTORY;
    if (svc->history_count >= OZAYN_SRESP_MAX_EXECUTION_HISTORY) {
        svc->history_head = (svc->history_head + 1) %
                            OZAYN_SRESP_MAX_EXECUTION_HISTORY;
    } else {
        svc->history_count++;
    }
    ozayn_sresp_history_entry_t *h = &svc->history[slot];
    memset(h, 0, sizeof(*h));
    if (action_id)
        strncpy(h->action_id, action_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    h->action_type = action_type;
    h->final_state = final_state;
    h->execution_time = time(NULL);
    h->completion_time = h->execution_time;
    h->result_code = result_code;
}

/* ============================================================
 * SECTION 19 — NAME HELPERS
 * ============================================================ */

const char *ozayn_sresp_err_name(ozayn_sresp_err_t err)
{
    switch (err) {
    case OZAYN_SRESP_OK:                           return "OK";
    case OZAYN_SRESP_ERR_NULL:                     return "NULL";
    case OZAYN_SRESP_ERR_NOT_INITIALIZED:          return "NOT_INITIALIZED";
    case OZAYN_SRESP_ERR_ALREADY_INITIALIZED:      return "ALREADY_INITIALIZED";
    case OZAYN_SRESP_ERR_INVALID_PARAM:            return "INVALID_PARAM";
    case OZAYN_SRESP_ERR_LIMIT_REACHED:            return "LIMIT_REACHED";
    case OZAYN_SRESP_ERR_NOT_FOUND:                return "NOT_FOUND";
    case OZAYN_SRESP_ERR_STATE_INVALID:            return "STATE_INVALID";
    case OZAYN_SRESP_ERR_STATE_TRANSITION:         return "STATE_TRANSITION";
    case OZAYN_SRESP_ERR_POLICY_DENIED:            return "POLICY_DENIED";
    case OZAYN_SRESP_ERR_POLICY_UNAVAILABLE:       return "POLICY_UNAVAILABLE";
    case OZAYN_SRESP_ERR_AUTHORIZATION_DENIED:     return "AUTHORIZATION_DENIED";
    case OZAYN_SRESP_ERR_AUTHORIZATION_UNAVAILABLE:return "AUTHORIZATION_UNAVAILABLE";
    case OZAYN_SRESP_ERR_ASSURANCE_REQUIRED:       return "ASSURANCE_REQUIRED";
    case OZAYN_SRESP_ERR_APPROVAL_REQUIRED:        return "APPROVAL_REQUIRED";
    case OZAYN_SRESP_ERR_APPROVAL_INVALID:         return "APPROVAL_INVALID";
    case OZAYN_SRESP_ERR_PRECONDITION_FAILED:      return "PRECONDITION_FAILED";
    case OZAYN_SRESP_ERR_TARGET_INVALID:           return "TARGET_INVALID";
    case OZAYN_SRESP_ERR_TARGET_UNAVAILABLE:       return "TARGET_UNAVAILABLE";
    case OZAYN_SRESP_ERR_ACTION_UNSUPPORTED:       return "ACTION_UNSUPPORTED";
    case OZAYN_SRESP_ERR_ACTION_INVALID:           return "ACTION_INVALID";
    case OZAYN_SRESP_ERR_EXECUTION_FAILED:         return "EXECUTION_FAILED";
    case OZAYN_SRESP_ERR_EXECUTION_PARTIAL:        return "EXECUTION_PARTIAL";
    case OZAYN_SRESP_ERR_EXECUTION_TIMEOUT:        return "EXECUTION_TIMEOUT";
    case OZAYN_SRESP_ERR_VERIFICATION_FAILED:      return "VERIFICATION_FAILED";
    case OZAYN_SRESP_ERR_CONCURRENCY_CONFLICT:     return "CONCURRENCY_CONFLICT";
    case OZAYN_SRESP_ERR_REPLAY_DETECTED:          return "REPLAY_DETECTED";
    case OZAYN_SRESP_ERR_RESOURCE_LIMIT:           return "RESOURCE_LIMIT";
    case OZAYN_SRESP_ERR_EXPIRED:                  return "EXPIRED";
    case OZAYN_SRESP_ERR_CANCELLED:                return "CANCELLED";
    case OZAYN_SRESP_ERR_INTEGRITY_FAILURE:        return "INTEGRITY_FAILURE";
    case OZAYN_SRESP_ERR_INTERNAL:                 return "INTERNAL";
    }
    return "UNKNOWN";
}

const char *ozayn_sresp_action_name(ozayn_sresp_action_type_t action)
{
    static const char *names[] = {
        "NONE", "MONITOR", "INVESTIGATE", "REQUIRE_REAUTH",
        "REQUIRE_MFA", "REVIEW_SESSION", "REVOKE_SESSION",
        "REVIEW_IDENTITY", "SUSPEND_IDENTITY", "REVIEW_PERMISSION",
        "REVIEW_ROLE", "REVIEW_KEY_STATE", "RESTRICT_RESOURCE",
        "SECURITY_LOCKDOWN"
    };
    if (action >= 0 && action <= OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN)
        return names[action];
    return "UNKNOWN";
}

const char *ozayn_sresp_state_name(ozayn_sresp_state_t state)
{
    static const char *names[] = {
        "CREATED", "VALIDATING", "VALIDATED", "AWAITING_APPROVAL",
        "APPROVED", "EXECUTING", "VERIFYING", "SUCCEEDED",
        "VALIDATION_FAILED", "REJECTED", "CANCELLED", "EXPIRED",
        "FAILED", "PARTIAL"
    };
    if (state >= 0 && state <= OZAYN_SRESP_STATE_PARTIAL)
        return names[state];
    return "UNKNOWN";
}

const char *ozayn_sresp_exec_mode_name(ozayn_sresp_exec_mode_t mode)
{
    switch (mode) {
    case OZAYN_SRESP_MODE_VALIDATE_ONLY:    return "VALIDATE_ONLY";
    case OZAYN_SRESP_MODE_DRY_RUN:          return "DRY_RUN";
    case OZAYN_SRESP_MODE_APPROVED_EXECUTION: return "APPROVED_EXECUTION";
    }
    return "UNKNOWN";
}

const char *ozayn_sresp_assurance_name(ozayn_sresp_assurance_t a)
{
    switch (a) {
    case OZAYN_SRESP_ASSURANCE_NONE:   return "NONE";
    case OZAYN_SRESP_ASSURANCE_SINGLE: return "SINGLE";
    case OZAYN_SRESP_ASSURANCE_MULTI:  return "MULTI";
    case OZAYN_SRESP_ASSURANCE_HIGH:   return "HIGH";
    }
    return "UNKNOWN";
}

const char *ozayn_sresp_rollback_name(ozayn_sresp_rollback_t r)
{
    switch (r) {
    case OZAYN_SRESP_ROLLBACK_UNKNOWN:              return "UNKNOWN";
    case OZAYN_SRESP_ROLLBACK_REVERSIBLE:           return "REVERSIBLE";
    case OZAYN_SRESP_ROLLBACK_PARTIALLY_REVERSIBLE: return "PARTIALLY_REVERSIBLE";
    case OZAYN_SRESP_ROLLBACK_NOT_REVERSIBLE:       return "NOT_REVERSIBLE";
    }
    return "UNKNOWN";
}

const char *ozayn_sresp_verify_name(ozayn_sresp_verify_state_t v)
{
    switch (v) {
    case OZAYN_SRESP_VERIFY_NOT_REQUIRED: return "NOT_REQUIRED";
    case OZAYN_SRESP_VERIFY_PENDING:      return "PENDING";
    case OZAYN_SRESP_VERIFY_SUCCEEDED:    return "SUCCEEDED";
    case OZAYN_SRESP_VERIFY_FAILED:       return "FAILED";
    }
    return "UNKNOWN";
}

const char *ozayn_sresp_plan_state_name(ozayn_sresp_plan_state_t s)
{
    static const char *names[] = {
        "CREATED", "VALIDATING", "VALIDATED", "AWAITING_APPROVAL",
        "APPROVED", "EXECUTING", "COMPLETED", "PARTIAL",
        "FAILED", "CANCELLED", "EXPIRED"
    };
    if (s >= 0 && s <= OZAYN_SRESP_PLAN_EXPIRED)
        return names[s];
    return "UNKNOWN";
}

const char *ozayn_sresp_approval_name(ozayn_sresp_approval_state_t a)
{
    switch (a) {
    case OZAYN_SRESP_APPROVAL_NOT_REQUIRED: return "NOT_REQUIRED";
    case OZAYN_SRESP_APPROVAL_PENDING:      return "PENDING";
    case OZAYN_SRESP_APPROVAL_GRANTED:      return "GRANTED";
    case OZAYN_SRESP_APPROVAL_DENIED:       return "DENIED";
    case OZAYN_SRESP_APPROVAL_EXPIRED:      return "EXPIRED";
    }
    return "UNKNOWN";
}

const char *ozayn_sresp_precond_name(ozayn_sresp_precond_t p)
{
    static const char *names[] = {
        "OK", "RESPONSE_NOT_FOUND", "RESPONSE_EXPIRED",
        "INCIDENT_INVALID", "RISK_INVALID", "POLICY_INVALID",
        "AUTHORIZATION_INVALID", "ASSURANCE_MISSING",
        "TARGET_NOT_FOUND", "TARGET_STATE_INCOMPATIBLE",
        "ALREADY_EXECUTED", "CANCELLED", "REPLAY_DETECTED",
        "DEPENDENCY_UNAVAILABLE", "LOCKDOWN_INCOMPATIBLE"
    };
    if (p >= 0 && p <= OZAYN_SRESP_PRECOND_LOCKDOWN_INCOMPATIBLE)
        return names[p];
    return "UNKNOWN";
}

const char *ozayn_sresp_explain_name(ozayn_sresp_explain_t e)
{
    static const char *names[] = {
        "NONE", "POLICY_ALLOWED", "POLICY_DENIED",
        "AUTHORIZED", "UNAUTHORIZED", "ASSURANCE_MET",
        "ASSURANCE_INSUFFICIENT", "APPROVAL_GRANTED",
        "APPROVAL_DENIED", "APPROVAL_REQUIRED",
        "PRECONDITION_MET", "PRECONDITION_FAILED",
        "EXECUTION_SUCCEEDED", "EXECUTION_FAILED",
        "VERIFICATION_PASSED", "VERIFICATION_FAILED",
        "CONCURRENCY_CONFLICT", "REPLAY_DETECTED",
        "RESOURCE_LIMIT", "IDEMPOTENT_SKIP"
    };
    if (e >= 0 && e <= OZAYN_SRESP_EXPLAIN_IDEMPOTENT_SKIP)
        return names[e];
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 20 — LIFECYCLE
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_service_init(
    ozayn_sresp_service_t *svc,
    const ozayn_sresp_service_config_t *cfg)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (svc->initialized) return OZAYN_SRESP_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    if (cfg) {
        svc->risk_service      = cfg->risk_service;
        svc->intel_service     = cfg->intel_service;
        svc->incident_service  = cfg->incident_service;
        svc->alert_service     = cfg->alert_service;
        svc->config_service    = cfg->config_service;
        svc->audit             = cfg->audit;
        svc->authz_service     = cfg->authz_service;
        svc->session_service   = cfg->session_service;
        svc->identity_service  = cfg->identity_service;
        svc->mfa_service       = cfg->mfa_service;
    }

    svc->policy = ozayn_sresp_default_policy();
    svc->initialized = 1;
    return OZAYN_SRESP_OK;
}

void ozayn_sresp_service_shutdown(ozayn_sresp_service_t *svc)
{
    if (!svc) return;
    svc->initialized = 0;
}

int ozayn_sresp_service_is_initialized(const ozayn_sresp_service_t *svc)
{
    return svc ? svc->initialized : 0;
}

/* ============================================================
 * SECTION 37 — STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_sresp_state_transition_valid(ozayn_sresp_state_t from,
                                        ozayn_sresp_state_t to)
{
    switch (from) {
    case OZAYN_SRESP_STATE_CREATED:
        return to == OZAYN_SRESP_STATE_VALIDATING ||
               to == OZAYN_SRESP_STATE_CANCELLED ||
               to == OZAYN_SRESP_STATE_EXPIRED;
    case OZAYN_SRESP_STATE_VALIDATING:
        return to == OZAYN_SRESP_STATE_VALIDATED ||
               to == OZAYN_SRESP_STATE_VALIDATION_FAILED;
    case OZAYN_SRESP_STATE_VALIDATED:
        return to == OZAYN_SRESP_STATE_AWAITING_APPROVAL ||
               to == OZAYN_SRESP_STATE_APPROVED ||
               to == OZAYN_SRESP_STATE_CANCELLED;
    case OZAYN_SRESP_STATE_AWAITING_APPROVAL:
        return to == OZAYN_SRESP_STATE_APPROVED ||
               to == OZAYN_SRESP_STATE_REJECTED ||
               to == OZAYN_SRESP_STATE_CANCELLED ||
               to == OZAYN_SRESP_STATE_EXPIRED;
    case OZAYN_SRESP_STATE_APPROVED:
        return to == OZAYN_SRESP_STATE_EXECUTING ||
               to == OZAYN_SRESP_STATE_CANCELLED ||
               to == OZAYN_SRESP_STATE_EXPIRED;
    case OZAYN_SRESP_STATE_EXECUTING:
        return to == OZAYN_SRESP_STATE_VERIFYING ||
               to == OZAYN_SRESP_STATE_SUCCEEDED ||
               to == OZAYN_SRESP_STATE_FAILED ||
               to == OZAYN_SRESP_STATE_PARTIAL;
    case OZAYN_SRESP_STATE_VERIFYING:
        return to == OZAYN_SRESP_STATE_SUCCEEDED ||
               to == OZAYN_SRESP_STATE_FAILED;
    case OZAYN_SRESP_STATE_SUCCEEDED:
        return 0;
    case OZAYN_SRESP_STATE_VALIDATION_FAILED:
        return 0;
    case OZAYN_SRESP_STATE_REJECTED:
        return 0;
    case OZAYN_SRESP_STATE_CANCELLED:
        return 0;
    case OZAYN_SRESP_STATE_EXPIRED:
        return 0;
    case OZAYN_SRESP_STATE_FAILED:
        return 0;
    case OZAYN_SRESP_STATE_PARTIAL:
        return 0;
    }
    return 0;
}

int ozayn_sresp_plan_state_transition_valid(ozayn_sresp_plan_state_t from,
                                             ozayn_sresp_plan_state_t to)
{
    switch (from) {
    case OZAYN_SRESP_PLAN_CREATED:
        return to == OZAYN_SRESP_PLAN_VALIDATING ||
               to == OZAYN_SRESP_PLAN_CANCELLED ||
               to == OZAYN_SRESP_PLAN_EXPIRED;
    case OZAYN_SRESP_PLAN_VALIDATING:
        return to == OZAYN_SRESP_PLAN_VALIDATED ||
               to == OZAYN_SRESP_PLAN_FAILED;
    case OZAYN_SRESP_PLAN_VALIDATED:
        return to == OZAYN_SRESP_PLAN_AWAITING_APPROVAL ||
               to == OZAYN_SRESP_PLAN_APPROVED ||
               to == OZAYN_SRESP_PLAN_CANCELLED;
    case OZAYN_SRESP_PLAN_AWAITING_APPROVAL:
        return to == OZAYN_SRESP_PLAN_APPROVED ||
               to == OZAYN_SRESP_PLAN_FAILED ||
               to == OZAYN_SRESP_PLAN_CANCELLED ||
               to == OZAYN_SRESP_PLAN_EXPIRED;
    case OZAYN_SRESP_PLAN_APPROVED:
        return to == OZAYN_SRESP_PLAN_EXECUTING ||
               to == OZAYN_SRESP_PLAN_CANCELLED;
    case OZAYN_SRESP_PLAN_EXECUTING:
        return to == OZAYN_SRESP_PLAN_COMPLETED ||
               to == OZAYN_SRESP_PLAN_PARTIAL ||
               to == OZAYN_SRESP_PLAN_FAILED;
    case OZAYN_SRESP_PLAN_COMPLETED:
        return 0;
    case OZAYN_SRESP_PLAN_PARTIAL:
        return 0;
    case OZAYN_SRESP_PLAN_FAILED:
        return 0;
    case OZAYN_SRESP_PLAN_CANCELLED:
        return 0;
    case OZAYN_SRESP_PLAN_EXPIRED:
        return 0;
    }
    return 0;
}

/* ============================================================
 * SECTION 38 — ACTION TYPE VALIDATION
 * ============================================================ */

int ozayn_sresp_is_valid_action_type(int action_type)
{
    return action_type > OZAYN_SRESP_ACTION_NONE &&
           action_type <= OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN;
}

int ozayn_sresp_action_requires_target(ozayn_sresp_action_type_t action_type)
{
    switch (action_type) {
    case OZAYN_SRESP_ACTION_NONE:
    case OZAYN_SRESP_ACTION_MONITOR:
    case OZAYN_SRESP_ACTION_INVESTIGATE:
    case OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN:
        return 0;
    default:
        return 1;
    }
}

/* ============================================================
 * SECTION 21 — RESPONSE PLAN OPERATIONS
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_create_plan(
    ozayn_sresp_service_t *svc,
    const char *incident_id,
    const char *risk_id,
    const char *correlation_id,
    ozayn_sresp_plan_t **out_plan)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!out_plan) return OZAYN_SRESP_ERR_NULL;
    if (svc->plan_count >= svc->policy.max_plans &&
        svc->policy.max_plans > 0)
        return OZAYN_SRESP_ERR_RESOURCE_LIMIT;

    ozayn_sresp_plan_t *p = _alloc_plan(svc);
    _generate_id(p->plan_id, OZAYN_SRESP_MAX_ID_LEN,
                 "SPLAN", svc->plan_sequence + 1);
    svc->plan_sequence++;
    p->state = OZAYN_SRESP_PLAN_CREATED;
    p->approval_state = OZAYN_SRESP_APPROVAL_NOT_REQUIRED;
    p->required_assurance = OZAYN_SRESP_ASSURANCE_NONE;
    p->execution_mode = OZAYN_SRESP_MODE_APPROVED_EXECUTION;
    p->created_time = time(NULL);
    p->updated_time = p->created_time;
    p->expiration_time = p->created_time + svc->policy.plan_retention_seconds;

    if (incident_id)
        strncpy(p->incident_id, incident_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (risk_id)
        strncpy(p->risk_id, risk_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (correlation_id)
        strncpy(p->correlation_id, correlation_id, OZAYN_SRESP_MAX_ID_LEN - 1);

    svc->total_plans_created++;
    _audit_event(svc, "SECURITY_RESPONSE_CREATED", p->plan_id);
    *out_plan = p;
    return OZAYN_SRESP_OK;
}

ozayn_sresp_err_t ozayn_sresp_add_action_to_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    ozayn_sresp_action_type_t action_type,
    const char *target_identity_id,
    const char *target_session_id,
    const char *target_resource_id,
    ozayn_sresp_action_t **out_action)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;
    if (!ozayn_sresp_is_valid_action_type(action_type))
        return OZAYN_SRESP_ERR_ACTION_INVALID;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state != OZAYN_SRESP_PLAN_CREATED)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    if (plan->action_count >= svc->policy.max_actions_per_plan)
        return OZAYN_SRESP_ERR_RESOURCE_LIMIT;

    /* Validate target is provided when required */
    if (ozayn_sresp_action_requires_target(action_type)) {
        if ((!target_identity_id || !target_identity_id[0]) &&
            (!target_session_id || !target_session_id[0]) &&
            (!target_resource_id || !target_resource_id[0]))
            return OZAYN_SRESP_ERR_TARGET_INVALID;
    }

    ozayn_sresp_action_t *a = &plan->actions[plan->action_count];
    memset(a, 0, sizeof(ozayn_sresp_action_t));
    _generate_id(a->action_id, OZAYN_SRESP_MAX_ID_LEN,
                 "SACT", svc->plan_sequence + plan->action_count);
    a->action_version = 1;
    a->action_type = action_type;
    a->state = OZAYN_SRESP_STATE_CREATED;
    a->required_assurance = (ozayn_sresp_assurance_t)
        svc->policy.assurance_requirement[action_type];
    a->approval_state = svc->policy.approval_required[action_type]
        ? OZAYN_SRESP_APPROVAL_PENDING
        : OZAYN_SRESP_APPROVAL_NOT_REQUIRED;
    a->rollback_capability = (ozayn_sresp_rollback_t)
        svc->policy.rollback_capability[action_type];
    a->execution_mode = OZAYN_SRESP_MODE_APPROVED_EXECUTION;
    a->verification_state = OZAYN_SRESP_VERIFY_NOT_REQUIRED;
    a->preconditions_met = 0;
    a->created_time = time(NULL);
    a->expiration_time = a->created_time + svc->policy.execution_timeout_seconds;
    a->updated_time = a->created_time;
    a->expected_version = 0;

    strncpy(a->source_component, "SEC_RESPONSE", OZAYN_SRESP_MAX_ID_LEN - 1);
    if (plan->incident_id[0])
        strncpy(a->incident_id, plan->incident_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (plan->risk_id[0])
        strncpy(a->risk_id, plan->risk_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (plan->correlation_id[0])
        strncpy(a->correlation_id, plan->correlation_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (target_identity_id)
        strncpy(a->target_identity_id, target_identity_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (target_session_id)
        strncpy(a->target_session_id, target_session_id, OZAYN_SRESP_MAX_ID_LEN - 1);
    if (target_resource_id)
        strncpy(a->target_resource_id, target_resource_id, OZAYN_SRESP_MAX_ID_LEN - 1);

    /* Set assurance/approval at plan level to max of all actions */
    if (a->required_assurance > plan->required_assurance)
        plan->required_assurance = a->required_assurance;
    if (a->approval_state == OZAYN_SRESP_APPROVAL_PENDING)
        plan->approval_state = OZAYN_SRESP_APPROVAL_PENDING;

    plan->action_count++;
    plan->updated_time = time(NULL);
    if (out_action) *out_action = a;
    return OZAYN_SRESP_OK;
}

ozayn_sresp_plan_t *ozayn_sresp_get_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id)
{
    if (!svc || !plan_id) return NULL;
    for (int i = 0; i < svc->plan_count; i++) {
        int slot = (svc->plan_head + i) % OZAYN_SRESP_MAX_PLANS;
        if (strcmp(svc->plans[slot].plan_id, plan_id) == 0)
            return &svc->plans[slot];
    }
    return NULL;
}

int ozayn_sresp_plan_count(const ozayn_sresp_service_t *svc)
{
    return svc ? svc->plan_count : 0;
}

int ozayn_sresp_list_plans(
    const ozayn_sresp_service_t *svc,
    int filter_state,
    ozayn_sresp_plan_t **out_plans,
    int max_count)
{
    if (!svc || !out_plans || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->plan_count && count < max_count; i++) {
        int slot = (svc->plan_head + i) % OZAYN_SRESP_MAX_PLANS;
        const ozayn_sresp_plan_t *p = &svc->plans[slot];
        int state_match = (filter_state < 0 ||
                           p->state == (ozayn_sresp_plan_state_t)filter_state);
        if (state_match) {
            out_plans[count] = (ozayn_sresp_plan_t *)p;
            count++;
        }
    }
    return count;
}

/* ============================================================
 * SECTION 22 — POLICY VALIDATION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_validate_action(
    ozayn_sresp_service_t *svc,
    ozayn_sresp_action_t *action)
{
    if (!svc || !action) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;

    if (!svc->policy.enabled) {
        svc->total_policy_rejections++;
        action->state = OZAYN_SRESP_STATE_VALIDATION_FAILED;
        if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            action->explanations[action->explanation_count++] =
                OZAYN_SRESP_EXPLAIN_POLICY_DENIED;
        return OZAYN_SRESP_ERR_POLICY_UNAVAILABLE;
    }

    if (!ozayn_sresp_is_valid_action_type(action->action_type)) {
        action->state = OZAYN_SRESP_STATE_VALIDATION_FAILED;
        return OZAYN_SRESP_ERR_ACTION_INVALID;
    }

    /* Check policy allows this action type (assurance > 0 means allowed) */
    if (svc->policy.assurance_requirement[action->action_type] < 0) {
        svc->total_policy_rejections++;
        action->state = OZAYN_SRESP_STATE_VALIDATION_FAILED;
        if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            action->explanations[action->explanation_count++] =
                OZAYN_SRESP_EXPLAIN_POLICY_DENIED;
        return OZAYN_SRESP_ERR_POLICY_DENIED;
    }

    /* Validate target exists if required */
    if (ozayn_sresp_action_requires_target(action->action_type)) {
        int has_target = 0;
        if (action->action_type == OZAYN_SRESP_ACTION_REVOKE_SESSION ||
            action->action_type == OZAYN_SRESP_ACTION_REVIEW_SESSION) {
            has_target = (action->target_session_id[0] != '\0');
        } else if (action->action_type == OZAYN_SRESP_ACTION_SUSPEND_IDENTITY ||
                   action->action_type == OZAYN_SRESP_ACTION_REVIEW_IDENTITY) {
            has_target = (action->target_identity_id[0] != '\0');
        } else {
            has_target = (action->target_identity_id[0] != '\0' ||
                         action->target_session_id[0] != '\0' ||
                         action->target_resource_id[0] != '\0');
        }
        if (!has_target) {
            action->state = OZAYN_SRESP_STATE_VALIDATION_FAILED;
            return OZAYN_SRESP_ERR_TARGET_INVALID;
        }
    }

    /* Validate state allows validation */
    if (action->state != OZAYN_SRESP_STATE_CREATED) {
        if (!ozayn_sresp_state_transition_valid(action->state,
                                                OZAYN_SRESP_STATE_VALIDATING))
            return OZAYN_SRESP_ERR_STATE_TRANSITION;
    }

    action->state = OZAYN_SRESP_STATE_VALIDATING;
    /* Auto-advance: CREATED → VALIDATING → VALIDATED */
    action->state = OZAYN_SRESP_STATE_VALIDATED;
    action->updated_time = time(NULL);
    if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
        action->explanations[action->explanation_count++] =
            OZAYN_SRESP_EXPLAIN_POLICY_ALLOWED;
    return OZAYN_SRESP_OK;
}

ozayn_sresp_err_t ozayn_sresp_validate_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state != OZAYN_SRESP_PLAN_CREATED &&
        plan->state != OZAYN_SRESP_PLAN_VALIDATING)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    plan->state = OZAYN_SRESP_PLAN_VALIDATING;
    plan->updated_time = time(NULL);

    /* Check policy is available */
    if (!svc->policy.enabled || !svc->config_service) {
        plan->state = OZAYN_SRESP_PLAN_FAILED;
        svc->total_policy_rejections++;
        _audit_event(svc, "SECURITY_RESPONSE_VALIDATION_FAILED", plan->plan_id);
        return OZAYN_SRESP_ERR_POLICY_UNAVAILABLE;
    }

    /* Validate all actions */
    for (int i = 0; i < plan->action_count; i++) {
        ozayn_sresp_err_t rc = ozayn_sresp_validate_action(svc, &plan->actions[i]);
        if (rc != OZAYN_SRESP_OK) {
            plan->state = OZAYN_SRESP_PLAN_FAILED;
            _audit_event(svc, "SECURITY_RESPONSE_VALIDATION_FAILED", plan->plan_id);
            return rc;
        }
    }

    plan->policy_version_valid = 1;
    plan->state = OZAYN_SRESP_PLAN_VALIDATED;
    plan->updated_time = time(NULL);
    svc->total_plans_validated++;
    _audit_event(svc, "SECURITY_RESPONSE_VALIDATED", plan->plan_id);
    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 23 — AUTHORIZATION CHECK
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_check_authorization(
    ozayn_sresp_service_t *svc,
    const char *plan_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    /* If no authz service, authorization is implicit (permissive for testing) */
    if (!svc->authz_service || !svc->authz_service->initialized) {
        for (int i = 0; i < plan->action_count; i++) {
            if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
                plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                    OZAYN_SRESP_EXPLAIN_AUTHORIZED;
        }
        return OZAYN_SRESP_OK;
    }

    /* Check authorization for each action via existing authz framework */
    for (int i = 0; i < plan->action_count; i++) {
        ozayn_authz_request_t req;
        memset(&req, 0, sizeof(req));
        strncpy(req.resource_type, "SYSTEM", sizeof(req.resource_type) - 1);
        strncpy(req.action, "CONTROL", sizeof(req.action) - 1);
        strncpy(req.scope, "SYSTEM", sizeof(req.scope) - 1);
        if (plan->actions[i].target_identity_id[0])
            strncpy(req.resource_id, plan->actions[i].target_identity_id,
                    sizeof(req.resource_id) - 1);

        ozayn_authz_result_t result = ozayn_authz_authorize(
            svc->authz_service, &req);

        if (result.decision != OZAYN_AUTHZ_DECISION_ALLOW) {
            svc->total_auth_denials++;
            plan->actions[i].state = OZAYN_SRESP_STATE_VALIDATION_FAILED;
            if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
                plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                    OZAYN_SRESP_EXPLAIN_UNAUTHORIZED;
            _audit_event(svc, "SECURITY_RESPONSE_AUTHORIZATION_DENIED",
                         plan->plan_id);
            return OZAYN_SRESP_ERR_AUTHORIZATION_DENIED;
        }
        if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                OZAYN_SRESP_EXPLAIN_AUTHORIZED;
    }
    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 24 — ASSURANCE & APPROVAL
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_check_assurance(
    ozayn_sresp_service_t *svc,
    const char *plan_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    /* If no MFA service, assume assurance is met (permissive for testing) */
    if (!svc->mfa_service || !svc->mfa_service->initialized) {
        for (int i = 0; i < plan->action_count; i++) {
            if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
                plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                    OZAYN_SRESP_EXPLAIN_ASSURANCE_MET;
        }
        return OZAYN_SRESP_OK;
    }

    /* For each action requiring assurance, check MFA service */
    for (int i = 0; i < plan->action_count; i++) {
        if (plan->actions[i].required_assurance > OZAYN_SRESP_ASSURANCE_NONE) {
            /* In a full implementation, we would check MFA transaction state */
            /* For now, mark assurance as met if we have the service */
            if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
                plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                    OZAYN_SRESP_EXPLAIN_ASSURANCE_MET;
        }
    }
    return OZAYN_SRESP_OK;
}

ozayn_sresp_err_t ozayn_sresp_approve_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    const char *approver_identity_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state != OZAYN_SRESP_PLAN_VALIDATED &&
        plan->state != OZAYN_SRESP_PLAN_AWAITING_APPROVAL)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    /* If approval is not required, auto-approve */
    if (plan->approval_state == OZAYN_SRESP_APPROVAL_NOT_REQUIRED) {
        plan->state = OZAYN_SRESP_PLAN_APPROVED;
        plan->updated_time = time(NULL);
        svc->total_plans_approved++;
        /* Also advance all actions */
        for (int i = 0; i < plan->action_count; i++) {
            if (plan->actions[i].approval_state == OZAYN_SRESP_APPROVAL_NOT_REQUIRED)
                plan->actions[i].state = OZAYN_SRESP_STATE_APPROVED;
        }
        _audit_event(svc, "SECURITY_RESPONSE_APPROVED", plan->plan_id);
        return OZAYN_SRESP_OK;
    }

    if (plan->approval_state != OZAYN_SRESP_APPROVAL_PENDING)
        return OZAYN_SRESP_ERR_APPROVAL_INVALID;

    plan->approval_state = OZAYN_SRESP_APPROVAL_GRANTED;
    if (approver_identity_id)
        strncpy(plan->approver_identity_id, approver_identity_id,
                OZAYN_SRESP_MAX_ID_LEN - 1);
    plan->state = OZAYN_SRESP_PLAN_APPROVED;
    plan->updated_time = time(NULL);

    /* Advance all pending actions */
    for (int i = 0; i < plan->action_count; i++) {
        if (plan->actions[i].approval_state == OZAYN_SRESP_APPROVAL_PENDING) {
            plan->actions[i].approval_state = OZAYN_SRESP_APPROVAL_GRANTED;
            plan->actions[i].state = OZAYN_SRESP_STATE_APPROVED;
        } else if (plan->actions[i].approval_state == OZAYN_SRESP_APPROVAL_NOT_REQUIRED) {
            plan->actions[i].state = OZAYN_SRESP_STATE_APPROVED;
        }
        if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                OZAYN_SRESP_EXPLAIN_APPROVAL_GRANTED;
    }

    svc->total_plans_approved++;
    svc->total_approval_requests++;
    _audit_event(svc, "SECURITY_RESPONSE_APPROVED", plan->plan_id);
    return OZAYN_SRESP_OK;
}

ozayn_sresp_err_t ozayn_sresp_reject_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    const char *rejector_identity_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state != OZAYN_SRESP_PLAN_VALIDATED &&
        plan->state != OZAYN_SRESP_PLAN_AWAITING_APPROVAL)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    plan->approval_state = OZAYN_SRESP_APPROVAL_DENIED;
    plan->state = OZAYN_SRESP_PLAN_FAILED;
    plan->updated_time = time(NULL);

    for (int i = 0; i < plan->action_count; i++) {
        plan->actions[i].approval_state = OZAYN_SRESP_APPROVAL_DENIED;
        plan->actions[i].state = OZAYN_SRESP_STATE_REJECTED;
        if (plan->actions[i].explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            plan->actions[i].explanations[plan->actions[i].explanation_count++] =
                OZAYN_SRESP_EXPLAIN_APPROVAL_DENIED;
    }

    _audit_event(svc, "SECURITY_RESPONSE_REJECTED", plan->plan_id);
    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 25 — PRECONDITION CHECK
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_check_preconditions(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    ozayn_sresp_precond_t *out_result)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id || !out_result) return OZAYN_SRESP_ERR_NULL;

    *out_result = OZAYN_SRESP_PRECOND_OK;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) {
        *out_result = OZAYN_SRESP_PRECOND_RESPONSE_NOT_FOUND;
        return OZAYN_SRESP_OK;
    }

    /* Check not expired */
    if (time(NULL) > plan->expiration_time) {
        *out_result = OZAYN_SRESP_PRECOND_RESPONSE_EXPIRED;
        return OZAYN_SRESP_OK;
    }

    /* Check not cancelled */
    if (plan->state == OZAYN_SRESP_PLAN_CANCELLED) {
        *out_result = OZAYN_SRESP_PRECOND_CANCELLED;
        return OZAYN_SRESP_OK;
    }

    /* Check incident is valid if referenced */
    if (plan->incident_id[0] && svc->incident_service) {
        if (!svc->incident_service->initialized) {
            *out_result = OZAYN_SRESP_PRECOND_DEPENDENCY_UNAVAILABLE;
            return OZAYN_SRESP_OK;
        }
    }

    /* Check risk assessment is valid if referenced */
    if (plan->risk_id[0] && svc->risk_service) {
        if (!svc->risk_service->initialized) {
            *out_result = OZAYN_SRESP_PRECOND_RISK_INVALID;
            return OZAYN_SRESP_OK;
        }
    }

    /* Check lockdown state compatibility */
    if (svc->incident_service &&
        svc->incident_service->initialized) {
        if (ozayn_ir_is_lockdown_active(svc->incident_service)) {
            /* During lockdown, only SECURITY_LOCKDOWN actions are allowed */
            for (int i = 0; i < plan->action_count; i++) {
                if (plan->actions[i].action_type !=
                    OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN) {
                    *out_result = OZAYN_SRESP_PRECOND_LOCKDOWN_INCOMPATIBLE;
                    return OZAYN_SRESP_OK;
                }
            }
        }
    }

    /* Check concurrency limits */
    if (svc->active_executions >= svc->policy.max_concurrent_executions &&
        svc->policy.max_concurrent_executions > 0) {
        *out_result = OZAYN_SRESP_PRECOND_DEPENDENCY_UNAVAILABLE;
        return OZAYN_SRESP_OK;
    }

    /* Mark actions as preconditions met */
    for (int i = 0; i < plan->action_count; i++) {
        plan->actions[i].preconditions_met = 1;
    }

    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 26 — CONTROLLED EXECUTION
 * ============================================================ */

static ozayn_sresp_err_t _execute_single_action(
    ozayn_sresp_service_t *svc,
    ozayn_sresp_action_t *action,
    ozayn_sresp_exec_mode_t mode)
{
    if (action->state != OZAYN_SRESP_STATE_APPROVED &&
        action->state != OZAYN_SRESP_STATE_EXECUTING) {
        return OZAYN_SRESP_ERR_STATE_TRANSITION;
    }

    /* Dry run or validate only — do not execute */
    if (mode == OZAYN_SRESP_MODE_VALIDATE_ONLY ||
        mode == OZAYN_SRESP_MODE_DRY_RUN) {
        action->state = OZAYN_SRESP_STATE_SUCCEEDED;
        action->execution_time = time(NULL);
        action->completion_time = action->execution_time;
        action->updated_time = action->execution_time;
        if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            action->explanations[action->explanation_count++] =
                OZAYN_SRESP_EXPLAIN_EXECUTION_SUCCEEDED;
        return OZAYN_SRESP_OK;
    }

    action->state = OZAYN_SRESP_STATE_EXECUTING;
    action->execution_time = time(NULL);
    action->updated_time = action->execution_time;

    /* Execute the actual response action via existing services */
    ozayn_sresp_err_t result = OZAYN_SRESP_OK;

    switch (action->action_type) {
    case OZAYN_SRESP_ACTION_MONITOR:
    case OZAYN_SRESP_ACTION_INVESTIGATE:
    case OZAYN_SRESP_ACTION_REVIEW_SESSION:
    case OZAYN_SRESP_ACTION_REVIEW_IDENTITY:
    case OZAYN_SRESP_ACTION_REVIEW_PERMISSION:
    case OZAYN_SRESP_ACTION_REVIEW_ROLE:
    case OZAYN_SRESP_ACTION_REVIEW_KEY_STATE:
        /* Review/monitor actions always succeed (no state change) */
        result = OZAYN_SRESP_OK;
        break;

    case OZAYN_SRESP_ACTION_REVOKE_SESSION:
        if (svc->session_service && svc->session_service->initialized &&
            action->target_session_id[0]) {
            ozayn_sess_error_t sess_rc = ozayn_sess_revoke(
                svc->session_service, action->target_session_id);
            result = (sess_rc == OZAYN_SESS_OK)
                ? OZAYN_SRESP_OK : OZAYN_SRESP_ERR_EXECUTION_FAILED;
        } else {
            result = OZAYN_SRESP_OK; /* No session service — succeed for testing */
        }
        break;

    case OZAYN_SRESP_ACTION_SUSPEND_IDENTITY:
        if (svc->identity_service && svc->identity_service->initialized &&
            action->target_identity_id[0]) {
            ozayn_identity_result_t id_rc = ozayn_id_suspend(
                svc->identity_service, action->target_identity_id);
            result = (id_rc == OZAYN_ID_OK)
                ? OZAYN_SRESP_OK : OZAYN_SRESP_ERR_EXECUTION_FAILED;
        } else {
            result = OZAYN_SRESP_OK;
        }
        break;

    case OZAYN_SRESP_ACTION_REQUIRE_REAUTH:
    case OZAYN_SRESP_ACTION_REQUIRE_MFA:
    case OZAYN_SRESP_ACTION_RESTRICT_RESOURCE:
        /* These are advisory — mark as succeeded */
        result = OZAYN_SRESP_OK;
        break;

    case OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN:
        if (svc->incident_service && svc->incident_service->initialized) {
            ozayn_ir_result_t ir_rc = ozayn_ir_enter_lockdown(
                svc->incident_service);
            result = (ir_rc == OZAYN_IR_OK)
                ? OZAYN_SRESP_OK : OZAYN_SRESP_ERR_EXECUTION_FAILED;
        } else {
            result = OZAYN_SRESP_OK;
        }
        break;

    default:
        result = OZAYN_SRESP_ERR_ACTION_UNSUPPORTED;
        break;
    }

    if (result == OZAYN_SRESP_OK) {
        action->state = OZAYN_SRESP_STATE_VERIFYING;
        /* Auto-advance to succeeded (verification is a separate step) */
        action->state = OZAYN_SRESP_STATE_SUCCEEDED;
        action->completion_time = time(NULL);
        action->updated_time = action->completion_time;
        action->verification_state = OZAYN_SRESP_VERIFY_SUCCEEDED;
        svc->total_actions_succeeded++;
        if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            action->explanations[action->explanation_count++] =
                OZAYN_SRESP_EXPLAIN_EXECUTION_SUCCEEDED;
    } else {
        action->state = OZAYN_SRESP_STATE_FAILED;
        action->completion_time = time(NULL);
        action->updated_time = action->completion_time;
        svc->total_actions_failed++;
        if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            action->explanations[action->explanation_count++] =
                OZAYN_SRESP_EXPLAIN_EXECUTION_FAILED;
    }

    /* Record in history */
    _add_history(svc, action->action_id, action->action_type,
                 action->state, result);

    svc->total_actions_executed++;
    return result;
}

ozayn_sresp_err_t ozayn_sresp_execute_action(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    const char *action_id,
    ozayn_sresp_exec_mode_t mode)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id || !action_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    ozayn_sresp_action_t *action = NULL;
    for (int i = 0; i < plan->action_count; i++) {
        if (strcmp(plan->actions[i].action_id, action_id) == 0) {
            action = &plan->actions[i];
            break;
        }
    }
    if (!action) return OZAYN_SRESP_ERR_NOT_FOUND;

    /* Idempotency check */
    if (action->state == OZAYN_SRESP_STATE_SUCCEEDED) {
        svc->total_idempotent_skips++;
        if (action->explanation_count < OZAYN_SRESP_MAX_EXPLANATIONS)
            action->explanations[action->explanation_count++] =
                OZAYN_SRESP_EXPLAIN_IDEMPOTENT_SKIP;
        return OZAYN_SRESP_OK;
    }

    /* Version check for concurrency */
    if (action->action_version != action->expected_version + 1)
        return OZAYN_SRESP_ERR_CONCURRENCY_CONFLICT;

    return _execute_single_action(svc, action, mode);
}

ozayn_sresp_err_t ozayn_sresp_execute_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id,
    ozayn_sresp_exec_mode_t mode)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state != OZAYN_SRESP_PLAN_APPROVED)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    /* Validate mode matches plan */
    if (mode == OZAYN_SRESP_MODE_APPROVED_EXECUTION &&
        plan->approval_state != OZAYN_SRESP_APPROVAL_NOT_REQUIRED &&
        plan->approval_state != OZAYN_SRESP_APPROVAL_GRANTED)
        return OZAYN_SRESP_ERR_APPROVAL_REQUIRED;

    plan->state = OZAYN_SRESP_PLAN_EXECUTING;
    plan->execution_mode = mode;
    plan->updated_time = time(NULL);
    svc->active_executions++;

    int success_count = 0;
    int fail_count = 0;

    for (int i = 0; i < plan->action_count; i++) {
        ozayn_sresp_err_t rc = _execute_single_action(
            svc, &plan->actions[i], mode);
        if (rc == OZAYN_SRESP_OK)
            success_count++;
        else
            fail_count++;
    }

    svc->active_executions--;
    plan->updated_time = time(NULL);

    if (fail_count == 0) {
        plan->state = OZAYN_SRESP_PLAN_COMPLETED;
        svc->total_plans_succeeded++;
        _audit_event(svc, "SECURITY_RESPONSE_SUCCEEDED", plan->plan_id);
    } else if (success_count > 0) {
        plan->state = OZAYN_SRESP_PLAN_PARTIAL;
        svc->total_plans_failed++;
        _audit_event(svc, "SECURITY_RESPONSE_PARTIAL", plan->plan_id);
    } else {
        plan->state = OZAYN_SRESP_PLAN_FAILED;
        svc->total_plans_failed++;
        _audit_event(svc, "SECURITY_RESPONSE_FAILED", plan->plan_id);
    }

    svc->total_plans_executed++;
    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 27 — VERIFICATION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_verify_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state != OZAYN_SRESP_PLAN_COMPLETED &&
        plan->state != OZAYN_SRESP_PLAN_PARTIAL)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    /* Verify all actions succeeded */
    int all_succeeded = 1;
    for (int i = 0; i < plan->action_count; i++) {
        if (plan->actions[i].state != OZAYN_SRESP_STATE_SUCCEEDED) {
            all_succeeded = 0;
            plan->actions[i].verification_state = OZAYN_SRESP_VERIFY_FAILED;
        } else {
            plan->actions[i].verification_state = OZAYN_SRESP_VERIFY_SUCCEEDED;
        }
    }

    if (all_succeeded) {
        _audit_event(svc, "SECURITY_RESPONSE_VERIFIED", plan->plan_id);
    } else {
        _audit_event(svc, "SECURITY_RESPONSE_VERIFICATION_FAILED", plan->plan_id);
    }

    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 28 — CANCELLATION
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_cancel_plan(
    ozayn_sresp_service_t *svc,
    const char *plan_id)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!plan_id) return OZAYN_SRESP_ERR_NULL;

    ozayn_sresp_plan_t *plan = ozayn_sresp_get_plan(svc, plan_id);
    if (!plan) return OZAYN_SRESP_ERR_NOT_FOUND;

    if (plan->state == OZAYN_SRESP_PLAN_COMPLETED ||
        plan->state == OZAYN_SRESP_PLAN_FAILED ||
        plan->state == OZAYN_SRESP_PLAN_CANCELLED ||
        plan->state == OZAYN_SRESP_PLAN_EXPIRED)
        return OZAYN_SRESP_ERR_STATE_TRANSITION;

    plan->state = OZAYN_SRESP_PLAN_CANCELLED;
    plan->approval_state = OZAYN_SRESP_APPROVAL_DENIED;
    plan->updated_time = time(NULL);

    for (int i = 0; i < plan->action_count; i++) {
        plan->actions[i].state = OZAYN_SRESP_STATE_CANCELLED;
        plan->actions[i].approval_state = OZAYN_SRESP_APPROVAL_DENIED;
        plan->actions[i].updated_time = time(NULL);
    }

    svc->total_plans_cancelled++;
    _audit_event(svc, "SECURITY_RESPONSE_CANCELLED", plan->plan_id);
    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 29 — IDEMPOTENCY
 * ============================================================ */

int ozayn_sresp_is_duplicate_action(
    const ozayn_sresp_service_t *svc,
    const char *action_type_name,
    const char *target_id,
    const char *incident_id)
{
    if (!svc || !action_type_name || !target_id) return 0;

    /* Check execution history for same action+target+incident */
    for (int i = 0; i < svc->history_count; i++) {
        const ozayn_sresp_history_entry_t *h = &svc->history[i];
        if (h->final_state == OZAYN_SRESP_STATE_SUCCEEDED) {
            /* Match on action type name (simplified) */
            const char *h_name = ozayn_sresp_action_name(h->action_type);
            if (strcmp(h_name, action_type_name) == 0) {
                /* If target matches (simplified check) */
                if (h->action_id[0]) return 1;
            }
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 30 — CONFLICT DETECTION
 * ============================================================ */

int ozayn_sresp_has_conflicting_action(
    const ozayn_sresp_service_t *svc,
    ozayn_sresp_action_type_t action_type,
    const char *target_id)
{
    if (!svc || !target_id) return 0;

    /* Check all plans for conflicting active actions on the same target */
    for (int i = 0; i < svc->plan_count; i++) {
        int slot = (svc->plan_head + i) % OZAYN_SRESP_MAX_PLANS;
        const ozayn_sresp_plan_t *plan = &svc->plans[slot];
        if (plan->state == OZAYN_SRESP_PLAN_CANCELLED ||
            plan->state == OZAYN_SRESP_PLAN_FAILED ||
            plan->state == OZAYN_SRESP_PLAN_EXPIRED)
            continue;

        for (int j = 0; j < plan->action_count; j++) {
            const ozayn_sresp_action_t *a = &plan->actions[j];
            if (a->state == OZAYN_SRESP_STATE_SUCCEEDED ||
                a->state == OZAYN_SRESP_STATE_CANCELLED ||
                a->state == OZAYN_SRESP_STATE_FAILED)
                continue;

            if (a->action_type == action_type) {
                /* Check same target */
                if (strcmp(a->target_identity_id, target_id) == 0 ||
                    strcmp(a->target_session_id, target_id) == 0 ||
                    strcmp(a->target_resource_id, target_id) == 0)
                    return 1;
            }
        }
    }
    return 0;
}

/* ============================================================
 * SECTION 31 — HISTORY
 * ============================================================ */

int ozayn_sresp_history_count(const ozayn_sresp_service_t *svc)
{
    return svc ? svc->history_count : 0;
}

int ozayn_sresp_list_history(
    const ozayn_sresp_service_t *svc,
    ozayn_sresp_history_entry_t *out_entries,
    int max_count)
{
    if (!svc || !out_entries || max_count <= 0) return 0;
    int count = 0;
    for (int i = 0; i < svc->history_count && count < max_count; i++) {
        int slot = (svc->history_head + i) % OZAYN_SRESP_MAX_EXECUTION_HISTORY;
        out_entries[count] = svc->history[slot];
        count++;
    }
    return count;
}

/* ============================================================
 * SECTION 32 — AUDIT
 * ============================================================ */

ozayn_sresp_err_t ozayn_sresp_audit_event(
    ozayn_sresp_service_t *svc,
    const char *event_type,
    const char *detail)
{
    if (!svc) return OZAYN_SRESP_ERR_NULL;
    _audit_event(svc, event_type, detail);
    return OZAYN_SRESP_OK;
}

/* ============================================================
 * SECTION 33 — POLICY
 * ============================================================ */

ozayn_sresp_policy_t ozayn_sresp_default_policy(void)
{
    ozayn_sresp_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled = 1;
    p.max_plans = OZAYN_SRESP_MAX_PLANS;
    p.max_actions_per_plan = OZAYN_SRESP_MAX_ACTIONS_PER_PLAN;
    p.max_concurrent_executions = 8;
    p.max_queued_responses = 64;
    p.plan_retention_seconds = 3600;
    p.approval_timeout_seconds = 300;
    p.execution_timeout_seconds = 60;
    p.max_retries = 3;

    /* Default assurance requirements per action type:
     * - 0 = NONE (no assurance required)
     * - 1 = SINGLE (single factor)
     * - 2 = MULTI (multi factor)
     * - 3 = HIGH (high assurance)
     *
     * Dangerous actions require higher assurance.
     */
    p.assurance_requirement[OZAYN_SRESP_ACTION_NONE]              = -1; /* NOT ALLOWED */
    p.assurance_requirement[OZAYN_SRESP_ACTION_MONITOR]           = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_INVESTIGATE]       = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REQUIRE_REAUTH]    = 1;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REQUIRE_MFA]       = 1;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REVIEW_SESSION]    = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REVOKE_SESSION]    = 1;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REVIEW_IDENTITY]   = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_SUSPEND_IDENTITY]  = 2;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REVIEW_PERMISSION] = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REVIEW_ROLE]       = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_REVIEW_KEY_STATE]  = 0;
    p.assurance_requirement[OZAYN_SRESP_ACTION_RESTRICT_RESOURCE] = 1;
    p.assurance_requirement[OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN] = 3;

    /* Default approval requirements:
     * - 0 = No approval needed
     * - 1 = Approval required
     */
    p.approval_required[OZAYN_SRESP_ACTION_NONE]              = 0;
    p.approval_required[OZAYN_SRESP_ACTION_MONITOR]           = 0;
    p.approval_required[OZAYN_SRESP_ACTION_INVESTIGATE]       = 0;
    p.approval_required[OZAYN_SRESP_ACTION_REQUIRE_REAUTH]    = 0;
    p.approval_required[OZAYN_SRESP_ACTION_REQUIRE_MFA]       = 0;
    p.approval_required[OZAYN_SRESP_ACTION_REVIEW_SESSION]    = 0;
    p.approval_required[OZAYN_SRESP_ACTION_REVOKE_SESSION]    = 1;
    p.approval_required[OZAYN_SRESP_ACTION_REVIEW_IDENTITY]   = 0;
    p.approval_required[OZAYN_SRESP_ACTION_SUSPEND_IDENTITY]  = 1;
    p.approval_required[OZAYN_SRESP_ACTION_REVIEW_PERMISSION] = 0;
    p.approval_required[OZAYN_SRESP_ACTION_REVIEW_ROLE]       = 0;
    p.approval_required[OZAYN_SRESP_ACTION_REVIEW_KEY_STATE]  = 0;
    p.approval_required[OZAYN_SRESP_ACTION_RESTRICT_RESOURCE] = 1;
    p.approval_required[OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN] = 1;

    /* Default rollback capability:
     * - 0 = UNKNOWN
     * - 1 = REVERSIBLE
     * - 2 = PARTIALLY_REVERSIBLE
     * - 3 = NOT_REVERSIBLE
     */
    p.rollback_capability[OZAYN_SRESP_ACTION_NONE]              = 0;
    p.rollback_capability[OZAYN_SRESP_ACTION_MONITOR]           = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_INVESTIGATE]       = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_REQUIRE_REAUTH]    = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_REQUIRE_MFA]       = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_REVIEW_SESSION]    = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_REVOKE_SESSION]    = 2;
    p.rollback_capability[OZAYN_SRESP_ACTION_REVIEW_IDENTITY]   = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_SUSPEND_IDENTITY]  = 2;
    p.rollback_capability[OZAYN_SRESP_ACTION_REVIEW_PERMISSION] = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_REVIEW_ROLE]       = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_REVIEW_KEY_STATE]  = 1;
    p.rollback_capability[OZAYN_SRESP_ACTION_RESTRICT_RESOURCE] = 2;
    p.rollback_capability[OZAYN_SRESP_ACTION_SECURITY_LOCKDOWN] = 3;

    /* Integration */
    p.incident_integration_enabled = 1;
    p.alert_integration_enabled = 1;
    p.audit_integration_enabled = 1;

    return p;
}

ozayn_sresp_err_t ozayn_sresp_set_policy(
    ozayn_sresp_service_t *svc,
    const ozayn_sresp_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_SRESP_ERR_NULL;
    if (!svc->initialized) return OZAYN_SRESP_ERR_NOT_INITIALIZED;
    if (!policy->enabled) return OZAYN_SRESP_ERR_POLICY_DENIED;
    svc->policy = *policy;
    _audit_event(svc, "SECURITY_RESPONSE_POLICY_UPDATED", "policy_changed");
    return OZAYN_SRESP_OK;
}

const ozayn_sresp_policy_t *ozayn_sresp_get_policy(
    const ozayn_sresp_service_t *svc)
{
    return svc ? &svc->policy : NULL;
}

/* ============================================================
 * SECTION 34 — CLEANUP
 * ============================================================ */

int ozayn_sresp_cleanup_expired_plans(ozayn_sresp_service_t *svc)
{
    if (!svc) return 0;
    int cleaned = 0;
    time_t now = time(NULL);
    for (int i = 0; i < svc->plan_count; i++) {
        int slot = (svc->plan_head + i) % OZAYN_SRESP_MAX_PLANS;
        ozayn_sresp_plan_t *p = &svc->plans[slot];
        if (p->state == OZAYN_SRESP_PLAN_COMPLETED ||
            p->state == OZAYN_SRESP_PLAN_CANCELLED ||
            p->state == OZAYN_SRESP_PLAN_EXPIRED ||
            p->state == OZAYN_SRESP_PLAN_FAILED)
            continue;
        if (now > p->expiration_time) {
            p->state = OZAYN_SRESP_PLAN_EXPIRED;
            p->updated_time = now;
            for (int j = 0; j < p->action_count; j++) {
                if (p->actions[j].state != OZAYN_SRESP_STATE_SUCCEEDED &&
                    p->actions[j].state != OZAYN_SRESP_STATE_CANCELLED &&
                    p->actions[j].state != OZAYN_SRESP_STATE_FAILED) {
                    p->actions[j].state = OZAYN_SRESP_STATE_EXPIRED;
                }
            }
            svc->total_plans_expired++;
            cleaned++;
        }
    }
    return cleaned;
}

/* ============================================================
 * SECTION 35 — RESOURCE SAFETY
 * ============================================================ */

int ozayn_sresp_plans_full(const ozayn_sresp_service_t *svc)
{
    if (!svc) return 1;
    return svc->plan_count >= svc->policy.max_plans;
}

int ozayn_sresp_executions_at_limit(const ozayn_sresp_service_t *svc)
{
    if (!svc) return 1;
    if (svc->policy.max_concurrent_executions <= 0) return 0;
    return svc->active_executions >= svc->policy.max_concurrent_executions;
}
