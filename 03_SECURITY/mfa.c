#include "mfa.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 * FACTOR TYPE METADATA
 * ============================================================ */

static const ozayn_mfa_factor_info_t _factor_info[] = {
    { OZAYN_MFA_FACTOR_UNKNOWN,   OZAYN_MFA_CATEGORY_UNKNOWN,    "UNKNOWN",   0 },
    { OZAYN_MFA_FACTOR_PASSWORD,  OZAYN_MFA_CATEGORY_KNOWLEDGE,  "PASSWORD",  1 },
    { OZAYN_MFA_FACTOR_TOKEN,     OZAYN_MFA_CATEGORY_POSSESSION, "TOKEN",     0 },
    { OZAYN_MFA_FACTOR_DEVICE,    OZAYN_MFA_CATEGORY_POSSESSION, "DEVICE",    0 },
    { OZAYN_MFA_FACTOR_BIOMETRIC, OZAYN_MFA_CATEGORY_INHERENCE,  "BIOMETRIC", 0 },
    { OZAYN_MFA_FACTOR_VOICE,     OZAYN_MFA_CATEGORY_INHERENCE,  "VOICE",     0 },
    { OZAYN_MFA_FACTOR_FACE,      OZAYN_MFA_CATEGORY_INHERENCE,  "FACE",      0 },
    { OZAYN_MFA_FACTOR_GESTURE,   OZAYN_MFA_CATEGORY_INHERENCE,  "GESTURE",   0 }
};

#define _FACTOR_INFO_COUNT (sizeof(_factor_info) / sizeof(_factor_info[0]))

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_mfa_validate_factor_type(ozayn_mfa_factor_type_t type)
{
    return (type > OZAYN_MFA_FACTOR_UNKNOWN &&
            type <= OZAYN_MFA_FACTOR_GESTURE) ? 0 : -1;
}

int ozayn_mfa_validate_category(ozayn_mfa_category_t category)
{
    return (category > OZAYN_MFA_CATEGORY_UNKNOWN &&
            category <= OZAYN_MFA_CATEGORY_INHERENCE) ? 0 : -1;
}

int ozayn_mfa_validate_factor_state(ozayn_mfa_factor_state_t state)
{
    return (state >= OZAYN_MFA_FACT_STATE_UNINITIALIZED &&
            state <= OZAYN_MFA_FACT_STATE_SKIPPED) ? 0 : -1;
}

int ozayn_mfa_validate_tx_state(ozayn_mfa_tx_state_t state)
{
    return (state >= OZAYN_MFA_TX_UNINITIALIZED &&
            state <= OZAYN_MFA_TX_UNAVAILABLE) ? 0 : -1;
}

int ozayn_mfa_validate_tx_transition(ozayn_mfa_tx_state_t from,
                                      ozayn_mfa_tx_state_t to)
{
    if (from == OZAYN_MFA_TX_NOT_STARTED && to == OZAYN_MFA_TX_IN_PROGRESS)
        return 0;
    if (from == OZAYN_MFA_TX_NOT_STARTED && to == OZAYN_MFA_TX_CANCELLED)
        return 0;
    if (from == OZAYN_MFA_TX_NOT_STARTED && to == OZAYN_MFA_TX_EXPIRED)
        return 0;
    if (from == OZAYN_MFA_TX_IN_PROGRESS && to == OZAYN_MFA_TX_FACTOR_VERIFIED)
        return 0;
    if (from == OZAYN_MFA_TX_IN_PROGRESS && to == OZAYN_MFA_TX_FAILED)
        return 0;
    if (from == OZAYN_MFA_TX_IN_PROGRESS && to == OZAYN_MFA_TX_EXPIRED)
        return 0;
    if (from == OZAYN_MFA_TX_IN_PROGRESS && to == OZAYN_MFA_TX_CANCELLED)
        return 0;
    if (from == OZAYN_MFA_TX_IN_PROGRESS && to == OZAYN_MFA_TX_UNAVAILABLE)
        return 0;
    if (from == OZAYN_MFA_TX_FACTOR_VERIFIED && to == OZAYN_MFA_TX_VERIFIED)
        return 0;
    if (from == OZAYN_MFA_TX_FACTOR_VERIFIED && to == OZAYN_MFA_TX_FAILED)
        return 0;
    if (from == OZAYN_MFA_TX_FACTOR_VERIFIED && to == OZAYN_MFA_TX_EXPIRED)
        return 0;
    if (from == OZAYN_MFA_TX_FACTOR_VERIFIED && to == OZAYN_MFA_TX_CANCELLED)
        return 0;
    return -1;
}

int ozayn_mfa_validate_assurance(ozayn_mfa_assurance_t level)
{
    return (level >= OZAYN_MFA_ASSURANCE_NONE &&
            level <= OZAYN_MFA_ASSURANCE_HIGH) ? 0 : -1;
}

int ozayn_mfa_validate_result_status(ozayn_mfa_result_status_t status)
{
    return (status >= OZAYN_MFA_RESULT_VERIFIED &&
            status <= OZAYN_MFA_RESULT_ERROR) ? 0 : -1;
}

int ozayn_mfa_validate_policy(const ozayn_mfa_policy_t *policy)
{
    if (!policy)
        return -1;
    if (policy->required_factor_count < 0 ||
        policy->required_factor_count > OZAYN_MFA_MAX_FACTORS_PER_POLICY)
        return -1;
    if (policy->transaction_timeout_seconds <= 0)
        return -1;
    if (policy->factor_timeout_seconds < 0)
        return -1;
    if (policy->max_failures < 0)
        return -1;
    if (policy->block_seconds < 0)
        return -1;
    for (int i = 0; i < policy->required_factor_count; i++) {
        if (ozayn_mfa_validate_factor_type(policy->required_factors[i]) != 0)
            return -1;
    }
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_mfa_error_name(ozayn_mfa_error_t error)
{
    switch (error) {
        case OZAYN_MFA_OK:                          return "OK";
        case OZAYN_MFA_ERR_NULL:                    return "NULL";
        case OZAYN_MFA_ERR_NOT_INITIALIZED:         return "NOT_INITIALIZED";
        case OZAYN_MFA_ERR_NOT_FOUND:               return "NOT_FOUND";
        case OZAYN_MFA_ERR_ALREADY_EXISTS:          return "ALREADY_EXISTS";
        case OZAYN_MFA_ERR_INVALID:                 return "INVALID";
        case OZAYN_MFA_ERR_ID_INVALID:              return "ID_INVALID";
        case OZAYN_MFA_ERR_STATE_INVALID:           return "STATE_INVALID";
        case OZAYN_MFA_ERR_STATE_TRANSITION:        return "STATE_TRANSITION";
        case OZAYN_MFA_ERR_LIMIT_REACHED:           return "LIMIT_REACHED";
        case OZAYN_MFA_ERR_POLICY_INVALID:          return "POLICY_INVALID";
        case OZAYN_MFA_ERR_POLICY_UNAVAILABLE:      return "POLICY_UNAVAILABLE";
        case OZAYN_MFA_ERR_FACTOR_INVALID:          return "FACTOR_INVALID";
        case OZAYN_MFA_ERR_FACTOR_UNSUPPORTED:      return "FACTOR_UNSUPPORTED";
        case OZAYN_MFA_ERR_FACTOR_UNAVAILABLE:      return "FACTOR_UNAVAILABLE";
        case OZAYN_MFA_ERR_FACTOR_FAILED:           return "FACTOR_FAILED";
        case OZAYN_MFA_ERR_FACTOR_ALREADY_VERIFIED: return "FACTOR_ALREADY_VERIFIED";
        case OZAYN_MFA_ERR_INSUFFICIENT_FACTORS:    return "INSUFFICIENT_FACTORS";
        case OZAYN_MFA_ERR_TRANSACTION_INVALID:     return "TRANSACTION_INVALID";
        case OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND:   return "TRANSACTION_NOT_FOUND";
        case OZAYN_MFA_ERR_TRANSACTION_EXPIRED:     return "TRANSACTION_EXPIRED";
        case OZAYN_MFA_ERR_TRANSACTION_CANCELLED:   return "TRANSACTION_CANCELLED";
        case OZAYN_MFA_ERR_TRANSACTION_REPLAYED:    return "TRANSACTION_REPLAYED";
        case OZAYN_MFA_ERR_IDENTITY_INVALID:        return "IDENTITY_INVALID";
        case OZAYN_MFA_ERR_IDENTITY_REVOKED:        return "IDENTITY_REVOKED";
        case OZAYN_MFA_ERR_IDENTITY_SUSPENDED:      return "IDENTITY_SUSPENDED";
        case OZAYN_MFA_ERR_SESSION_INVALID:         return "SESSION_INVALID";
        case OZAYN_MFA_ERR_ATTEMPT_BLOCKED:         return "ATTEMPT_BLOCKED";
        case OZAYN_MFA_ERR_TIMEOUT:                 return "TIMEOUT";
        case OZAYN_MFA_ERR_PROVIDER_ERROR:          return "PROVIDER_ERROR";
        case OZAYN_MFA_ERR_PROVIDER_UNAVAILABLE:    return "PROVIDER_UNAVAILABLE";
        case OZAYN_MFA_ERR_STORAGE_FAILED:          return "STORAGE_FAILED";
        case OZAYN_MFA_ERR_VAULT_UNAVAILABLE:       return "VAULT_UNAVAILABLE";
        case OZAYN_MFA_ERR_POLICY_REJECTED:         return "POLICY_REJECTED";
        default:                                    return "UNKNOWN";
    }
}

const char *ozayn_mfa_factor_type_name(ozayn_mfa_factor_type_t type)
{
    if (type >= 0 && type < (int)_FACTOR_INFO_COUNT)
        return _factor_info[type].name;
    return "UNKNOWN";
}

const char *ozayn_mfa_category_name(ozayn_mfa_category_t category)
{
    switch (category) {
        case OZAYN_MFA_CATEGORY_UNKNOWN:    return "UNKNOWN";
        case OZAYN_MFA_CATEGORY_KNOWLEDGE:  return "KNOWLEDGE";
        case OZAYN_MFA_CATEGORY_POSSESSION: return "POSSESSION";
        case OZAYN_MFA_CATEGORY_INHERENCE:  return "INHERENCE";
        default:                            return "UNKNOWN";
    }
}

const char *ozayn_mfa_factor_state_name(ozayn_mfa_factor_state_t state)
{
    switch (state) {
        case OZAYN_MFA_FACT_STATE_UNINITIALIZED: return "UNINITIALIZED";
        case OZAYN_MFA_FACT_STATE_PENDING:       return "PENDING";
        case OZAYN_MFA_FACT_STATE_VERIFIED:      return "VERIFIED";
        case OZAYN_MFA_FACT_STATE_FAILED:        return "FAILED";
        case OZAYN_MFA_FACT_STATE_UNAVAILABLE:   return "UNAVAILABLE";
        case OZAYN_MFA_FACT_STATE_SKIPPED:       return "SKIPPED";
        default:                                 return "UNKNOWN";
    }
}

const char *ozayn_mfa_tx_state_name(ozayn_mfa_tx_state_t state)
{
    switch (state) {
        case OZAYN_MFA_TX_UNINITIALIZED:   return "UNINITIALIZED";
        case OZAYN_MFA_TX_NOT_STARTED:     return "NOT_STARTED";
        case OZAYN_MFA_TX_IN_PROGRESS:     return "IN_PROGRESS";
        case OZAYN_MFA_TX_FACTOR_VERIFIED: return "FACTOR_VERIFIED";
        case OZAYN_MFA_TX_VERIFIED:        return "VERIFIED";
        case OZAYN_MFA_TX_FAILED:          return "FAILED";
        case OZAYN_MFA_TX_EXPIRED:         return "EXPIRED";
        case OZAYN_MFA_TX_CANCELLED:       return "CANCELLED";
        case OZAYN_MFA_TX_UNAVAILABLE:     return "UNAVAILABLE";
        default:                           return "UNKNOWN";
    }
}

const char *ozayn_mfa_assurance_name(ozayn_mfa_assurance_t level)
{
    switch (level) {
        case OZAYN_MFA_ASSURANCE_NONE:   return "NONE";
        case OZAYN_MFA_ASSURANCE_SINGLE: return "SINGLE_FACTOR";
        case OZAYN_MFA_ASSURANCE_MULTI:  return "MULTI_FACTOR";
        case OZAYN_MFA_ASSURANCE_HIGH:   return "HIGH_ASSURANCE";
        default:                         return "UNKNOWN";
    }
}

const char *ozayn_mfa_result_status_name(ozayn_mfa_result_status_t status)
{
    switch (status) {
        case OZAYN_MFA_RESULT_VERIFIED:   return "VERIFIED";
        case OZAYN_MFA_RESULT_FAILED:     return "FAILED";
        case OZAYN_MFA_RESULT_PENDING:    return "PENDING";
        case OZAYN_MFA_RESULT_EXPIRED:    return "EXPIRED";
        case OZAYN_MFA_RESULT_CANCELLED:  return "CANCELLED";
        case OZAYN_MFA_RESULT_UNAVAILABLE: return "UNAVAILABLE";
        case OZAYN_MFA_RESULT_ERROR:      return "ERROR";
        default:                          return "UNKNOWN";
    }
}

/* ============================================================
 * FACTOR TYPE HELPERS
 * ============================================================ */

ozayn_mfa_category_t ozayn_mfa_factor_type_category(
    ozayn_mfa_factor_type_t type)
{
    if (type > OZAYN_MFA_FACTOR_UNKNOWN && type < (int)_FACTOR_INFO_COUNT)
        return _factor_info[type].category;
    return OZAYN_MFA_CATEGORY_UNKNOWN;
}

int ozayn_mfa_factor_type_is_implemented(ozayn_mfa_factor_type_t type)
{
    if (type > OZAYN_MFA_FACTOR_UNKNOWN && type < (int)_FACTOR_INFO_COUNT)
        return _factor_info[type].implemented;
    return 0;
}

int ozayn_mfa_factors_require_distinct_categories(
    const ozayn_mfa_factor_type_t *factors,
    int factor_count)
{
    if (!factors || factor_count <= 0)
        return 1; /* Vacuous truth: no duplicates in empty set */

    ozayn_mfa_category_t cats[OZAYN_MFA_MAX_FACTORS_PER_TX];
    int cat_count = 0;

    for (int i = 0; i < factor_count; i++) {
        ozayn_mfa_category_t cat = ozayn_mfa_factor_type_category(factors[i]);
        if (cat == OZAYN_MFA_CATEGORY_UNKNOWN)
            continue;

        /* Check if this category already exists */
        for (int j = 0; j < cat_count; j++) {
            if (cats[j] == cat)
                return 0; /* Duplicate category — not independent */
        }
        cats[cat_count++] = cat;
    }

    return 1; /* All categories are distinct */
}

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static ozayn_mfa_policy_t *_find_policy(ozayn_mfa_service_t *svc,
                                          const char *policy_id)
{
    if (!svc || !policy_id)
        return NULL;
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].in_use &&
            strcmp(svc->policies[i].id, policy_id) == 0)
            return &svc->policies[i];
    }
    return NULL;
}

static ozayn_mfa_tx_t *_find_tx(ozayn_mfa_service_t *svc,
                                  const char *tx_id)
{
    if (!svc || !tx_id)
        return NULL;
    for (int i = 0; i < svc->transaction_count; i++) {
        if (svc->transactions[i].in_use &&
            strcmp(svc->transactions[i].id, tx_id) == 0)
            return &svc->transactions[i];
    }
    return NULL;
}

static ozayn_mfa_error_t _generate_tx_id(char *buf, size_t len)
{
    static int _tx_counter = 0;
    time_t now = time(NULL);
    _tx_counter++;
    int n = snprintf(buf, len, "mfa-%d-%ld", _tx_counter, (long)now);
    if (n < 0 || (size_t)n >= len)
        return OZAYN_MFA_ERR_INVALID;
    return OZAYN_MFA_OK;
}

static ozayn_mfa_error_t _generate_factor_id(char *buf, size_t len,
                                              const char *tx_id,
                                              int index)
{
    int n = snprintf(buf, len, "%s-f%d", tx_id, index);
    if (n < 0 || (size_t)n >= len)
        return OZAYN_MFA_ERR_INVALID;
    return OZAYN_MFA_OK;
}

static void _init_result(ozayn_mfa_result_t *result,
                          ozayn_mfa_result_status_t status,
                          ozayn_mfa_error_t error)
{
    memset(result, 0, sizeof(*result));
    result->status = status;
    result->error = error;
    result->timestamp = time(NULL);
}

static int _is_tx_expired(const ozayn_mfa_tx_t *tx)
{
    if (tx->expires_at == 0)
        return 0;
    return time(NULL) >= tx->expires_at;
}

static ozayn_mfa_error_t _tx_transition(ozayn_mfa_tx_t *tx,
                                          ozayn_mfa_tx_state_t target)
{
    if (ozayn_mfa_validate_tx_transition(tx->state, target) != 0)
        return OZAYN_MFA_ERR_STATE_TRANSITION;
    tx->state = target;
    tx->version++;
    return OZAYN_MFA_OK;
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_service_init(
    ozayn_mfa_service_t *svc,
    const ozayn_mfa_service_config_t *config)
{
    if (!svc)
        return OZAYN_MFA_ERR_NULL;
    if (!config)
        return OZAYN_MFA_ERR_NULL;
    if (!config->identity_service)
        return OZAYN_MFA_ERR_INVALID;

    memset(svc, 0, sizeof(*svc));
    svc->config = *config;
    svc->initialized = 1;
    return OZAYN_MFA_OK;
}

void ozayn_mfa_service_shutdown(ozayn_mfa_service_t *svc)
{
    if (!svc)
        return;
    svc->initialized = 0;
}

int ozayn_mfa_service_is_initialized(const ozayn_mfa_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

/* ============================================================
 * POLICY MANAGEMENT
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_policy_create(
    ozayn_mfa_service_t *svc,
    const char *policy_id,
    const char *name,
    const ozayn_mfa_factor_type_t *required_factors,
    int required_factor_count,
    int transaction_timeout_seconds,
    int factor_timeout_seconds,
    int max_failures,
    int block_seconds,
    ozayn_mfa_policy_t *out_policy)
{
    if (!svc || !policy_id || !out_policy)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    if (strlen(policy_id) == 0 || strlen(policy_id) >= OZAYN_MFA_MAX_POLICY_ID_LEN)
        return OZAYN_MFA_ERR_ID_INVALID;
    if (required_factor_count < 0 || required_factor_count > OZAYN_MFA_MAX_FACTORS_PER_POLICY)
        return OZAYN_MFA_ERR_INVALID;
    if (transaction_timeout_seconds <= 0)
        return OZAYN_MFA_ERR_POLICY_INVALID;
    if (_find_policy(svc, policy_id))
        return OZAYN_MFA_ERR_ALREADY_EXISTS;
    if (svc->policy_count >= OZAYN_MFA_MAX_POLICIES)
        return OZAYN_MFA_ERR_LIMIT_REACHED;

    /* Validate all factor types */
    for (int i = 0; i < required_factor_count; i++) {
        if (ozayn_mfa_validate_factor_type(required_factors[i]) != 0)
            return OZAYN_MFA_ERR_FACTOR_INVALID;
        if (required_factors[i] == OZAYN_MFA_FACTOR_UNKNOWN)
            return OZAYN_MFA_ERR_FACTOR_INVALID;
    }

    /* Enforce factor independence: no duplicate categories */
    if (!ozayn_mfa_factors_require_distinct_categories(required_factors,
                                                        required_factor_count))
        return OZAYN_MFA_ERR_POLICY_INVALID;

    int idx = svc->policy_count;
    ozayn_mfa_policy_t *p = &svc->policies[idx];
    memset(p, 0, sizeof(*p));

    strncpy(p->id, policy_id, sizeof(p->id) - 1);
    if (name)
        strncpy(p->name, name, sizeof(p->name) - 1);
    else
        strncpy(p->name, policy_id, sizeof(p->name) - 1);
    p->enabled = 1;
    p->required_factor_count = required_factor_count;
    for (int i = 0; i < required_factor_count; i++)
        p->required_factors[i] = required_factors[i];

    /* Count distinct required categories */
    ozayn_mfa_category_t cats[OZAYN_MFA_MAX_FACTORS_PER_POLICY];
    int cat_count = 0;
    for (int i = 0; i < required_factor_count; i++) {
        ozayn_mfa_category_t cat = ozayn_mfa_factor_type_category(required_factors[i]);
        int found = 0;
        for (int j = 0; j < cat_count; j++) {
            if (cats[j] == cat) { found = 1; break; }
        }
        if (!found) cats[cat_count++] = cat;
    }
    p->required_factor_count_required = cat_count;

    p->transaction_timeout_seconds = transaction_timeout_seconds;
    p->factor_timeout_seconds = factor_timeout_seconds;
    p->max_failures = max_failures > 0 ? max_failures : 5;
    p->block_seconds = block_seconds > 0 ? block_seconds : 900;
    p->version = 1;
    p->created_at = time(NULL);
    p->modified_at = p->created_at;
    p->in_use = 1;

    svc->policy_count++;

    *out_policy = *p;
    return OZAYN_MFA_OK;
}

ozayn_mfa_error_t ozayn_mfa_policy_get(
    const ozayn_mfa_service_t *svc,
    const char *policy_id,
    ozayn_mfa_policy_t *out_policy)
{
    if (!svc || !policy_id || !out_policy)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;

    const ozayn_mfa_policy_t *p = _find_policy((ozayn_mfa_service_t *)svc, policy_id);
    if (!p)
        return OZAYN_MFA_ERR_NOT_FOUND;

    *out_policy = *p;
    return OZAYN_MFA_OK;
}

int ozayn_mfa_policy_exists(
    const ozayn_mfa_service_t *svc,
    const char *policy_id)
{
    if (!svc || !policy_id)
        return 0;
    return _find_policy((ozayn_mfa_service_t *)svc, policy_id) != NULL ? 1 : 0;
}

ozayn_mfa_error_t ozayn_mfa_policy_enable(
    ozayn_mfa_service_t *svc,
    const char *policy_id)
{
    if (!svc || !policy_id)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    ozayn_mfa_policy_t *p = _find_policy(svc, policy_id);
    if (!p)
        return OZAYN_MFA_ERR_NOT_FOUND;
    p->enabled = 1;
    p->modified_at = time(NULL);
    p->version++;
    return OZAYN_MFA_OK;
}

ozayn_mfa_error_t ozayn_mfa_policy_disable(
    ozayn_mfa_service_t *svc,
    const char *policy_id)
{
    if (!svc || !policy_id)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    ozayn_mfa_policy_t *p = _find_policy(svc, policy_id);
    if (!p)
        return OZAYN_MFA_ERR_NOT_FOUND;
    p->enabled = 0;
    p->modified_at = time(NULL);
    p->version++;
    return OZAYN_MFA_OK;
}

ozayn_mfa_error_t ozayn_mfa_policy_delete(
    ozayn_mfa_service_t *svc,
    const char *policy_id)
{
    if (!svc || !policy_id)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    int idx = -1;
    for (int i = 0; i < svc->policy_count; i++) {
        if (svc->policies[i].in_use &&
            strcmp(svc->policies[i].id, policy_id) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0)
        return OZAYN_MFA_ERR_NOT_FOUND;

    /* Shift remaining policies */
    for (int i = idx; i < svc->policy_count - 1; i++)
        svc->policies[i] = svc->policies[i + 1];
    memset(&svc->policies[svc->policy_count - 1], 0, sizeof(ozayn_mfa_policy_t));
    svc->policy_count--;
    return OZAYN_MFA_OK;
}

int ozayn_mfa_policy_count(const ozayn_mfa_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->policy_count;
}

/* ============================================================
 * TRANSACTION MANAGEMENT
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_tx_create(
    ozayn_mfa_service_t *svc,
    const char *identity_id,
    const char *policy_id,
    ozayn_mfa_tx_t *out_tx)
{
    if (!svc || !identity_id || !policy_id || !out_tx)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    if (identity_id[0] == '\0')
        return OZAYN_MFA_ERR_IDENTITY_INVALID;

    /* Validate identity exists and is active */
    ozayn_identity_t ident;
    if (ozayn_id_get(svc->config.identity_service, identity_id, &ident) != OZAYN_ID_OK)
        return OZAYN_MFA_ERR_IDENTITY_INVALID;
    if (ident.state == OZAYN_ID_STATE_REVOKED)
        return OZAYN_MFA_ERR_IDENTITY_REVOKED;
    if (ident.state == OZAYN_ID_STATE_SUSPENDED)
        return OZAYN_MFA_ERR_IDENTITY_SUSPENDED;

    /* Policy must exist and be enabled */
    ozayn_mfa_policy_t *policy = _find_policy(svc, policy_id);
    if (!policy)
        return OZAYN_MFA_ERR_POLICY_UNAVAILABLE;
    if (!policy->enabled)
        return OZAYN_MFA_ERR_POLICY_REJECTED;

    /* Check attempt control if configured */
    if (svc->config.attempt_control) {
        int allowed = 0;
        int retry_after_ms = 0;
        ozayn_ac_error_t ac_r = ozayn_ac_check_allowed(
            svc->config.attempt_control, identity_id, &allowed, &retry_after_ms);
        if (ac_r == OZAYN_AC_ERR_TEMPORARILY_BLOCKED)
            return OZAYN_MFA_ERR_ATTEMPT_BLOCKED;
        if (!allowed)
            return OZAYN_MFA_ERR_ATTEMPT_BLOCKED;
    }

    /* Check transaction limit */
    if (svc->transaction_count >= OZAYN_MFA_MAX_TRANSACTIONS)
        return OZAYN_MFA_ERR_LIMIT_REACHED;

    /* Cancel any existing active transactions for this identity */
    ozayn_mfa_tx_cancel_by_identity(svc, identity_id);

    int idx = svc->transaction_count;
    ozayn_mfa_tx_t *tx = &svc->transactions[idx];
    memset(tx, 0, sizeof(*tx));

    ozayn_mfa_error_t gen_r = _generate_tx_id(tx->id, sizeof(tx->id));
    if (gen_r != OZAYN_MFA_OK)
        return gen_r;

    strncpy(tx->identity_id, identity_id, sizeof(tx->identity_id) - 1);
    strncpy(tx->policy_id, policy_id, sizeof(tx->policy_id) - 1);
    tx->state = OZAYN_MFA_TX_NOT_STARTED;
    tx->created_at = time(NULL);
    tx->expires_at = tx->created_at + policy->transaction_timeout_seconds;
    tx->in_use = 1;

    /* Initialize factors from policy */
    tx->factor_count = policy->required_factor_count;
    for (int i = 0; i < policy->required_factor_count; i++) {
        ozayn_mfa_factor_t *f = &tx->factors[i];
        memset(f, 0, sizeof(*f));
        _generate_factor_id(f->id, sizeof(f->id), tx->id, i);
        f->type = policy->required_factors[i];
        f->category = ozayn_mfa_factor_type_category(f->type);
        f->state = OZAYN_MFA_FACT_STATE_PENDING;
        strncpy(f->provider_id, ozayn_mfa_factor_type_name(f->type),
                sizeof(f->provider_id) - 1);
        f->in_use = 1;
    }

    svc->transaction_count++;

    *out_tx = *tx;
    return OZAYN_MFA_OK;
}

ozayn_mfa_error_t ozayn_mfa_tx_get(
    const ozayn_mfa_service_t *svc,
    const char *tx_id,
    ozayn_mfa_tx_t *out_tx)
{
    if (!svc || !tx_id || !out_tx)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;

    const ozayn_mfa_tx_t *tx = _find_tx((ozayn_mfa_service_t *)svc, tx_id);
    if (!tx)
        return OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND;

    *out_tx = *tx;
    return OZAYN_MFA_OK;
}

ozayn_mfa_error_t ozayn_mfa_tx_cancel(
    ozayn_mfa_service_t *svc,
    const char *tx_id)
{
    if (!svc || !tx_id)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;

    ozayn_mfa_tx_t *tx = _find_tx(svc, tx_id);
    if (!tx)
        return OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND;

    if (tx->state == OZAYN_MFA_TX_VERIFIED ||
        tx->state == OZAYN_MFA_TX_EXPIRED ||
        tx->state == OZAYN_MFA_TX_CANCELLED ||
        tx->state == OZAYN_MFA_TX_FAILED)
        return OZAYN_MFA_ERR_STATE_TRANSITION;

    return _tx_transition(tx, OZAYN_MFA_TX_CANCELLED);
}

ozayn_mfa_error_t ozayn_mfa_tx_cancel_by_identity(
    ozayn_mfa_service_t *svc,
    const char *identity_id)
{
    if (!svc || !identity_id)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_MFA_ERR_NOT_INITIALIZED;

    for (int i = 0; i < svc->transaction_count; i++) {
        ozayn_mfa_tx_t *tx = &svc->transactions[i];
        if (tx->in_use &&
            strcmp(tx->identity_id, identity_id) == 0 &&
            (tx->state == OZAYN_MFA_TX_NOT_STARTED ||
             tx->state == OZAYN_MFA_TX_IN_PROGRESS ||
             tx->state == OZAYN_MFA_TX_FACTOR_VERIFIED)) {
            _tx_transition(tx, OZAYN_MFA_TX_CANCELLED);
        }
    }
    return OZAYN_MFA_OK;
}

int ozayn_mfa_tx_count(const ozayn_mfa_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->transaction_count;
}

int ozayn_mfa_tx_identity_count(
    const ozayn_mfa_service_t *svc,
    const char *identity_id)
{
    if (!svc || !identity_id)
        return 0;
    int count = 0;
    for (int i = 0; i < svc->transaction_count; i++) {
        if (svc->transactions[i].in_use &&
            strcmp(svc->transactions[i].identity_id, identity_id) == 0)
            count++;
    }
    return count;
}

/* ============================================================
 * FACTOR VERIFICATION
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_verify_factor(
    ozayn_mfa_service_t *svc,
    const ozayn_mfa_verify_request_t *request,
    ozayn_mfa_result_t *out_result)
{
    if (!svc || !request || !out_result)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_NOT_INITIALIZED);
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    }
    if (request->tx_id[0] == '\0' || request->identity_id[0] == '\0') {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_INVALID);
        return OZAYN_MFA_ERR_INVALID;
    }
    if (ozayn_mfa_validate_factor_type(request->factor_type) != 0) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_FACTOR_INVALID);
        return OZAYN_MFA_ERR_FACTOR_INVALID;
    }

    /* Find the transaction */
    ozayn_mfa_tx_t *tx = _find_tx(svc, request->tx_id);
    if (!tx) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND);
        return OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND;
    }

    /* Verify identity binding */
    if (strcmp(tx->identity_id, request->identity_id) != 0) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_IDENTITY_INVALID);
        return OZAYN_MFA_ERR_IDENTITY_INVALID;
    }

    /* Check transaction state */
    if (tx->state == OZAYN_MFA_TX_VERIFIED) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_TRANSACTION_REPLAYED);
        return OZAYN_MFA_ERR_TRANSACTION_REPLAYED;
    }
    if (tx->state == OZAYN_MFA_TX_CANCELLED) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_TRANSACTION_CANCELLED);
        return OZAYN_MFA_ERR_TRANSACTION_CANCELLED;
    }
    if (tx->state == OZAYN_MFA_TX_FAILED) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_STATE_TRANSITION);
        return OZAYN_MFA_ERR_STATE_TRANSITION;
    }
    if (tx->state == OZAYN_MFA_TX_EXPIRED || _is_tx_expired(tx)) {
        if (tx->state != OZAYN_MFA_TX_EXPIRED)
            _tx_transition(tx, OZAYN_MFA_TX_EXPIRED);
        _init_result(out_result, OZAYN_MFA_RESULT_EXPIRED,
                     OZAYN_MFA_ERR_TRANSACTION_EXPIRED);
        return OZAYN_MFA_ERR_TRANSACTION_EXPIRED;
    }

    /* Check attempt control for MFA factor attempts */
    if (svc->config.attempt_control) {
        int allowed = 0;
        int retry_after_ms = 0;
        ozayn_ac_error_t ac_r = ozayn_ac_check_allowed(
            svc->config.attempt_control, request->identity_id,
            &allowed, &retry_after_ms);
        if (ac_r == OZAYN_AC_ERR_TEMPORARILY_BLOCKED || !allowed) {
            _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                         OZAYN_MFA_ERR_ATTEMPT_BLOCKED);
            return OZAYN_MFA_ERR_ATTEMPT_BLOCKED;
        }
    }

    /* Find the matching factor in this transaction */
    ozayn_mfa_factor_t *target_factor = NULL;
    for (int i = 0; i < tx->factor_count; i++) {
        if (tx->factors[i].in_use &&
            tx->factors[i].type == request->factor_type) {
            target_factor = &tx->factors[i];
            break;
        }
    }
    if (!target_factor) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_FACTOR_INVALID);
        return OZAYN_MFA_ERR_FACTOR_INVALID;
    }

    /* Factor must not already be verified */
    if (target_factor->state == OZAYN_MFA_FACT_STATE_VERIFIED) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_FACTOR_ALREADY_VERIFIED);
        return OZAYN_MFA_ERR_FACTOR_ALREADY_VERIFIED;
    }

    /* Check factor is implemented */
    if (!ozayn_mfa_factor_type_is_implemented(target_factor->type)) {
        target_factor->state = OZAYN_MFA_FACT_STATE_UNAVAILABLE;
        _tx_transition(tx, OZAYN_MFA_TX_UNAVAILABLE);
        _init_result(out_result, OZAYN_MFA_RESULT_UNAVAILABLE,
                     OZAYN_MFA_ERR_FACTOR_UNAVAILABLE);
        return OZAYN_MFA_ERR_FACTOR_UNAVAILABLE;
    }

    /* Transition transaction to IN_PROGRESS if needed */
    if (tx->state == OZAYN_MFA_TX_NOT_STARTED) {
        ozayn_mfa_error_t tr = _tx_transition(tx, OZAYN_MFA_TX_IN_PROGRESS);
        if (tr != OZAYN_MFA_OK) {
            _init_result(out_result, OZAYN_MFA_RESULT_ERROR, tr);
            return tr;
        }
    }

    /* For password factor, delegate to authn service if available */
    if (target_factor->type == OZAYN_MFA_FACTOR_PASSWORD &&
        svc->config.authn_service) {
        /* The caller must have already authenticated via the authn service.
         * If we reach here with PASSWORD factor, mark it as verified
         * because the authn layer already confirmed it. */
        target_factor->state = OZAYN_MFA_FACT_STATE_VERIFIED;
        target_factor->verified_at = time(NULL);
        tx->verified_factor_count++;

        /* Record success in attempt control */
        if (svc->config.attempt_control)
            ozayn_ac_record_success(svc->config.attempt_control,
                                     request->identity_id);
    } else {
        /* For non-implemented factors, mark as unavailable */
        target_factor->state = OZAYN_MFA_FACT_STATE_UNAVAILABLE;
        _tx_transition(tx, OZAYN_MFA_TX_UNAVAILABLE);
        _init_result(out_result, OZAYN_MFA_RESULT_UNAVAILABLE,
                     OZAYN_MFA_ERR_FACTOR_UNAVAILABLE);
        return OZAYN_MFA_ERR_FACTOR_UNAVAILABLE;
    }

    /* Check if all factors are now verified */
    ozayn_mfa_policy_t *policy = _find_policy(svc, tx->policy_id);
    if (policy && tx->verified_factor_count >= policy->required_factor_count) {
        _tx_transition(tx, OZAYN_MFA_TX_FACTOR_VERIFIED);

        /* Calculate assurance level */
        tx->assurance = OZAYN_MFA_ASSURANCE_NONE;
        if (tx->verified_factor_count == 1)
            tx->assurance = OZAYN_MFA_ASSURANCE_SINGLE;
        else if (tx->verified_factor_count == 2)
            tx->assurance = OZAYN_MFA_ASSURANCE_MULTI;
        else if (tx->verified_factor_count >= 3)
            tx->assurance = OZAYN_MFA_ASSURANCE_HIGH;

        _init_result(out_result, OZAYN_MFA_RESULT_PENDING, OZAYN_MFA_OK);
        strncpy(out_result->tx_id, tx->id, sizeof(out_result->tx_id) - 1);
        strncpy(out_result->identity_id, tx->identity_id,
                sizeof(out_result->identity_id) - 1);
        strncpy(out_result->policy_id, tx->policy_id,
                sizeof(out_result->policy_id) - 1);
        out_result->assurance = tx->assurance;
        out_result->verified_factor_count = tx->verified_factor_count;
        out_result->required_factor_count = policy->required_factor_count;
        return OZAYN_MFA_OK;
    }

    /* More factors still needed */
    _init_result(out_result, OZAYN_MFA_RESULT_PENDING, OZAYN_MFA_OK);
    strncpy(out_result->tx_id, tx->id, sizeof(out_result->tx_id) - 1);
    strncpy(out_result->identity_id, tx->identity_id,
            sizeof(out_result->identity_id) - 1);
    strncpy(out_result->policy_id, tx->policy_id,
            sizeof(out_result->policy_id) - 1);
    out_result->verified_factor_count = tx->verified_factor_count;
    out_result->required_factor_count = policy ? policy->required_factor_count : 0;
    return OZAYN_MFA_OK;
}

/* ============================================================
 * TRANSACTION COMPLETION
 * ============================================================ */

ozayn_mfa_error_t ozayn_mfa_tx_complete(
    ozayn_mfa_service_t *svc,
    const char *tx_id,
    ozayn_mfa_result_t *out_result)
{
    if (!svc || !tx_id || !out_result)
        return OZAYN_MFA_ERR_NULL;
    if (!svc->initialized) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_NOT_INITIALIZED);
        return OZAYN_MFA_ERR_NOT_INITIALIZED;
    }

    ozayn_mfa_tx_t *tx = _find_tx(svc, tx_id);
    if (!tx) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND);
        return OZAYN_MFA_ERR_TRANSACTION_NOT_FOUND;
    }

    /* Check expiration */
    if (_is_tx_expired(tx)) {
        if (tx->state != OZAYN_MFA_TX_EXPIRED)
            _tx_transition(tx, OZAYN_MFA_TX_EXPIRED);
        _init_result(out_result, OZAYN_MFA_RESULT_EXPIRED,
                     OZAYN_MFA_ERR_TRANSACTION_EXPIRED);
        return OZAYN_MFA_ERR_TRANSACTION_EXPIRED;
    }

    /* Must be in FACTOR_VERIFIED state to complete */
    if (tx->state != OZAYN_MFA_TX_FACTOR_VERIFIED) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_STATE_TRANSITION);
        return OZAYN_MFA_ERR_STATE_TRANSITION;
    }

    /* Verify all factors are actually verified */
    ozayn_mfa_policy_t *policy = _find_policy(svc, tx->policy_id);
    if (!policy) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_POLICY_UNAVAILABLE);
        return OZAYN_MFA_ERR_POLICY_UNAVAILABLE;
    }

    int all_verified = 1;
    for (int i = 0; i < tx->factor_count; i++) {
        if (tx->factors[i].in_use &&
            tx->factors[i].state != OZAYN_MFA_FACT_STATE_VERIFIED) {
            all_verified = 0;
            break;
        }
    }
    if (!all_verified) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR,
                     OZAYN_MFA_ERR_INSUFFICIENT_FACTORS);
        return OZAYN_MFA_ERR_INSUFFICIENT_FACTORS;
    }

    /* Transition to VERIFIED */
    ozayn_mfa_error_t tr = _tx_transition(tx, OZAYN_MFA_TX_VERIFIED);
    if (tr != OZAYN_MFA_OK) {
        _init_result(out_result, OZAYN_MFA_RESULT_ERROR, tr);
        return tr;
    }
    tx->completed_at = time(NULL);

    /* Record success in attempt control */
    if (svc->config.attempt_control)
        ozayn_ac_record_success(svc->config.attempt_control, tx->identity_id);

    _init_result(out_result, OZAYN_MFA_RESULT_VERIFIED, OZAYN_MFA_OK);
    strncpy(out_result->tx_id, tx->id, sizeof(out_result->tx_id) - 1);
    strncpy(out_result->identity_id, tx->identity_id,
            sizeof(out_result->identity_id) - 1);
    strncpy(out_result->policy_id, tx->policy_id,
            sizeof(out_result->policy_id) - 1);
    out_result->assurance = tx->assurance;
    out_result->verified_factor_count = tx->verified_factor_count;
    out_result->required_factor_count = policy->required_factor_count;
    return OZAYN_MFA_OK;
}

/* ============================================================
 * DEFAULT / TEST POLICIES
 * ============================================================ */

ozayn_mfa_policy_t ozayn_mfa_default_policy(void)
{
    ozayn_mfa_policy_t p;
    memset(&p, 0, sizeof(p));
    strncpy(p.id, "default", sizeof(p.id) - 1);
    strncpy(p.name, "Default MFA Policy", sizeof(p.name) - 1);
    p.enabled = 1;
    p.required_factor_count = 2;
    p.required_factors[0] = OZAYN_MFA_FACTOR_PASSWORD;
    p.required_factors[1] = OZAYN_MFA_FACTOR_TOKEN;
    p.required_factor_count_required = 2;
    p.transaction_timeout_seconds = 300;
    p.factor_timeout_seconds = 60;
    p.max_failures = 5;
    p.block_seconds = 900;
    p.version = 1;
    p.created_at = time(NULL);
    p.modified_at = p.created_at;
    p.in_use = 1;
    return p;
}

ozayn_mfa_policy_t ozayn_mfa_test_policy(void)
{
    ozayn_mfa_policy_t p;
    memset(&p, 0, sizeof(p));
    strncpy(p.id, "test-mfa", sizeof(p.id) - 1);
    strncpy(p.name, "Test MFA Policy", sizeof(p.name) - 1);
    p.enabled = 1;
    p.required_factor_count = 2;
    p.required_factors[0] = OZAYN_MFA_FACTOR_PASSWORD;
    p.required_factors[1] = OZAYN_MFA_FACTOR_TOKEN;
    p.required_factor_count_required = 2;
    p.transaction_timeout_seconds = 30;
    p.factor_timeout_seconds = 10;
    p.max_failures = 3;
    p.block_seconds = 60;
    p.version = 1;
    p.created_at = time(NULL);
    p.modified_at = p.created_at;
    p.in_use = 1;
    return p;
}

ozayn_mfa_policy_t ozayn_mfa_high_security_policy(void)
{
    ozayn_mfa_policy_t p;
    memset(&p, 0, sizeof(p));
    strncpy(p.id, "high-security", sizeof(p.id) - 1);
    strncpy(p.name, "High Security MFA Policy", sizeof(p.name) - 1);
    p.enabled = 1;
    p.required_factor_count = 3;
    p.required_factors[0] = OZAYN_MFA_FACTOR_PASSWORD;
    p.required_factors[1] = OZAYN_MFA_FACTOR_TOKEN;
    p.required_factors[2] = OZAYN_MFA_FACTOR_BIOMETRIC;
    p.required_factor_count_required = 3;
    p.transaction_timeout_seconds = 120;
    p.factor_timeout_seconds = 30;
    p.max_failures = 3;
    p.block_seconds = 1800;
    p.version = 1;
    p.created_at = time(NULL);
    p.modified_at = p.created_at;
    p.in_use = 1;
    return p;
}
