#include "attempt_control.h"
#include <string.h>
#include <math.h>
#include <time.h>

/* ============================================================
 * CLOCK HELPER
 * ============================================================ */

static uint64_t _clock_monotonic_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t _seconds_to_us(int seconds)
{
    return (uint64_t)seconds * 1000000ULL;
}

/* ============================================================
 * DEFAULT / TEST POLICIES
 * ============================================================ */

ozayn_ac_policy_t ozayn_ac_default_policy(void)
{
    ozayn_ac_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled              = 1;
    p.max_failures         = 5;
    p.window_seconds       = 300;
    p.initial_delay_ms     = 1000;
    p.max_delay_ms         = 30000;
    p.backoff_multiplier   = 2.0;
    p.block_seconds        = 900;
    p.counter_reset_seconds = 0;
    return p;
}

ozayn_ac_policy_t ozayn_ac_test_policy(void)
{
    ozayn_ac_policy_t p;
    memset(&p, 0, sizeof(p));
    p.enabled              = 1;
    p.max_failures         = 3;
    p.window_seconds       = 5;
    p.initial_delay_ms     = 100;
    p.max_delay_ms         = 2000;
    p.backoff_multiplier   = 2.0;
    p.block_seconds        = 10;
    p.counter_reset_seconds = 0;
    return p;
}

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_ac_validate_policy(const ozayn_ac_policy_t *policy)
{
    if (!policy)
        return -1;
    if (policy->enabled == 0)
        return 0;
    if (policy->max_failures < 1)
        return -1;
    if (policy->window_seconds < 1)
        return -1;
    if (policy->initial_delay_ms < 0)
        return -1;
    if (policy->max_delay_ms < 0)
        return -1;
    if (policy->backoff_multiplier < 1.0)
        return -1;
    if (policy->block_seconds < 1)
        return -1;
    if (policy->counter_reset_seconds < 0)
        return -1;
    return 0;
}

int ozayn_ac_validate_state(ozayn_ac_state_t state)
{
    if (state < OZAYN_AC_STATE_READY || state > OZAYN_AC_STATE_BLOCKED)
        return -1;
    return 0;
}

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_ac_state_name(ozayn_ac_state_t state)
{
    switch (state) {
        case OZAYN_AC_STATE_READY:     return "READY";
        case OZAYN_AC_STATE_THROTTLED: return "THROTTLED";
        case OZAYN_AC_STATE_BLOCKED:   return "BLOCKED";
        default:                       return "UNKNOWN";
    }
}

const char *ozayn_ac_error_name(ozayn_ac_error_t error)
{
    switch (error) {
        case OZAYN_AC_OK:                      return "OK";
        case OZAYN_AC_ERR_NULL:                return "NULL";
        case OZAYN_AC_ERR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
        case OZAYN_AC_ERR_INVALID:             return "INVALID";
        case OZAYN_AC_ERR_POLICY_INVALID:      return "POLICY_INVALID";
        case OZAYN_AC_ERR_STATE_INVALID:       return "STATE_INVALID";
        case OZAYN_AC_ERR_COUNTER_OVERFLOW:    return "COUNTER_OVERFLOW";
        case OZAYN_AC_ERR_STORAGE_FAILED:      return "STORAGE_FAILED";
        case OZAYN_AC_ERR_NOT_FOUND:           return "NOT_FOUND";
        case OZAYN_AC_ERR_TIME_INVALID:        return "TIME_INVALID";
        case OZAYN_AC_ERR_RATE_LIMITED:        return "RATE_LIMITED";
        case OZAYN_AC_ERR_TEMPORARILY_BLOCKED: return "TEMPORARILY_BLOCKED";
        default:                               return "UNKNOWN";
    }
}

/* ============================================================
 * ENTRY LOOKUP
 * ============================================================ */

static ozayn_ac_entry_t *_find_entry(ozayn_ac_service_t *svc,
                                      const char *identity_id)
{
    if (!svc || !identity_id)
        return NULL;
    for (int i = 0; i < svc->entry_count; i++) {
        if (svc->entries[i].in_use &&
            strcmp(svc->entries[i].identity_id, identity_id) == 0)
            return &svc->entries[i];
    }
    return NULL;
}

static ozayn_ac_entry_t *_find_or_create_entry(ozayn_ac_service_t *svc,
                                                 const char *identity_id)
{
    ozayn_ac_entry_t *entry = _find_entry(svc, identity_id);
    if (entry)
        return entry;

    if (svc->entry_count >= OZAYN_AC_MAX_TRACKED_IDENTITIES)
        return NULL;

    entry = &svc->entries[svc->entry_count];
    memset(entry, 0, sizeof(*entry));
    strncpy(entry->identity_id, identity_id,
            sizeof(entry->identity_id) - 1);
    entry->in_use          = 1;
    entry->state           = OZAYN_AC_STATE_READY;
    entry->failure_count   = 0;
    entry->last_failure_us = 0;
    entry->window_start_us = 0;
    entry->block_until_us  = 0;
    entry->current_delay_ms = 0;
    entry->version         = 1;
    svc->entry_count++;

    return entry;
}

/* ============================================================
 * LAZY CLEANUP
 *
 * Remove entries for identities that have been clean
 * (no failures, not blocked) for a long time.
 * ============================================================ */

static void _lazy_cleanup(ozayn_ac_service_t *svc, uint64_t now_us)
{
    if (!svc->config.policy.enabled)
        return;

    uint64_t cleanup_interval = _seconds_to_us(svc->config.policy.window_seconds * 2);
    if (cleanup_interval < 300000000ULL)
        cleanup_interval = 300000000ULL;

    if (now_us - svc->last_cleanup_us < cleanup_interval)
        return;

    svc->last_cleanup_us = now_us;

    for (int i = 0; i < svc->entry_count; i++) {
        ozayn_ac_entry_t *e = &svc->entries[i];
        if (!e->in_use)
            continue;
        if (e->state != OZAYN_AC_STATE_READY)
            continue;
        if (e->failure_count != 0)
            continue;

        uint64_t window_sec = _seconds_to_us(svc->config.policy.window_seconds);
        if (e->window_start_us > 0 && now_us - e->window_start_us > window_sec * 2) {
            e->in_use = 0;
            memset(e, 0, sizeof(*e));
        }
    }
}

/* ============================================================
 * COMPUTE BACKOFF DELAY
 * ============================================================ */

static int _compute_delay_ms(const ozayn_ac_policy_t *policy, int failure_count)
{
    if (failure_count <= 0)
        return 0;

    double delay = (double)policy->initial_delay_ms;
    for (int i = 1; i < failure_count; i++) {
        delay *= policy->backoff_multiplier;
        if (delay >= (double)policy->max_delay_ms)
            return policy->max_delay_ms;
    }
    if (delay >= (double)policy->max_delay_ms)
        return policy->max_delay_ms;
    return (int)delay;
}

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_ac_error_t ozayn_ac_service_init(ozayn_ac_service_t *svc,
                                        const ozayn_ac_service_config_t *config)
{
    if (!svc || !config)
        return OZAYN_AC_ERR_NULL;

    if (ozayn_ac_validate_policy(&config->policy) != 0)
        return OZAYN_AC_ERR_POLICY_INVALID;

    memset(svc, 0, sizeof(*svc));
    svc->config            = *config;
    svc->initialized       = 1;
    svc->last_cleanup_us   = _clock_monotonic_us();

    return OZAYN_AC_OK;
}

void ozayn_ac_service_shutdown(ozayn_ac_service_t *svc)
{
    if (!svc)
        return;

    for (int i = 0; i < svc->entry_count; i++) {
        if (svc->entries[i].in_use) {
            memset(&svc->entries[i], 0, sizeof(svc->entries[i]));
        }
    }

    svc->entry_count   = 0;
    svc->initialized   = 0;
}

/* ============================================================
 * CHECK IF ATTEMPT IS ALLOWED
 *
 * Returns:
 *   *out_allowed = 1 if the attempt may proceed
 *   *out_allowed = 0 if the attempt is blocked
 *   *out_retry_after_ms = suggested wait time (0 if allowed)
 * ============================================================ */

ozayn_ac_error_t ozayn_ac_check_allowed(ozayn_ac_service_t *svc,
                                          const char *identity_id,
                                          int *out_allowed,
                                          int *out_retry_after_ms)
{
    if (!svc || !identity_id || !out_allowed || !out_retry_after_ms)
        return OZAYN_AC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AC_ERR_NOT_INITIALIZED;
    if (!identity_id[0])
        return OZAYN_AC_ERR_INVALID;

    if (!svc->config.policy.enabled) {
        *out_allowed      = 1;
        *out_retry_after_ms = 0;
        return OZAYN_AC_OK;
    }

    uint64_t now_us = _clock_monotonic_us();
    _lazy_cleanup(svc, now_us);

    ozayn_ac_entry_t *entry = _find_entry(svc, identity_id);
    if (!entry) {
        *out_allowed      = 1;
        *out_retry_after_ms = 0;
        return OZAYN_AC_OK;
    }

    /* Check if still in block period */
    if (entry->state == OZAYN_AC_STATE_BLOCKED) {
        if (now_us < entry->block_until_us) {
            uint64_t remaining = entry->block_until_us - now_us;
            *out_allowed      = 0;
            *out_retry_after_ms = (int)((remaining + 999ULL) / 1000ULL);
            return OZAYN_AC_ERR_TEMPORARILY_BLOCKED;
        }
        entry->state         = OZAYN_AC_STATE_READY;
        entry->failure_count = 0;
        entry->current_delay_ms = 0;
        entry->block_until_us = 0;
        entry->version++;
    }

    /* Check if in throttle period (backoff delay) */
    if (entry->state == OZAYN_AC_STATE_THROTTLED) {
        uint64_t elapsed = now_us - entry->last_failure_us;
        uint64_t delay_us = (uint64_t)entry->current_delay_ms * 1000ULL;

        if (elapsed < delay_us) {
            uint64_t remaining = delay_us - elapsed;
            *out_allowed      = 0;
            *out_retry_after_ms = (int)((remaining + 999ULL) / 1000ULL);
            return OZAYN_AC_ERR_RATE_LIMITED;
        }
        entry->state         = OZAYN_AC_STATE_READY;
        entry->current_delay_ms = 0;
        entry->version++;
    }

    /* Check if within failure window */
    if (entry->failure_count > 0 &&
        (now_us - entry->window_start_us) < _seconds_to_us(svc->config.policy.window_seconds)) {
        /* Still within window, check if approaching limit */
        if (entry->failure_count >= svc->config.policy.max_failures) {
            entry->state = OZAYN_AC_STATE_BLOCKED;
            entry->block_until_us = now_us + _seconds_to_us(svc->config.policy.block_seconds);
            entry->version++;
            *out_allowed      = 0;
            *out_retry_after_ms = svc->config.policy.block_seconds * 1000;
            return OZAYN_AC_ERR_TEMPORARILY_BLOCKED;
        }
        /* Within window but not yet blocked — allow with delay */
        int delay = _compute_delay_ms(&svc->config.policy, entry->failure_count);
        if (delay > 0) {
            uint64_t elapsed_since_failure = now_us - entry->last_failure_us;
            uint64_t delay_us_val = (uint64_t)delay * 1000ULL;
            if (elapsed_since_failure < delay_us_val) {
                uint64_t remaining = delay_us_val - elapsed_since_failure;
                entry->state = OZAYN_AC_STATE_THROTTLED;
                entry->version++;
                *out_allowed      = 0;
                *out_retry_after_ms = (int)((remaining + 999ULL) / 1000ULL);
                return OZAYN_AC_ERR_RATE_LIMITED;
            }
        }
    }

    *out_allowed      = 1;
    *out_retry_after_ms = 0;
    return OZAYN_AC_OK;
}

/* ============================================================
 * RECORD FAILURE
 * ============================================================ */

ozayn_ac_error_t ozayn_ac_record_failure(ozayn_ac_service_t *svc,
                                           const char *identity_id)
{
    if (!svc || !identity_id)
        return OZAYN_AC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AC_ERR_NOT_INITIALIZED;
    if (!identity_id[0])
        return OZAYN_AC_ERR_INVALID;
    if (!svc->config.policy.enabled)
        return OZAYN_AC_OK;

    uint64_t now_us = _clock_monotonic_us();
    ozayn_ac_entry_t *entry = _find_or_create_entry(svc, identity_id);
    if (!entry)
        return OZAYN_AC_ERR_COUNTER_OVERFLOW;

    uint64_t window_us = _seconds_to_us(svc->config.policy.window_seconds);

    /* Reset window if expired */
    if (entry->failure_count > 0 &&
        (now_us - entry->window_start_us) >= window_us) {
        entry->failure_count   = 0;
        entry->current_delay_ms = 0;
        entry->state           = OZAYN_AC_STATE_READY;
    }

    /* First failure — start the window */
    if (entry->failure_count == 0) {
        entry->window_start_us = now_us;
    }

    entry->failure_count++;
    entry->last_failure_us = now_us;
    entry->version++;

    /* Check if should transition to THROTTLED or BLOCKED */
    if (entry->failure_count >= svc->config.policy.max_failures) {
        entry->state           = OZAYN_AC_STATE_BLOCKED;
        entry->block_until_us  = now_us + _seconds_to_us(svc->config.policy.block_seconds);
        entry->current_delay_ms = 0;
    } else {
        entry->state           = OZAYN_AC_STATE_THROTTLED;
        entry->current_delay_ms = _compute_delay_ms(&svc->config.policy,
                                                     entry->failure_count);
    }

    return OZAYN_AC_OK;
}

/* ============================================================
 * RECORD SUCCESS
 * ============================================================ */

ozayn_ac_error_t ozayn_ac_record_success(ozayn_ac_service_t *svc,
                                           const char *identity_id)
{
    if (!svc || !identity_id)
        return OZAYN_AC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AC_ERR_NOT_INITIALIZED;
    if (!identity_id[0])
        return OZAYN_AC_ERR_INVALID;

    if (!svc->config.policy.enabled)
        return OZAYN_AC_OK;

    ozayn_ac_entry_t *entry = _find_entry(svc, identity_id);
    if (!entry)
        return OZAYN_AC_OK;

    entry->failure_count     = 0;
    entry->current_delay_ms  = 0;
    entry->state             = OZAYN_AC_STATE_READY;
    entry->block_until_us    = 0;
    entry->window_start_us   = 0;
    entry->last_failure_us   = 0;
    entry->version++;

    return OZAYN_AC_OK;
}

/* ============================================================
 * RESET
 * ============================================================ */

ozayn_ac_error_t ozayn_ac_reset(ozayn_ac_service_t *svc,
                                  const char *identity_id)
{
    if (!svc || !identity_id)
        return OZAYN_AC_ERR_NULL;
    if (!svc->initialized)
        return OZAYN_AC_ERR_NOT_INITIALIZED;
    if (!identity_id[0])
        return OZAYN_AC_ERR_INVALID;

    ozayn_ac_entry_t *entry = _find_entry(svc, identity_id);
    if (!entry)
        return OZAYN_AC_OK;

    entry->failure_count     = 0;
    entry->current_delay_ms  = 0;
    entry->state             = OZAYN_AC_STATE_READY;
    entry->block_until_us    = 0;
    entry->window_start_us   = 0;
    entry->last_failure_us   = 0;
    entry->version++;

    return OZAYN_AC_OK;
}

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_ac_service_is_initialized(const ozayn_ac_service_t *svc)
{
    if (!svc)
        return 0;
    return svc->initialized;
}

int ozayn_ac_service_entry_count(const ozayn_ac_service_t *svc)
{
    if (!svc || !svc->initialized)
        return 0;
    return svc->entry_count;
}

int ozayn_ac_get_failure_count(const ozayn_ac_service_t *svc,
                                const char *identity_id)
{
    if (!svc || !identity_id || !svc->initialized)
        return -1;
    const ozayn_ac_entry_t *entry = _find_entry((ozayn_ac_service_t *)svc,
                                                  identity_id);
    if (!entry)
        return 0;
    return entry->failure_count;
}

ozayn_ac_state_t ozayn_ac_get_state(const ozayn_ac_service_t *svc,
                                     const char *identity_id)
{
    if (!svc || !identity_id || !svc->initialized)
        return OZAYN_AC_STATE_READY;
    const ozayn_ac_entry_t *entry = _find_entry((ozayn_ac_service_t *)svc,
                                                  identity_id);
    if (!entry)
        return OZAYN_AC_STATE_READY;
    return entry->state;
}
