#ifndef OZAYN_ATTEMPT_CONTROL_H
#define OZAYN_ATTEMPT_CONTROL_H

#include "authentication.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * attempt_control.h — Authentication Attempt Control & Brute-Force
 *                      Protection (Section 03, Step 15).
 *
 * Protects the authentication system against repeated failures,
 * brute-force attacks, credential guessing, and uncontrolled
 * authentication requests. Provides per-identity attempt tracking,
 * progressive backoff, temporary blocking, and rate limiting.
 *
 * Architecture:
 *   AUTHENTICATION REQUEST
 *          |
 *          v
 *   ATTEMPT CONTROL  <-- this layer
 *          |
 *   +------+------+
 *   |      |      |
 *   v      v      v
 *  RATE  BACKOFF  BLOCK
 *  LIMIT
 *          |
 *          v
 *   PASSWORD AUTHENTICATION
 *          |
 *          v
 *   ATTEMPT RESULT UPDATE
 *          |
 *          v
 *   AUTHENTICATION RESULT
 *
 * Step 15 scope:
 *   - Authentication attempt tracking (per-identity)
 *   - Failure counting with progressive backoff
 *   - Rate limiting with configurable window
 *   - Temporary authentication blocking
 *   - Successful authentication reset behavior
 *   - Attempt state lifecycle
 *   - Anti-enumeration (unified failure responses)
 *   - Security policy configuration
 *   - Monotonic clock for timing decisions
 *   - Bounded memory (max tracked identities)
 *   - Lazy cleanup of expired entries
 *   - Provider/vault failure differentiation
 *   - No bypasses (no master/debug/developer password)
 *
 * NOT in scope:
 *   - MFA / multi-factor
 *   - Face / voice / gesture / biometric authentication
 *   - Session management
 *   - Authorization / RBAC
 *   - Login GUI
 *   - Password recovery / account recovery
 *   - Account lockout (permanent)
 *   - Persistent attempt state across restarts
 */

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_AC_MAX_TRACKED_IDENTITIES  256
#define OZAYN_AC_MAX_ID_LEN              64

/* ============================================================
 * ATTEMPT STATE
 * ============================================================ */

typedef enum {
    OZAYN_AC_STATE_READY     = 0,  /* Normal, attempts allowed */
    OZAYN_AC_STATE_THROTTLED = 1,  /* Rate-limited, backoff active */
    OZAYN_AC_STATE_BLOCKED   = 2   /* Temporarily blocked */
} ozayn_ac_state_t;

/* ============================================================
 * ATTEMPT CONTROL ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_AC_OK                       =   0,
    OZAYN_AC_ERR_NULL                 =  -1,
    OZAYN_AC_ERR_NOT_INITIALIZED      =  -2,
    OZAYN_AC_ERR_INVALID              =  -3,
    OZAYN_AC_ERR_POLICY_INVALID       =  -4,
    OZAYN_AC_ERR_STATE_INVALID        =  -5,
    OZAYN_AC_ERR_COUNTER_OVERFLOW     =  -6,
    OZAYN_AC_ERR_STORAGE_FAILED       =  -7,
    OZAYN_AC_ERR_NOT_FOUND            =  -8,
    OZAYN_AC_ERR_TIME_INVALID         =  -9,
    OZAYN_AC_ERR_RATE_LIMITED         = -10,
    OZAYN_AC_ERR_TEMPORARILY_BLOCKED  = -11
} ozayn_ac_error_t;

/* ============================================================
 * ATTEMPT SECURITY POLICY
 *
 * All security-sensitive values are centralized here.
 * Invalid policy configurations are rejected at init time.
 * ============================================================ */

typedef struct {
    int     enabled;              /* 1 = attempt control active, 0 = disabled */
    int     max_failures;         /* Failures before temporary block (default 5) */
    int     window_seconds;       /* Time window for counting failures (default 300) */
    int     initial_delay_ms;     /* Initial backoff delay in ms (default 1000) */
    int     max_delay_ms;         /* Maximum backoff delay in ms (default 30000) */
    double  backoff_multiplier;   /* Multiplier per failure (default 2.0) */
    int     block_seconds;        /* Temporary block duration (default 900) */
    int     counter_reset_seconds;/* Reset failure count after N seconds of success (default 0 = immediate) */
} ozayn_ac_policy_t;

/* ============================================================
 * ATTEMPT ENTRY (per-identity tracking state)
 * ============================================================ */

typedef struct {
    char                    identity_id[OZAYN_AC_MAX_ID_LEN];
    int                     failure_count;
    uint64_t                last_failure_us;      /* Monotonic timestamp of last failure */
    uint64_t                window_start_us;      /* Start of current counting window */
    uint64_t                block_until_us;       /* Block expiration timestamp */
    int                     current_delay_ms;     /* Current backoff delay */
    ozayn_ac_state_t        state;
    int                     in_use;
    uint32_t                version;
} ozayn_ac_entry_t;

/* ============================================================
 * ATTEMPT CONTROL SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_ac_policy_t       policy;
} ozayn_ac_service_config_t;

/* ============================================================
 * ATTEMPT CONTROL SERVICE
 * ============================================================ */

typedef struct {
    ozayn_ac_entry_t        entries[OZAYN_AC_MAX_TRACKED_IDENTITIES];
    int                     entry_count;
    ozayn_ac_service_config_t config;
    int                     initialized;
    uint64_t                last_cleanup_us;
} ozayn_ac_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_ac_error_t ozayn_ac_service_init(ozayn_ac_service_t *svc,
                                        const ozayn_ac_service_config_t *config);

void ozayn_ac_service_shutdown(ozayn_ac_service_t *svc);

/* ============================================================
 * ATTEMPT CONTROL OPERATIONS
 * ============================================================ */

/* Check if an authentication attempt is currently allowed */
ozayn_ac_error_t ozayn_ac_check_allowed(ozayn_ac_service_t *svc,
                                          const char *identity_id,
                                          int *out_allowed,
                                          int *out_retry_after_ms);

/* Record a failed authentication attempt */
ozayn_ac_error_t ozayn_ac_record_failure(ozayn_ac_service_t *svc,
                                           const char *identity_id);

/* Record a successful authentication (resets failure state) */
ozayn_ac_error_t ozayn_ac_record_success(ozayn_ac_service_t *svc,
                                           const char *identity_id);

/* Reset attempt state for an identity */
ozayn_ac_error_t ozayn_ac_reset(ozayn_ac_service_t *svc,
                                  const char *identity_id);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_ac_service_is_initialized(const ozayn_ac_service_t *svc);
int ozayn_ac_service_entry_count(const ozayn_ac_service_t *svc);
int ozayn_ac_get_failure_count(const ozayn_ac_service_t *svc,
                                const char *identity_id);
ozayn_ac_state_t ozayn_ac_get_state(const ozayn_ac_service_t *svc,
                                     const char *identity_id);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_ac_validate_policy(const ozayn_ac_policy_t *policy);
int ozayn_ac_validate_state(ozayn_ac_state_t state);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_ac_state_name(ozayn_ac_state_t state);
const char *ozayn_ac_error_name(ozayn_ac_error_t error);

/* ============================================================
 * DEFAULT POLICY
 * ============================================================ */

ozayn_ac_policy_t ozayn_ac_default_policy(void);
ozayn_ac_policy_t ozayn_ac_test_policy(void);

#endif
