#ifndef OZAYN_SESS_H
#define OZAYN_SESS_H

#include "authentication.h"
#include "identity.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
 * session_management.h — Secure Session Management Foundation
 *
 * Manages authenticated sessions after successful authentication.
 * Provides session creation, validation, activity tracking,
 * expiration, termination, and revocation.
 *
 * Uses ozayn_sess_ prefix to avoid collision with platform-level
 * ozayn_session_* functions (OS lock-screen session state).
 *
 * Architecture:
 *   AUTHENTICATION SUCCESS
 *          |
 *          v
 *   SESSION SERVICE  <-- this layer
 *          |
 *   +------+------+------+
 *   |      |      |      |
 *   v      v      v      v
 *  CREATE VALIDATE TOUCH  TERMINATE
 *   / REVOKE / EXPIRE
 *
 * Step 16 scope:
 *   - Session identifier generation (cryptographically secure)
 *   - Session object lifecycle
 *   - Session creation after authentication
 *   - Session validation (state + expiration + identity check)
 *   - Session activity tracking (touch)
 *   - Session idle timeout
 *   - Session absolute lifetime
 *   - Session termination (user-initiated)
 *   - Session revocation (security-initiated)
 *   - Identity-state integration (active/suspended/revoked)
 *   - Session limits (max per identity, max total)
 *   - Session fixation protection (fresh IDs on create)
 *   - In-memory session store (no persistence)
 *   - Monotonic clock for timing decisions
 *   - Session security tests
 *
 * NOT in scope:
 *   - Authorization / RBAC / Permissions / Roles
 *   - MFA / Biometric / Face / Voice / Gesture
 *   - Password recovery / Account recovery
 *   - Login GUI / Session dashboard
 *   - OAuth / JWT / Cloud sessions
 *   - Remote / distributed sessions
 *   - API gateway authentication
 *   - Administrative bypasses
 */

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define OZAYN_SESS_MAX_ID_LEN        64
#define OZAYN_SESS_MAX_IDENTITY_LEN  64
#define OZAYN_SESS_MAX_SESSIONS      512
#define OZAYN_SESS_ID_BYTES          32

/* ============================================================
 * SESSION STATE
 * ============================================================ */

typedef enum {
    OZAYN_SESS_STATE_UNINITIALIZED = 0,
    OZAYN_SESS_STATE_ACTIVE        = 1,
    OZAYN_SESS_STATE_EXPIRED       = 2,
    OZAYN_SESS_STATE_REVOKED       = 3,
    OZAYN_SESS_STATE_TERMINATED    = 4
} ozayn_sess_state_t;

/* ============================================================
 * SESSION ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_SESS_OK                            =   0,
    OZAYN_SESS_ERR_NULL                      =  -1,
    OZAYN_SESS_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_SESS_ERR_NOT_FOUND                 =  -3,
    OZAYN_SESS_ERR_INVALID                   =  -4,
    OZAYN_SESS_ERR_ID_INVALID                =  -5,
    OZAYN_SESS_ERR_ID_GENERATION_FAILED      =  -6,
    OZAYN_SESS_ERR_IDENTITY_INVALID          =  -7,
    OZAYN_SESS_ERR_IDENTITY_REVOKED          =  -8,
    OZAYN_SESS_ERR_IDENTITY_SUSPENDED        =  -9,
    OZAYN_SESS_ERR_AUTH_REQUIRED             = -10,
    OZAYN_SESS_ERR_AUTH_FAILED               = -11,
    OZAYN_SESS_ERR_STATE_INVALID             = -12,
    OZAYN_SESS_ERR_STATE_TRANSITION_INVALID  = -13,
    OZAYN_SESS_ERR_EXPIRED                   = -14,
    OZAYN_SESS_ERR_REVOKED                   = -15,
    OZAYN_SESS_ERR_TERMINATED                = -16,
    OZAYN_SESS_ERR_LIMIT_REACHED             = -17,
    OZAYN_SESS_ERR_POLICY_INVALID            = -18,
    OZAYN_SESS_ERR_TIMEOUT_INVALID           = -19,
    OZAYN_SESS_ERR_UNAVAILABLE               = -20
} ozayn_sess_error_t;

/* ============================================================
 * SESSION POLICY
 * ============================================================ */

typedef struct {
    int     enabled;
    int     max_sessions_total;
    int     max_sessions_per_identity;
    int     idle_timeout_seconds;
    int     absolute_lifetime_seconds;
} ozayn_sess_policy_t;

/* ============================================================
 * SESSION OBJECT
 * ============================================================ */

typedef struct {
    char                        id[OZAYN_SESS_MAX_ID_LEN];
    char                        identity_id[OZAYN_SESS_MAX_IDENTITY_LEN];
    ozayn_authn_method_t        method;
    ozayn_sess_state_t          state;
    time_t                      created_at;
    time_t                      last_activity_at;
    time_t                      expires_at;
    time_t                      absolute_expires_at;
    uint32_t                    version;
    int                         in_use;
} ozayn_sess_t;

/* ============================================================
 * SESSION SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    ozayn_identity_service_t    *identity_service;
    ozayn_sess_policy_t         policy;
} ozayn_sess_service_config_t;

/* ============================================================
 * SESSION SERVICE
 * ============================================================ */

typedef struct {
    ozayn_sess_t                    sessions[OZAYN_SESS_MAX_SESSIONS];
    int                             session_count;
    ozayn_sess_service_config_t     config;
    int                             initialized;
} ozayn_sess_service_t;

/* ============================================================
 * SERVICE LIFECYCLE
 * ============================================================ */

ozayn_sess_error_t ozayn_sess_service_init(
    ozayn_sess_service_t *svc,
    const ozayn_sess_service_config_t *config);

void ozayn_sess_service_shutdown(ozayn_sess_service_t *svc);

/* ============================================================
 * SESSION OPERATIONS
 * ============================================================ */

/* Create a new session after successful authentication.
 * Requires: auth response with RESULT_SUCCESS and VERIFY_VERIFIED.
 * Requires: identity in ACTIVE state.
 * Generates a cryptographically secure session ID. */
ozayn_sess_error_t ozayn_sess_create(
    ozayn_sess_service_t *svc,
    const ozayn_authn_response_t *auth_response,
    ozayn_sess_t *out_session);

/* Validate a session by ID.
 * Checks: existence, state, expiration, identity validity.
 * Returns the session data in out_session on success. */
ozayn_sess_error_t ozayn_sess_validate(
    ozayn_sess_service_t *svc,
    const char *session_id,
    ozayn_sess_t *out_session);

/* Look up a session by ID without validation checks.
 * Returns session data without checking expiration or identity. */
ozayn_sess_error_t ozayn_sess_get(
    ozayn_sess_service_t *svc,
    const char *session_id,
    ozayn_sess_t *out_session);

/* Record session activity (touch).
 * Updates last_activity_at. Does NOT extend absolute expiration. */
ozayn_sess_error_t ozayn_sess_touch(
    ozayn_sess_service_t *svc,
    const char *session_id);

/* Terminate a session (user-initiated logout). */
ozayn_sess_error_t ozayn_sess_terminate(
    ozayn_sess_service_t *svc,
    const char *session_id);

/* Revoke a session (security-initiated). */
ozayn_sess_error_t ozayn_sess_revoke(
    ozayn_sess_service_t *svc,
    const char *session_id);

/* Expire sessions that have passed their timeout.
 * Scans all sessions and transitions expired ones. */
ozayn_sess_error_t ozayn_sess_expire(
    ozayn_sess_service_t *svc);

/* ============================================================
 * QUERY
 * ============================================================ */

int ozayn_sess_service_is_initialized(const ozayn_sess_service_t *svc);
int ozayn_sess_service_session_count(const ozayn_sess_service_t *svc);

/* ============================================================
 * VALIDATION
 * ============================================================ */

int ozayn_sess_validate_state(ozayn_sess_state_t state);
int ozayn_sess_validate_policy(const ozayn_sess_policy_t *policy);
int ozayn_sess_validate_transition(ozayn_sess_state_t from,
                                    ozayn_sess_state_t to);
int ozayn_sess_validate_id(const char *session_id);

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_sess_state_name(ozayn_sess_state_t state);
const char *ozayn_sess_error_name(ozayn_sess_error_t error);

/* ============================================================
 * DEFAULT / TEST POLICIES
 * ============================================================ */

ozayn_sess_policy_t ozayn_sess_default_policy(void);
ozayn_sess_policy_t ozayn_sess_test_policy(void);

#endif
