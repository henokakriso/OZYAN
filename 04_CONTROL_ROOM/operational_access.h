/*
 * operational_access.h — Section 04, Step 28
 * Operational Access, Session & Command Authority Management Foundation
 *
 * Access Control Integration Layer.
 * Consumes Section 03 security decisions — does NOT replace them.
 *
 * Operational Authority is a bounded Control Room execution context
 * derived from the authoritative security system. It does not create,
 * grant, escalate, or replace permissions.
 */

#ifndef OZAYN_OPERATIONAL_ACCESS_H
#define OZAYN_OPERATIONAL_ACCESS_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * LIMITS
 * ============================================================ */

#define OZAYN_OAC_MAX_ID_LEN          64
#define OZAYN_OAC_MAX_IDENTITY_LEN    64
#define OZAYN_OAC_MAX_SESSION_LEN     64
#define OZAYN_OAC_MAX_AUTHZ_REF_LEN   64
#define OZAYN_OAC_MAX_TARGET_LEN      64
#define OZAYN_OAC_MAX_CAPABILITY_LEN  64
#define OZAYN_OAC_MAX_ACTION_LEN      64
#define OZAYN_OAC_MAX_PERMISSION_LEN  64
#define OZAYN_OAC_MAX_META_LEN       256
#define OZAYN_OAC_MAX_SCOPES          8

#define OZAYN_OAC_MAX_ACCESS_CONTEXTS  64
#define OZAYN_OAC_MAX_AUTHORITIES     128
#define OZAYN_OAC_MAX_AUTHORITY_HISTORY 64
#define OZAYN_OAC_MAX_VALIDATION_LOG   64

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_OAC_OK                        =   0,
    OZAYN_OAC_ERR_NULL                  =  -1,
    OZAYN_OAC_ERR_NOT_INITIALIZED       =  -2,
    OZAYN_OAC_ERR_ALREADY_INITIALIZED   =  -3,
    OZAYN_OAC_ERR_NOT_FOUND             =  -4,
    OZAYN_OAC_ERR_FULL                  =  -5,
    OZAYN_OAC_ERR_DUPLICATE             =  -6,
    OZAYN_OAC_ERR_STATE_TRANSITION      =  -7,
    OZAYN_OAC_ERR_INVALID_PARAM         =  -8,

    OZAYN_OAC_ERR_ACCESS_INVALID        = -10,
    OZAYN_OAC_ERR_ACCESS_DENIED         = -11,
    OZAYN_OAC_ERR_ACCESS_EXPIRED        = -12,
    OZAYN_OAC_ERR_ACCESS_REVOKED        = -13,

    OZAYN_OAC_ERR_SESSION_INVALID       = -20,
    OZAYN_OAC_ERR_SESSION_EXPIRED       = -21,
    OZAYN_OAC_ERR_SESSION_REVOKED       = -22,
    OZAYN_OAC_ERR_SESSION_MISMATCH      = -23,

    OZAYN_OAC_ERR_AUTHORITY_INVALID     = -30,
    OZAYN_OAC_ERR_AUTHORITY_EXPIRED     = -31,
    OZAYN_OAC_ERR_AUTHORITY_REVOKED     = -32,
    OZAYN_OAC_ERR_AUTHORITY_CONSUMED    = -33,
    OZAYN_OAC_ERR_AUTHORITY_MISMATCH    = -34,
    OZAYN_OAC_ERR_AUTHORITY_DUPLICATE   = -35,
    OZAYN_OAC_ERR_AUTHORITY_SCOPE       = -36,

    OZAYN_OAC_ERR_IDENTITY_MISMATCH     = -40,

    OZAYN_OAC_ERR_AUTHORIZATION_UNAVAIL = -50,
    OZAYN_OAC_ERR_AUTHORIZATION_FAILED  = -51,
    OZAYN_OAC_ERR_PERMISSION_DENIED     = -52,

    OZAYN_OAC_ERR_CONCURRENCY           = -60,
    OZAYN_OAC_ERR_STORAGE               = -61,
    OZAYN_OAC_ERR_AUDIT                 = -62,
    OZAYN_OAC_ERR_EVENT                 = -63
} ozayn_oac_err_t;

/* ============================================================
 * ACCESS LEVELS
 * ============================================================
 * These are NOT replacements for permissions.
 * A broad access level does NOT grant unlimited authority.
 */

typedef enum {
    OZAYN_OAC_LEVEL_NONE       = 0,
    OZAYN_OAC_LEVEL_OBSERVE    = 1,
    OZAYN_OAC_LEVEL_DIAGNOSTIC = 2,
    OZAYN_OAC_LEVEL_OPERATE    = 3,
    OZAYN_OAC_LEVEL_ADMIN      = 4
} ozayn_oac_access_level_t;

/* ============================================================
 * ACCESS CONTEXT STATES
 * ============================================================ */

typedef enum {
    OZAYN_OAC_CTX_CREATED        = 0,
    OZAYN_OAC_CTX_ACTIVE         = 1,
    OZAYN_OAC_CTX_VALIDATED      = 2,
    OZAYN_OAC_CTX_EXPIRED        = 3,
    OZAYN_OAC_CTX_REVOKED        = 4,
    OZAYN_OAC_CTX_TERMINATED     = 5
} ozayn_oac_ctx_state_t;

/* ============================================================
 * OPERATIONAL AUTHORITY STATES
 * ============================================================ */

typedef enum {
    OZAYN_OAC_AUTH_REQUESTED    = 0,
    OZAYN_OAC_AUTH_VALIDATING   = 1,
    OZAYN_OAC_AUTH_AUTHORIZED   = 2,
    OZAYN_OAC_AUTH_DENIED       = 3,
    OZAYN_OAC_AUTH_EXPIRED      = 4,
    OZAYN_OAC_AUTH_REVOKED      = 5,
    OZAYN_OAC_AUTH_INVALID      = 6,
    OZAYN_OAC_AUTH_CONSUMED     = 7,
    OZAYN_OAC_AUTH_CANCELLED    = 8
} ozayn_oac_auth_state_t;

/* ============================================================
 * ACCESS SCOPE TYPES
 * ============================================================ */

typedef enum {
    OZAYN_OAC_SCOPE_SYSTEM_WIDE        = 0,
    OZAYN_OAC_SCOPE_COMPONENT_SPECIFIC = 1,
    OZAYN_OAC_SCOPE_CAPABILITY_SPECIFIC = 2,
    OZAYN_OAC_SCOPE_OPERATION_SPECIFIC = 3,
    OZAYN_OAC_SCOPE_WORKFLOW_SPECIFIC  = 4,
    OZAYN_OAC_SCOPE_DEVICE_SPECIFIC    = 5,
    OZAYN_OAC_SCOPE_RESOURCE_SPECIFIC  = 6
} ozayn_oac_scope_type_t;

/* ============================================================
 * VALIDATION EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_OAC_EVT_ACCESS_CREATED       = 0,
    OZAYN_OAC_EVT_ACCESS_VALIDATED     = 1,
    OZAYN_OAC_EVT_ACCESS_DENIED        = 2,
    OZAYN_OAC_EVT_ACCESS_EXPIRED       = 3,
    OZAYN_OAC_EVT_ACCESS_REVOKED       = 4,
    OZAYN_OAC_EVT_AUTHORITY_REQUESTED  = 5,
    OZAYN_OAC_EVT_AUTHORITY_GRANTED    = 6,
    OZAYN_OAC_EVT_AUTHORITY_DENIED     = 7,
    OZAYN_OAC_EVT_AUTHORITY_EXPIRED    = 8,
    OZAYN_OAC_EVT_AUTHORITY_REVOKED    = 9,
    OZAYN_OAC_EVT_AUTHORITY_CONSUMED   = 10,
    OZAYN_OAC_EVT_AUTHORITY_INVALIDATED = 11,
    OZAYN_OAC_EVT_DUPLICATE_ATTEMPT    = 12,
    OZAYN_OAC_EVT_STALE_AUTHORITY      = 13,
    OZAYN_OAC_EVT_SESSION_INVALIDATED  = 14,
    OZAYN_OAC_EVT_MODE_CHANGE_INVALIDATED = 15
} ozayn_oac_event_type_t;

/* ============================================================
 * STRUCTS
 * ============================================================ */

/* Access Context — binds a security session to Control Room access */
typedef struct {
    char                    context_id[OZAYN_OAC_MAX_ID_LEN];
    uint32_t                version;
    char                    identity_id[OZAYN_OAC_MAX_IDENTITY_LEN];
    char                    session_id[OZAYN_OAC_MAX_SESSION_LEN];
    char                    authorization_ref[OZAYN_OAC_MAX_AUTHZ_REF_LEN];
    ozayn_oac_access_level_t access_level;
    ozayn_oac_ctx_state_t   state;
    ozayn_oac_scope_type_t  scope_type;
    char                    scope_target[OZAYN_OAC_MAX_TARGET_LEN];
    time_t                  created_time;
    time_t                  last_validated_time;
    time_t                  expiration_time;
    int                     validation_count;
    int                     active;
} ozayn_oac_access_ctx_t;

/* Operational Authority — bounded operation-specific authority */
typedef struct {
    char                    authority_id[OZAYN_OAC_MAX_ID_LEN];
    uint32_t                version;
    char                    identity_id[OZAYN_OAC_MAX_IDENTITY_LEN];
    char                    session_id[OZAYN_OAC_MAX_SESSION_LEN];
    char                    context_id[OZAYN_OAC_MAX_ID_LEN];
    char                    request_id[OZAYN_OAC_MAX_ID_LEN];
    char                    operation_id[OZAYN_OAC_MAX_ID_LEN];
    char                    target[OZAYN_OAC_MAX_TARGET_LEN];
    char                    capability[OZAYN_OAC_MAX_CAPABILITY_LEN];
    char                    action[OZAYN_OAC_MAX_ACTION_LEN];
    char                    required_permission[OZAYN_OAC_MAX_PERMISSION_LEN];
    ozayn_oac_auth_state_t  state;
    int                     consumed;
    time_t                  created_time;
    time_t                  expiration_time;
    int                     active;
} ozayn_oac_authority_t;

/* Validation Log Entry — records a validation attempt */
typedef struct {
    char                    authority_id[OZAYN_OAC_MAX_ID_LEN];
    char                    session_id[OZAYN_OAC_MAX_SESSION_LEN];
    ozayn_oac_event_type_t  event_type;
    time_t                  timestamp;
    int                     result_code;
} ozayn_oac_validation_entry_t;

/* Statistics */
typedef struct {
    uint64_t                total_access_contexts_created;
    uint64_t                total_access_denials;
    uint64_t                total_access_expired;
    uint64_t                total_access_revoked;
    uint64_t                total_authorities_created;
    uint64_t                total_authorities_granted;
    uint64_t                total_authorities_denied;
    uint64_t                total_authorities_expired;
    uint64_t                total_authorities_revoked;
    uint64_t                total_authorities_consumed;
    uint64_t                total_authorities_invalidated;
    uint64_t                total_duplicate_authority_attempts;
    uint64_t                total_stale_authority_attempts;
    uint64_t                total_validations;
    uint64_t                total_session_invalidations;
    uint64_t                total_mode_change_invalidations;
    uint32_t                current_active_contexts;
    uint32_t                current_active_authorities;
} ozayn_oac_stats_t;

/* Subsystem Bind (void* dependency injection) */
typedef struct {
    void *session_service;
    void *authorization_service;
    void *audit_service;
    void *event_engine;
    void *operational_metrics;
    void *operational_alert;
} ozayn_oac_subsys_bind_t;

/* Service */
typedef struct {
    int                         initialized;
    ozayn_oac_access_ctx_t      contexts[OZAYN_OAC_MAX_ACCESS_CONTEXTS];
    int                         context_count;
    ozayn_oac_authority_t       authorities[OZAYN_OAC_MAX_AUTHORITIES];
    int                         authority_count;
    ozayn_oac_authority_t       authority_history[OZAYN_OAC_MAX_AUTHORITY_HISTORY];
    int                         history_count;
    ozayn_oac_validation_entry_t validation_log[OZAYN_OAC_MAX_VALIDATION_LOG];
    int                         validation_head;
    int                         validation_count;
    ozayn_oac_stats_t           stats;
    ozayn_oac_subsys_bind_t     bind;
} ozayn_oac_service_t;

/* ============================================================
 * NAME HELPERS
 * ============================================================ */

const char *ozayn_oac_err_name(ozayn_oac_err_t err);
const char *ozayn_oac_access_level_name(ozayn_oac_access_level_t level);
const char *ozayn_oac_ctx_state_name(ozayn_oac_ctx_state_t state);
const char *ozayn_oac_auth_state_name(ozayn_oac_auth_state_t state);
const char *ozayn_oac_scope_type_name(ozayn_oac_scope_type_t scope);
const char *ozayn_oac_event_type_name(ozayn_oac_event_type_t evt);

/* ============================================================
 * STATE TRANSITION VALIDATION
 * ============================================================ */

int ozayn_oac_ctx_state_transition_valid(ozayn_oac_ctx_state_t from, ozayn_oac_ctx_state_t to);
int ozayn_oac_auth_state_transition_valid(ozayn_oac_auth_state_t from, ozayn_oac_auth_state_t to);

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_init(ozayn_oac_service_t *svc);
ozayn_oac_err_t ozayn_oac_shutdown(ozayn_oac_service_t *svc);
int             ozayn_oac_is_initialized(const ozayn_oac_service_t *svc);

/* ============================================================
 * SUBSYSTEM BIND
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_bind_subsystems(ozayn_oac_service_t *svc, const ozayn_oac_subsys_bind_t *bind);

/* ============================================================
 * ACCESS CONTEXT
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_context_create(ozayn_oac_service_t *svc,
                                          const char *identity_id,
                                          const char *session_id,
                                          const char *authorization_ref,
                                          ozayn_oac_access_level_t level,
                                          ozayn_oac_scope_type_t scope_type,
                                          const char *scope_target,
                                          uint64_t lifetime_seconds,
                                          uint64_t *out_context_id);

ozayn_oac_err_t ozayn_oac_context_get(const ozayn_oac_service_t *svc,
                                       uint64_t context_id,
                                       const ozayn_oac_access_ctx_t **out_ctx);

ozayn_oac_err_t ozayn_oac_context_validate(ozayn_oac_service_t *svc, uint64_t context_id);

ozayn_oac_err_t ozayn_oac_context_expire(ozayn_oac_service_t *svc, uint64_t context_id);
ozayn_oac_err_t ozayn_oac_context_revoke(ozayn_oac_service_t *svc, uint64_t context_id);
ozayn_oac_err_t ozayn_oac_context_terminate(ozayn_oac_service_t *svc, uint64_t context_id);

int             ozayn_oac_context_active_count(const ozayn_oac_service_t *svc);
int             ozayn_oac_context_total_count(const ozayn_oac_service_t *svc);

ozayn_oac_err_t ozayn_oac_context_list_by_identity(const ozayn_oac_service_t *svc,
                                                     const char *identity_id,
                                                     const ozayn_oac_access_ctx_t **out_results,
                                                     uint32_t max_results,
                                                     uint32_t *out_count);

/* ============================================================
 * OPERATIONAL AUTHORITY
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_authority_create(ozayn_oac_service_t *svc,
                                            uint64_t context_id,
                                            const char *request_id,
                                            const char *operation_id,
                                            const char *target,
                                            const char *capability,
                                            const char *action,
                                            const char *required_permission,
                                            uint64_t lifetime_seconds,
                                            uint64_t *out_authority_id);

ozayn_oac_err_t ozayn_oac_authority_get(const ozayn_oac_service_t *svc,
                                         uint64_t authority_id,
                                         const ozayn_oac_authority_t **out_auth);

ozayn_oac_err_t ozayn_oac_authority_validate(ozayn_oac_service_t *svc,
                                               uint64_t authority_id,
                                               const char *request_id,
                                               const char *operation_id,
                                               const char *session_id,
                                               const char *identity_id);

ozayn_oac_err_t ozayn_oac_authority_consume(ozayn_oac_service_t *svc, uint64_t authority_id);

ozayn_oac_err_t ozayn_oac_authority_expire(ozayn_oac_service_t *svc, uint64_t authority_id);
ozayn_oac_err_t ozayn_oac_authority_revoke(ozayn_oac_service_t *svc, uint64_t authority_id);
ozayn_oac_err_t ozayn_oac_authority_cancel(ozayn_oac_service_t *svc, uint64_t authority_id);

ozayn_oac_err_t ozayn_oac_authority_invalidate_by_session(ozayn_oac_service_t *svc,
                                                           const char *session_id);
ozayn_oac_err_t ozayn_oac_authority_invalidate_by_context(ozayn_oac_service_t *svc,
                                                           uint64_t context_id);

int             ozayn_oac_authority_active_count(const ozayn_oac_service_t *svc);
int             ozayn_oac_authority_total_count(const ozayn_oac_service_t *svc);

ozayn_oac_err_t ozayn_oac_authority_list_by_session(const ozayn_oac_service_t *svc,
                                                      const char *session_id,
                                                      const ozayn_oac_authority_t **out_results,
                                                      uint32_t max_results,
                                                      uint32_t *out_count);

ozayn_oac_err_t ozayn_oac_authority_list_by_context(const ozayn_oac_service_t *svc,
                                                      uint64_t context_id,
                                                      const ozayn_oac_authority_t **out_results,
                                                      uint32_t max_results,
                                                      uint32_t *out_count);

/* ============================================================
 * AUTHORITY HISTORY (for duplicate detection)
 * ============================================================ */

int ozayn_oac_history_find(const ozayn_oac_service_t *svc,
                            const char *request_id,
                            const char *operation_id);

/* ============================================================
 * BATCH INVALIDATION
 * ============================================================ */

ozayn_oac_err_t ozayn_oac_revoke_all_for_session(ozayn_oac_service_t *svc,
                                                   const char *session_id,
                                                   uint32_t *out_count);

ozayn_oac_err_t ozayn_oac_expire_all_for_context(ozayn_oac_service_t *svc,
                                                   uint64_t context_id,
                                                   uint32_t *out_count);

ozayn_oac_err_t ozayn_oac_cleanup_expired(ozayn_oac_service_t *svc);

/* ============================================================
 * VALIDATION LOG
 * ============================================================ */

int ozayn_oac_validation_log_count(const ozayn_oac_service_t *svc);

/* ============================================================
 * STATS
 * ============================================================ */

ozayn_oac_stats_t ozayn_oac_get_stats(const ozayn_oac_service_t *svc);

#endif /* OZAYN_OPERATIONAL_ACCESS_H */
