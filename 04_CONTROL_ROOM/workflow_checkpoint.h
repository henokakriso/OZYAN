/*
 * workflow_checkpoint.h — Persistent Workflow Recovery State & Restart Reconciliation
 *
 * Provides controlled checkpoint creation, durable recovery state,
 * recovery journaling, restart reconciliation, stale-state detection,
 * duplicate-execution prevention, and safe resume eligibility assessment.
 *
 * Architecture:
 *   WORKFLOW → CHECKPOINT MANAGER → PERSISTENT RECOVERY STATE
 *   → RESTART → RECOVERY STATE LOAD → STATE VALIDATION
 *   → RESTART RECONCILIATION → RECOVERY ELIGIBILITY ASSESSMENT
 *   → CONTROLLED DECISION
 *
 * This module does NOT:
 *   - Automatically resume workflows
 *   - Create a second authorization system
 *   - Execute arbitrary commands
 *   - Bypass existing Section 03 security
 *   - Own workflow execution
 *
 * Step 18/35 — Control Room
 */

#ifndef OZAYN_WORKFLOW_CHECKPOINT_H
#define OZAYN_WORKFLOW_CHECKPOINT_H

#include <stdint.h>
#include <time.h>

/* ============================================================
 * SECTION 1 — ERROR CODES
 * ============================================================ */

typedef enum {
    OZAYN_PRS_OK                            =   0,
    OZAYN_PRS_ERR_NULL                      =  -1,
    OZAYN_PRS_ERR_NOT_INITIALIZED           =  -2,
    OZAYN_PRS_ERR_ALREADY_INIT              =  -3,
    OZAYN_PRS_ERR_INVALID_PARAM             =  -4,
    OZAYN_PRS_ERR_LIMIT_REACHED             =  -5,
    OZAYN_PRS_ERR_NOT_FOUND                 =  -6,
    OZAYN_PRS_ERR_DUPLICATE                 =  -7,
    OZAYN_PRS_ERR_STATE_INVALID             =  -8,
    OZAYN_PRS_ERR_CHECKPOINT_INVALID        =  -9,
    OZAYN_PRS_ERR_CHECKPOINT_FAILED         = -10,
    OZAYN_PRS_ERR_CHECKPOINT_COMMIT_FAILED  = -11,
    OZAYN_PRS_ERR_SCHEMA_UNSUPPORTED        = -12,
    OZAYN_PRS_ERR_SCHEMA_MIGRATION_FAILED   = -13,
    OZAYN_PRS_ERR_STATE_CORRUPTED           = -14,
    OZAYN_PRS_ERR_RECONCILIATION_FAILED     = -15,
    OZAYN_PRS_ERR_DUPLICATE_EXECUTION_RISK  = -16,
    OZAYN_PRS_ERR_JOURNAL_FAILED            = -17,
    OZAYN_PRS_ERR_EXPIRED                   = -18,
    OZAYN_PRS_ERR_UNAVAILABLE               = -19,
    OZAYN_PRS_ERR_CONCURRENCY               = -20,
    OZAYN_PRS_ERR_AUTHORIZATION_FAILED      = -21,
    OZAYN_PRS_ERR_SAFETY_RECHECK_FAILED     = -22,
    OZAYN_PRS_ERR_RESOURCE_RECHECK_FAILED   = -23,
    OZAYN_PRS_ERR_DEVICE_RECHECK_FAILED     = -24,
    OZAYN_PRS_ERR_MANUAL_REVIEW_REQUIRED    = -25,
    OZAYN_PRS_ERR_WORKFLOW_INVALID          = -26,
    OZAYN_PRS_ERR_OPERATION_INTERRUPTED     = -27,
    OZAYN_PRS_ERR_OPERATION_UNKNOWN         = -28,
    OZAYN_PRS_ERR_REJECTED                  = -29,
    OZAYN_PRS_ERR_EVENT_ERROR               = -30
} ozayn_prs_err_t;

/* ============================================================
 * SECTION 2 — CHECKPOINT STATES
 * ============================================================ */

typedef enum {
    OZAYN_PRS_CP_CREATED = 0,
    OZAYN_PRS_CP_VALIDATING,
    OZAYN_PRS_CP_COMMITTED,
    OZAYN_PRS_CP_SUPERSEDED,
    OZAYN_PRS_CP_INVALID,
    OZAYN_PRS_CP_CORRUPTED,
    OZAYN_PRS_CP_EXPIRED,
    OZAYN_PRS_CP_RECOVERY_REQUIRED,
    OZAYN_PRS_CP_RECOVERED,
    OZAYN_PRS_CP_STATE_COUNT
} ozayn_prs_checkpoint_state_t;

/* ============================================================
 * SECTION 3 — RECOVERY ELIGIBILITY
 * ============================================================ */

typedef enum {
    OZAYN_PRS_ELIGIBLE = 0,
    OZAYN_PRS_INELIGIBLE,
    OZAYN_PRS_REQUIRES_REAUTHORIZATION,
    OZAYN_PRS_REQUIRES_SAFETY_RECHECK,
    OZAYN_PRS_REQUIRES_RESOURCE_RECHECK,
    OZAYN_PRS_REQUIRES_DEVICE_RECHECK,
    OZAYN_PRS_REQUIRES_MANUAL_REVIEW,
    OZAYN_PRS_RECOVERY_EXPIRED,
    OZAYN_PRS_RECOVERY_CORRUPTED,
    OZAYN_PRS_RECOVERY_UNAVAILABLE,
    OZAYN_PRS_RECOVERY_DUPLICATE_RISK,
    OZAYN_PRS_RECOVERY_ELIGIBILITY_COUNT
} ozayn_prs_recovery_eligibility_t;

/* ============================================================
 * SECTION 4 — RECONCILIATION STATES
 * ============================================================ */

typedef enum {
    OZAYN_PRS_RECON_PENDING = 0,
    OZAYN_PRS_RECON_IN_PROGRESS,
    OZAYN_PRS_RECON_COMPLETED,
    OZAYN_PRS_RECON_FAILED,
    OZAYN_PRS_RECON_BLOCKED,
    OZAYN_PRS_RECON_STATE_COUNT
} ozayn_prs_reconciliation_state_t;

/* ============================================================
 * SECTION 5 — RECONCILIATION VERDICTS
 * ============================================================ */

typedef enum {
    OZAYN_PRS_VERDICT_COMPLETED = 0,
    OZAYN_PRS_VERDICT_INTERRUPTED,
    OZAYN_PRS_VERDICT_FAILED,
    OZAYN_PRS_VERDICT_UNKNOWN_RESULT,
    OZAYN_PRS_VERDICT_RECOVERY_REQUIRED,
    OZAYN_PRS_VERDICT_EXPIRED,
    OZAYN_PRS_VERDICT_CORRUPTED,
    OZAYN_PRS_VERDICT_INELIGIBLE,
    OZAYN_PRS_VERDICT_COUNT
} ozayn_prs_reconciliation_verdict_t;

/* ============================================================
 * SECTION 6 — JOURNAL EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_PRS_JOURNAL_CHECKPOINT_CREATED = 0,
    OZAYN_PRS_JOURNAL_CHECKPOINT_COMMITTED,
    OZAYN_PRS_JOURNAL_CHECKPOINT_INVALIDATED,
    OZAYN_PRS_JOURNAL_CHECKPOINT_SUPERSEDED,
    OZAYN_PRS_JOURNAL_WORKFLOW_INTERRUPTED,
    OZAYN_PRS_JOURNAL_RECOVERY_STARTED,
    OZAYN_PRS_JOURNAL_RECONCILIATION_STARTED,
    OZAYN_PRS_JOURNAL_RECONCILIATION_COMPLETED,
    OZAYN_PRS_JOURNAL_RECOVERY_ELIGIBLE,
    OZAYN_PRS_JOURNAL_RECOVERY_BLOCKED,
    OZAYN_PRS_JOURNAL_RECOVERY_REJECTED,
    OZAYN_PRS_JOURNAL_RECOVERY_COMPLETED,
    OZAYN_PRS_JOURNAL_DUPLICATE_EXECUTION_BLOCKED,
    OZAYN_PRS_JOURNAL_STATE_CORRUPTED,
    OZAYN_PRS_JOURNAL_SCHEMA_INCOMPATIBLE,
    OZAYN_PRS_JOURNAL_RESTART_DETECTED,
    OZAYN_PRS_JOURNAL_COUNT
} ozayn_prs_journal_event_type_t;

/* ============================================================
 * SECTION 7 — STAGE RECONCILIATION RESULTS
 * ============================================================ */

typedef enum {
    OZAYN_PRS_STAGE_COMPLETED = 0,
    OZAYN_PRS_STAGE_FAILED,
    OZAYN_PRS_STAGE_INTERRUPTED,
    OZAYN_PRS_STAGE_UNKNOWN,
    OZAYN_PRS_STAGE_REQUIRES_REEVALUATION,
    OZAYN_PRS_STAGE_RESULT_COUNT
} ozayn_prs_stage_recon_result_t;

/* ============================================================
 * SECTION 8 — OPERATION RECONCILIATION RESULTS
 * ============================================================ */

typedef enum {
    OZAYN_PRS_OP_COMPLETED = 0,
    OZAYN_PRS_OP_FAILED,
    OZAYN_PRS_OP_INTERRUPTED,
    OZAYN_PRS_OP_UNKNOWN_RESULT,
    OZAYN_PRS_OP_DUPLICATE_RISK,
    OZAYN_PRS_OP_RESULT_COUNT
} ozayn_prs_operation_recon_result_t;

/* ============================================================
 * SECTION 9 — EVENT TYPES
 * ============================================================ */

typedef enum {
    OZAYN_PRS_EVENT_CHECKPOINT_CREATED = 0,
    OZAYN_PRS_EVENT_CHECKPOINT_COMMITTED,
    OZAYN_PRS_EVENT_CHECKPOINT_FAILED,
    OZAYN_PRS_EVENT_STATE_INVALID,
    OZAYN_PRS_EVENT_STATE_CORRUPTED,
    OZAYN_PRS_EVENT_RESTART_DETECTED,
    OZAYN_PRS_EVENT_RECONCILIATION_STARTED,
    OZAYN_PRS_EVENT_RECONCILIATION_COMPLETED,
    OZAYN_PRS_EVENT_WORKFLOW_INTERRUPTED,
    OZAYN_PRS_EVENT_ELIGIBLE,
    OZAYN_PRS_EVENT_BLOCKED,
    OZAYN_PRS_EVENT_REQUIRES_REAUTHORIZATION,
    OZAYN_PRS_EVENT_REQUIRES_SAFETY_RECHECK,
    OZAYN_PRS_EVENT_REQUIRES_RESOURCE_RECHECK,
    OZAYN_PRS_EVENT_REQUIRES_DEVICE_RECHECK,
    OZAYN_PRS_EVENT_MANUAL_REVIEW,
    OZAYN_PRS_EVENT_EXPIRED,
    OZAYN_PRS_EVENT_DUPLICATE_BLOCKED,
    OZAYN_PRS_EVENT_COUNT
} ozayn_prs_event_type_t;

/* ============================================================
 * SECTION 10 — CONSTANTS
 * ============================================================ */

#define OZAYN_PRS_MAX_CHECKPOINTS          64
#define OZAYN_PRS_MAX_JOURNAL_ENTRIES      128
#define OZAYN_PRS_MAX_EVENTS               64
#define OZAYN_PRS_MAX_ID_LEN                64
#define OZAYN_PRS_MAX_VERSION_LEN           32
#define OZAYN_PRS_MAX_NAME_LEN              64
#define OZAYN_PRS_MAX_DESC_LEN             128
#define OZAYN_PRS_MAX_METADATA_LEN         256
#define OZAYN_PRS_MAX_STAGES               16
#define OZAYN_PRS_MAX_REFERENCES            8
#define OZAYN_PRS_MAX_RECON_STAGES         16
#define OZAYN_PRS_MAX_RECON_OPERATIONS     16

#define OZAYN_PRS_SCHEMA_VERSION            1
#define OZAYN_PRS_MAX_CHECKPOINT_SIZE       4096
#define OZAYN_PRS_MAX_RECOVERY_DEPTH         8
#define OZAYN_PRS_DEFAULT_CHECKPOINT_AGE_S 86400

/* ============================================================
 * SECTION 11 — CHECKPOINT STAGE SUMMARY
 * ============================================================ */

typedef struct {
    char    stage_id[OZAYN_PRS_MAX_ID_LEN];
    char    operation_id[OZAYN_PRS_MAX_ID_LEN];
    char    pipeline_id[OZAYN_PRS_MAX_ID_LEN];
    int     stage_state;
    int     retry_count;
    int     is_optional;
    int     is_critical;
    int64_t  timeout_ms;
    int64_t  started_time;
    int64_t  completed_time;
} ozayn_prs_checkpoint_stage_t;

/* ============================================================
 * SECTION 12 — CHECKPOINT STRUCTURE
 * ============================================================ */

typedef struct {
    char    checkpoint_id[OZAYN_PRS_MAX_ID_LEN];
    char    workflow_id[OZAYN_PRS_MAX_ID_LEN];
    char    workflow_version[OZAYN_PRS_MAX_VERSION_LEN];
    char    name[OZAYN_PRS_MAX_NAME_LEN];
    char    description[OZAYN_PRS_MAX_DESC_LEN];
    char    owner_ref[OZAYN_PRS_MAX_ID_LEN];
    char    authorization_ref[OZAYN_PRS_MAX_ID_LEN];
    char    safety_decision_ref[OZAYN_PRS_MAX_ID_LEN];
    char    security_session_ref[OZAYN_PRS_MAX_ID_LEN];
    char    operation_id[OZAYN_PRS_MAX_ID_LEN];
    char    failure_references[OZAYN_PRS_MAX_REFERENCES][OZAYN_PRS_MAX_ID_LEN];
    int     failure_reference_count;
    char    recovery_decision_id[OZAYN_PRS_MAX_ID_LEN];
    char    recovery_state_ref[OZAYN_PRS_MAX_ID_LEN];
    char    resource_references[OZAYN_PRS_MAX_REFERENCES][OZAYN_PRS_MAX_ID_LEN];
    int     resource_reference_count;
    char    device_references[OZAYN_PRS_MAX_REFERENCES][OZAYN_PRS_MAX_ID_LEN];
    int     device_reference_count;
    char    safe_metadata[OZAYN_PRS_MAX_METADATA_LEN];

    int     schema_version;
    int     checkpoint_version;
    int     sequence;
    int     workflow_state;
    int     workflow_type;
    int     failure_policy;
    int     concurrency_policy;
    int     stage_count;
    int     completed_stage_count;
    int     failed_stage_count;
    int     retry_count;
    int     max_retries;
    int     version_number;
    int     authorized;
    int     safety_ok;
    int     active;

    ozayn_prs_checkpoint_state_t state;

    int64_t  created_time;
    int64_t  committed_time;
    int64_t  last_confirmed_time;
    int64_t  expiration_time;
    int64_t  workflow_timeout_ms;
    int64_t  start_deadline_ms;
    int64_t  execution_deadline_ms;
    uint64_t result_code;
} ozayn_prs_checkpoint_t;

/* ============================================================
 * SECTION 13 — RECOVERY JOURNAL ENTRY
 * ============================================================ */

typedef struct {
    char    journal_id[OZAYN_PRS_MAX_ID_LEN];
    char    checkpoint_id[OZAYN_PRS_MAX_ID_LEN];
    char    workflow_id[OZAYN_PRS_MAX_ID_LEN];
    char    stage_id[OZAYN_PRS_MAX_ID_LEN];
    char    operation_id[OZAYN_PRS_MAX_ID_LEN];
    char    pipeline_id[OZAYN_PRS_MAX_ID_LEN];
    char    failure_id[OZAYN_PRS_MAX_ID_LEN];
    char    event_id[OZAYN_PRS_MAX_ID_LEN];
    char    description[OZAYN_PRS_MAX_DESC_LEN];
    char    safe_metadata[OZAYN_PRS_MAX_METADATA_LEN];
    ozayn_prs_journal_event_type_t event_type;
    int64_t  timestamp;
    int      active;
} ozayn_prs_journal_entry_t;

/* ============================================================
 * SECTION 14 — STAGE RECONCILIATION RECORD
 * ============================================================ */

typedef struct {
    char    stage_id[OZAYN_PRS_MAX_ID_LEN];
    char    operation_id[OZAYN_PRS_MAX_ID_LEN];
    char    pipeline_id[OZAYN_PRS_MAX_ID_LEN];
    int     persisted_state;
    ozayn_prs_stage_recon_result_t result;
    int     active;
} ozayn_prs_recon_stage_t;

/* ============================================================
 * SECTION 15 — OPERATION RECONCILIATION RECORD
 * ============================================================ */

typedef struct {
    char    operation_id[OZAYN_PRS_MAX_ID_LEN];
    char    execution_record_id[OZAYN_PRS_MAX_ID_LEN];
    char    attempt_id[OZAYN_PRS_MAX_ID_LEN];
    int     persisted_state;
    ozayn_prs_operation_recon_result_t result;
    int     active;
} ozayn_prs_recon_operation_t;

/* ============================================================
 * SECTION 16 — WORKFLOW RECONCILIATION RECORD
 * ============================================================ */

typedef struct {
    char    workflow_id[OZAYN_PRS_MAX_ID_LEN];
    char    checkpoint_id[OZAYN_PRS_MAX_ID_LEN];
    int     persisted_workflow_state;
    int     current_runtime_state;
    ozayn_prs_reconciliation_state_t recon_state;
    ozayn_prs_reconciliation_verdict_t verdict;
    ozayn_prs_recovery_eligibility_t eligibility;
    ozayn_prs_recon_stage_t stages[OZAYN_PRS_MAX_RECON_STAGES];
    int     stage_count;
    ozayn_prs_recon_operation_t operations[OZAYN_PRS_MAX_RECON_OPERATIONS];
    int     operation_count;
    int     device_valid;
    int     resource_valid;
    int     security_valid;
    int     safety_valid;
    int     authorization_valid;
    int     duplicate_risk;
    int     active;
    int64_t  reconciliation_time;
    int64_t  detection_time;
    char    error_detail[OZAYN_PRS_MAX_DESC_LEN];
} ozayn_prs_reconciliation_t;

/* ============================================================
 * SECTION 17 — EVENT STRUCTURE
 * ============================================================ */

typedef struct {
    char    event_id[OZAYN_PRS_MAX_ID_LEN];
    char    checkpoint_id[OZAYN_PRS_MAX_ID_LEN];
    char    workflow_id[OZAYN_PRS_MAX_ID_LEN];
    char    message[OZAYN_PRS_MAX_DESC_LEN];
    ozayn_prs_event_type_t event_type;
    int64_t  timestamp;
    uint64_t sequence;
    int      active;
} ozayn_prs_event_t;

/* ============================================================
 * SECTION 18 — STATISTICS
 * ============================================================ */

typedef struct {
    uint64_t  total_checkpoints_created;
    uint64_t  total_checkpoints_committed;
    uint64_t  total_checkpoints_superseded;
    uint64_t  total_checkpoints_invalidated;
    uint64_t  total_checkpoints_expired;
    uint64_t  total_journal_entries;
    uint64_t  total_reconciliations_started;
    uint64_t  total_reconciliations_completed;
    uint64_t  total_reconciliations_failed;
    uint64_t  total_workflows_interrupted;
    uint64_t  total_workflows_eligible;
    uint64_t  total_workflows_blocked;
    uint64_t  total_duplicate_blocks;
    uint64_t  total_state_corruptions;
    uint64_t  total_schema_incompatibilities;
    uint64_t  total_events_emitted;
    uint64_t  total_restarts_detected;
    int       current_checkpoints;
    int       current_journal_entries;
    int       current_reconciliations;
    int       active_workflows_tracked;
} ozayn_prs_stats_t;

/* ============================================================
 * SECTION 19 — SERVICE CONFIGURATION
 * ============================================================ */

typedef struct {
    void *workflow_orchestrator;
    void *workflow_recovery;
    void *operation_history;
    void *pipeline_scheduler;
    void *resource_manager;
    void *safety_engine;
    void *component_registry;
    void *diagnostics;
    void *audit;
    int   max_checkpoints_per_workflow;
    int   max_checkpoint_age_seconds;
    int   max_journal_entries;
    int   max_recovery_depth;
} ozayn_prs_service_config_t;

/* ============================================================
 * SECTION 20 — SERVICE STATE
 * ============================================================ */

typedef struct {
    int                           initialized;
    ozayn_prs_service_config_t    config;
    ozayn_prs_checkpoint_t        checkpoints[OZAYN_PRS_MAX_CHECKPOINTS];
    int                           checkpoint_count;
    int                           checkpoint_sequence;
    ozayn_prs_journal_entry_t     journal[OZAYN_PRS_MAX_JOURNAL_ENTRIES];
    int                           journal_count;
    int                           journal_head;
    int                           journal_sequence;
    ozayn_prs_reconciliation_t    reconciliations[OZAYN_PRS_MAX_CHECKPOINTS];
    int                           reconciliation_count;
    ozayn_prs_event_t             events[OZAYN_PRS_MAX_EVENTS];
    int                           event_count;
    int                           event_head;
    uint64_t                      event_sequence;
    ozayn_prs_stats_t             stats;
    int64_t                       last_tick_time;
    int64_t                       init_time;
    int64_t                       restart_time;
    void                         *audit;
} ozayn_prs_service_t;

/* ============================================================
 * SECTION 21 — LIFECYCLE FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_service_init(ozayn_prs_service_t *svc,
                                        const ozayn_prs_service_config_t *config);
ozayn_prs_err_t ozayn_prs_service_shutdown(ozayn_prs_service_t *svc);
int             ozayn_prs_is_initialized(const ozayn_prs_service_t *svc);
ozayn_prs_service_t *ozayn_prs_get_global(void);

/* ============================================================
 * SECTION 22 — CHECKPOINT FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_checkpoint_create(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    const char *workflow_version,
    const char *name,
    const char *description,
    int workflow_state,
    int workflow_type,
    int failure_policy,
    int concurrency_policy,
    int stage_count,
    int completed_stages,
    int failed_stages,
    int retry_count,
    int max_retries,
    int authorized,
    int safety_ok,
    const char *owner_ref,
    const char *authorization_ref,
    const char *safety_ref,
    const char *session_ref,
    const char *operation_id,
    const char *safe_metadata,
    int64_t timeout_ms,
    int64_t start_deadline_ms,
    int64_t execution_deadline_ms,
    uint64_t result_code,
    char *out_checkpoint_id,
    int out_id_len);

ozayn_prs_err_t ozayn_prs_checkpoint_validate(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id);

ozayn_prs_err_t ozayn_prs_checkpoint_commit(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id);

ozayn_prs_err_t ozayn_prs_checkpoint_supersede(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id);

ozayn_prs_err_t ozayn_prs_checkpoint_invalidate(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *reason);

ozayn_prs_err_t ozayn_prs_checkpoint_mark_recovered(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id);

/* ============================================================
 * SECTION 23 — CHECKPOINT STAGE FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_checkpoint_add_stage(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *stage_id,
    const char *operation_id,
    const char *pipeline_id,
    int stage_state,
    int retry_count,
    int is_optional,
    int is_critical,
    int64_t timeout_ms,
    int64_t started_time,
    int64_t completed_time);

/* ============================================================
 * SECTION 24 — CHECKPOINT REFERENCE FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_checkpoint_add_failure_ref(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *failure_id);

ozayn_prs_err_t ozayn_prs_checkpoint_add_resource_ref(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *resource_id);

ozayn_prs_err_t ozayn_prs_checkpoint_add_device_ref(
    ozayn_prs_service_t *svc,
    const char *checkpoint_id,
    const char *device_id);

/* ============================================================
 * SECTION 25 — CHECKPOINT QUERY FUNCTIONS
 * ============================================================ */

const ozayn_prs_checkpoint_t *ozayn_prs_checkpoint_get(
    const ozayn_prs_service_t *svc, const char *checkpoint_id);

const ozayn_prs_checkpoint_t *ozayn_prs_checkpoint_get_latest_valid(
    const ozayn_prs_service_t *svc, const char *workflow_id);

const ozayn_prs_checkpoint_t *ozayn_prs_checkpoint_get_by_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id, int index);

int ozayn_prs_checkpoint_count(const ozayn_prs_service_t *svc);

int ozayn_prs_checkpoint_count_by_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id);

int ozayn_prs_checkpoint_is_valid(const ozayn_prs_checkpoint_t *cp);

int ozayn_prs_checkpoint_is_expired(const ozayn_prs_checkpoint_t *cp,
                                     int64_t now_ms);

/* ============================================================
 * SECTION 26 — JOURNAL FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_journal_write(
    ozayn_prs_service_t *svc,
    ozayn_prs_journal_event_type_t event_type,
    const char *checkpoint_id,
    const char *workflow_id,
    const char *stage_id,
    const char *operation_id,
    const char *pipeline_id,
    const char *failure_id,
    const char *description,
    const char *safe_metadata);

const ozayn_prs_journal_entry_t *ozayn_prs_journal_get(
    const ozayn_prs_service_t *svc, int index);

int ozayn_prs_journal_count(const ozayn_prs_service_t *svc);

const ozayn_prs_journal_entry_t *ozayn_prs_journal_get_latest_for_workflow(
    const ozayn_prs_service_t *svc, const char *workflow_id);

/* ============================================================
 * SECTION 27 — RESTART RECONCILIATION FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_detect_restart(
    ozayn_prs_service_t *svc,
    int64_t now_ms);

ozayn_prs_err_t ozayn_prs_reconcile_workflow(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    int current_runtime_state,
    const int *stage_states,
    int stage_state_count,
    const int *operation_states,
    int operation_state_count,
    int device_available,
    int resource_available,
    int security_session_valid,
    int safety_valid,
    int authorization_valid,
    ozayn_prs_reconciliation_t **out_recon);

const ozayn_prs_reconciliation_t *ozayn_prs_reconciliation_get(
    const ozayn_prs_service_t *svc, const char *workflow_id);

ozayn_prs_err_t ozayn_prs_reconciliation_advance(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    ozayn_prs_reconciliation_state_t new_state);

int ozayn_prs_reconciliation_count(const ozayn_prs_service_t *svc);

/* ============================================================
 * SECTION 28 — RECOVERY ELIGIBILITY FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_assess_eligibility(
    ozayn_prs_service_t *svc,
    const char *workflow_id,
    int current_runtime_state,
    int checkpoint_valid,
    int schema_compatible,
    int dependency_valid,
    int operation_valid,
    int pipeline_valid,
    int device_available,
    int resource_available,
    int security_session_valid,
    int authorization_valid,
    int safety_valid,
    int64_t now_ms,
    ozayn_prs_recovery_eligibility_t *out_eligibility);

const char *ozayn_prs_eligibility_reason(
    ozayn_prs_recovery_eligibility_t eligibility);

/* ============================================================
 * SECTION 29 — DUPLICATE EXECUTION PROTECTION
 * ============================================================ */

int ozayn_prs_check_duplicate_execution(
    const ozayn_prs_service_t *svc,
    const char *operation_id,
    const char *execution_record_id);

ozayn_prs_err_t ozayn_prs_record_execution_attempt(
    ozayn_prs_service_t *svc,
    const char *operation_id,
    const char *execution_record_id,
    const char *attempt_id);

/* ============================================================
 * SECTION 30 — RETENTION AND CLEANUP
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_retention_enforce(
    ozayn_prs_service_t *svc,
    int64_t now_ms);

ozayn_prs_err_t ozayn_prs_cleanup_expired_checkpoints(
    ozayn_prs_service_t *svc,
    int64_t now_ms);

ozayn_prs_err_t ozayn_prs_cleanup_all(ozayn_prs_service_t *svc);

int ozayn_prs_journal_cleanup_old(
    ozayn_prs_service_t *svc,
    int max_age_seconds,
    int64_t now_ms);

/* ============================================================
 * SECTION 31 — TICK / ORCHESTRATION
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_tick(ozayn_prs_service_t *svc, int64_t now_ms);

/* ============================================================
 * SECTION 32 — EVENT FUNCTIONS
 * ============================================================ */

ozayn_prs_err_t ozayn_prs_emit_event(
    ozayn_prs_service_t *svc,
    ozayn_prs_event_type_t event_type,
    const char *checkpoint_id,
    const char *workflow_id,
    const char *message);

const ozayn_prs_event_t *ozayn_prs_get_event(
    const ozayn_prs_service_t *svc, int index);

int ozayn_prs_event_count(const ozayn_prs_service_t *svc);

/* ============================================================
 * SECTION 33 — STATISTICS FUNCTIONS
 * ============================================================ */

const ozayn_prs_stats_t *ozayn_prs_get_stats(const ozayn_prs_service_t *svc);
ozayn_prs_err_t ozayn_prs_reset_stats(ozayn_prs_service_t *svc);

/* ============================================================
 * SECTION 34 — VALIDATION FUNCTIONS
 * ============================================================ */

int ozayn_prs_validate_checkpoint(const ozayn_prs_checkpoint_t *cp);
int ozayn_prs_validate_config(const ozayn_prs_service_config_t *config);
int ozayn_prs_is_valid_checkpoint_transition(
    ozayn_prs_checkpoint_state_t from,
    ozayn_prs_checkpoint_state_t to);

/* ============================================================
 * SECTION 35 — NAME HELPER FUNCTIONS
 * ============================================================ */

const char *ozayn_prs_err_name(ozayn_prs_err_t err);
const char *ozayn_prs_checkpoint_state_name(ozayn_prs_checkpoint_state_t state);
const char *ozayn_prs_recovery_eligibility_name(ozayn_prs_recovery_eligibility_t elig);
const char *ozayn_prs_reconciliation_state_name(ozayn_prs_reconciliation_state_t state);
const char *ozayn_prs_reconciliation_verdict_name(ozayn_prs_reconciliation_verdict_t verdict);
const char *ozayn_prs_journal_event_type_name(ozayn_prs_journal_event_type_t type);
const char *ozayn_prs_stage_recon_result_name(ozayn_prs_stage_recon_result_t result);
const char *ozayn_prs_operation_recon_result_name(ozayn_prs_operation_recon_result_t result);
const char *ozayn_prs_event_type_name(ozayn_prs_event_type_t type);

#endif /* OZAYN_WORKFLOW_CHECKPOINT_H */
