#ifndef OZAYN_EVENTS_H
#define OZAYN_EVENTS_H

#include "ozayn.h"
#include <time.h>

/*
 * ozayn_events.h — Internal event engine.
 *
 * Producers publish events. Subscribers register callbacks.
 * The Runtime loop drains the queue and dispatches synchronously.
 */

/* Event types — only those with actual producers/subscribers */
typedef enum {
    OZAYN_EVENT_NONE               = 0,
    OZAYN_EVENT_CORE_STARTED       = 1,
    OZAYN_EVENT_CORE_STOPPING      = 2,
    OZAYN_EVENT_RUNTIME_STARTED    = 3,
    OZAYN_EVENT_RUNTIME_STOPPING   = 4,
    OZAYN_EVENT_CONFIG_LOADED      = 5,
    OZAYN_EVENT_LOGGER_READY       = 6,
    OZAYN_EVENT_RECOVERY_RAISED    = 7,
    OZAYN_EVENT_TASK_CREATED       = 8,
    OZAYN_EVENT_TASK_COMPLETED     = 9,
    OZAYN_EVENT_TASK_FAILED        = 10,
    OZAYN_EVENT_TASK_CANCELLED     = 11,
    OZAYN_EVENT_PROCESS_STARTED    = 12,
    OZAYN_EVENT_PROCESS_EXITED     = 13,
    OZAYN_EVENT_PROCESS_FAILED     = 14,
    OZAYN_EVENT_MODULE_REGISTERED  = 15,
    OZAYN_EVENT_MODULE_INITIALIZED = 16,
    OZAYN_EVENT_MODULE_STARTED     = 17,
    OZAYN_EVENT_MODULE_STOPPED     = 18,
    OZAYN_EVENT_MODULE_SHUTDOWN    = 19,
    OZAYN_EVENT_MODULE_FAILED      = 20,
    OZAYN_EVENT_PLUGIN_DISCOVERED  = 21,
    OZAYN_EVENT_PLUGIN_LOADED      = 22,
    OZAYN_EVENT_PLUGIN_INITIALIZED = 23,
    OZAYN_EVENT_PLUGIN_STARTED     = 24,
    OZAYN_EVENT_PLUGIN_STOPPED     = 25,
    OZAYN_EVENT_PLUGIN_UNLOADED    = 26,
    OZAYN_EVENT_PLUGIN_FAILED      = 27,
    /* IPC events (28-33) */
    OZAYN_EVENT_IPC_STARTED        = 28,
    OZAYN_EVENT_IPC_STOPPING       = 29,
    OZAYN_EVENT_IPC_CLIENT_CONNECTED  = 30,
    OZAYN_EVENT_IPC_CLIENT_DISCONNECTED = 31,
    OZAYN_EVENT_IPC_REQUEST_RECEIVED = 32,
    OZAYN_EVENT_IPC_RESPONSE_SENT    = 33,
    OZAYN_EVENT_IPC_ERROR          = 34,
    /* Service Registry events (35-40) */
    OZAYN_EVENT_SERVICE_REGISTERED = 35,
    OZAYN_EVENT_SERVICE_READY      = 36,
    OZAYN_EVENT_SERVICE_DEGRADED   = 37,
    OZAYN_EVENT_SERVICE_FAILED     = 38,
    OZAYN_EVENT_SERVICE_OFFLINE    = 39,
    OZAYN_EVENT_SERVICE_UNREGISTERED = 40,
    /* Security events (41-47) */
    OZAYN_EVENT_IDENTITY_REGISTERED = 41,
    OZAYN_EVENT_AUTH_SUCCESS        = 42,
    OZAYN_EVENT_AUTH_FAILURE        = 43,
    OZAYN_EVENT_ACCESS_DENIED       = 44,
    OZAYN_EVENT_IDENTITY_REVOKED    = 45,
    OZAYN_EVENT_CREDENTIAL_EXPIRED  = 46,
    OZAYN_EVENT_SECURITY_ALERT      = 47,
    /* Authorization events (48-52) */
    OZAYN_EVENT_AUTHORIZATION_ALLOWED = 48,
    OZAYN_EVENT_AUTHORIZATION_DENIED  = 49,
    OZAYN_EVENT_ROLE_ASSIGNED         = 50,
    OZAYN_EVENT_ROLE_REVOKED          = 51,
    OZAYN_EVENT_POLICY_CHANGED        = 52,
    /* Resource Manager events (53-57) */
    OZAYN_EVENT_RESOURCE_CREATED      = 53,
    OZAYN_EVENT_RESOURCE_ALLOCATED    = 54,
    OZAYN_EVENT_RESOURCE_RELEASED     = 55,
    OZAYN_EVENT_RESOURCE_FAILED       = 56,
    OZAYN_EVENT_RESOURCE_ORPHANED     = 57,
    /* Scheduler events (58-64) */
    OZAYN_EVENT_SCHED_TASK_READY      = 58,
    OZAYN_EVENT_SCHED_TASK_STARTED    = 59,
    OZAYN_EVENT_SCHED_TASK_WAITING    = 60,
    OZAYN_EVENT_SCHED_TASK_BLOCKED    = 61,
    OZAYN_EVENT_SCHED_TASK_RESUMED    = 62,
    OZAYN_EVENT_SCHED_PRIORITY_CHANGED = 63,
    OZAYN_EVENT_SCHED_TASK_CANCELLED  = 64,
    /* Monitoring events (65-72) */
    OZAYN_EVENT_MONITORING_COLLECTED  = 65,
    OZAYN_EVENT_HEALTH_CHANGED        = 66,
    OZAYN_EVENT_HEALTH_CHECK_FAILED   = 67,
    OZAYN_EVENT_METRIC_UPDATED        = 68,
    OZAYN_EVENT_INCIDENT_CREATED      = 69,
    OZAYN_EVENT_INCIDENT_RESOLVED     = 70,
    OZAYN_EVENT_MONITORING_ERROR      = 71,
    OZAYN_EVENT_MONITORING_STARTED    = 72,
    /* Diagnostics events (73-84) */
    OZAYN_EVENT_DIAG_EVIDENCE_RECORDED = 73,
    OZAYN_EVENT_DIAG_FINDING_CREATED   = 74,
    OZAYN_EVENT_DIAG_SESSION_STARTED   = 75,
    OZAYN_EVENT_DIAG_SESSION_COMPLETED = 76,
    OZAYN_EVENT_DIAG_SNAPSHOT_CAPTURED = 77,
    OZAYN_EVENT_DIAG_FAILURE_RECORDED  = 78,
    OZAYN_EVENT_DIAG_REPEATED_FAILURE  = 79,
    OZAYN_EVENT_DIAG_LEVEL_CHANGED     = 80,
    OZAYN_EVENT_DIAG_TIMELINE_UPDATED  = 81,
    OZAYN_EVENT_DIAG_INVESTIGATION     = 82,
    OZAYN_EVENT_DIAG_ROOT_CAUSE        = 83,
    OZAYN_EVENT_DIAG_REDACTION         = 84,
    /* Security Boundary events (85-96) */
    OZAYN_EVENT_SEC_CONTEXT_REGISTERED = 85,
    OZAYN_EVENT_SEC_CONTEXT_REMOVED    = 86,
    OZAYN_EVENT_SEC_CAP_GRANTED        = 87,
    OZAYN_EVENT_SEC_CAP_REVOKED        = 88,
    OZAYN_EVENT_SEC_VIOLATION          = 89,
    OZAYN_EVENT_SEC_ACCESS_DENIED      = 90,
    OZAYN_EVENT_SEC_PRIVILEGE_BLOCKED  = 91,
    OZAYN_EVENT_SEC_SANDBOX_VIOLATION  = 92,
    OZAYN_EVENT_SEC_RESOURCE_ABUSE     = 93,
    OZAYN_EVENT_SEC_COMPONENT_RESTRICTED = 94,
    OZAYN_EVENT_SEC_COMPONENT_ISOLATED = 95,
    OZAYN_EVENT_SEC_COMPONENT_RESTORED = 96,
    OZAYN_EVENT_SEC_CHECK_PERFORMED    = 97,
    /* State Manager events (98-110) */
    OZAYN_EVENT_STATE_CREATED         = 98,
    OZAYN_EVENT_STATE_LOADED          = 99,
    OZAYN_EVENT_STATE_SAVED           = 100,
    OZAYN_EVENT_STATE_CHANGED         = 101,
    OZAYN_EVENT_STATE_DELETED         = 102,
    OZAYN_EVENT_STATE_VALIDATED       = 103,
    OZAYN_EVENT_STATE_INVALID         = 104,
    OZAYN_EVENT_STATE_BACKUP_CREATED  = 105,
    OZAYN_EVENT_STATE_RECOVERY_STARTED = 106,
    OZAYN_EVENT_STATE_RECOVERY_COMPLETED = 107,
    OZAYN_EVENT_STATE_CORRUPTED       = 108,
    OZAYN_EVENT_STATE_DIRTY           = 109,
    OZAYN_EVENT_STATE_SYNCED          = 110,
    /* Lifecycle events (111-123) */
    OZAYN_LC_EVENT_INIT_BEGAN            = 111,
    OZAYN_LC_EVENT_INIT_PHASE_COMPLETE   = 112,
    OZAYN_LC_EVENT_INIT_COMPLETE         = 113,
    OZAYN_LC_EVENT_ONLINE                = 114,
    OZAYN_LC_EVENT_SHUTDOWN_REQUESTED    = 115,
    OZAYN_LC_EVENT_SHUTDOWN_BEGAN        = 116,
    OZAYN_LC_EVENT_SHUTDOWN_COMPLETED    = 117,
    OZAYN_LC_EVENT_RESTART_REQUESTED     = 118,
    OZAYN_LC_EVENT_COMPONENT_FAILED      = 119,
    OZAYN_LC_EVENT_STARTUP_ROLLBACK      = 120,
    OZAYN_LC_EVENT_READINESS_PASSED      = 121,
    OZAYN_LC_EVENT_READINESS_FAILED      = 122,
    OZAYN_LC_EVENT_STATE_CHANGED         = 123,
    /* Dependency events (124-130) */
    OZAYN_DEP_EVENT_REGISTERED          = 124,
    OZAYN_DEP_EVENT_EDGE_ADDED          = 125,
    OZAYN_DEP_EVENT_RESOLVED            = 126,
    OZAYN_DEP_EVENT_CYCLE_DETECTED      = 127,
    OZAYN_DEP_EVENT_MISSING_DETECTED    = 128,
    OZAYN_DEP_EVENT_STATE_CHANGED       = 129,
    OZAYN_DEP_EVENT_PROPAGATED          = 130,
    /* Service lifecycle events (131-140) */
    OZAYN_SVC_LC_EVENT_REGISTERED       = 131,
    OZAYN_SVC_LC_EVENT_STARTING         = 132,
    OZAYN_SVC_LC_EVENT_STARTED          = 133,
    OZAYN_SVC_LC_EVENT_DRAINING         = 134,
    OZAYN_SVC_LC_EVENT_STOPPED          = 135,
    OZAYN_SVC_LC_EVENT_RESTARTING       = 136,
    OZAYN_SVC_LC_EVENT_RESTART_FAILED   = 137,
    OZAYN_SVC_LC_EVENT_HEALTH_CHANGED   = 138,
    OZAYN_SVC_LC_EVENT_HEALTH_CHECK     = 139,
    OZAYN_SVC_LC_EVENT_SUSPENDED        = 140,
    OZAYN_SVC_LC_EVENT_RESUMED          = 141,
    OZAYN_SVC_LC_EVENT_FAILED           = 142,
    /* Config manager events (143-150) */
    OZAYN_CFG_MGR_EVENT_REGISTERED      = 143,
    OZAYN_CFG_MGR_EVENT_KEY_SET         = 144,
    OZAYN_CFG_MGR_EVENT_KEY_CHANGED     = 145,
    OZAYN_CFG_MGR_EVENT_LOADED          = 146,
    OZAYN_CFG_MGR_EVENT_SNAPSHOT_SAVED  = 147,
    OZAYN_CFG_MGR_EVENT_SNAPSHOT_LOADED = 148,
    OZAYN_CFG_MGR_EVENT_LISTENER_ADDED  = 149,
    OZAYN_CFG_MGR_EVENT_LISTENER_REMOVED = 150,
    /* Core API events (151-160) */
    OZAYN_API_EVENT_INTERFACE_REGISTERED = 151,
    OZAYN_API_EVENT_INTERFACE_REMOVED    = 152,
    OZAYN_API_EVENT_REQUEST_BEGIN        = 153,
    OZAYN_API_EVENT_REQUEST_COMPLETE     = 154,
    OZAYN_API_EVENT_REQUEST_CANCELLED    = 155,
    OZAYN_API_EVENT_REQUEST_TIMEOUT      = 156,
    OZAYN_API_EVENT_VERSION_CHECK        = 157,
    OZAYN_API_EVENT_ERROR_PROPAGATED     = 158,
    OZAYN_API_EVENT_METHOD_ADDED         = 159,
    OZAYN_API_EVENT_COMPAT_CHECK         = 160,
    /* Reload manager events (161-175) */
    OZAYN_RELOAD_EVENT_REQUESTED         = 161,
    OZAYN_RELOAD_EVENT_VALIDATING        = 162,
    OZAYN_RELOAD_EVENT_VALIDATED         = 163,
    OZAYN_RELOAD_EVENT_QUIESCING         = 164,
    OZAYN_RELOAD_EVENT_QUIESCED          = 165,
    OZAYN_RELOAD_EVENT_STOPPING          = 166,
    OZAYN_RELOAD_EVENT_STOPPED           = 167,
    OZAYN_RELOAD_EVENT_STATE_SAVED       = 168,
    OZAYN_RELOAD_EVENT_UNLOADED          = 169,
    OZAYN_RELOAD_EVENT_LOADED            = 170,
    OZAYN_RELOAD_EVENT_INITIALIZED       = 171,
    OZAYN_RELOAD_EVENT_STATE_RESTORED    = 172,
    OZAYN_RELOAD_EVENT_STARTED           = 173,
    OZAYN_RELOAD_EVENT_HEALTH_PASSED     = 174,
    OZAYN_RELOAD_EVENT_READY             = 175,
    OZAYN_RELOAD_EVENT_COMPLETED         = 176,
    OZAYN_RELOAD_EVENT_FAILED            = 177,
    OZAYN_RELOAD_EVENT_CANCELLED         = 178,
    OZAYN_RELOAD_EVENT_ROLLBACK_STARTED  = 179,
    OZAYN_RELOAD_EVENT_ROLLBACK          = 180,
    OZAYN_RELOAD_EVENT_ROLLBACK_COMPLETED = 181,
    /* Performance manager events (182-195) */
    OZAYN_PERF_EVENT_SNAPSHOT_TAKEN      = 182,
    OZAYN_PERF_EVENT_THRESHOLD_WARNING   = 183,
    OZAYN_PERF_EVENT_THRESHOLD_CRITICAL  = 184,
    OZAYN_PERF_EVENT_BENCHMARK_STARTED   = 185,
    OZAYN_PERF_EVENT_BENCHMARK_COMPLETED = 186,
    OZAYN_PERF_EVENT_BENCHMARK_CANCELLED = 187,
    OZAYN_PERF_EVENT_STARTUP_RECORDED    = 188,
    OZAYN_PERF_EVENT_CPU_HIGH            = 189,
    OZAYN_PERF_EVENT_MEMORY_HIGH         = 190,
    OZAYN_PERF_EVENT_EVENT_QUEUE_SATURATED = 191,
    OZAYN_PERF_EVENT_SCHEDULER_OVERLOADED = 192,
    OZAYN_PERF_EVENT_CONFIG_CHANGED      = 193,
    OZAYN_PERF_EVENT_BENCH_ITERATION     = 194,
    OZAYN_PERF_EVENT_COLLECT_FAILED      = 195,
    /* Defense / hardening events (196-215) */
    OZAYN_DEFENSE_EVENT_VIOLATION        = 196,
    OZAYN_DEFENSE_EVENT_INPUT_REJECTED   = 197,
    OZAYN_DEFENSE_EVENT_RESOURCE_DENIED  = 198,
    OZAYN_DEFENSE_EVENT_BACKPRESSURE     = 199,
    OZAYN_DEFENSE_EVENT_RATE_LIMITED     = 200,
    OZAYN_CB_EVENT_OPENED                = 201,
    OZAYN_CB_EVENT_CLOSED                = 202,
    OZAYN_CB_EVENT_HALF_OPENED           = 203,
    OZAYN_CB_EVENT_CALL_REJECTED         = 204,
    OZAYN_HT_EVENT_STATE_CHANGED         = 205,
    OZAYN_HT_EVENT_HEARTBEAT_MISSED      = 206,
    OZAYN_HT_EVENT_COMPONENT_FAILED      = 207,
    OZAYN_HT_EVENT_QUARANTINED           = 208,
    OZAYN_HT_EVENT_RECOVERED             = 209,
    OZAYN_CL_EVENT_CRASH_LOOP            = 210,
    OZAYN_CL_EVENT_QUARANTINED           = 211,
    OZAYN_CL_EVENT_RELEASED              = 212,
    OZAYN_CV_EVENT_VALIDATED             = 213,
    OZAYN_CV_EVENT_VALIDATION_FAILED     = 214,
    OZAYN_CV_EVENT_ROLLBACK              = 215,
    /* Release manager events (216-235) */
    OZAYN_REL_EVENT_MANIFEST_READ       = 216,
    OZAYN_REL_EVENT_MANIFEST_WRITE      = 217,
    OZAYN_REL_EVENT_DEPS_VERIFIED       = 218,
    OZAYN_REL_EVENT_DEPS_MISSING        = 219,
    OZAYN_REL_EVENT_INTEGRITY_OK        = 220,
    OZAYN_REL_EVENT_INTEGRITY_FAIL      = 221,
    OZAYN_REL_EVENT_BACKUP_CREATED      = 222,
    OZAYN_REL_EVENT_BACKUP_RESTORED     = 223,
    OZAYN_REL_EVENT_INSTALL_STARTED     = 224,
    OZAYN_REL_EVENT_INSTALL_COMPLETE    = 225,
    OZAYN_REL_EVENT_ROLLBACK_STARTED    = 226,
    OZAYN_REL_EVENT_ROLLBACK_COMPLETE   = 227,
    OZAYN_REL_EVENT_SMOKE_PASSED        = 228,
    OZAYN_REL_EVENT_SMOKE_FAILED        = 229,
    OZAYN_REL_EVENT_GATE_PASSED         = 230,
    OZAYN_REL_EVENT_GATE_FAILED         = 231,
    OZAYN_REL_EVENT_READY               = 232,
    OZAYN_REL_EVENT_NOT_READY           = 233,
    OZAYN_REL_EVENT_MIGRATED            = 234,
    OZAYN_REL_EVENT_LOGGED              = 235,
    /* Application-domain events (236-245) */
    OZAYN_APP_EVENT_FACE_DETECTED       = 236,
    OZAYN_APP_EVENT_VOICE_DETECTED      = 237,
    OZAYN_APP_EVENT_GESTURE_DETECTED    = 238,
    OZAYN_APP_EVENT_WINDOW_OPENED       = 239,
    OZAYN_APP_EVENT_WINDOW_CLOSED       = 240,
    OZAYN_APP_EVENT_COMMAND_RECEIVED    = 241,
    OZAYN_APP_EVENT_COMMAND_COMPLETED   = 242,
    OZAYN_APP_EVENT_ARWE_CONNECTED      = 243,
    OZAYN_APP_EVENT_ARWE_DISCONNECTED   = 244,
    OZAYN_APP_EVENT_MODULE_ACTION       = 245,
} ozayn_event_type_t;

/* Event source */
typedef enum {
    OZAYN_SRC_CORE     = 0,
    OZAYN_SRC_RUNTIME  = 1,
    OZAYN_SRC_CONFIG   = 2,
    OZAYN_SRC_LOGGER   = 3,
    OZAYN_SRC_RECOVERY = 4,
    OZAYN_SRC_USER     = 5,
    OZAYN_SRC_MODULE   = 6,
    OZAYN_SRC_PLUGIN   = 7,
    OZAYN_SRC_IPC      = 8,
    OZAYN_SRC_REGISTRY = 9,
    OZAYN_SRC_SECURITY   = 10,
    OZAYN_SRC_STATE      = 11,
    OZAYN_SRC_LIFECYCLE  = 12,
    OZAYN_SRC_DEP        = 13,
    OZAYN_SRC_SVC_LC     = 14,
    OZAYN_SRC_CONFIG_MGR = 15,
    OZAYN_SRC_API        = 16,
    OZAYN_SRC_RELOAD     = 17,
    OZAYN_SRC_PERF       = 18,
    OZAYN_SRC_DEFENSE    = 19,
    OZAYN_SRC_RELEASE    = 20,
} ozayn_event_source_t;

/* Event structure */
typedef struct {
    ozayn_event_type_t   type;
    ozayn_event_source_t source;
    time_t               timestamp;
    void                *payload;  /* owned by producer, opaque to engine */
} ozayn_event_t;

/* Subscriber callback */
typedef void (*ozayn_event_handler_t)(const ozayn_event_t *event, void *context);

/* Subscription handle */
typedef struct {
    int                   active;
    ozayn_event_type_t    type;
    ozayn_event_handler_t handler;
    void                 *context;
} ozayn_subscription_t;

/* Event engine configuration */
typedef struct {
    int queue_capacity;      /* max queued events */
    int max_subscribers;     /* max subscriptions */
} ozayn_event_config_t;

/* Event engine */
typedef struct ozayn_event_engine_s {
    ozayn_event_t      *queue;
    int                 queue_capacity;
    int                 queue_head;
    int                 queue_tail;
    int                 queue_count;

    ozayn_subscription_t *subscriptions;
    int                 max_subscribers;
    int                 sub_count;

    int                 dispatching;
    int                 initialized;
} ozayn_event_engine_t;

/* Lifecycle */
ozayn_result_t ozayn_events_init(ozayn_event_engine_t *engine, const ozayn_event_config_t *cfg);
void           ozayn_events_shutdown(ozayn_event_engine_t *engine);

/* Publish */
ozayn_result_t ozayn_events_publish(ozayn_event_engine_t *engine,
                                    ozayn_event_type_t type,
                                    ozayn_event_source_t source,
                                    void *payload);

/* Subscribe / unsubscribe */
int            ozayn_events_subscribe(ozayn_event_engine_t *engine,
                                      ozayn_event_type_t type,
                                      ozayn_event_handler_t handler,
                                      void *context);
void           ozayn_events_unsubscribe(ozayn_event_engine_t *engine, int sub_id);

/* Process — called from Runtime loop */
int            ozayn_events_process(ozayn_event_engine_t *engine);

/* Query */
const char    *ozayn_event_type_name(ozayn_event_type_t type);
const char    *ozayn_event_source_name(ozayn_event_source_t src);
int            ozayn_events_queue_count(const ozayn_event_engine_t *engine);

#endif
