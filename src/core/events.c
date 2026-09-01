#include "events.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

/* ---------- Names ---------- */

const char *ozayn_event_type_name(ozayn_event_type_t type) {
    switch (type) {
        case OZAYN_EVENT_NONE:             return "NONE";
        case OZAYN_EVENT_CORE_STARTED:     return "CORE_STARTED";
        case OZAYN_EVENT_CORE_STOPPING:    return "CORE_STOPPING";
        case OZAYN_EVENT_RUNTIME_STARTED:  return "RUNTIME_STARTED";
        case OZAYN_EVENT_RUNTIME_STOPPING: return "RUNTIME_STOPPING";
        case OZAYN_EVENT_CONFIG_LOADED:    return "CONFIG_LOADED";
        case OZAYN_EVENT_LOGGER_READY:     return "LOGGER_READY";
        case OZAYN_EVENT_RECOVERY_RAISED:  return "RECOVERY_RAISED";
        case OZAYN_EVENT_TASK_CREATED:     return "TASK_CREATED";
        case OZAYN_EVENT_TASK_COMPLETED:   return "TASK_COMPLETED";
        case OZAYN_EVENT_TASK_FAILED:      return "TASK_FAILED";
        case OZAYN_EVENT_TASK_CANCELLED:   return "TASK_CANCELLED";
        case OZAYN_EVENT_PROCESS_STARTED:  return "PROCESS_STARTED";
        case OZAYN_EVENT_PROCESS_EXITED:   return "PROCESS_EXITED";
        case OZAYN_EVENT_PROCESS_FAILED:   return "PROCESS_FAILED";
        case OZAYN_EVENT_MODULE_REGISTERED:  return "MODULE_REGISTERED";
        case OZAYN_EVENT_MODULE_INITIALIZED: return "MODULE_INITIALIZED";
        case OZAYN_EVENT_MODULE_STARTED:     return "MODULE_STARTED";
        case OZAYN_EVENT_MODULE_STOPPED:     return "MODULE_STOPPED";
        case OZAYN_EVENT_MODULE_SHUTDOWN:    return "MODULE_SHUTDOWN";
        case OZAYN_EVENT_MODULE_FAILED:      return "MODULE_FAILED";
        case OZAYN_EVENT_PLUGIN_DISCOVERED:  return "PLUGIN_DISCOVERED";
        case OZAYN_EVENT_PLUGIN_LOADED:      return "PLUGIN_LOADED";
        case OZAYN_EVENT_PLUGIN_INITIALIZED: return "PLUGIN_INITIALIZED";
        case OZAYN_EVENT_PLUGIN_STARTED:     return "PLUGIN_STARTED";
        case OZAYN_EVENT_PLUGIN_STOPPED:     return "PLUGIN_STOPPED";
        case OZAYN_EVENT_PLUGIN_UNLOADED:    return "PLUGIN_UNLOADED";
        case OZAYN_EVENT_PLUGIN_FAILED:      return "PLUGIN_FAILED";
        case OZAYN_EVENT_IPC_STARTED:        return "IPC_STARTED";
        case OZAYN_EVENT_IPC_STOPPING:       return "IPC_STOPPING";
        case OZAYN_EVENT_IPC_CLIENT_CONNECTED:    return "IPC_CLIENT_CONNECTED";
        case OZAYN_EVENT_IPC_CLIENT_DISCONNECTED: return "IPC_CLIENT_DISCONNECTED";
        case OZAYN_EVENT_IPC_REQUEST_RECEIVED:    return "IPC_REQUEST_RECEIVED";
        case OZAYN_EVENT_IPC_RESPONSE_SENT:       return "IPC_RESPONSE_SENT";
        case OZAYN_EVENT_IPC_ERROR:          return "IPC_ERROR";
        case OZAYN_EVENT_SERVICE_REGISTERED: return "SERVICE_REGISTERED";
        case OZAYN_EVENT_SERVICE_READY:      return "SERVICE_READY";
        case OZAYN_EVENT_SERVICE_DEGRADED:   return "SERVICE_DEGRADED";
        case OZAYN_EVENT_SERVICE_FAILED:     return "SERVICE_FAILED";
        case OZAYN_EVENT_SERVICE_OFFLINE:    return "SERVICE_OFFLINE";
        case OZAYN_EVENT_SERVICE_UNREGISTERED: return "SERVICE_UNREGISTERED";
        case OZAYN_EVENT_IDENTITY_REGISTERED: return "IDENTITY_REGISTERED";
        case OZAYN_EVENT_AUTH_SUCCESS:        return "AUTH_SUCCESS";
        case OZAYN_EVENT_AUTH_FAILURE:        return "AUTH_FAILURE";
        case OZAYN_EVENT_ACCESS_DENIED:       return "ACCESS_DENIED";
        case OZAYN_EVENT_IDENTITY_REVOKED:    return "IDENTITY_REVOKED";
        case OZAYN_EVENT_CREDENTIAL_EXPIRED:  return "CREDENTIAL_EXPIRED";
        case OZAYN_EVENT_SECURITY_ALERT:      return "SECURITY_ALERT";
        case OZAYN_EVENT_AUTHORIZATION_ALLOWED: return "AUTHORIZATION_ALLOWED";
        case OZAYN_EVENT_AUTHORIZATION_DENIED:  return "AUTHORIZATION_DENIED";
        case OZAYN_EVENT_ROLE_ASSIGNED:         return "ROLE_ASSIGNED";
        case OZAYN_EVENT_ROLE_REVOKED:          return "ROLE_REVOKED";
        case OZAYN_EVENT_POLICY_CHANGED:        return "POLICY_CHANGED";
        case OZAYN_EVENT_RESOURCE_CREATED:      return "RESOURCE_CREATED";
        case OZAYN_EVENT_RESOURCE_ALLOCATED:    return "RESOURCE_ALLOCATED";
        case OZAYN_EVENT_RESOURCE_RELEASED:     return "RESOURCE_RELEASED";
        case OZAYN_EVENT_RESOURCE_FAILED:       return "RESOURCE_FAILED";
        case OZAYN_EVENT_RESOURCE_ORPHANED:     return "RESOURCE_ORPHANED";
        case OZAYN_EVENT_SCHED_TASK_READY:      return "SCHED_TASK_READY";
        case OZAYN_EVENT_SCHED_TASK_STARTED:    return "SCHED_TASK_STARTED";
        case OZAYN_EVENT_SCHED_TASK_WAITING:    return "SCHED_TASK_WAITING";
        case OZAYN_EVENT_SCHED_TASK_BLOCKED:    return "SCHED_TASK_BLOCKED";
        case OZAYN_EVENT_SCHED_TASK_RESUMED:    return "SCHED_TASK_RESUMED";
        case OZAYN_EVENT_SCHED_PRIORITY_CHANGED: return "SCHED_PRIORITY_CHANGED";
        case OZAYN_EVENT_SCHED_TASK_CANCELLED:  return "SCHED_TASK_CANCELLED";
        case OZAYN_EVENT_MONITORING_COLLECTED:  return "MONITORING_COLLECTED";
        case OZAYN_EVENT_HEALTH_CHANGED:        return "HEALTH_CHANGED";
        case OZAYN_EVENT_HEALTH_CHECK_FAILED:   return "HEALTH_CHECK_FAILED";
        case OZAYN_EVENT_METRIC_UPDATED:        return "METRIC_UPDATED";
        case OZAYN_EVENT_INCIDENT_CREATED:      return "INCIDENT_CREATED";
        case OZAYN_EVENT_INCIDENT_RESOLVED:     return "INCIDENT_RESOLVED";
        case OZAYN_EVENT_MONITORING_ERROR:      return "MONITORING_ERROR";
        case OZAYN_EVENT_MONITORING_STARTED:    return "MONITORING_STARTED";
        case OZAYN_EVENT_DIAG_EVIDENCE_RECORDED: return "DIAG_EVIDENCE_RECORDED";
        case OZAYN_EVENT_DIAG_FINDING_CREATED:   return "DIAG_FINDING_CREATED";
        case OZAYN_EVENT_DIAG_SESSION_STARTED:   return "DIAG_SESSION_STARTED";
        case OZAYN_EVENT_DIAG_SESSION_COMPLETED: return "DIAG_SESSION_COMPLETED";
        case OZAYN_EVENT_DIAG_SNAPSHOT_CAPTURED: return "DIAG_SNAPSHOT_CAPTURED";
        case OZAYN_EVENT_DIAG_FAILURE_RECORDED:  return "DIAG_FAILURE_RECORDED";
        case OZAYN_EVENT_DIAG_REPEATED_FAILURE:  return "DIAG_REPEATED_FAILURE";
        case OZAYN_EVENT_DIAG_LEVEL_CHANGED:     return "DIAG_LEVEL_CHANGED";
        case OZAYN_EVENT_DIAG_TIMELINE_UPDATED:  return "DIAG_TIMELINE_UPDATED";
        case OZAYN_EVENT_DIAG_INVESTIGATION:     return "DIAG_INVESTIGATION";
        case OZAYN_EVENT_DIAG_ROOT_CAUSE:        return "DIAG_ROOT_CAUSE";
        case OZAYN_EVENT_DIAG_REDACTION:         return "DIAG_REDACTION";
        case OZAYN_EVENT_SEC_CONTEXT_REGISTERED: return "SEC_CONTEXT_REGISTERED";
        case OZAYN_EVENT_SEC_CONTEXT_REMOVED:    return "SEC_CONTEXT_REMOVED";
        case OZAYN_EVENT_SEC_CAP_GRANTED:        return "SEC_CAP_GRANTED";
        case OZAYN_EVENT_SEC_CAP_REVOKED:        return "SEC_CAP_REVOKED";
        case OZAYN_EVENT_SEC_VIOLATION:          return "SEC_VIOLATION";
        case OZAYN_EVENT_SEC_ACCESS_DENIED:      return "SEC_ACCESS_DENIED";
        case OZAYN_EVENT_SEC_PRIVILEGE_BLOCKED:  return "SEC_PRIVILEGE_BLOCKED";
        case OZAYN_EVENT_SEC_SANDBOX_VIOLATION:  return "SEC_SANDBOX_VIOLATION";
        case OZAYN_EVENT_SEC_RESOURCE_ABUSE:     return "SEC_RESOURCE_ABUSE";
        case OZAYN_EVENT_SEC_COMPONENT_RESTRICTED: return "SEC_COMPONENT_RESTRICTED";
        case OZAYN_EVENT_SEC_COMPONENT_ISOLATED: return "SEC_COMPONENT_ISOLATED";
        case OZAYN_EVENT_SEC_COMPONENT_RESTORED: return "SEC_COMPONENT_RESTORED";
        case OZAYN_EVENT_SEC_CHECK_PERFORMED:    return "SEC_CHECK_PERFORMED";
        case OZAYN_EVENT_STATE_CREATED:         return "STATE_CREATED";
        case OZAYN_EVENT_STATE_LOADED:          return "STATE_LOADED";
        case OZAYN_EVENT_STATE_SAVED:           return "STATE_SAVED";
        case OZAYN_EVENT_STATE_CHANGED:         return "STATE_CHANGED";
        case OZAYN_EVENT_STATE_DELETED:         return "STATE_DELETED";
        case OZAYN_EVENT_STATE_VALIDATED:       return "STATE_VALIDATED";
        case OZAYN_EVENT_STATE_INVALID:         return "STATE_INVALID";
        case OZAYN_EVENT_STATE_BACKUP_CREATED:  return "STATE_BACKUP_CREATED";
        case OZAYN_EVENT_STATE_RECOVERY_STARTED: return "STATE_RECOVERY_STARTED";
        case OZAYN_EVENT_STATE_RECOVERY_COMPLETED: return "STATE_RECOVERY_COMPLETED";
        case OZAYN_EVENT_STATE_CORRUPTED:       return "STATE_CORRUPTED";
        case OZAYN_EVENT_STATE_DIRTY:           return "STATE_DIRTY";
        case OZAYN_EVENT_STATE_SYNCED:          return "STATE_SYNCED";
        case OZAYN_LC_EVENT_INIT_BEGAN:         return "LC_INIT_BEGAN";
        case OZAYN_LC_EVENT_INIT_PHASE_COMPLETE: return "LC_INIT_PHASE_COMPLETE";
        case OZAYN_LC_EVENT_INIT_COMPLETE:      return "LC_INIT_COMPLETE";
        case OZAYN_LC_EVENT_ONLINE:             return "LC_ONLINE";
        case OZAYN_LC_EVENT_SHUTDOWN_REQUESTED: return "LC_SHUTDOWN_REQUESTED";
        case OZAYN_LC_EVENT_SHUTDOWN_BEGAN:     return "LC_SHUTDOWN_BEGAN";
        case OZAYN_LC_EVENT_SHUTDOWN_COMPLETED: return "LC_SHUTDOWN_COMPLETED";
        case OZAYN_LC_EVENT_RESTART_REQUESTED:  return "LC_RESTART_REQUESTED";
        case OZAYN_LC_EVENT_COMPONENT_FAILED:   return "LC_COMPONENT_FAILED";
        case OZAYN_LC_EVENT_STARTUP_ROLLBACK:   return "LC_STARTUP_ROLLBACK";
        case OZAYN_LC_EVENT_READINESS_PASSED:   return "LC_READINESS_PASSED";
        case OZAYN_LC_EVENT_READINESS_FAILED:   return "LC_READINESS_FAILED";
        case OZAYN_LC_EVENT_STATE_CHANGED:      return "LC_STATE_CHANGED";
        case OZAYN_DEP_EVENT_REGISTERED:        return "DEP_REGISTERED";
        case OZAYN_DEP_EVENT_EDGE_ADDED:        return "DEP_EDGE_ADDED";
        case OZAYN_DEP_EVENT_RESOLVED:          return "DEP_RESOLVED";
        case OZAYN_DEP_EVENT_CYCLE_DETECTED:    return "DEP_CYCLE_DETECTED";
        case OZAYN_DEP_EVENT_MISSING_DETECTED:  return "DEP_MISSING_DETECTED";
        case OZAYN_DEP_EVENT_STATE_CHANGED:     return "DEP_STATE_CHANGED";
        case OZAYN_DEP_EVENT_PROPAGATED:        return "DEP_PROPAGATED";
        case OZAYN_SVC_LC_EVENT_REGISTERED:     return "SVC_LC_REGISTERED";
        case OZAYN_SVC_LC_EVENT_STARTING:       return "SVC_LC_STARTING";
        case OZAYN_SVC_LC_EVENT_STARTED:        return "SVC_LC_STARTED";
        case OZAYN_SVC_LC_EVENT_DRAINING:       return "SVC_LC_DRAINING";
        case OZAYN_SVC_LC_EVENT_STOPPED:        return "SVC_LC_STOPPED";
        case OZAYN_SVC_LC_EVENT_RESTARTING:     return "SVC_LC_RESTARTING";
        case OZAYN_SVC_LC_EVENT_RESTART_FAILED: return "SVC_LC_RESTART_FAILED";
        case OZAYN_SVC_LC_EVENT_HEALTH_CHANGED: return "SVC_LC_HEALTH_CHANGED";
        case OZAYN_SVC_LC_EVENT_HEALTH_CHECK:   return "SVC_LC_HEALTH_CHECK";
        case OZAYN_SVC_LC_EVENT_SUSPENDED:      return "SVC_LC_SUSPENDED";
        case OZAYN_SVC_LC_EVENT_RESUMED:        return "SVC_LC_RESUMED";
        case OZAYN_SVC_LC_EVENT_FAILED:         return "SVC_LC_FAILED";
        case OZAYN_CFG_MGR_EVENT_REGISTERED:    return "CFG_MGR_REGISTERED";
        case OZAYN_CFG_MGR_EVENT_KEY_SET:       return "CFG_MGR_KEY_SET";
        case OZAYN_CFG_MGR_EVENT_KEY_CHANGED:   return "CFG_MGR_KEY_CHANGED";
        case OZAYN_CFG_MGR_EVENT_LOADED:        return "CFG_MGR_LOADED";
        case OZAYN_CFG_MGR_EVENT_SNAPSHOT_SAVED:  return "CFG_MGR_SNAPSHOT_SAVED";
        case OZAYN_CFG_MGR_EVENT_SNAPSHOT_LOADED: return "CFG_MGR_SNAPSHOT_LOADED";
        case OZAYN_CFG_MGR_EVENT_LISTENER_ADDED:   return "CFG_MGR_LISTENER_ADDED";
        case OZAYN_CFG_MGR_EVENT_LISTENER_REMOVED: return "CFG_MGR_LISTENER_REMOVED";
        case OZAYN_API_EVENT_INTERFACE_REGISTERED: return "API_IFACE_REGISTERED";
        case OZAYN_API_EVENT_INTERFACE_REMOVED:    return "API_IFACE_REMOVED";
        case OZAYN_API_EVENT_REQUEST_BEGIN:        return "API_REQUEST_BEGIN";
        case OZAYN_API_EVENT_REQUEST_COMPLETE:     return "API_REQUEST_COMPLETE";
        case OZAYN_API_EVENT_REQUEST_CANCELLED:    return "API_REQUEST_CANCELLED";
        case OZAYN_API_EVENT_REQUEST_TIMEOUT:      return "API_REQUEST_TIMEOUT";
        case OZAYN_API_EVENT_VERSION_CHECK:        return "API_VERSION_CHECK";
        case OZAYN_API_EVENT_ERROR_PROPAGATED:     return "API_ERROR_PROPAGATED";
        case OZAYN_API_EVENT_METHOD_ADDED:         return "API_METHOD_ADDED";
        case OZAYN_API_EVENT_COMPAT_CHECK:         return "API_COMPAT_CHECK";
        case OZAYN_RELOAD_EVENT_REQUESTED:         return "RELOAD_REQUESTED";
        case OZAYN_RELOAD_EVENT_VALIDATING:        return "RELOAD_VALIDATING";
        case OZAYN_RELOAD_EVENT_VALIDATED:         return "RELOAD_VALIDATED";
        case OZAYN_RELOAD_EVENT_QUIESCING:         return "RELOAD_QUIESCING";
        case OZAYN_RELOAD_EVENT_QUIESCED:          return "RELOAD_QUIESCED";
        case OZAYN_RELOAD_EVENT_STOPPING:          return "RELOAD_STOPPING";
        case OZAYN_RELOAD_EVENT_STOPPED:           return "RELOAD_STOPPED";
        case OZAYN_RELOAD_EVENT_STATE_SAVED:       return "RELOAD_STATE_SAVED";
        case OZAYN_RELOAD_EVENT_UNLOADED:          return "RELOAD_UNLOADED";
        case OZAYN_RELOAD_EVENT_LOADED:            return "RELOAD_LOADED";
        case OZAYN_RELOAD_EVENT_INITIALIZED:       return "RELOAD_INITIALIZED";
        case OZAYN_RELOAD_EVENT_STATE_RESTORED:    return "RELOAD_STATE_RESTORED";
        case OZAYN_RELOAD_EVENT_STARTED:           return "RELOAD_STARTED";
        case OZAYN_RELOAD_EVENT_HEALTH_PASSED:     return "RELOAD_HEALTH_PASSED";
        case OZAYN_RELOAD_EVENT_READY:             return "RELOAD_READY";
        case OZAYN_RELOAD_EVENT_COMPLETED:         return "RELOAD_COMPLETED";
        case OZAYN_RELOAD_EVENT_FAILED:            return "RELOAD_FAILED";
        case OZAYN_RELOAD_EVENT_CANCELLED:         return "RELOAD_CANCELLED";
        case OZAYN_RELOAD_EVENT_ROLLBACK_STARTED:  return "RELOAD_ROLLBACK_STARTED";
        case OZAYN_RELOAD_EVENT_ROLLBACK:          return "RELOAD_ROLLBACK";
        case OZAYN_RELOAD_EVENT_ROLLBACK_COMPLETED: return "RELOAD_ROLLBACK_COMPLETED";
        case OZAYN_PERF_EVENT_SNAPSHOT_TAKEN:       return "PERF_SNAPSHOT_TAKEN";
        case OZAYN_PERF_EVENT_THRESHOLD_WARNING:    return "PERF_THRESHOLD_WARNING";
        case OZAYN_PERF_EVENT_THRESHOLD_CRITICAL:   return "PERF_THRESHOLD_CRITICAL";
        case OZAYN_PERF_EVENT_BENCHMARK_STARTED:    return "PERF_BENCHMARK_STARTED";
        case OZAYN_PERF_EVENT_BENCHMARK_COMPLETED:  return "PERF_BENCHMARK_COMPLETED";
        case OZAYN_PERF_EVENT_BENCHMARK_CANCELLED:  return "PERF_BENCHMARK_CANCELLED";
        case OZAYN_PERF_EVENT_STARTUP_RECORDED:     return "PERF_STARTUP_RECORDED";
        case OZAYN_PERF_EVENT_CPU_HIGH:             return "PERF_CPU_HIGH";
        case OZAYN_PERF_EVENT_MEMORY_HIGH:          return "PERF_MEMORY_HIGH";
        case OZAYN_PERF_EVENT_EVENT_QUEUE_SATURATED: return "PERF_EVENT_QUEUE_SATURATED";
        case OZAYN_PERF_EVENT_SCHEDULER_OVERLOADED: return "PERF_SCHEDULER_OVERLOADED";
        case OZAYN_PERF_EVENT_CONFIG_CHANGED:       return "PERF_CONFIG_CHANGED";
        case OZAYN_PERF_EVENT_BENCH_ITERATION:      return "PERF_BENCH_ITERATION";
        case OZAYN_PERF_EVENT_COLLECT_FAILED:       return "PERF_COLLECT_FAILED";
        case OZAYN_DEFENSE_EVENT_VIOLATION:         return "DEFENSE_VIOLATION";
        case OZAYN_DEFENSE_EVENT_INPUT_REJECTED:    return "DEFENSE_INPUT_REJECTED";
        case OZAYN_DEFENSE_EVENT_RESOURCE_DENIED:   return "DEFENSE_RESOURCE_DENIED";
        case OZAYN_DEFENSE_EVENT_BACKPRESSURE:      return "DEFENSE_BACKPRESSURE";
        case OZAYN_DEFENSE_EVENT_RATE_LIMITED:      return "DEFENSE_RATE_LIMITED";
        case OZAYN_CB_EVENT_OPENED:                 return "CB_OPENED";
        case OZAYN_CB_EVENT_CLOSED:                 return "CB_CLOSED";
        case OZAYN_CB_EVENT_HALF_OPENED:            return "CB_HALF_OPENED";
        case OZAYN_CB_EVENT_CALL_REJECTED:          return "CB_CALL_REJECTED";
        case OZAYN_HT_EVENT_STATE_CHANGED:          return "HT_STATE_CHANGED";
        case OZAYN_HT_EVENT_HEARTBEAT_MISSED:       return "HT_HEARTBEAT_MISSED";
        case OZAYN_HT_EVENT_COMPONENT_FAILED:       return "HT_COMPONENT_FAILED";
        case OZAYN_HT_EVENT_QUARANTINED:            return "HT_QUARANTINED";
        case OZAYN_HT_EVENT_RECOVERED:              return "HT_RECOVERED";
        case OZAYN_CL_EVENT_CRASH_LOOP:             return "CL_CRASH_LOOP";
        case OZAYN_CL_EVENT_QUARANTINED:            return "CL_QUARANTINED";
        case OZAYN_CL_EVENT_RELEASED:               return "CL_RELEASED";
        case OZAYN_CV_EVENT_VALIDATED:              return "CV_VALIDATED";
        case OZAYN_CV_EVENT_VALIDATION_FAILED:      return "CV_VALIDATION_FAILED";
        case OZAYN_CV_EVENT_ROLLBACK:               return "CV_ROLLBACK";
        case OZAYN_REL_EVENT_MANIFEST_READ:         return "REL_MANIFEST_READ";
        case OZAYN_REL_EVENT_MANIFEST_WRITE:        return "REL_MANIFEST_WRITE";
        case OZAYN_REL_EVENT_DEPS_VERIFIED:         return "REL_DEPS_VERIFIED";
        case OZAYN_REL_EVENT_DEPS_MISSING:          return "REL_DEPS_MISSING";
        case OZAYN_REL_EVENT_INTEGRITY_OK:          return "REL_INTEGRITY_OK";
        case OZAYN_REL_EVENT_INTEGRITY_FAIL:        return "REL_INTEGRITY_FAIL";
        case OZAYN_REL_EVENT_BACKUP_CREATED:        return "REL_BACKUP_CREATED";
        case OZAYN_REL_EVENT_BACKUP_RESTORED:       return "REL_BACKUP_RESTORED";
        case OZAYN_REL_EVENT_INSTALL_STARTED:       return "REL_INSTALL_STARTED";
        case OZAYN_REL_EVENT_INSTALL_COMPLETE:      return "REL_INSTALL_COMPLETE";
        case OZAYN_REL_EVENT_ROLLBACK_STARTED:      return "REL_ROLLBACK_STARTED";
        case OZAYN_REL_EVENT_ROLLBACK_COMPLETE:     return "REL_ROLLBACK_COMPLETE";
        case OZAYN_REL_EVENT_SMOKE_PASSED:          return "REL_SMOKE_PASSED";
        case OZAYN_REL_EVENT_SMOKE_FAILED:          return "REL_SMOKE_FAILED";
        case OZAYN_REL_EVENT_GATE_PASSED:           return "REL_GATE_PASSED";
        case OZAYN_REL_EVENT_GATE_FAILED:           return "REL_GATE_FAILED";
        case OZAYN_REL_EVENT_READY:                 return "REL_READY";
        case OZAYN_REL_EVENT_NOT_READY:             return "REL_NOT_READY";
        case OZAYN_REL_EVENT_MIGRATED:              return "REL_MIGRATED";
        case OZAYN_REL_EVENT_LOGGED:                return "REL_LOGGED";
        /* Application-domain events */
        case OZAYN_APP_EVENT_FACE_DETECTED:         return "APP_FACE_DETECTED";
        case OZAYN_APP_EVENT_VOICE_DETECTED:        return "APP_VOICE_DETECTED";
        case OZAYN_APP_EVENT_GESTURE_DETECTED:      return "APP_GESTURE_DETECTED";
        case OZAYN_APP_EVENT_WINDOW_OPENED:         return "APP_WINDOW_OPENED";
        case OZAYN_APP_EVENT_WINDOW_CLOSED:         return "APP_WINDOW_CLOSED";
        case OZAYN_APP_EVENT_COMMAND_RECEIVED:      return "APP_COMMAND_RECEIVED";
        case OZAYN_APP_EVENT_COMMAND_COMPLETED:     return "APP_COMMAND_COMPLETED";
        case OZAYN_APP_EVENT_ARWE_CONNECTED:        return "APP_ARWE_CONNECTED";
        case OZAYN_APP_EVENT_ARWE_DISCONNECTED:     return "APP_ARWE_DISCONNECTED";
        case OZAYN_APP_EVENT_MODULE_ACTION:         return "APP_MODULE_ACTION";
    }
    return "UNKNOWN";
}

const char *ozayn_event_source_name(ozayn_event_source_t src) {
    switch (src) {
        case OZAYN_SRC_CORE:     return "CORE";
        case OZAYN_SRC_RUNTIME:  return "RUNTIME";
        case OZAYN_SRC_CONFIG:   return "CONFIG";
        case OZAYN_SRC_LOGGER:   return "LOGGER";
        case OZAYN_SRC_RECOVERY: return "RECOVERY";
        case OZAYN_SRC_USER:     return "USER";
        case OZAYN_SRC_MODULE:   return "MODULE";
        case OZAYN_SRC_PLUGIN:   return "PLUGIN";
        case OZAYN_SRC_IPC:      return "IPC";
        case OZAYN_SRC_REGISTRY: return "REGISTRY";
        case OZAYN_SRC_SECURITY:  return "SECURITY";
        case OZAYN_SRC_STATE:     return "STATE";
        case OZAYN_SRC_LIFECYCLE: return "LIFECYCLE";
        case OZAYN_SRC_DEP:       return "DEPENDENCY";
        case OZAYN_SRC_SVC_LC:    return "SVC_LIFECYCLE";
        case OZAYN_SRC_CONFIG_MGR: return "CONFIG_MGR";
        case OZAYN_SRC_API:        return "CORE_API";
        case OZAYN_SRC_RELOAD:     return "RELOAD";
        case OZAYN_SRC_PERF:       return "PERF";
        case OZAYN_SRC_DEFENSE:    return "DEFENSE";
        case OZAYN_SRC_RELEASE:    return "RELEASE";
    }
    return "UNKNOWN";
}

/* ---------- Init ---------- */

ozayn_result_t ozayn_events_init(ozayn_event_engine_t *engine, const ozayn_event_config_t *cfg) {
    if (!engine || !cfg) return OZAYN_ERR_NULL;

    memset(engine, 0, sizeof(ozayn_event_engine_t));

    engine->queue_capacity = cfg->queue_capacity;
    engine->queue = calloc((size_t)cfg->queue_capacity, sizeof(ozayn_event_t));
    if (!engine->queue) return OZAYN_ERR;

    engine->max_subscribers = cfg->max_subscribers;
    engine->subscriptions = calloc((size_t)cfg->max_subscribers, sizeof(ozayn_subscription_t));
    if (!engine->subscriptions) {
        free(engine->queue);
        return OZAYN_ERR;
    }

    engine->queue_head = 0;
    engine->queue_tail = 0;
    engine->queue_count = 0;
    engine->sub_count = 0;
    engine->dispatching = 0;
    engine->initialized = 1;

    LOG_INFO("EVENTS", "Event engine initialized (queue=%d, subscribers=%d)",
             cfg->queue_capacity, cfg->max_subscribers);

    return OZAYN_OK;
}

/* ---------- Shutdown ---------- */

void ozayn_events_shutdown(ozayn_event_engine_t *engine) {
    if (!engine || !engine->initialized) return;

    free(engine->queue);
    engine->queue = NULL;

    free(engine->subscriptions);
    engine->subscriptions = NULL;

    engine->initialized = 0;
    engine->queue_count = 0;
    engine->sub_count = 0;

    LOG_INFO("EVENTS", "Event engine shut down");
}

/* ---------- Publish ---------- */

ozayn_result_t ozayn_events_publish(ozayn_event_engine_t *engine,
                                    ozayn_event_type_t type,
                                    ozayn_event_source_t source,
                                    void *payload) {
    if (!engine || !engine->initialized) return OZAYN_ERR_STATE;
    if (type == OZAYN_EVENT_NONE) return OZAYN_ERR;

    /* Queue full → drop event, log warning */
    if (engine->queue_count >= engine->queue_capacity) {
        LOG_WARN("EVENTS", "Queue overflow — dropping %s from %s",
                 ozayn_event_type_name(type), ozayn_event_source_name(source));
        return OZAYN_ERR;
    }

    ozayn_event_t *ev = &engine->queue[engine->queue_tail];
    ev->type      = type;
    ev->source    = source;
    ev->timestamp = time(NULL);
    ev->payload   = payload;

    engine->queue_tail = (engine->queue_tail + 1) % engine->queue_capacity;
    engine->queue_count++;

    LOG_DEBUG("EVENTS", "Published %s from %s",
              ozayn_event_type_name(type), ozayn_event_source_name(source));

    return OZAYN_OK;
}

/* ---------- Subscribe ---------- */

int ozayn_events_subscribe(ozayn_event_engine_t *engine,
                           ozayn_event_type_t type,
                           ozayn_event_handler_t handler,
                           void *context) {
    if (!engine || !engine->initialized) return -1;
    if (!handler) return -1;

    if (engine->sub_count >= engine->max_subscribers) {
        LOG_WARN("EVENTS", "Subscriber limit reached");
        return -1;
    }

    int id = engine->sub_count;
    ozayn_subscription_t *sub = &engine->subscriptions[id];
    sub->active  = 1;
    sub->type    = type;
    sub->handler = handler;
    sub->context = context;

    engine->sub_count++;

    LOG_DEBUG("EVENTS", "Subscribed to %s (id=%d)", ozayn_event_type_name(type), id);
    return id;
}

/* ---------- Unsubscribe ---------- */

void ozayn_events_unsubscribe(ozayn_event_engine_t *engine, int sub_id) {
    if (!engine || !engine->initialized) return;
    if (sub_id < 0 || sub_id >= engine->max_subscribers) return;

    engine->subscriptions[sub_id].active = 0;
    LOG_DEBUG("EVENTS", "Unsubscribed id=%d", sub_id);
}

/* ---------- Process ---------- */

int ozayn_events_process(ozayn_event_engine_t *engine) {
    if (!engine || !engine->initialized) return 0;
    if (engine->dispatching) return 0; /* prevent reentrant dispatch */

    int processed = 0;
    engine->dispatching = 1;

    while (engine->queue_count > 0) {
        /* Pop front */
        ozayn_event_t ev = engine->queue[engine->queue_head];
        engine->queue_head = (engine->queue_head + 1) % engine->queue_capacity;
        engine->queue_count--;

        /* Dispatch to matching subscribers */
        for (int i = 0; i < engine->sub_count; i++) {
            ozayn_subscription_t *sub = &engine->subscriptions[i];
            if (!sub->active) continue;
            if (sub->type != OZAYN_EVENT_NONE && sub->type != ev.type) continue;

            if (sub->handler) {
                sub->handler(&ev, sub->context);
            }
        }

        processed++;
    }

    engine->dispatching = 0;
    return processed;
}

/* ---------- Query ---------- */

int ozayn_events_queue_count(const ozayn_event_engine_t *engine) {
    if (!engine) return 0;
    return engine->queue_count;
}
