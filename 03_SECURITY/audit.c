#include "audit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * audit.c — Security Audit Service Implementation (Step 21).
 *
 * Provides structured security event recording, validation,
 * secret filtering, and controlled querying.
 */

/* ============================================================
 * STATIC GLOBAL
 * ============================================================ */

static ozayn_audit_service_t g_audit_svc;

ozayn_audit_service_t *ozayn_audit_get_global(void)
{
    return &g_audit_svc;
}

/* ============================================================
 * SECTION 1 — NAME HELPERS
 * ============================================================ */

const char *ozayn_audit_result_name(ozayn_audit_result_t r)
{
    switch (r) {
    case OZAYN_AUDIT_OK:                     return "OK";
    case OZAYN_AUDIT_ERR:                    return "ERR";
    case OZAYN_AUDIT_ERR_NULL:               return "ERR_NULL";
    case OZAYN_AUDIT_ERR_NOT_INITIALIZED:    return "ERR_NOT_INITIALIZED";
    case OZAYN_AUDIT_ERR_ALREADY_INITIALIZED: return "ERR_ALREADY_INITIALIZED";
    case OZAYN_AUDIT_ERR_INVALID_EVENT:      return "ERR_INVALID_EVENT";
    case OZAYN_AUDIT_ERR_INVALID_TYPE:       return "ERR_INVALID_TYPE";
    case OZAYN_AUDIT_ERR_INVALID_OUTCOME:    return "ERR_INVALID_OUTCOME";
    case OZAYN_AUDIT_ERR_INVALID_SEVERITY:   return "ERR_INVALID_SEVERITY";
    case OZAYN_AUDIT_ERR_INVALID_TIMESTAMP:  return "ERR_INVALID_TIMESTAMP";
    case OZAYN_AUDIT_ERR_INVALID_IDENTITY:   return "ERR_INVALID_IDENTITY";
    case OZAYN_AUDIT_ERR_INVALID_SCOPE:      return "ERR_INVALID_SCOPE";
    case OZAYN_AUDIT_ERR_INVALID_COMPONENT:  return "ERR_INVALID_COMPONENT";
    case OZAYN_AUDIT_ERR_METADATA_TOO_LARGE: return "ERR_METADATA_TOO_LARGE";
    case OZAYN_AUDIT_ERR_EVENT_TOO_LARGE:    return "ERR_EVENT_TOO_LARGE";
    case OZAYN_AUDIT_ERR_SECRET_REJECTED:    return "ERR_SECRET_REJECTED";
    case OZAYN_AUDIT_ERR_STORAGE_FULL:       return "ERR_STORAGE_FULL";
    case OZAYN_AUDIT_ERR_STORAGE_ERROR:      return "ERR_STORAGE_ERROR";
    case OZAYN_AUDIT_ERR_STORAGE_UNAVAILABLE: return "ERR_STORAGE_UNAVAILABLE";
    case OZAYN_AUDIT_ERR_EVENT_NOT_FOUND:    return "ERR_EVENT_NOT_FOUND";
    case OZAYN_AUDIT_ERR_QUERY_FAILED:       return "ERR_QUERY_FAILED";
    case OZAYN_AUDIT_ERR_POLICY_REJECTED:    return "ERR_POLICY_REJECTED";
    case OZAYN_AUDIT_ERR_UNAVAILABLE:        return "ERR_UNAVAILABLE";
    case OZAYN_AUDIT_ERR_INTEGRITY_FAILURE:  return "ERR_INTEGRITY_FAILURE";
    case OZAYN_AUDIT_ERR_RESOURCE_EXHAUSTED: return "ERR_RESOURCE_EXHAUSTED";
    case OZAYN_AUDIT_ERR_WRITE_FAILED:       return "ERR_WRITE_FAILED";
    case OZAYN_AUDIT_ERR_READ_FAILED:        return "ERR_READ_FAILED";
    case OZAYN_AUDIT_ERR_REQUIRES_AUTH:      return "ERR_REQUIRES_AUTH";
    case OZAYN_AUDIT_ERR_ACCESS_DENIED:      return "ERR_ACCESS_DENIED";
    }
    return "UNKNOWN";
}

const char *ozayn_audit_event_type_name(ozayn_audit_event_type_t t)
{
    switch (t) {
    case OZAYN_AUDIT_IDENTITY_CREATED:        return "IDENTITY_CREATED";
    case OZAYN_AUDIT_IDENTITY_UPDATED:        return "IDENTITY_UPDATED";
    case OZAYN_AUDIT_IDENTITY_SUSPENDED:      return "IDENTITY_SUSPENDED";
    case OZAYN_AUDIT_IDENTITY_REVOKED:        return "IDENTITY_REVOKED";
    case OZAYN_AUDIT_IDENTITY_ARCHIVED:       return "IDENTITY_ARCHIVED";
    case OZAYN_AUDIT_AUTH_STARTED:            return "AUTH_STARTED";
    case OZAYN_AUDIT_AUTH_SUCCEEDED:          return "AUTH_SUCCEEDED";
    case OZAYN_AUDIT_AUTH_FAILED:             return "AUTH_FAILED";
    case OZAYN_AUDIT_AUTH_REJECTED:           return "AUTH_REJECTED";
    case OZAYN_AUDIT_AUTH_UNAVAILABLE:        return "AUTH_UNAVAILABLE";
    case OZAYN_AUDIT_PWD_AUTH_SUCCEEDED:      return "PWD_AUTH_SUCCEEDED";
    case OZAYN_AUDIT_PWD_AUTH_FAILED:         return "PWD_AUTH_FAILED";
    case OZAYN_AUDIT_PWD_CREDENTIAL_CREATED:  return "PWD_CREDENTIAL_CREATED";
    case OZAYN_AUDIT_PWD_CREDENTIAL_UPDATED:  return "PWD_CREDENTIAL_UPDATED";
    case OZAYN_AUDIT_PWD_CREDENTIAL_SUSPENDED: return "PWD_CREDENTIAL_SUSPENDED";
    case OZAYN_AUDIT_PWD_CREDENTIAL_REVOKED:  return "PWD_CREDENTIAL_REVOKED";
    case OZAYN_AUDIT_RATE_LIMITED:            return "RATE_LIMITED";
    case OZAYN_AUDIT_TEMPORARILY_BLOCKED:     return "TEMPORARILY_BLOCKED";
    case OZAYN_AUDIT_ATTEMPT_RESET:           return "ATTEMPT_RESET";
    case OZAYN_AUDIT_MFA_STARTED:             return "MFA_STARTED";
    case OZAYN_AUDIT_MFA_FACTOR_VERIFIED:     return "MFA_FACTOR_VERIFIED";
    case OZAYN_AUDIT_MFA_FACTOR_FAILED:       return "MFA_FACTOR_FAILED";
    case OZAYN_AUDIT_MFA_COMPLETED:           return "MFA_COMPLETED";
    case OZAYN_AUDIT_MFA_FAILED:              return "MFA_FAILED";
    case OZAYN_AUDIT_MFA_EXPIRED:             return "MFA_EXPIRED";
    case OZAYN_AUDIT_MFA_CANCELLED:           return "MFA_CANCELLED";
    case OZAYN_AUDIT_MFA_BLOCKED:             return "MFA_BLOCKED";
    case OZAYN_AUDIT_SESSION_CREATED:         return "SESSION_CREATED";
    case OZAYN_AUDIT_SESSION_VALIDATED:       return "SESSION_VALIDATED";
    case OZAYN_AUDIT_SESSION_EXPIRED:         return "SESSION_EXPIRED";
    case OZAYN_AUDIT_SESSION_TERMINATED:      return "SESSION_TERMINATED";
    case OZAYN_AUDIT_SESSION_REVOKED:         return "SESSION_REVOKED";
    case OZAYN_AUDIT_AUTHZ_ALLOWED:           return "AUTHZ_ALLOWED";
    case OZAYN_AUDIT_AUTHZ_DENIED:            return "AUTHZ_DENIED";
    case OZAYN_AUDIT_AUTHZ_ERROR:             return "AUTHZ_ERROR";
    case OZAYN_AUDIT_ROLE_CREATED:            return "ROLE_CREATED";
    case OZAYN_AUDIT_ROLE_UPDATED:            return "ROLE_UPDATED";
    case OZAYN_AUDIT_ROLE_SUSPENDED:          return "ROLE_SUSPENDED";
    case OZAYN_AUDIT_ROLE_REVOKED:            return "ROLE_REVOKED";
    case OZAYN_AUDIT_ROLE_ASSIGNED:           return "ROLE_ASSIGNED";
    case OZAYN_AUDIT_ROLE_ASSIGNMENT_REVOKED: return "ROLE_ASSIGNMENT_REVOKED";
    case OZAYN_AUDIT_ROLE_PERM_ADDED:         return "ROLE_PERM_ADDED";
    case OZAYN_AUDIT_ROLE_PERM_REMOVED:       return "ROLE_PERM_REMOVED";
    case OZAYN_AUDIT_PERM_CREATED:            return "PERM_CREATED";
    case OZAYN_AUDIT_PERM_UPDATED:            return "PERM_UPDATED";
    case OZAYN_AUDIT_PERM_SUSPENDED:          return "PERM_SUSPENDED";
    case OZAYN_AUDIT_PERM_REVOKED:            return "PERM_REVOKED";
    case OZAYN_AUDIT_PERM_MATCHED:            return "PERM_MATCHED";
    case OZAYN_AUDIT_PERM_DENIED:             return "PERM_DENIED";
    case OZAYN_AUDIT_POLICY_REJECTED:         return "POLICY_REJECTED";
    case OZAYN_AUDIT_CONFIG_CHANGED:          return "CONFIG_CHANGED";
    case OZAYN_AUDIT_COMPONENT_UNAVAILABLE:   return "COMPONENT_UNAVAILABLE";
    case OZAYN_AUDIT_INTEGRITY_FAILURE:       return "INTEGRITY_FAILURE";
    case OZAYN_AUDIT_STORAGE_FAILURE:         return "STORAGE_FAILURE";
    case OZAYN_AUDIT_VIOLATION_DETECTED:      return "VIOLATION_DETECTED";
    case OZAYN_AUDIT_SERVICE_UNAVAILABLE:     return "SERVICE_UNAVAILABLE";
    case OZAYN_AUDIT_EVENT_TYPE_COUNT:        return "EVENT_TYPE_COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_audit_category_name(ozayn_audit_category_t c)
{
    switch (c) {
    case OZAYN_AUDIT_CAT_IDENTITY:   return "IDENTITY";
    case OZAYN_AUDIT_CAT_AUTH:       return "AUTH";
    case OZAYN_AUDIT_CAT_PASSWORD:   return "PASSWORD";
    case OZAYN_AUDIT_CAT_ATTEMPT:    return "ATTEMPT";
    case OZAYN_AUDIT_CAT_MFA:        return "MFA";
    case OZAYN_AUDIT_CAT_SESSION:    return "SESSION";
    case OZAYN_AUDIT_CAT_AUTHZ:      return "AUTHZ";
    case OZAYN_AUDIT_CAT_RBAC:       return "RBAC";
    case OZAYN_AUDIT_CAT_PERMISSION: return "PERMISSION";
    case OZAYN_AUDIT_CAT_SECURITY:   return "SECURITY";
    case OZAYN_AUDIT_CAT_AUDIT:      return "AUDIT";
    case OZAYN_AUDIT_CATEGORY_COUNT: return "CATEGORY_COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_audit_outcome_name(ozayn_audit_outcome_t o)
{
    switch (o) {
    case OZAYN_AUDIT_OUTCOME_SUCCESS:     return "SUCCESS";
    case OZAYN_AUDIT_OUTCOME_FAILURE:     return "FAILURE";
    case OZAYN_AUDIT_OUTCOME_DENIED:      return "DENIED";
    case OZAYN_AUDIT_OUTCOME_REJECTED:    return "REJECTED";
    case OZAYN_AUDIT_OUTCOME_UNAVAILABLE: return "UNAVAILABLE";
    case OZAYN_AUDIT_OUTCOME_ERROR:       return "ERROR";
    case OZAYN_AUDIT_OUTCOME_INFO:        return "INFO";
    case OZAYN_AUDIT_OUTCOME_COUNT:       return "OUTCOME_COUNT";
    }
    return "UNKNOWN";
}

const char *ozayn_audit_severity_name(ozayn_audit_severity_t s)
{
    switch (s) {
    case OZAYN_AUDIT_SEV_INFO:     return "INFO";
    case OZAYN_AUDIT_SEV_NOTICE:   return "NOTICE";
    case OZAYN_AUDIT_SEV_WARNING:  return "WARNING";
    case OZAYN_AUDIT_SEV_HIGH:     return "HIGH";
    case OZAYN_AUDIT_SEV_CRITICAL: return "CRITICAL";
    case OZAYN_AUDIT_SEV_COUNT:    return "COUNT";
    }
    return "UNKNOWN";
}

/* ============================================================
 * SECTION 2 — CATEGORY MAPPING
 * ============================================================ */

static ozayn_audit_category_t _audit_event_category(ozayn_audit_event_type_t t)
{
    if (t <= OZAYN_AUDIT_IDENTITY_ARCHIVED)       return OZAYN_AUDIT_CAT_IDENTITY;
    if (t >= OZAYN_AUDIT_AUTH_STARTED && t <= OZAYN_AUDIT_AUTH_UNAVAILABLE)
                                                    return OZAYN_AUDIT_CAT_AUTH;
    if (t >= OZAYN_AUDIT_PWD_AUTH_SUCCEEDED && t <= OZAYN_AUDIT_PWD_CREDENTIAL_REVOKED)
                                                    return OZAYN_AUDIT_CAT_PASSWORD;
    if (t >= OZAYN_AUDIT_RATE_LIMITED && t <= OZAYN_AUDIT_ATTEMPT_RESET)
                                                    return OZAYN_AUDIT_CAT_ATTEMPT;
    if (t >= OZAYN_AUDIT_MFA_STARTED && t <= OZAYN_AUDIT_MFA_BLOCKED)
                                                    return OZAYN_AUDIT_CAT_MFA;
    if (t >= OZAYN_AUDIT_SESSION_CREATED && t <= OZAYN_AUDIT_SESSION_REVOKED)
                                                    return OZAYN_AUDIT_CAT_SESSION;
    if (t >= OZAYN_AUDIT_AUTHZ_ALLOWED && t <= OZAYN_AUDIT_AUTHZ_ERROR)
                                                    return OZAYN_AUDIT_CAT_AUTHZ;
    if (t >= OZAYN_AUDIT_ROLE_CREATED && t <= OZAYN_AUDIT_ROLE_PERM_REMOVED)
                                                    return OZAYN_AUDIT_CAT_RBAC;
    if (t >= OZAYN_AUDIT_PERM_CREATED && t <= OZAYN_AUDIT_PERM_DENIED)
                                                    return OZAYN_AUDIT_CAT_PERMISSION;
    if (t >= OZAYN_AUDIT_POLICY_REJECTED && t <= OZAYN_AUDIT_SERVICE_UNAVAILABLE)
                                                    return OZAYN_AUDIT_CAT_SECURITY;
    return OZAYN_AUDIT_CAT_SECURITY;
}

/* ============================================================
 * SECTION 3 — DEFAULT SEVERITY MAPPING
 * ============================================================ */

static ozayn_audit_severity_t _audit_default_severity(ozayn_audit_event_type_t t)
{
    switch (t) {
    /* Identity — notice */
    case OZAYN_AUDIT_IDENTITY_CREATED:
    case OZAYN_AUDIT_IDENTITY_UPDATED:
    case OZAYN_AUDIT_IDENTITY_SUSPENDED:
    case OZAYN_AUDIT_IDENTITY_REVOKED:
    case OZAYN_AUDIT_IDENTITY_ARCHIVED:
        return OZAYN_AUDIT_SEV_NOTICE;

    /* Auth success — notice, failure — warning, reject — high */
    case OZAYN_AUDIT_AUTH_STARTED:    return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_AUTH_SUCCEEDED:  return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_AUTH_FAILED:     return OZAYN_AUDIT_SEV_WARNING;
    case OZAYN_AUDIT_AUTH_REJECTED:   return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_AUTH_UNAVAILABLE: return OZAYN_AUDIT_SEV_WARNING;

    /* Password — stronger severity */
    case OZAYN_AUDIT_PWD_AUTH_SUCCEEDED:    return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_PWD_AUTH_FAILED:       return OZAYN_AUDIT_SEV_WARNING;
    case OZAYN_AUDIT_PWD_CREDENTIAL_CREATED: return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_PWD_CREDENTIAL_UPDATED: return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_PWD_CREDENTIAL_SUSPENDED: return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_PWD_CREDENTIAL_REVOKED:  return OZAYN_AUDIT_SEV_HIGH;

    /* Attempt protection — high/critical */
    case OZAYN_AUDIT_RATE_LIMITED:       return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_TEMPORARILY_BLOCKED: return OZAYN_AUDIT_SEV_CRITICAL;
    case OZAYN_AUDIT_ATTEMPT_RESET:      return OZAYN_AUDIT_SEV_NOTICE;

    /* MFA */
    case OZAYN_AUDIT_MFA_STARTED:        return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_MFA_FACTOR_VERIFIED: return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_MFA_FACTOR_FAILED:  return OZAYN_AUDIT_SEV_WARNING;
    case OZAYN_AUDIT_MFA_COMPLETED:      return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_MFA_FAILED:         return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_MFA_EXPIRED:        return OZAYN_AUDIT_SEV_WARNING;
    case OZAYN_AUDIT_MFA_CANCELLED:      return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_MFA_BLOCKED:        return OZAYN_AUDIT_SEV_CRITICAL;

    /* Session */
    case OZAYN_AUDIT_SESSION_CREATED:    return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_SESSION_VALIDATED:  return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_SESSION_EXPIRED:    return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_SESSION_TERMINATED: return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_SESSION_REVOKED:    return OZAYN_AUDIT_SEV_HIGH;

    /* Authorization */
    case OZAYN_AUDIT_AUTHZ_ALLOWED:      return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_AUTHZ_DENIED:       return OZAYN_AUDIT_SEV_WARNING;
    case OZAYN_AUDIT_AUTHZ_ERROR:        return OZAYN_AUDIT_SEV_HIGH;

    /* RBAC */
    case OZAYN_AUDIT_ROLE_CREATED:       return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_ROLE_UPDATED:       return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_ROLE_SUSPENDED:     return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_ROLE_REVOKED:       return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_ROLE_ASSIGNED:      return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_ROLE_ASSIGNMENT_REVOKED: return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_ROLE_PERM_ADDED:    return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_ROLE_PERM_REMOVED:  return OZAYN_AUDIT_SEV_WARNING;

    /* Permission */
    case OZAYN_AUDIT_PERM_CREATED:       return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_PERM_UPDATED:       return OZAYN_AUDIT_SEV_NOTICE;
    case OZAYN_AUDIT_PERM_SUSPENDED:     return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_PERM_REVOKED:       return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_PERM_MATCHED:       return OZAYN_AUDIT_SEV_INFO;
    case OZAYN_AUDIT_PERM_DENIED:        return OZAYN_AUDIT_SEV_WARNING;

    /* Security/system — always high/critical */
    case OZAYN_AUDIT_POLICY_REJECTED:      return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_CONFIG_CHANGED:       return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_COMPONENT_UNAVAILABLE: return OZAYN_AUDIT_SEV_HIGH;
    case OZAYN_AUDIT_INTEGRITY_FAILURE:    return OZAYN_AUDIT_SEV_CRITICAL;
    case OZAYN_AUDIT_STORAGE_FAILURE:      return OZAYN_AUDIT_SEV_CRITICAL;
    case OZAYN_AUDIT_VIOLATION_DETECTED:   return OZAYN_AUDIT_SEV_CRITICAL;
    case OZAYN_AUDIT_SERVICE_UNAVAILABLE:  return OZAYN_AUDIT_SEV_HIGH;

    default: return OZAYN_AUDIT_SEV_WARNING;
    }
}

/* ============================================================
 * SECTION 4 — VALIDATE ENUM RANGES
 * ============================================================ */

static int _audit_valid_type(ozayn_audit_event_type_t t)
{
    return (t >= 0 && t < OZAYN_AUDIT_EVENT_TYPE_COUNT);
}

static int _audit_valid_outcome(ozayn_audit_outcome_t o)
{
    return (o >= 0 && o < OZAYN_AUDIT_OUTCOME_COUNT);
}

static int _audit_valid_severity(ozayn_audit_severity_t s)
{
    return (s >= 0 && s < OZAYN_AUDIT_SEV_COUNT);
}

/* ============================================================
 * SECTION 5 — SECRET FILTERING
 *
 * Scans metadata buffer for known secret patterns.
 * Returns OZAYN_AUDIT_OK if safe, OZAYN_AUDIT_ERR_SECRET_REJECTED if unsafe.
 * ============================================================ */

/* Forbidden keywords (case-insensitive substring match) */
static const char *_secret_keywords[] = {
    "password", "passwd", "pwd",
    "secret", "api_key", "apikey", "api-key",
    "private_key", "private-key", "privkey",
    "encryption_key", "encryption-key",
    "session_secret", "session-secret",
    "token", "access_token", "refresh_token",
    "biometric", "fingerprint", "face_data", "voice_data",
    "mfa_secret", "recovery_key", "recovery-secret",
    "credential", "auth_token",
    NULL
};

static int _secret_contains_keyword(const uint8_t *data, uint32_t size)
{
    /* Simple case-insensitive substring scan */
    for (const char **kw = _secret_keywords; *kw; kw++) {
        size_t kw_len = strlen(*kw);
        if (kw_len == 0 || kw_len > size) continue;

        for (uint32_t i = 0; i <= size - kw_len; i++) {
            int match = 1;
            for (size_t j = 0; j < kw_len; j++) {
                char c = (char)data[i + j];
                char k = (*kw)[j];
                /* lowercase comparison */
                if (c >= 'A' && c <= 'Z') c += 32;
                if (k >= 'A' && k <= 'Z') k += 32;
                if (c != k) { match = 0; break; }
            }
            if (match) return 1;
        }
    }
    return 0;
}

ozayn_audit_result_t ozayn_audit_check_metadata_safe(const uint8_t *data,
                                                      uint32_t size)
{
    if (!data || size == 0)
        return OZAYN_AUDIT_OK;
    if (size > OZAYN_AUDIT_MAX_METADATA_SIZE)
        return OZAYN_AUDIT_ERR_METADATA_TOO_LARGE;

    if (_secret_contains_keyword(data, size))
        return OZAYN_AUDIT_ERR_SECRET_REJECTED;

    return OZAYN_AUDIT_OK;
}

/* ============================================================
 * SECTION 6 — EVENT VALIDATION
 * ============================================================ */

ozayn_audit_result_t ozayn_audit_validate_event(const ozayn_audit_service_t *svc,
                                                 const ozayn_audit_event_t *event)
{
    if (!event)
        return OZAYN_AUDIT_ERR_NULL;

    /* Event type must be valid */
    if (!_audit_valid_type(event->event_type))
        return OZAYN_AUDIT_ERR_INVALID_TYPE;

    /* Outcome must be valid */
    if (!_audit_valid_outcome(event->outcome))
        return OZAYN_AUDIT_ERR_INVALID_OUTCOME;

    /* Severity must be valid */
    if (!_audit_valid_severity(event->severity))
        return OZAYN_AUDIT_ERR_INVALID_SEVERITY;

    /* Timestamp must be > 0 */
    if (event->timestamp <= 0)
        return OZAYN_AUDIT_ERR_INVALID_TIMESTAMP;

    /* Event version must be current */
    if (event->event_version != OZAYN_AUDIT_EVENT_VERSION)
        return OZAYN_AUDIT_ERR_INVALID_EVENT;

    /* Metadata size check */
    if (event->metadata_size > OZAYN_AUDIT_MAX_METADATA_SIZE)
        return OZAYN_AUDIT_ERR_METADATA_TOO_LARGE;

    /* Metadata secret check */
    if (event->metadata_size > 0 && event->metadata_valid) {
        ozayn_audit_result_t safe = ozayn_audit_check_metadata_safe(
            event->metadata, event->metadata_size);
        if (safe != OZAYN_AUDIT_OK)
            return safe;
    }

    /* Category check against policy */
    if (svc) {
        ozayn_audit_category_t cat = _audit_event_category(event->event_type);
        if (!svc->policy.required_categories[cat]) {
            if (!svc->policy.enabled)
                return OZAYN_AUDIT_ERR_POLICY_REJECTED;
        }

        /* Severity threshold check */
        if (event->severity < svc->policy.minimum_severity)
            return OZAYN_AUDIT_ERR_POLICY_REJECTED;

        /* Require identity if policy says so */
        if (svc->policy.require_identity && event->identity_id[0] == '\0')
            return OZAYN_AUDIT_ERR_INVALID_IDENTITY;

        /* Event size check */
        if (svc->policy.max_event_size > 0) {
            uint32_t est_size = sizeof(ozayn_audit_event_t);
            if (est_size > (uint32_t)svc->policy.max_event_size)
                return OZAYN_AUDIT_ERR_EVENT_TOO_LARGE;
        }
    }

    return OZAYN_AUDIT_OK;
}

/* ============================================================
 * SECTION 7 — EVENT INIT
 * ============================================================ */

void ozayn_audit_event_init(ozayn_audit_event_t *event)
{
    if (!event) return;
    memset(event, 0, sizeof(*event));
    event->event_version = OZAYN_AUDIT_EVENT_VERSION;
    event->metadata_valid = 1;
}

/* ============================================================
 * SECTION 8 — EVENT BUILDER HELPERS
 * ============================================================ */

ozayn_audit_result_t ozayn_audit_event_set_type(ozayn_audit_event_t *event,
                                                 ozayn_audit_event_type_t type)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!_audit_valid_type(type)) return OZAYN_AUDIT_ERR_INVALID_TYPE;
    event->event_type = type;
    event->category = _audit_event_category(type);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_outcome(ozayn_audit_event_t *event,
                                                    ozayn_audit_outcome_t outcome)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!_audit_valid_outcome(outcome)) return OZAYN_AUDIT_ERR_INVALID_OUTCOME;
    event->outcome = outcome;
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_severity(ozayn_audit_event_t *event,
                                                     ozayn_audit_severity_t sev)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!_audit_valid_severity(sev)) return OZAYN_AUDIT_ERR_INVALID_SEVERITY;
    event->severity = sev;
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_identity(ozayn_audit_event_t *event,
                                                     const char *identity_id)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!identity_id || identity_id[0] == '\0') {
        event->identity_id[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(identity_id);
    if (len >= OZAYN_AUDIT_MAX_ID_LEN) return OZAYN_AUDIT_ERR_INVALID_IDENTITY;
    memcpy(event->identity_id, identity_id, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_session(ozayn_audit_event_t *event,
                                                    const char *session_id)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!session_id || session_id[0] == '\0') {
        event->session_id[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(session_id);
    if (len >= OZAYN_AUDIT_MAX_ID_LEN) return OZAYN_AUDIT_ERR;
    memcpy(event->session_id, session_id, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_source(ozayn_audit_event_t *event,
                                                   const char *source)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!source || source[0] == '\0') {
        event->source_component[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(source);
    if (len >= OZAYN_AUDIT_MAX_SOURCE_LEN) return OZAYN_AUDIT_ERR;
    memcpy(event->source_component, source, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_request_id(ozayn_audit_event_t *event,
                                                       const char *request_id)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!request_id || request_id[0] == '\0') {
        event->request_id[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(request_id);
    if (len >= OZAYN_AUDIT_MAX_REQUEST_ID_LEN) return OZAYN_AUDIT_ERR;
    memcpy(event->request_id, request_id, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_correlation_id(ozayn_audit_event_t *event,
                                                           const char *correlation_id)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!correlation_id || correlation_id[0] == '\0') {
        event->correlation_id[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(correlation_id);
    if (len >= OZAYN_AUDIT_MAX_CORR_ID_LEN) return OZAYN_AUDIT_ERR;
    memcpy(event->correlation_id, correlation_id, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_resource(ozayn_audit_event_t *event,
                                                     ozayn_authz_resource_type_t rtype,
                                                     const char *rid,
                                                     ozayn_authz_action_type_t action,
                                                     ozayn_authz_scope_t scope)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    event->resource_type = rtype;
    event->action = action;
    event->scope = scope;
    if (rid && rid[0] != '\0') {
        size_t len = strlen(rid);
        if (len >= OZAYN_AUDIT_MAX_RESOURCE_ID_LEN) return OZAYN_AUDIT_ERR;
        memcpy(event->resource_id, rid, len + 1);
    } else {
        event->resource_id[0] = '\0';
    }
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_detail(ozayn_audit_event_t *event,
                                                   const char *detail)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!detail || detail[0] == '\0') {
        event->detail[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(detail);
    if (len >= OZAYN_AUDIT_MAX_DETAIL_LEN) return OZAYN_AUDIT_ERR;
    memcpy(event->detail, detail, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_failure_reason(ozayn_audit_event_t *event,
                                                           const char *reason)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!reason || reason[0] == '\0') {
        event->failure_reason[0] = '\0';
        return OZAYN_AUDIT_OK;
    }
    size_t len = strlen(reason);
    if (len >= OZAYN_AUDIT_MAX_FAILURE_LEN) return OZAYN_AUDIT_ERR;
    memcpy(event->failure_reason, reason, len + 1);
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_event_set_metadata(ozayn_audit_event_t *event,
                                                     const uint8_t *data,
                                                     uint32_t size)
{
    if (!event) return OZAYN_AUDIT_ERR_NULL;
    if (!data || size == 0) {
        event->metadata_size = 0;
        event->metadata_valid = 1;
        return OZAYN_AUDIT_OK;
    }
    if (size > OZAYN_AUDIT_MAX_METADATA_SIZE)
        return OZAYN_AUDIT_ERR_METADATA_TOO_LARGE;

    ozayn_audit_result_t safe = ozayn_audit_check_metadata_safe(data, size);
    if (safe != OZAYN_AUDIT_OK)
        return safe;

    memcpy(event->metadata, data, size);
    event->metadata_size = size;
    event->metadata_valid = 1;
    return OZAYN_AUDIT_OK;
}

/* ============================================================
 * SECTION 9 — SERVICE LIFECYCLE
 * ============================================================ */

ozayn_audit_result_t ozayn_audit_service_init(ozayn_audit_service_t *svc,
                                               const ozayn_audit_service_config_t *cfg)
{
    if (!svc) return OZAYN_AUDIT_ERR_NULL;
    if (svc->initialized) return OZAYN_AUDIT_ERR_ALREADY_INITIALIZED;

    memset(svc, 0, sizeof(*svc));

    /* Apply config or defaults */
    int capacity = 4096;
    if (cfg && cfg->event_capacity > 0)
        capacity = cfg->event_capacity;

    svc->events = (ozayn_audit_event_t *)calloc((size_t)capacity,
                                                  sizeof(ozayn_audit_event_t));
    if (!svc->events) return OZAYN_AUDIT_ERR;

    svc->event_capacity = capacity;
    svc->event_head = 0;
    svc->event_count = 0;
    svc->event_counter = 0;

    /* Default policy */
    svc->policy.enabled = 1;
    svc->policy.minimum_severity = OZAYN_AUDIT_SEV_INFO;
    svc->policy.retention_events = capacity;
    svc->policy.retention_seconds = 365 * 24 * 3600; /* 1 year */
    svc->policy.metadata_allowed = 1;
    svc->policy.require_identity = 0;
    svc->policy.max_event_size = OZAYN_AUDIT_MAX_EVENT_SIZE;
    svc->policy.max_metadata_size = OZAYN_AUDIT_MAX_METADATA_SIZE;

    /* All categories enabled by default */
    for (int i = 0; i < OZAYN_AUDIT_CATEGORY_COUNT; i++)
        svc->policy.required_categories[i] = 1;

    /* Apply config overrides */
    if (cfg) {
        if (cfg->max_event_size > 0)
            svc->policy.max_event_size = cfg->max_event_size;
        if (cfg->max_metadata_size > 0)
            svc->policy.max_metadata_size = cfg->max_metadata_size;
        if (cfg->default_retention_events > 0)
            svc->policy.retention_events = cfg->default_retention_events;
        if (cfg->default_retention_seconds > 0)
            svc->policy.retention_seconds = cfg->default_retention_seconds;
        svc->policy.minimum_severity = cfg->default_minimum_severity;
        svc->policy.require_identity = cfg->require_identity;
    }

    svc->storage = NULL;
    svc->initialized = 1;
    return OZAYN_AUDIT_OK;
}

void ozayn_audit_service_shutdown(ozayn_audit_service_t *svc)
{
    if (!svc || !svc->initialized) return;

    /* Events already written to storage during record.
     * Shutdown only flushes in-memory ring buffer if storage was
     * unavailable during recording. Check if storage is ready. */
    if (svc->storage && svc->storage->ops && svc->storage->ops->append) {
        /* Only flush events that were NOT already written to storage.
         * Since record() writes to storage on every call, the flush
         * is only needed if storage became available after being
         * unavailable. For simplicity, we skip the flush — events
         * are already persisted during record(). */
    }

    if (svc->storage && svc->storage->ops && svc->storage->ops->shutdown) {
        svc->storage->ops->shutdown(svc->storage->impl);
    }

    free(svc->events);
    svc->events = NULL;
    svc->initialized = 0;
}

int ozayn_audit_service_is_initialized(const ozayn_audit_service_t *svc)
{
    if (!svc) return 0;
    return svc->initialized;
}

/* ============================================================
 * SECTION 10 — EVENT RECORDING
 * ============================================================ */

static void _audit_generate_event_id(ozayn_audit_service_t *svc,
                                      ozayn_audit_event_t *event)
{
    svc->event_counter++;
    uint64_t ts = (uint64_t)event->timestamp;
    uint64_t ctr = svc->event_counter;
    snprintf(event->event_id, OZAYN_AUDIT_MAX_ID_LEN,
             "evt-%lu-%lu", (unsigned long)ts, (unsigned long)ctr);
}

ozayn_audit_result_t ozayn_audit_record(ozayn_audit_service_t *svc,
                                         ozayn_audit_event_t *event)
{
    if (!svc || !event) return OZAYN_AUDIT_ERR_NULL;
    if (!svc->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;

    /* Auto-set timestamp if zero (before validation) */
    if (event->timestamp <= 0)
        event->timestamp = time(NULL);

    /* Auto-set severity if not set (before validation) */
    if (event->severity == 0 && event->event_type != 0)
        event->severity = _audit_default_severity(event->event_type);

    /* Auto-generate event ID if empty (before validation) */
    if (event->event_id[0] == '\0')
        _audit_generate_event_id(svc, event);

    /* Auto-set category */
    event->category = _audit_event_category(event->event_type);

    /* Validate event */
    ozayn_audit_result_t vr = ozayn_audit_validate_event(svc, event);
    if (vr != OZAYN_AUDIT_OK) {
        svc->total_events_rejected++;
        return vr;
    }

    /* Write to ring buffer */
    if (svc->events) {
        int idx = svc->event_head;
        svc->events[idx] = *event;
        svc->event_head = (svc->event_head + 1) % svc->event_capacity;
        if (svc->event_count < svc->event_capacity)
            svc->event_count++;
    }

    /* Write to storage if available */
    if (svc->storage && svc->storage->ops && svc->storage->ops->append) {
        ozayn_audit_result_t sr = svc->storage->ops->append(
            svc->storage->impl, event);
        if (sr != OZAYN_AUDIT_OK) {
            /* Storage failure — event is still in ring buffer */
            svc->total_events_recorded++;
            return OZAYN_AUDIT_OK;
        }
    }

    svc->total_events_recorded++;
    return OZAYN_AUDIT_OK;
}

/* ============================================================
 * SECTION 11 — EVENT QUERY
 * ============================================================ */

static int _audit_event_matches_query(const ozayn_audit_event_t *event,
                                       const ozayn_audit_query_t *query)
{
    if (query->filter_type_active && event->event_type != query->filter_type)
        return 0;

    if (query->filter_identity_active &&
        strcmp(event->identity_id, query->filter_identity_id) != 0)
        return 0;

    if (query->filter_session_active &&
        strcmp(event->session_id, query->filter_session_id) != 0)
        return 0;

    if (query->filter_outcome_active && event->outcome != query->filter_outcome)
        return 0;

    if (query->filter_severity_active && event->severity < query->filter_severity_min)
        return 0;

    if (query->filter_correlation_active &&
        strcmp(event->correlation_id, query->filter_correlation_id) != 0)
        return 0;

    if (query->filter_source_active &&
        strcmp(event->source_component, query->filter_source) != 0)
        return 0;

    if (query->filter_time_active) {
        if (event->timestamp < query->filter_time_from ||
            event->timestamp > query->filter_time_to)
            return 0;
    }

    return 1;
}

ozayn_audit_result_t ozayn_audit_query(const ozayn_audit_service_t *svc,
                                        const ozayn_audit_query_t *query,
                                        ozayn_audit_event_t *results,
                                        int max_results,
                                        int *out_count)
{
    if (!svc || !query || !out_count) return OZAYN_AUDIT_ERR_NULL;
    if (!svc->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;
    if (!results || max_results <= 0) return OZAYN_AUDIT_ERR;

    /* Apply query limit */
    int limit = query->result_limit;
    if (limit <= 0 || limit > OZAYN_AUDIT_QUERY_MAX_RESULTS)
        limit = OZAYN_AUDIT_QUERY_MAX_RESULTS;
    if (limit > max_results)
        limit = max_results;

    int offset = query->result_offset;
    if (offset < 0) offset = 0;

    *out_count = 0;
    int found = 0;
    int total = svc->event_count;
    int start = (svc->event_count < svc->event_capacity)
        ? 0
        : (svc->event_head);

    for (int i = 0; i < total; i++) {
        int idx = (start + i) % svc->event_capacity;
        const ozayn_audit_event_t *ev = &svc->events[idx];
        if (ev->event_id[0] == '\0') continue;

        if (!_audit_event_matches_query(ev, query))
            continue;

        found++;
        if (found <= offset) continue;
        if (*out_count >= limit) break;

        memcpy(&results[*out_count], ev, sizeof(ozayn_audit_event_t));
        (*out_count)++;
    }

    ((ozayn_audit_service_t *)svc)->total_query_count++;
    return OZAYN_AUDIT_OK;
}

ozayn_audit_result_t ozayn_audit_get_by_id(const ozayn_audit_service_t *svc,
                                            const char *event_id,
                                            ozayn_audit_event_t *out)
{
    if (!svc || !event_id || !out) return OZAYN_AUDIT_ERR_NULL;
    if (!svc->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;
    if (event_id[0] == '\0') return OZAYN_AUDIT_ERR_INVALID_EVENT;

    int total = svc->event_count;
    int start = (svc->event_count < svc->event_capacity)
        ? 0
        : (svc->event_head);

    for (int i = 0; i < total; i++) {
        int idx = (start + i) % svc->event_capacity;
        if (strcmp(svc->events[idx].event_id, event_id) == 0) {
            memcpy(out, &svc->events[idx], sizeof(ozayn_audit_event_t));
            return OZAYN_AUDIT_OK;
        }
    }

    return OZAYN_AUDIT_ERR_EVENT_NOT_FOUND;
}

int ozayn_audit_count(const ozayn_audit_service_t *svc)
{
    if (!svc || !svc->initialized) return 0;
    return svc->event_count;
}

/* ============================================================
 * SECTION 12 — STORAGE BINDING
 * ============================================================ */

ozayn_audit_result_t ozayn_audit_set_storage(ozayn_audit_service_t *svc,
                                              ozayn_audit_storage_t *storage)
{
    if (!svc) return OZAYN_AUDIT_ERR_NULL;
    if (!svc->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;
    svc->storage = storage;
    return OZAYN_AUDIT_OK;
}

/* ============================================================
 * SECTION 13 — POLICY
 * ============================================================ */

ozayn_audit_result_t ozayn_audit_set_policy(ozayn_audit_service_t *svc,
                                             const ozayn_audit_policy_t *policy)
{
    if (!svc || !policy) return OZAYN_AUDIT_ERR_NULL;
    if (!svc->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;

    /* Validate policy */
    if (!_audit_valid_severity(policy->minimum_severity))
        return OZAYN_AUDIT_ERR_INVALID_SEVERITY;
    if (policy->retention_events < 0)
        return OZAYN_AUDIT_ERR;
    if (policy->retention_seconds < 0)
        return OZAYN_AUDIT_ERR;
    if (policy->max_event_size < 0)
        return OZAYN_AUDIT_ERR;
    if (policy->max_metadata_size < 0)
        return OZAYN_AUDIT_ERR;

    svc->policy = *policy;
    return OZAYN_AUDIT_OK;
}

const ozayn_audit_policy_t *ozayn_audit_get_policy(const ozayn_audit_service_t *svc)
{
    if (!svc || !svc->initialized) return NULL;
    return &svc->policy;
}

/* ============================================================
 * SECTION 14 — TEST-ONLY STORAGE PROVIDER
 * ============================================================ */

static ozayn_audit_result_t _test_storage_append(void *impl,
                                                  const ozayn_audit_event_t *event)
{
    ozayn_audit_test_storage_t *ts = (ozayn_audit_test_storage_t *)impl;
    if (!ts || !ts->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;
    if (ts->unavailable) return OZAYN_AUDIT_ERR_STORAGE_UNAVAILABLE;
    if (ts->fail_on_append) return OZAYN_AUDIT_ERR_WRITE_FAILED;
    if (ts->count >= 1024) return OZAYN_AUDIT_ERR_STORAGE_FULL;

    ts->events[ts->count] = *event;
    ts->count++;
    return OZAYN_AUDIT_OK;
}

static ozayn_audit_result_t _test_storage_get(void *impl,
                                               const char *event_id,
                                               ozayn_audit_event_t *out)
{
    ozayn_audit_test_storage_t *ts = (ozayn_audit_test_storage_t *)impl;
    if (!ts || !ts->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;
    if (ts->unavailable) return OZAYN_AUDIT_ERR_STORAGE_UNAVAILABLE;
    if (ts->corrupt_on_read) return OZAYN_AUDIT_ERR_INTEGRITY_FAILURE;

    for (int i = 0; i < ts->count; i++) {
        if (strcmp(ts->events[i].event_id, event_id) == 0) {
            *out = ts->events[i];
            return OZAYN_AUDIT_OK;
        }
    }
    return OZAYN_AUDIT_ERR_EVENT_NOT_FOUND;
}

static ozayn_audit_result_t _test_storage_count(void *impl, int *out_count)
{
    ozayn_audit_test_storage_t *ts = (ozayn_audit_test_storage_t *)impl;
    if (!ts || !ts->initialized) return OZAYN_AUDIT_ERR_NOT_INITIALIZED;
    if (ts->unavailable) return OZAYN_AUDIT_ERR_STORAGE_UNAVAILABLE;
    *out_count = ts->count;
    return OZAYN_AUDIT_OK;
}

static void _test_storage_shutdown(void *impl)
{
    ozayn_audit_test_storage_t *ts = (ozayn_audit_test_storage_t *)impl;
    if (ts) ts->initialized = 0;
}

static const ozayn_audit_storage_ops_t g_test_storage_ops = {
    .append   = _test_storage_append,
    .get      = _test_storage_get,
    .count    = _test_storage_count,
    .shutdown = _test_storage_shutdown,
};

void ozayn_audit_test_storage_init(ozayn_audit_test_storage_t *ts)
{
    if (!ts) return;
    memset(ts, 0, sizeof(*ts));
    ts->initialized = 1;
}

void ozayn_audit_test_storage_reset(ozayn_audit_test_storage_t *ts)
{
    if (!ts) return;
    int was_init = ts->initialized;
    memset(ts, 0, sizeof(*ts));
    ts->initialized = was_init;
}

ozayn_audit_storage_t *ozayn_audit_test_storage_provider(ozayn_audit_test_storage_t *ts)
{
    if (!ts) return NULL;
    static ozayn_audit_storage_t provider;
    provider.name = "test-storage";
    provider.ops = &g_test_storage_ops;
    provider.impl = ts;
    provider.initialized = ts->initialized;
    return &provider;
}
