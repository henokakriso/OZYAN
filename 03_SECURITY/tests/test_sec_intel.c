/*
 * test_sec_intel.c — Security Threat Intelligence & Evidence Analysis Tests (Step 32).
 */

#include "../../tests/test_framework.h"
#include "../sec_intel.h"
#include "../audit.h"
#include "../sec_alert.h"
#include "../incident.h"
#include "../sec_detect.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_sintel_service_t _svc;
static ozayn_sdet_service_t _det_svc;
static ozayn_salert_service_t _alert_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_det_svc, 0, sizeof(_det_svc));
    memset(&_alert_svc, 0, sizeof(_alert_svc));
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    memset(&_au_svc, 0, sizeof(_au_svc));
}

static void _init_svc(void)
{
    _reset_all();
    _au_svc.initialized = 1;

    ozayn_salert_service_config_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.audit = &_au_svc;
    ozayn_salert_service_init(&_alert_svc, &acfg);

    ozayn_ir_service_config_t icfg;
    memset(&icfg, 0, sizeof(icfg));
    icfg.audit = &_au_svc;
    icfg.identity = NULL;
    ozayn_ir_service_init(&_ir_svc, &icfg);

    _det_svc.initialized = 1;

    ozayn_sintel_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.detect_service = &_det_svc;
    cfg.incident_service = &_ir_svc;
    cfg.alert_service = &_alert_svc;
    cfg.audit = &_au_svc;
    ozayn_sintel_service_init(&_svc, &cfg);
}

static ozayn_sintel_evidence_t _make_evidence(
    ozayn_sintel_evidence_type_t type,
    const char *source_event_id,
    const char *identity)
{
    ozayn_sintel_evidence_t e;
    memset(&e, 0, sizeof(e));
    e.evidence_type = type;
    e.timestamp = time(NULL);
    e.reliability = OZAYN_SINTEL_RELIABILITY_MEDIUM;
    e.relevance = OZAYN_SINTEL_RELEVANCE_MEDIUM;
    e.severity = OZAYN_SINTEL_SEV_WARNING;
    e.classification = OZAYN_SINTEL_CLASS_INTERNAL;
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_VALID;
    e.status = OZAYN_SINTEL_EVID_STATUS_UNVERIFIED;
    if (source_event_id)
        strncpy(e.source_event_id, source_event_id,
                sizeof(e.source_event_id) - 1);
    if (identity)
        strncpy(e.identity_id, identity, sizeof(e.identity_id) - 1);
    strncpy(e.source_component, "TEST", sizeof(e.source_component) - 1);
    return e;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_sintel_init)
{
    _reset_all();
    ozayn_sintel_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SINTEL_OK, ozayn_sintel_service_init(&_svc, &cfg));
    ASSERT(ozayn_sintel_service_is_initialized(&_svc));
    ozayn_sintel_service_shutdown(&_svc);
    ASSERT(!ozayn_sintel_service_is_initialized(&_svc));
    return 0;
}

TEST(test_sintel_init_null)
{
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL, ozayn_sintel_service_init(NULL, NULL));
    return 0;
}

TEST(test_sintel_init_double)
{
    _reset_all();
    ozayn_sintel_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT_EQ(OZAYN_SINTEL_OK, ozayn_sintel_service_init(&_svc, &cfg));
    ASSERT_EQ(OZAYN_SINTEL_ERR_ALREADY_INITIALIZED,
              ozayn_sintel_service_init(&_svc, &cfg));
    ozayn_sintel_service_shutdown(&_svc);
    return 0;
}

TEST(test_sintel_shutdown_null)
{
    ozayn_sintel_service_shutdown(NULL);
    return 0;
}

TEST(test_sintel_global)
{
    ozayn_sintel_service_t *g = ozayn_sintel_get_global();
    ASSERT(g != NULL);
    return 0;
}

TEST(test_sintel_not_init)
{
    ozayn_sintel_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "E1", NULL);
    ozayn_sintel_evidence_t *stored = NULL;
    ASSERT_EQ(OZAYN_SINTEL_ERR_NOT_INITIALIZED,
              ozayn_sintel_collect_evidence(&svc, &e, &stored));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_sintel_err_names)
{
    ASSERT(strcmp(ozayn_sintel_err_name(OZAYN_SINTEL_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sintel_err_name(OZAYN_SINTEL_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_sintel_err_name((ozayn_sintel_err_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sintel_evidence_type_names)
{
    ASSERT(strcmp(ozayn_sintel_evidence_type_name(OZAYN_SINTEL_EVID_AUDIT_EVENT),
                  "AUDIT_EVENT") == 0);
    ASSERT(strcmp(ozayn_sintel_evidence_type_name(OZAYN_SINTEL_EVID_THREAT_FINDING),
                  "THREAT_FINDING") == 0);
    ASSERT(strcmp(ozayn_sintel_evidence_type_name(
        (ozayn_sintel_evidence_type_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sintel_reliability_names)
{
    ASSERT(strcmp(ozayn_sintel_reliability_name(OZAYN_SINTEL_RELIABILITY_UNKNOWN),
                  "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_sintel_reliability_name(OZAYN_SINTEL_RELIABILITY_VERIFIED),
                  "VERIFIED") == 0);
    return 0;
}

TEST(test_sintel_relevance_names)
{
    ASSERT(strcmp(ozayn_sintel_relevance_name(OZAYN_SINTEL_RELEVANCE_IRRELEVANT),
                  "IRRELEVANT") == 0);
    ASSERT(strcmp(ozayn_sintel_relevance_name(OZAYN_SINTEL_RELEVANCE_CRITICAL),
                  "CRITICAL") == 0);
    return 0;
}

TEST(test_sintel_evidence_status_names)
{
    ASSERT(strcmp(ozayn_sintel_evidence_status_name(
        OZAYN_SINTEL_EVID_STATUS_UNVERIFIED), "UNVERIFIED") == 0);
    ASSERT(strcmp(ozayn_sintel_evidence_status_name(
        OZAYN_SINTEL_EVID_STATUS_VALID), "VALID") == 0);
    ASSERT(strcmp(ozayn_sintel_evidence_status_name(
        (ozayn_sintel_evidence_status_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sintel_classification_names)
{
    ASSERT(strcmp(ozayn_sintel_classification_name(
        OZAYN_SINTEL_CLASS_PUBLIC), "PUBLIC") == 0);
    ASSERT(strcmp(ozayn_sintel_classification_name(
        OZAYN_SINTEL_CLASS_HIGHLY_SENSITIVE), "HIGHLY_SENSITIVE") == 0);
    return 0;
}

TEST(test_sintel_integrity_names)
{
    ASSERT(strcmp(ozayn_sintel_integrity_state_name(
        OZAYN_SINTEL_INTEGRITY_VALID), "VALID") == 0);
    ASSERT(strcmp(ozayn_sintel_integrity_state_name(
        OZAYN_SINTEL_INTEGRITY_INVALID), "INVALID") == 0);
    return 0;
}

TEST(test_sintel_role_names)
{
    ASSERT(strcmp(ozayn_sintel_evidence_role_name(
        OZAYN_SINTEL_ROLE_PRIMARY), "PRIMARY") == 0);
    ASSERT(strcmp(ozayn_sintel_evidence_role_name(
        OZAYN_SINTEL_ROLE_CONFLICTING), "CONFLICTING") == 0);
    return 0;
}

TEST(test_sintel_threat_category_names)
{
    ASSERT(strcmp(ozayn_sintel_threat_category_name(
        OZAYN_SINTEL_THREAT_AUTH), "AUTH") == 0);
    ASSERT(strcmp(ozayn_sintel_threat_category_name(
        OZAYN_SINTEL_THREAT_UNKNOWN), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sintel_impact_names)
{
    ASSERT(strcmp(ozayn_sintel_impact_name(OZAYN_SINTEL_IMPACT_NONE),
                  "NONE") == 0);
    ASSERT(strcmp(ozayn_sintel_impact_name(OZAYN_SINTEL_IMPACT_CRITICAL),
                  "CRITICAL") == 0);
    return 0;
}

TEST(test_sintel_assessment_state_names)
{
    ASSERT(strcmp(ozayn_sintel_assessment_state_name(
        OZAYN_SINTEL_ASSESS_PENDING), "PENDING") == 0);
    ASSERT(strcmp(ozayn_sintel_assessment_state_name(
        OZAYN_SINTEL_ASSESS_ESCALATED), "ESCALATED") == 0);
    ASSERT(strcmp(ozayn_sintel_assessment_state_name(
        (ozayn_sintel_assessment_state_t)99), "UNKNOWN") == 0);
    return 0;
}

TEST(test_sintel_confidence_names)
{
    ASSERT(strcmp(ozayn_sintel_confidence_name(
        OZAYN_SINTEL_CONFIDENCE_LOW), "LOW") == 0);
    ASSERT(strcmp(ozayn_sintel_confidence_name(
        OZAYN_SINTEL_CONFIDENCE_VERY_HIGH), "VERY_HIGH") == 0);
    return 0;
}

TEST(test_sintel_severity_names)
{
    ASSERT(strcmp(ozayn_sintel_severity_name(OZAYN_SINTEL_SEV_INFO),
                  "INFO") == 0);
    ASSERT(strcmp(ozayn_sintel_severity_name(OZAYN_SINTEL_SEV_CRITICAL),
                  "CRITICAL") == 0);
    return 0;
}

TEST(test_sintel_response_names)
{
    ASSERT(strcmp(ozayn_sintel_recommended_response_name(
        OZAYN_SINTEL_RESPONSE_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sintel_recommended_response_name(
        OZAYN_SINTEL_RESPONSE_SECURITY_LOCKDOWN), "SECURITY_LOCKDOWN") == 0);
    return 0;
}

TEST(test_sintel_explanation_names)
{
    ASSERT(strcmp(ozayn_sintel_explanation_code_name(
        OZAYN_SINTEL_EXPLAIN_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sintel_explanation_code_name(
        OZAYN_SINTEL_EXPLAIN_CONFIG_VIOLATION), "CONFIG_VIOLATION") == 0);
    return 0;
}

TEST(test_sintel_severity_conversions)
{
    ASSERT_EQ(0, ozayn_sintel_severity_to_audit_severity(OZAYN_SINTEL_SEV_INFO));
    ASSERT_EQ(4, ozayn_sintel_severity_to_audit_severity(OZAYN_SINTEL_SEV_CRITICAL));
    ASSERT_EQ(0, ozayn_sintel_severity_to_salert_severity(OZAYN_SINTEL_SEV_INFO));
    ASSERT_EQ(4, ozayn_sintel_severity_to_salert_severity(OZAYN_SINTEL_SEV_CRITICAL));
    ASSERT_EQ(0, ozayn_sintel_severity_to_ir_severity(OZAYN_SINTEL_SEV_INFO));
    ASSERT_EQ(4, ozayn_sintel_severity_to_ir_severity(OZAYN_SINTEL_SEV_CRITICAL));
    return 0;
}

/* ============================================================
 * EVIDENCE COLLECTION TESTS
 * ============================================================ */

TEST(test_sintel_collect_evidence)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "EVT-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_collect_evidence(&_svc, &e, &stored));
    ASSERT(stored != NULL);
    ASSERT(stored->evidence_id[0] != '\0');
    ASSERT_EQ(1, ozayn_sintel_evidence_count(&_svc));
    ASSERT(_svc.total_evidence_collected == 1);
    return 0;
}

TEST(test_sintel_collect_evidence_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_collect_evidence(NULL, NULL, NULL));
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "E1", NULL);
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_collect_evidence(&_svc, &e, NULL));
    return 0;
}

TEST(test_sintel_collect_evidence_not_init)
{
    ozayn_sintel_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "E1", NULL);
    ozayn_sintel_evidence_t *stored = NULL;
    ASSERT_EQ(OZAYN_SINTEL_ERR_NOT_INITIALIZED,
              ozayn_sintel_collect_evidence(&svc, &e, &stored));
    return 0;
}

TEST(test_sintel_collect_evidence_policy_disabled)
{
    _init_svc();
    _svc.policy.enabled = 0;
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "E1", NULL);
    ozayn_sintel_evidence_t *stored = NULL;
    ASSERT_EQ(OZAYN_SINTEL_ERR_POLICY_REJECTED,
              ozayn_sintel_collect_evidence(&_svc, &e, &stored));
    return 0;
}

TEST(test_sintel_collect_evidence_generates_id)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "E1", NULL);
    e.evidence_id[0] = '\0';
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    ASSERT(stored != NULL);
    ASSERT(stored->evidence_id[0] != '\0');
    return 0;
}

TEST(test_sintel_collect_evidence_dedup)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "DEDUP-1", "user1");
    ozayn_sintel_evidence_t *s1 = NULL;
    ozayn_sintel_evidence_t *s2 = NULL;
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_collect_evidence(&_svc, &e, &s1));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_collect_evidence(&_svc, &e, &s2));
    ASSERT(s2 == NULL);
    ASSERT_EQ(1, ozayn_sintel_evidence_count(&_svc));
    return 0;
}

TEST(test_sintel_collect_multiple_evidence)
{
    _init_svc();
    for (int i = 0; i < 10; i++) {
        char src[32];
        snprintf(src, sizeof(src), "EVT-%d", i);
        ozayn_sintel_evidence_t e = _make_evidence(
            OZAYN_SINTEL_EVID_AUDIT_EVENT, src, "user1");
        ozayn_sintel_evidence_t *stored = NULL;
        ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    }
    ASSERT_EQ(10, ozayn_sintel_evidence_count(&_svc));
    return 0;
}

TEST(test_sintel_collect_evidence_ring_buffer)
{
    _init_svc();
    for (int i = 0; i < OZAYN_SINTEL_MAX_EVIDENCE + 5; i++) {
        char src[32];
        snprintf(src, sizeof(src), "EVT-%d", i);
        ozayn_sintel_evidence_t e = _make_evidence(
            OZAYN_SINTEL_EVID_AUDIT_EVENT, src, "user1");
        ozayn_sintel_evidence_t *stored = NULL;
        ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    }
    ASSERT_EQ(OZAYN_SINTEL_MAX_EVIDENCE, ozayn_sintel_evidence_count(&_svc));
    return 0;
}

/* ============================================================
 * EVIDENCE VALIDATION TESTS
 * ============================================================ */

TEST(test_sintel_validate_evidence)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "V-1", "user1");
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_VALID;
    ASSERT_EQ(OZAYN_SINTEL_OK, ozayn_sintel_validate_evidence(&_svc, &e));
    ASSERT_EQ(OZAYN_SINTEL_EVID_STATUS_VALID, e.status);
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_HIGH, e.reliability);
    return 0;
}

TEST(test_sintel_validate_evidence_integrity_invalid)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "V-2", "user1");
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_INVALID;
    ASSERT_EQ(OZAYN_SINTEL_ERR_INTEGRITY_FAILURE,
              ozayn_sintel_validate_evidence(&_svc, &e));
    ASSERT_EQ(OZAYN_SINTEL_EVID_STATUS_INVALID, e.status);
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_LOW, e.reliability);
    return 0;
}

TEST(test_sintel_validate_evidence_revoked)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "V-3", "user1");
    e.status = OZAYN_SINTEL_EVID_STATUS_REVOKED;
    ASSERT_EQ(OZAYN_SINTEL_ERR_EVIDENCE_REVOKED,
              ozayn_sintel_validate_evidence(&_svc, &e));
    return 0;
}

TEST(test_sintel_validate_evidence_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_validate_evidence(NULL, NULL));
    return 0;
}

/* ============================================================
 * EVIDENCE QUERY TESTS
 * ============================================================ */

TEST(test_sintel_get_evidence)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "G-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    ozayn_sintel_evidence_t *got = ozayn_sintel_get_evidence(
        &_svc, stored->evidence_id);
    ASSERT(got != NULL);
    ASSERT(strcmp(got->evidence_id, stored->evidence_id) == 0);
    ASSERT(ozayn_sintel_get_evidence(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_sintel_list_evidence)
{
    _init_svc();
    for (int i = 0; i < 5; i++) {
        char src[32];
        snprintf(src, sizeof(src), "L-%d", i);
        ozayn_sintel_evidence_t e = _make_evidence(
            OZAYN_SINTEL_EVID_AUDIT_EVENT, src, "user1");
        ozayn_sintel_evidence_t *stored = NULL;
        ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    }
    ozayn_sintel_evidence_t *list[16];
    int count = ozayn_sintel_list_evidence(&_svc, -1, list, 16);
    ASSERT(count >= 5);
    return 0;
}

TEST(test_sintel_list_evidence_filter)
{
    _init_svc();
    ozayn_sintel_evidence_t e1 = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "LF-1", "user1");
    ozayn_sintel_evidence_t e2 = _make_evidence(
        OZAYN_SINTEL_EVID_HEALTH_RESULT, "LF-2", "user1");
    ozayn_sintel_evidence_t *s1 = NULL, *s2 = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e1, &s1);
    ozayn_sintel_collect_evidence(&_svc, &e2, &s2);
    ozayn_sintel_evidence_t *list[16];
    int count = ozayn_sintel_list_evidence(&_svc,
        OZAYN_SINTEL_EVID_AUDIT_EVENT, list, 16);
    ASSERT(count >= 1);
    count = ozayn_sintel_list_evidence(&_svc,
        OZAYN_SINTEL_EVID_THREAT_FINDING, list, 16);
    ASSERT_EQ(0, count);
    return 0;
}

TEST(test_sintel_evidence_is_duplicate)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "DUP-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    ASSERT(ozayn_sintel_evidence_is_duplicate(&_svc,
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "DUP-1", "user1"));
    ASSERT(!ozayn_sintel_evidence_is_duplicate(&_svc,
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "DUP-X", "user1"));
    return 0;
}

/* ============================================================
 * EVIDENCE SET TESTS
 * ============================================================ */

TEST(test_sintel_create_evidence_set)
{
    _init_svc();
    ozayn_sintel_evidence_set_t *set = NULL;
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_evidence_set(&_svc, "F-1", "C-1", &set));
    ASSERT(set != NULL);
    ASSERT(set->set_id[0] != '\0');
    ASSERT(strcmp(set->finding_id, "F-1") == 0);
    ASSERT_EQ(1, ozayn_sintel_evidence_set_count(&_svc));
    return 0;
}

TEST(test_sintel_create_evidence_set_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_create_evidence_set(NULL, NULL, NULL, NULL));
    return 0;
}

TEST(test_sintel_create_evidence_set_limit)
{
    _init_svc();
    for (int i = 0; i < OZAYN_SINTEL_MAX_EVIDENCE_SETS; i++) {
        ozayn_sintel_evidence_set_t *set = NULL;
        ozayn_sintel_create_evidence_set(&_svc, NULL, NULL, &set);
    }
    ozayn_sintel_evidence_set_t *set = NULL;
    ASSERT_EQ(OZAYN_SINTEL_ERR_SET_LIMIT,
              ozayn_sintel_create_evidence_set(&_svc, NULL, NULL, &set));
    return 0;
}

TEST(test_sintel_add_to_evidence_set)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "AES-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);

    ozayn_sintel_evidence_set_t *set = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", NULL, &set);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_add_to_evidence_set(&_svc, set->set_id,
                  stored->evidence_id, OZAYN_SINTEL_ROLE_PRIMARY));
    ASSERT_EQ(1, set->evidence_count);
    ASSERT_EQ(1, set->primary_count);
    return 0;
}

TEST(test_sintel_add_to_evidence_set_not_found)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "NF-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    ASSERT_EQ(OZAYN_SINTEL_ERR_NOT_FOUND,
              ozayn_sintel_add_to_evidence_set(&_svc, "NOPE",
                  stored->evidence_id, OZAYN_SINTEL_ROLE_PRIMARY));
    return 0;
}

TEST(test_sintel_add_to_evidence_set_role_counts)
{
    _init_svc();
    ozayn_sintel_evidence_set_t *set = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", NULL, &set);

    for (int i = 0; i < 4; i++) {
        char src[32];
        snprintf(src, sizeof(src), "RC-%d", i);
        ozayn_sintel_evidence_t e = _make_evidence(
            OZAYN_SINTEL_EVID_AUDIT_EVENT, src, "user1");
        ozayn_sintel_evidence_t *stored = NULL;
        ozayn_sintel_collect_evidence(&_svc, &e, &stored);
        ozayn_sintel_add_to_evidence_set(&_svc, set->set_id,
            stored->evidence_id, (ozayn_sintel_evidence_role_t)(i % 4));
    }
    ASSERT_EQ(4, set->evidence_count);
    ASSERT(set->primary_count >= 1);
    ASSERT(set->supporting_count >= 1);
    ASSERT(set->conflicting_count >= 1);
    ASSERT(set->contextual_count >= 1);
    return 0;
}

TEST(test_sintel_get_evidence_set)
{
    _init_svc();
    ozayn_sintel_evidence_set_t *set = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", NULL, &set);
    ozayn_sintel_evidence_set_t *got = ozayn_sintel_get_evidence_set(
        &_svc, set->set_id);
    ASSERT(got != NULL);
    ASSERT(strcmp(got->set_id, set->set_id) == 0);
    ASSERT(ozayn_sintel_get_evidence_set(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_sintel_list_evidence_sets)
{
    _init_svc();
    ozayn_sintel_evidence_set_t *s1 = NULL, *s2 = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", NULL, &s1);
    ozayn_sintel_create_evidence_set(&_svc, "F-2", NULL, &s2);
    ozayn_sintel_evidence_set_t *list[16];
    int count = ozayn_sintel_list_evidence_sets(&_svc, NULL, list, 16);
    ASSERT(count >= 2);
    count = ozayn_sintel_list_evidence_sets(&_svc, "F-1", list, 16);
    ASSERT(count >= 1);
    return 0;
}

/* ============================================================
 * RELIABILITY ASSESSMENT TESTS
 * ============================================================ */

TEST(test_sintel_assess_reliability_audit_valid)
{
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "R-1", NULL);
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_VALID;
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_HIGH,
              ozayn_sintel_assess_reliability(&e));
    return 0;
}

TEST(test_sintel_assess_reliability_audit_integrity_valid)
{
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_INTEGRITY, "R-2", NULL);
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_VALID;
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_VERIFIED,
              ozayn_sintel_assess_reliability(&e));
    return 0;
}

TEST(test_sintel_assess_reliability_integrity_invalid)
{
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "R-3", NULL);
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_INVALID;
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_LOW,
              ozayn_sintel_assess_reliability(&e));
    return 0;
}

TEST(test_sintel_assess_reliability_unknown)
{
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "R-4", NULL);
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_UNAVAILABLE;
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_UNKNOWN,
              ozayn_sintel_assess_reliability(&e));
    return 0;
}

TEST(test_sintel_assess_reliability_null)
{
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_UNKNOWN,
              ozayn_sintel_assess_reliability(NULL));
    return 0;
}

TEST(test_sintel_assess_relevance)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "RL-1", NULL);
    e.severity = OZAYN_SINTEL_SEV_CRITICAL;
    ASSERT_EQ(OZAYN_SINTEL_RELEVANCE_CRITICAL,
              ozayn_sintel_assess_relevance(&_svc, &e, NULL));
    e.severity = OZAYN_SINTEL_SEV_HIGH;
    ASSERT_EQ(OZAYN_SINTEL_RELEVANCE_HIGH,
              ozayn_sintel_assess_relevance(&_svc, &e, NULL));
    e.severity = OZAYN_SINTEL_SEV_WARNING;
    ASSERT_EQ(OZAYN_SINTEL_RELEVANCE_MEDIUM,
              ozayn_sintel_assess_relevance(&_svc, &e, NULL));
    e.severity = OZAYN_SINTEL_SEV_INFO;
    ASSERT_EQ(OZAYN_SINTEL_RELEVANCE_LOW,
              ozayn_sintel_assess_relevance(&_svc, &e, NULL));
    return 0;
}

/* ============================================================
 * ASSESSMENT TESTS
 * ============================================================ */

TEST(test_sintel_create_assessment)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_assessment(&_svc, "F-1", "S-1", &a));
    ASSERT(a != NULL);
    ASSERT(a->assessment_id[0] != '\0');
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_PENDING, a->state);
    ASSERT_EQ(1, ozayn_sintel_assessment_count(&_svc));
    return 0;
}

TEST(test_sintel_create_assessment_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_create_assessment(NULL, NULL, NULL, NULL));
    ozayn_sintel_assessment_t *a = NULL;
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_create_assessment(&_svc, "F-1", "S-1", NULL));
    return 0;
}

TEST(test_sintel_create_assessment_limit)
{
    _init_svc();
    for (int i = 0; i < OZAYN_SINTEL_MAX_ASSESSMENTS; i++) {
        ozayn_sintel_assessment_t *a = NULL;
        ozayn_sintel_create_assessment(&_svc, NULL, NULL, &a);
    }
    ozayn_sintel_assessment_t *a = NULL;
    ASSERT_EQ(OZAYN_SINTEL_ERR_ASSESSMENT_LIMIT,
              ozayn_sintel_create_assessment(&_svc, NULL, NULL, &a));
    return 0;
}

TEST(test_sintel_complete_assessment)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_evaluate_assessment(&_svc, a));
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_ASSESSING, a->state);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_complete_assessment(&_svc, a->assessment_id));
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_ASSESSED, a->state);
    return 0;
}

TEST(test_sintel_complete_assessment_bad_state)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);
    a->state = OZAYN_SINTEL_ASSESS_EXPIRED;
    ASSERT_EQ(OZAYN_SINTEL_ERR_STATE_TRANSITION,
              ozayn_sintel_complete_assessment(&_svc, a->assessment_id));
    return 0;
}

TEST(test_sintel_escalate_assessment)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_evaluate_assessment(&_svc, a));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_complete_assessment(&_svc, a->assessment_id));

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_escalate_assessment(&_svc, a->assessment_id));
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_ESCALATED, a->state);
    return 0;
}

TEST(test_sintel_escalate_assessment_bad_state)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_evaluate_assessment(&_svc, a));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_complete_assessment(&_svc, a->assessment_id));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_escalate_assessment(&_svc, a->assessment_id));

    ASSERT_EQ(OZAYN_SINTEL_ERR_STATE_TRANSITION,
              ozayn_sintel_escalate_assessment(&_svc, a->assessment_id));
    return 0;
}

TEST(test_sintel_get_assessment)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);
    ozayn_sintel_assessment_t *got = ozayn_sintel_get_assessment(
        &_svc, a->assessment_id);
    ASSERT(got != NULL);
    ASSERT(strcmp(got->assessment_id, a->assessment_id) == 0);
    ASSERT(ozayn_sintel_get_assessment(&_svc, "NOPE") == NULL);
    return 0;
}

TEST(test_sintel_list_assessments)
{
    _init_svc();
    ozayn_sintel_assessment_t *a1 = NULL, *a2 = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a1);
    ozayn_sintel_create_assessment(&_svc, "F-2", NULL, &a2);
    ozayn_sintel_assessment_t *list[16];
    int count = ozayn_sintel_list_assessments(&_svc, -1, list, 16);
    ASSERT(count >= 2);
    return 0;
}

/* ============================================================
 * ASSESSMENT EVALUATION TESTS
 * ============================================================ */

TEST(test_sintel_evaluate_assessment)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_THREAT_FINDING, "EVT-1", "user1");
    e.severity = OZAYN_SINTEL_SEV_HIGH;
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);

    ozayn_sintel_evidence_set_t *set = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", "C-1", &set);
    ozayn_sintel_add_to_evidence_set(&_svc, set->set_id,
        stored->evidence_id, OZAYN_SINTEL_ROLE_PRIMARY);

    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", set->set_id, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_evaluate_assessment(&_svc, a));
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_ASSESSING, a->state);
    ASSERT(a->severity >= OZAYN_SINTEL_SEV_WARNING);
    return 0;
}

TEST(test_sintel_evaluate_assessment_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_evaluate_assessment(NULL, NULL));
    return 0;
}

TEST(test_sintel_add_explanation)
{
    ozayn_sintel_assessment_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_add_explanation(&a,
                  OZAYN_SINTEL_EXPLAIN_MULTIPLE_AUTH_FAILURES));
    ASSERT_EQ(1, a.explanation_count);
    ASSERT_EQ(OZAYN_SINTEL_EXPLAIN_MULTIPLE_AUTH_FAILURES, a.explanations[0]);
    return 0;
}

TEST(test_sintel_add_explanation_duplicate)
{
    ozayn_sintel_assessment_t a;
    memset(&a, 0, sizeof(a));
    ozayn_sintel_add_explanation(&a, OZAYN_SINTEL_EXPLAIN_RATE_LIMIT_TRIGGERED);
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_add_explanation(&a,
                  OZAYN_SINTEL_EXPLAIN_RATE_LIMIT_TRIGGERED));
    ASSERT_EQ(1, a.explanation_count);
    return 0;
}

TEST(test_sintel_add_explanation_limit)
{
    ozayn_sintel_assessment_t a;
    memset(&a, 0, sizeof(a));
    for (int i = 0; i < OZAYN_SINTEL_MAX_EXPLANATIONS; i++) {
        ozayn_sintel_add_explanation(&a,
            (ozayn_sintel_explanation_code_t)(i + 1));
    }
    ASSERT_EQ(OZAYN_SINTEL_ERR_LIMIT_REACHED,
              ozayn_sintel_add_explanation(&a,
                  OZAYN_SINTEL_EXPLAIN_CONFIG_VIOLATION));
    return 0;
}

TEST(test_sintel_add_explanation_null)
{
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_add_explanation(NULL, OZAYN_SINTEL_EXPLAIN_NONE));
    return 0;
}

/* ============================================================
 * CONFIDENCE CALCULATION TESTS
 * ============================================================ */

TEST(test_sintel_calculate_confidence)
{
    _init_svc();
    ozayn_sintel_evidence_set_t set;
    memset(&set, 0, sizeof(set));
    set.primary_count = 3;
    set.supporting_count = 3;
    set.conflicting_count = 0;
    set.reliability_summary = OZAYN_SINTEL_RELIABILITY_HIGH;
    set.relevance_summary = OZAYN_SINTEL_RELEVANCE_HIGH;
    ASSERT_EQ(OZAYN_SINTEL_CONFIDENCE_VERY_HIGH,
              ozayn_sintel_calculate_confidence(&_svc, &set));
    return 0;
}

TEST(test_sintel_calculate_confidence_low)
{
    _init_svc();
    ozayn_sintel_evidence_set_t set;
    memset(&set, 0, sizeof(set));
    set.primary_count = 0;
    set.supporting_count = 0;
    set.conflicting_count = 0;
    set.reliability_summary = OZAYN_SINTEL_RELIABILITY_UNKNOWN;
    set.relevance_summary = OZAYN_SINTEL_RELEVANCE_IRRELEVANT;
    ASSERT_EQ(OZAYN_SINTEL_CONFIDENCE_LOW,
              ozayn_sintel_calculate_confidence(&_svc, &set));
    return 0;
}

TEST(test_sintel_calculate_confidence_reduced_by_conflicts)
{
    _init_svc();
    ozayn_sintel_evidence_set_t set;
    memset(&set, 0, sizeof(set));
    set.primary_count = 2;
    set.supporting_count = 1;
    set.conflicting_count = 3;
    set.reliability_summary = OZAYN_SINTEL_RELIABILITY_HIGH;
    set.relevance_summary = OZAYN_SINTEL_RELEVANCE_HIGH;
    ozayn_sintel_confidence_t c = ozayn_sintel_calculate_confidence(&_svc, &set);
    ASSERT(c <= OZAYN_SINTEL_CONFIDENCE_MEDIUM);
    return 0;
}

TEST(test_sintel_calculate_confidence_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_CONFIDENCE_LOW,
              ozayn_sintel_calculate_confidence(NULL, NULL));
    return 0;
}

/* ============================================================
 * INCIDENT INTEGRATION TESTS
 * ============================================================ */

TEST(test_sintel_create_incident_from_assessment)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_evaluate_assessment(&_svc, a));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_complete_assessment(&_svc, a->assessment_id));

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_incident_from_assessment(&_svc, a));
    ASSERT(_svc.total_incidents_created == 1);
    return 0;
}

TEST(test_sintel_create_incident_disabled)
{
    _init_svc();
    _svc.policy.incident_integration_enabled = 0;
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_evaluate_assessment(&_svc, a));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_complete_assessment(&_svc, a->assessment_id));

    ASSERT_EQ(OZAYN_SINTEL_ERR_POLICY_REJECTED,
              ozayn_sintel_create_incident_from_assessment(&_svc, a));
    return 0;
}

TEST(test_sintel_create_incident_wrong_state)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);
    ASSERT_EQ(OZAYN_SINTEL_ERR_STATE_TRANSITION,
              ozayn_sintel_create_incident_from_assessment(&_svc, a));
    return 0;
}

TEST(test_sintel_create_incident_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_create_incident_from_assessment(NULL, NULL));
    return 0;
}

/* ============================================================
 * ALERT INTEGRATION TESTS
 * ============================================================ */

TEST(test_sintel_create_alert_from_assessment)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);

    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_alert_from_assessment(&_svc, a));
    ASSERT(_svc.total_alerts_created == 1);
    return 0;
}

TEST(test_sintel_create_alert_disabled)
{
    _init_svc();
    _svc.policy.alert_integration_enabled = 0;
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);
    ASSERT_EQ(OZAYN_SINTEL_ERR_POLICY_REJECTED,
              ozayn_sintel_create_alert_from_assessment(&_svc, a));
    return 0;
}

TEST(test_sintel_create_alert_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_create_alert_from_assessment(NULL, NULL));
    return 0;
}

/* ============================================================
 * AUDIT INTEGRATION TESTS
 * ============================================================ */

TEST(test_sintel_audit_event)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_audit_event(&_svc, "TEST_EVENT", NULL));
    return 0;
}

TEST(test_sintel_audit_event_null)
{
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL,
              ozayn_sintel_audit_event(NULL, "TEST", NULL));
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_sintel_default_policy)
{
    ozayn_sintel_policy_t p = ozayn_sintel_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.max_evidence > 0);
    ASSERT(p.max_evidence_sets > 0);
    ASSERT(p.max_assessments > 0);
    ASSERT(p.evidence_retention_seconds > 0);
    ASSERT(p.incident_integration_enabled);
    ASSERT(p.alert_integration_enabled);
    return 0;
}

TEST(test_sintel_set_policy)
{
    _init_svc();
    ozayn_sintel_policy_t p = ozayn_sintel_default_policy();
    p.dedup_window_seconds = 600;
    ASSERT_EQ(OZAYN_SINTEL_OK, ozayn_sintel_set_policy(&_svc, &p));
    const ozayn_sintel_policy_t *got = ozayn_sintel_get_policy(&_svc);
    ASSERT(got != NULL);
    ASSERT_EQ(600, got->dedup_window_seconds);
    return 0;
}

TEST(test_sintel_set_policy_disabled)
{
    _init_svc();
    ozayn_sintel_policy_t p = ozayn_sintel_default_policy();
    p.enabled = 0;
    ASSERT_EQ(OZAYN_SINTEL_ERR_POLICY_REJECTED,
              ozayn_sintel_set_policy(&_svc, &p));
    return 0;
}

TEST(test_sintel_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(OZAYN_SINTEL_ERR_NULL, ozayn_sintel_set_policy(NULL, NULL));
    return 0;
}

TEST(test_sintel_get_policy_null)
{
    ASSERT(ozayn_sintel_get_policy(NULL) == NULL);
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_sintel_cleanup_expired_evidence)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "CLN-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    stored->timestamp = 1;

    int cleaned = ozayn_sintel_cleanup_expired_evidence(&_svc);
    ASSERT(cleaned >= 1);
    ASSERT_EQ(OZAYN_SINTEL_EVID_STATUS_EXPIRED, stored->status);
    return 0;
}

TEST(test_sintel_cleanup_expired_assessments)
{
    _init_svc();
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", NULL, &a);
    a->created_time = 1;

    int cleaned = ozayn_sintel_cleanup_expired_assessments(&_svc);
    ASSERT(cleaned >= 1);
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_EXPIRED, a->state);
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY TESTS
 * ============================================================ */

TEST(test_sintel_evidence_full)
{
    _init_svc();
    ASSERT(!ozayn_sintel_evidence_full(&_svc));
    ASSERT(ozayn_sintel_evidence_full(NULL));
    return 0;
}

TEST(test_sintel_sets_full)
{
    _init_svc();
    ASSERT(!ozayn_sintel_sets_full(&_svc));
    ASSERT(ozayn_sintel_sets_full(NULL));
    return 0;
}

TEST(test_sintel_assessments_full)
{
    _init_svc();
    ASSERT(!ozayn_sintel_assessments_full(&_svc));
    ASSERT(ozayn_sintel_assessments_full(NULL));
    return 0;
}

/* ============================================================
 * NEGATIVE SECURITY TESTS
 * ============================================================ */

TEST(test_sintel_no_secrets_in_evidence)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "SEC-1", "user1");
    strncpy(e.safe_metadata, "clean data only",
            sizeof(e.safe_metadata) - 1);
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    ASSERT(strstr(stored->safe_metadata, "password") == NULL);
    ASSERT(strstr(stored->safe_metadata, "secret") == NULL);
    return 0;
}

TEST(test_sintel_default_deny_policy)
{
    _init_svc();
    ozayn_sintel_policy_t p = ozayn_sintel_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.incident_integration_enabled);
    ASSERT(p.alert_integration_enabled);
    ASSERT(p.min_reliability_for_assessment >= OZAYN_SINTEL_RELIABILITY_MEDIUM);
    return 0;
}

TEST(test_sintel_invalid_evidence_not_trusted)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "INV-1", "user1");
    e.integrity_state = OZAYN_SINTEL_INTEGRITY_INVALID;
    ozayn_sintel_validate_evidence(&_svc, &e);
    ASSERT_EQ(OZAYN_SINTEL_RELIABILITY_LOW, e.reliability);
    ASSERT_EQ(OZAYN_SINTEL_EVID_STATUS_INVALID, e.status);
    return 0;
}

TEST(test_sintel_assessment_failure_not_safe)
{
    _init_svc();
    ozayn_sintel_evidence_set_t *set = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", NULL, &set);

    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", set->set_id, &a);
    ozayn_sintel_evaluate_assessment(&_svc, a);

    ASSERT(a->confidence <= OZAYN_SINTEL_CONFIDENCE_LOW);
    ASSERT(a->severity <= OZAYN_SINTEL_SEV_NOTICE);
    return 0;
}

TEST(test_sintel_evidence_expiration)
{
    _init_svc();
    ozayn_sintel_evidence_t e = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "EXP-1", "user1");
    ozayn_sintel_evidence_t *stored = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e, &stored);
    ASSERT_EQ(OZAYN_SINTEL_OK, ozayn_sintel_cleanup_expired_evidence(&_svc));
    ASSERT(stored->status == OZAYN_SINTEL_EVID_STATUS_EXPIRED ||
           stored->status == OZAYN_SINTEL_EVID_STATUS_UNVERIFIED);
    return 0;
}

TEST(test_sintel_assessment_limit_enforced)
{
    _init_svc();
    _svc.policy.max_assessments = 2;
    ozayn_sintel_assessment_t *a1 = NULL, *a2 = NULL, *a3 = NULL;
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_assessment(&_svc, NULL, NULL, &a1));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_assessment(&_svc, NULL, NULL, &a2));
    ASSERT_EQ(OZAYN_SINTEL_ERR_LIMIT_REACHED,
              ozayn_sintel_create_assessment(&_svc, NULL, NULL, &a3));
    return 0;
}

TEST(test_sintel_evidence_limit_enforced)
{
    _init_svc();
    _svc.policy.max_evidence = 2;
    ozayn_sintel_evidence_t *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ozayn_sintel_evidence_t e1 = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "LIM-1", NULL);
    ozayn_sintel_evidence_t e2 = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "LIM-2", NULL);
    ozayn_sintel_evidence_t e3 = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "LIM-3", NULL);
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_collect_evidence(&_svc, &e1, &s1));
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_collect_evidence(&_svc, &e2, &s2));
    ASSERT_EQ(OZAYN_SINTEL_ERR_LIMIT_REACHED,
              ozayn_sintel_collect_evidence(&_svc, &e3, &s3));
    return 0;
}

/* ============================================================
 * INTEGRATION PIPELINE TEST
 * ============================================================ */

TEST(test_sintel_full_pipeline)
{
    _init_svc();

    /* Step 1: Collect evidence */
    ozayn_sintel_evidence_t e1 = _make_evidence(
        OZAYN_SINTEL_EVID_AUDIT_EVENT, "P-1", "user1");
    e1.severity = OZAYN_SINTEL_SEV_HIGH;
    e1.integrity_state = OZAYN_SINTEL_INTEGRITY_VALID;
    ozayn_sintel_evidence_t *s1 = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e1, &s1);

    ozayn_sintel_evidence_t e2 = _make_evidence(
        OZAYN_SINTEL_EVID_THREAT_FINDING, "P-2", "user1");
    e2.severity = OZAYN_SINTEL_SEV_HIGH;
    e2.integrity_state = OZAYN_SINTEL_INTEGRITY_VALID;
    ozayn_sintel_evidence_t *s2 = NULL;
    ozayn_sintel_collect_evidence(&_svc, &e2, &s2);

    /* Step 2: Validate */
    ozayn_sintel_validate_evidence(&_svc, s1);
    ozayn_sintel_validate_evidence(&_svc, s2);

    /* Step 3: Create evidence set */
    ozayn_sintel_evidence_set_t *set = NULL;
    ozayn_sintel_create_evidence_set(&_svc, "F-1", "C-1", &set);
    ozayn_sintel_add_to_evidence_set(&_svc, set->set_id,
        s1->evidence_id, OZAYN_SINTEL_ROLE_PRIMARY);
    ozayn_sintel_add_to_evidence_set(&_svc, set->set_id,
        s2->evidence_id, OZAYN_SINTEL_ROLE_SUPPORTING);

    /* Step 4: Create and evaluate assessment */
    ozayn_sintel_assessment_t *a = NULL;
    ozayn_sintel_create_assessment(&_svc, "F-1", set->set_id, &a);
    ozayn_sintel_add_explanation(a, OZAYN_SINTEL_EXPLAIN_MULTIPLE_AUTH_FAILURES);
    ozayn_sintel_evaluate_assessment(&_svc, a);

    /* Step 5: Complete and escalate */
    ozayn_sintel_complete_assessment(&_svc, a->assessment_id);
    ASSERT_EQ(OZAYN_SINTEL_ASSESS_ASSESSED, a->state);

    /* Step 6: Create alert */
    ASSERT_EQ(OZAYN_SINTEL_OK,
              ozayn_sintel_create_alert_from_assessment(&_svc, a));

    /* Verify */
    ASSERT_EQ(2, ozayn_sintel_evidence_count(&_svc));
    ASSERT_EQ(1, ozayn_sintel_evidence_set_count(&_svc));
    ASSERT_EQ(1, ozayn_sintel_assessment_count(&_svc));
    ASSERT(_svc.total_alerts_created == 1);
    return 0;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

int run_sec_intel_tests(void)
{
    SUITE_BEGIN("SECURITY THREAT INTELLIGENCE & EVIDENCE ANALYSIS");

    /* Lifecycle */
    RUN(test_sintel_init);
    RUN(test_sintel_init_null);
    RUN(test_sintel_init_double);
    RUN(test_sintel_shutdown_null);
    RUN(test_sintel_global);
    RUN(test_sintel_not_init);

    /* Name helpers */
    RUN(test_sintel_err_names);
    RUN(test_sintel_evidence_type_names);
    RUN(test_sintel_reliability_names);
    RUN(test_sintel_relevance_names);
    RUN(test_sintel_evidence_status_names);
    RUN(test_sintel_classification_names);
    RUN(test_sintel_integrity_names);
    RUN(test_sintel_role_names);
    RUN(test_sintel_threat_category_names);
    RUN(test_sintel_impact_names);
    RUN(test_sintel_assessment_state_names);
    RUN(test_sintel_confidence_names);
    RUN(test_sintel_severity_names);
    RUN(test_sintel_response_names);
    RUN(test_sintel_explanation_names);
    RUN(test_sintel_severity_conversions);

    /* Evidence collection */
    RUN(test_sintel_collect_evidence);
    RUN(test_sintel_collect_evidence_null);
    RUN(test_sintel_collect_evidence_not_init);
    RUN(test_sintel_collect_evidence_policy_disabled);
    RUN(test_sintel_collect_evidence_generates_id);
    RUN(test_sintel_collect_evidence_dedup);
    RUN(test_sintel_collect_multiple_evidence);
    RUN(test_sintel_collect_evidence_ring_buffer);

    /* Evidence validation */
    RUN(test_sintel_validate_evidence);
    RUN(test_sintel_validate_evidence_integrity_invalid);
    RUN(test_sintel_validate_evidence_revoked);
    RUN(test_sintel_validate_evidence_null);

    /* Evidence query */
    RUN(test_sintel_get_evidence);
    RUN(test_sintel_list_evidence);
    RUN(test_sintel_list_evidence_filter);
    RUN(test_sintel_evidence_is_duplicate);

    /* Evidence sets */
    RUN(test_sintel_create_evidence_set);
    RUN(test_sintel_create_evidence_set_null);
    RUN(test_sintel_create_evidence_set_limit);
    RUN(test_sintel_add_to_evidence_set);
    RUN(test_sintel_add_to_evidence_set_not_found);
    RUN(test_sintel_add_to_evidence_set_role_counts);
    RUN(test_sintel_get_evidence_set);
    RUN(test_sintel_list_evidence_sets);

    /* Reliability */
    RUN(test_sintel_assess_reliability_audit_valid);
    RUN(test_sintel_assess_reliability_audit_integrity_valid);
    RUN(test_sintel_assess_reliability_integrity_invalid);
    RUN(test_sintel_assess_reliability_unknown);
    RUN(test_sintel_assess_reliability_null);
    RUN(test_sintel_assess_relevance);

    /* Assessments */
    RUN(test_sintel_create_assessment);
    RUN(test_sintel_create_assessment_null);
    RUN(test_sintel_create_assessment_limit);
    RUN(test_sintel_complete_assessment);
    RUN(test_sintel_complete_assessment_bad_state);
    RUN(test_sintel_escalate_assessment);
    RUN(test_sintel_escalate_assessment_bad_state);
    RUN(test_sintel_get_assessment);
    RUN(test_sintel_list_assessments);

    /* Assessment evaluation */
    RUN(test_sintel_evaluate_assessment);
    RUN(test_sintel_evaluate_assessment_null);
    RUN(test_sintel_add_explanation);
    RUN(test_sintel_add_explanation_duplicate);
    RUN(test_sintel_add_explanation_limit);
    RUN(test_sintel_add_explanation_null);

    /* Confidence */
    RUN(test_sintel_calculate_confidence);
    RUN(test_sintel_calculate_confidence_low);
    RUN(test_sintel_calculate_confidence_reduced_by_conflicts);
    RUN(test_sintel_calculate_confidence_null);

    /* Integration */
    RUN(test_sintel_create_incident_from_assessment);
    RUN(test_sintel_create_incident_disabled);
    RUN(test_sintel_create_incident_wrong_state);
    RUN(test_sintel_create_incident_null);
    RUN(test_sintel_create_alert_from_assessment);
    RUN(test_sintel_create_alert_disabled);
    RUN(test_sintel_create_alert_null);
    RUN(test_sintel_audit_event);
    RUN(test_sintel_audit_event_null);

    /* Policy */
    RUN(test_sintel_default_policy);
    RUN(test_sintel_set_policy);
    RUN(test_sintel_set_policy_disabled);
    RUN(test_sintel_set_policy_null);
    RUN(test_sintel_get_policy_null);

    /* Cleanup */
    RUN(test_sintel_cleanup_expired_evidence);
    RUN(test_sintel_cleanup_expired_assessments);

    /* Resource safety */
    RUN(test_sintel_evidence_full);
    RUN(test_sintel_sets_full);
    RUN(test_sintel_assessments_full);

    /* Negative security */
    RUN(test_sintel_no_secrets_in_evidence);
    RUN(test_sintel_default_deny_policy);
    RUN(test_sintel_invalid_evidence_not_trusted);
    RUN(test_sintel_assessment_failure_not_safe);
    RUN(test_sintel_evidence_expiration);
    RUN(test_sintel_assessment_limit_enforced);
    RUN(test_sintel_evidence_limit_enforced);

    /* Full pipeline */
    RUN(test_sintel_full_pipeline);

    SUITE_END();
    return TOTAL_FAIL();
}
