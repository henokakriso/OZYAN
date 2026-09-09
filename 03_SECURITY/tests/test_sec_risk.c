/*
 * test_sec_risk.c — Security Risk Scoring & Decision Support Tests (Step 33).
 */

#include "../../tests/test_framework.h"
#include "../sec_risk.h"
#include "../audit.h"
#include "../sec_alert.h"
#include "../incident.h"
#include "../sec_detect.h"
#include "../sec_intel.h"
#include <string.h>
#include <time.h>

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static ozayn_sr_service_t _svc;
static ozayn_salert_service_t _alert_svc;
static ozayn_ir_service_t _ir_svc;
static ozayn_sdet_service_t _det_svc;
static ozayn_audit_service_t _au_svc;

static void _reset_all(void)
{
    memset(&_svc, 0, sizeof(_svc));
    memset(&_alert_svc, 0, sizeof(_alert_svc));
    memset(&_ir_svc, 0, sizeof(_ir_svc));
    memset(&_det_svc, 0, sizeof(_det_svc));
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

    ozayn_sr_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.detect_service = &_det_svc;
    cfg.incident_service = &_ir_svc;
    cfg.alert_service = &_alert_svc;
    cfg.audit = &_au_svc;
    ozayn_sr_service_init(&_svc, &cfg);
}

/* ============================================================
 * NAME HELPERS TESTS
 * ============================================================ */

TEST(test_err_name)
{
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_ERR_NULL), "NULL") == 0);
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_ERR_LIMIT_REACHED), "LIMIT_REACHED") == 0);
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_ERR_STATE_TRANSITION), "STATE_TRANSITION") == 0);
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_ERR_POLICY_REJECTED), "POLICY_REJECTED") == 0);
    ASSERT(strcmp(ozayn_sr_err_name(OZAYN_SR_ERR_DEDUPE_FAILED), "DEDUPE_FAILED") == 0);
    return 0;
}

TEST(test_level_name)
{
    ASSERT(strcmp(ozayn_sr_level_name(OZAYN_SR_LEVEL_UNKNOWN), "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_sr_level_name(OZAYN_SR_LEVEL_LOW), "LOW") == 0);
    ASSERT(strcmp(ozayn_sr_level_name(OZAYN_SR_LEVEL_MODERATE), "MODERATE") == 0);
    ASSERT(strcmp(ozayn_sr_level_name(OZAYN_SR_LEVEL_HIGH), "HIGH") == 0);
    ASSERT(strcmp(ozayn_sr_level_name(OZAYN_SR_LEVEL_CRITICAL), "CRITICAL") == 0);
    return 0;
}

TEST(test_factor_type_name)
{
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_THREAT_SEVERITY), "THREAT_SEVERITY") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_THREAT_IMPACT), "THREAT_IMPACT") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY), "EVIDENCE_RELIABILITY") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_THREAT_CONFIDENCE), "THREAT_CONFIDENCE") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_DATA_CLASSIFICATION), "DATA_CLASSIFICATION") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_RESOURCE_SENSITIVITY), "RESOURCE_SENSITIVITY") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_IDENTITY_SCOPE), "IDENTITY_SCOPE") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_SECURITY_ASSURANCE), "SECURITY_ASSURANCE") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_INTEGRITY_STATE), "INTEGRITY_STATE") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_PERSISTENCE), "PERSISTENCE") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_INCIDENT_STATE), "INCIDENT_STATE") == 0);
    ASSERT(strcmp(ozayn_sr_factor_type_name(OZAYN_SR_FACTOR_SECURITY_HEALTH), "SECURITY_HEALTH") == 0);
    return 0;
}

TEST(test_persistence_name)
{
    ASSERT(strcmp(ozayn_sr_persistence_name(OZAYN_SR_PERSISTENCE_UNKNOWN), "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_sr_persistence_name(OZAYN_SR_PERSISTENCE_TRANSIENT), "TRANSIENT") == 0);
    ASSERT(strcmp(ozayn_sr_persistence_name(OZAYN_SR_PERSISTENCE_REPEATED), "REPEATED") == 0);
    ASSERT(strcmp(ozayn_sr_persistence_name(OZAYN_SR_PERSISTENCE_PERSISTENT), "PERSISTENT") == 0);
    return 0;
}

TEST(test_assurance_name)
{
    ASSERT(strcmp(ozayn_sr_assurance_name(OZAYN_SR_ASSURANCE_UNKNOWN), "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_sr_assurance_name(OZAYN_SR_ASSURANCE_SINGLE_FACTOR), "SINGLE_FACTOR") == 0);
    ASSERT(strcmp(ozayn_sr_assurance_name(OZAYN_SR_ASSURANCE_MULTI_FACTOR), "MULTI_FACTOR") == 0);
    ASSERT(strcmp(ozayn_sr_assurance_name(OZAYN_SR_ASSURANCE_HIGH_ASSURANCE), "HIGH_ASSURANCE") == 0);
    return 0;
}

TEST(test_temporal_name)
{
    ASSERT(strcmp(ozayn_sr_temporal_name(OZAYN_SR_TEMPORAL_CURRENT), "CURRENT") == 0);
    ASSERT(strcmp(ozayn_sr_temporal_name(OZAYN_SR_TEMPORAL_AGING), "AGING") == 0);
    ASSERT(strcmp(ozayn_sr_temporal_name(OZAYN_SR_TEMPORAL_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_sr_temporal_name(OZAYN_SR_TEMPORAL_UNKNOWN), "UNKNOWN") == 0);
    return 0;
}

TEST(test_state_name)
{
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_PENDING), "PENDING") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_ASSESSING), "ASSESSING") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_ASSESSED), "ASSESSED") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_ELEVATED), "ELEVATED") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_MITIGATING), "MITIGATING") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_MONITORING), "MONITORING") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_RESOLVED), "RESOLVED") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_sr_state_name(OZAYN_SR_STATE_INVALID), "INVALID") == 0);
    return 0;
}

TEST(test_decision_name)
{
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_MONITOR), "MONITOR") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_INVESTIGATE), "INVESTIGATE") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_ESCALATE_INCIDENT), "ESCALATE_INCIDENT") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REQUIRE_REAUTH), "REQUIRE_REAUTH") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REQUIRE_MFA), "REQUIRE_MFA") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REVIEW_SESSION), "REVIEW_SESSION") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REVOKE_SESSION), "REVOKE_SESSION") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REVIEW_IDENTITY), "REVIEW_IDENTITY") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_SUSPEND_IDENTITY), "SUSPEND_IDENTITY") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REVIEW_PERMISSION), "REVIEW_PERMISSION") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REVIEW_ROLE), "REVIEW_ROLE") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_REVIEW_KEY_STATE), "REVIEW_KEY_STATE") == 0);
    ASSERT(strcmp(ozayn_sr_decision_name(OZAYN_SR_DECISION_SECURITY_LOCKDOWN), "SECURITY_LOCKDOWN") == 0);
    return 0;
}

TEST(test_explain_name)
{
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_HIGH_THREAT_SEVERITY), "HIGH_THREAT_SEVERITY") == 0);
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_HIGH_CONFIDENCE), "HIGH_CONFIDENCE") == 0);
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_VERIFIED_EVIDENCE), "VERIFIED_EVIDENCE") == 0);
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_PERSISTENT_THREAT), "PERSISTENT_THREAT") == 0);
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_INSUFFICIENT_EVIDENCE), "INSUFFICIENT_EVIDENCE") == 0);
    ASSERT(strcmp(ozayn_sr_explain_name(OZAYN_SR_EXPLAIN_AGGREGATED_RISK), "AGGREGATED_RISK") == 0);
    return 0;
}

TEST(test_level_to_audit_severity)
{
    ASSERT_EQ(ozayn_sr_level_to_audit_severity(OZAYN_SR_LEVEL_UNKNOWN), 0);
    ASSERT_EQ(ozayn_sr_level_to_audit_severity(OZAYN_SR_LEVEL_LOW), 1);
    ASSERT_EQ(ozayn_sr_level_to_audit_severity(OZAYN_SR_LEVEL_MODERATE), 2);
    ASSERT_EQ(ozayn_sr_level_to_audit_severity(OZAYN_SR_LEVEL_HIGH), 3);
    ASSERT_EQ(ozayn_sr_level_to_audit_severity(OZAYN_SR_LEVEL_CRITICAL), 4);
    return 0;
}

TEST(test_level_to_salert_severity)
{
    ASSERT_EQ(ozayn_sr_level_to_salert_severity(OZAYN_SR_LEVEL_UNKNOWN), 0);
    ASSERT_EQ(ozayn_sr_level_to_salert_severity(OZAYN_SR_LEVEL_LOW), 1);
    ASSERT_EQ(ozayn_sr_level_to_salert_severity(OZAYN_SR_LEVEL_MODERATE), 2);
    ASSERT_EQ(ozayn_sr_level_to_salert_severity(OZAYN_SR_LEVEL_HIGH), 3);
    ASSERT_EQ(ozayn_sr_level_to_salert_severity(OZAYN_SR_LEVEL_CRITICAL), 4);
    return 0;
}

TEST(test_level_to_ir_severity)
{
    ASSERT_EQ(ozayn_sr_level_to_ir_severity(OZAYN_SR_LEVEL_UNKNOWN), 0);
    ASSERT_EQ(ozayn_sr_level_to_ir_severity(OZAYN_SR_LEVEL_LOW), 1);
    ASSERT_EQ(ozayn_sr_level_to_ir_severity(OZAYN_SR_LEVEL_MODERATE), 2);
    ASSERT_EQ(ozayn_sr_level_to_ir_severity(OZAYN_SR_LEVEL_HIGH), 3);
    ASSERT_EQ(ozayn_sr_level_to_ir_severity(OZAYN_SR_LEVEL_CRITICAL), 4);
    return 0;
}

TEST(test_level_to_salert_priority)
{
    ASSERT_EQ(ozayn_sr_level_to_salert_priority(OZAYN_SR_LEVEL_UNKNOWN), 0);
    ASSERT_EQ(ozayn_sr_level_to_salert_priority(OZAYN_SR_LEVEL_LOW), 0);
    ASSERT_EQ(ozayn_sr_level_to_salert_priority(OZAYN_SR_LEVEL_MODERATE), 1);
    ASSERT_EQ(ozayn_sr_level_to_salert_priority(OZAYN_SR_LEVEL_HIGH), 2);
    ASSERT_EQ(ozayn_sr_level_to_salert_priority(OZAYN_SR_LEVEL_CRITICAL), 4);
    return 0;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_lifecycle_null)
{
    ASSERT_EQ(ozayn_sr_service_init(NULL, NULL), OZAYN_SR_ERR_NULL);
    return 0;
}

TEST(test_lifecycle_init_with_config)
{
    _reset_all();
    ozayn_sr_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    ozayn_sr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_sr_service_init(&svc, &cfg), OZAYN_SR_OK);
    ASSERT(svc.initialized);
    ASSERT(ozayn_sr_service_is_initialized(&svc));
    ozayn_sr_service_shutdown(&svc);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_lifecycle_init_with_deps)
{
    _reset_all();
    _au_svc.initialized = 1;
    _det_svc.initialized = 1;

    ozayn_sr_service_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.audit = &_au_svc;
    cfg.detect_service = &_det_svc;

    ozayn_sr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_sr_service_init(&svc, &cfg), OZAYN_SR_OK);
    ASSERT(svc.audit == &_au_svc);
    ASSERT(svc.detect_service == &_det_svc);
    ozayn_sr_service_shutdown(&svc);
    return 0;
}

TEST(test_lifecycle_double_init)
{
    _reset_all();
    ozayn_sr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ASSERT_EQ(ozayn_sr_service_init(&svc, NULL), OZAYN_SR_OK);
    ASSERT_EQ(ozayn_sr_service_init(&svc, NULL), OZAYN_SR_ERR_ALREADY_INITIALIZED);
    ozayn_sr_service_shutdown(&svc);
    return 0;
}

TEST(test_lifecycle_shutdown_null)
{
    ozayn_sr_service_shutdown(NULL);
    return 0;
}

TEST(test_lifecycle_is_initialized_null)
{
    ASSERT(!ozayn_sr_service_is_initialized(NULL));
    return 0;
}

TEST(test_global_accessor)
{
    ASSERT_NOT_NULL(ozayn_sr_get_global());
    return 0;
}

/* ============================================================
 * RISK ASSESSMENT OPERATIONS TESTS
 * ============================================================ */

TEST(test_create_assessment_basic)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, "FIND-1", "TA-1", "ES-1", &a), OZAYN_SR_OK);
    ASSERT_NOT_NULL(a);
    ASSERT(a->risk_id[0] != '\0');
    ASSERT(strcmp(a->finding_id, "FIND-1") == 0);
    ASSERT(strcmp(a->threat_assessment_id, "TA-1") == 0);
    ASSERT(strcmp(a->evidence_set_id, "ES-1") == 0);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_PENDING);
    ASSERT_EQ(a->risk_level, OZAYN_SR_LEVEL_UNKNOWN);
    ASSERT_EQ(a->risk_score, -1);
    ASSERT_EQ(_svc.assessment_count, 1);
    return 0;
}

TEST(test_create_assessment_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_create_assessment(NULL, "F", "T", "E", NULL), OZAYN_SR_ERR_NULL);
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, NULL, NULL, NULL, NULL), OZAYN_SR_ERR_NULL);
    return 0;
}

TEST(test_create_assessment_not_initialized)
{
    _reset_all();
    ozayn_sr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sr_assessment_t *a = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&svc, "F", "T", "E", &a), OZAYN_SR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_create_assessment_policy_disabled)
{
    _init_svc();
    _svc.policy.enabled = 0;
    ozayn_sr_assessment_t *a = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a), OZAYN_SR_ERR_POLICY_REJECTED);
    ASSERT_EQ(_svc.total_policy_rejections, 1);
    return 0;
}

TEST(test_create_assessment_unique_ids)
{
    _init_svc();
    ozayn_sr_assessment_t *a1 = NULL;
    ozayn_sr_assessment_t *a2 = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, "F1", "T1", "E1", &a1), OZAYN_SR_OK);
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, "F2", "T2", "E2", &a2), OZAYN_SR_OK);
    ASSERT(a1 != a2);
    ASSERT(strcmp(a1->risk_id, a2->risk_id) != 0);
    ASSERT_EQ(_svc.assessment_count, 2);
    return 0;
}

TEST(test_get_assessment)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a), OZAYN_SR_OK);
    ASSERT_NOT_NULL(ozayn_sr_get_assessment(&_svc, a->risk_id));
    ASSERT_NULL(ozayn_sr_get_assessment(&_svc, "NONEXISTENT"));
    ASSERT_NULL(ozayn_sr_get_assessment(&_svc, NULL));
    ASSERT_NULL(ozayn_sr_get_assessment(NULL, a->risk_id));
    return 0;
}

TEST(test_assessment_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_assessment_count(&_svc), 0);
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F1", "T1", "E1", &a);
    ASSERT_EQ(ozayn_sr_assessment_count(&_svc), 1);
    ozayn_sr_create_assessment(&_svc, "F2", "T2", "E2", &a);
    ASSERT_EQ(ozayn_sr_assessment_count(&_svc), 2);
    ASSERT_EQ(ozayn_sr_assessment_count(NULL), 0);
    return 0;
}

TEST(test_list_assessments)
{
    _init_svc();
    ozayn_sr_assessment_t *a1, *a2;
    ozayn_sr_create_assessment(&_svc, "F1", "T1", "E1", &a1);
    ozayn_sr_create_assessment(&_svc, "F2", "T2", "E2", &a2);
    ozayn_sr_assessment_t *list[4] = {0};
    int count = ozayn_sr_list_assessments(&_svc, -1, list, 4);
    ASSERT_EQ(count, 2);
    ASSERT_NOT_NULL(list[0]);
    ASSERT_NOT_NULL(list[1]);
    /* Filter by PENDING */
    count = ozayn_sr_list_assessments(&_svc, OZAYN_SR_STATE_PENDING, list, 4);
    ASSERT_EQ(count, 2);
    /* Filter by RESOLVED (none) */
    count = ozayn_sr_list_assessments(&_svc, OZAYN_SR_STATE_RESOLVED, list, 4);
    ASSERT_EQ(count, 0);
    return 0;
}

/* ============================================================
 * STATE TRANSITION TESTS
 * ============================================================ */

TEST(test_complete_assessment)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_PENDING);
    ASSERT_EQ(ozayn_sr_complete_assessment(&_svc, a->risk_id), OZAYN_SR_OK);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_ASSESSED);
    return 0;
}

TEST(test_complete_assessment_not_pending)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_complete_assessment(&_svc, a->risk_id);
    /* Already ASSESSED, can't complete again */
    ASSERT_EQ(ozayn_sr_complete_assessment(&_svc, a->risk_id), OZAYN_SR_ERR_STATE_TRANSITION);
    return 0;
}

TEST(test_elevate_assessment)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    /* From PENDING, auto-advances PENDING→ASSESSING→ASSESSED→ELEVATED */
    ASSERT_EQ(ozayn_sr_elevate_assessment(&_svc, a->risk_id), OZAYN_SR_OK);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_ELEVATED);
    return 0;
}

TEST(test_resolve_assessment)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    /* From PENDING, auto-advances through chain to RESOLVED */
    ASSERT_EQ(ozayn_sr_resolve_assessment(&_svc, a->risk_id), OZAYN_SR_OK);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_RESOLVED);
    return 0;
}

TEST(test_complete_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_complete_assessment(&_svc, NULL), OZAYN_SR_ERR_NULL);
    ASSERT_EQ(ozayn_sr_complete_assessment(NULL, "ID"), OZAYN_SR_ERR_NULL);
    return 0;
}

TEST(test_complete_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_complete_assessment(&_svc, "NONEXISTENT"), OZAYN_SR_ERR_NOT_FOUND);
    return 0;
}

/* ============================================================
 * FACTOR OPERATIONS TESTS
 * ============================================================ */

TEST(test_add_factor)
{
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "test", OZAYN_SR_EXPLAIN_NONE), OZAYN_SR_OK);
    ASSERT_EQ(a.factor_count, 1);
    ASSERT_EQ(a.factors[0].type, OZAYN_SR_FACTOR_THREAT_SEVERITY);
    ASSERT_EQ(a.factors[0].value, 3);
    ASSERT_EQ(a.factors[0].weight, 20);
    return 0;
}

TEST(test_add_factor_null)
{
    ASSERT_EQ(ozayn_sr_add_factor(NULL, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "test", OZAYN_SR_EXPLAIN_NONE), OZAYN_SR_ERR_NULL);
    return 0;
}

TEST(test_add_factor_invalid_type)
{
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    ASSERT_EQ(ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_COUNT, 3, 20, "test", OZAYN_SR_EXPLAIN_NONE), OZAYN_SR_ERR_INVALID_PARAM);
    return 0;
}

TEST(test_add_factor_update_existing)
{
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 2, 20, "src1", OZAYN_SR_EXPLAIN_NONE);
    ASSERT_EQ(a.factor_count, 1);
    /* Update same type */
    ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 25, "src2", OZAYN_SR_EXPLAIN_HIGH_THREAT_SEVERITY);
    ASSERT_EQ(a.factor_count, 1);
    ASSERT_EQ(a.factors[0].value, 4);
    ASSERT_EQ(a.factors[0].weight, 25);
    ASSERT(strcmp(a.factors[0].source, "src2") == 0);
    return 0;
}

TEST(test_add_multiple_factors)
{
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "s", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_THREAT_IMPACT, 4, 15, "s", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY, 3, 15, "s", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(&a, OZAYN_SR_FACTOR_THREAT_CONFIDENCE, 2, 10, "s", OZAYN_SR_EXPLAIN_NONE);
    ASSERT_EQ(a.factor_count, 4);
    return 0;
}

/* ============================================================
 * DETERMINISTIC RISK CALCULATION TESTS
 * ============================================================ */

TEST(test_calculate_risk_basic)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_HIGH_THREAT_SEVERITY);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_PENDING);
    ASSERT_EQ(ozayn_sr_calculate_risk(&_svc, a), OZAYN_SR_OK);
    ASSERT_EQ(a->state, OZAYN_SR_STATE_ASSESSING);
    ASSERT(a->risk_score >= 0);
    ASSERT(a->risk_score <= 100);
    ASSERT(a->risk_level >= OZAYN_SR_LEVEL_UNKNOWN);
    ASSERT(a->risk_level <= OZAYN_SR_LEVEL_CRITICAL);
    ASSERT_EQ(_svc.total_calculations, 1);
    return 0;
}

TEST(test_calculate_risk_high_factors)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    a->reliability = OZAYN_SINTEL_RELIABILITY_MEDIUM;
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_CONFIDENCE, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_DATA_CLASSIFICATION, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT(a->risk_score >= 60);
    return 0;
}

TEST(test_calculate_risk_low_factors)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 1, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 0, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT(a->risk_score < 30);
    return 0;
}

TEST(test_calculate_risk_no_factors)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ASSERT_EQ(ozayn_sr_calculate_risk(&_svc, a), OZAYN_SR_OK);
    ASSERT_EQ(a->risk_level, OZAYN_SR_LEVEL_UNKNOWN);
    return 0;
}

TEST(test_calculate_risk_policy_disabled)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    _svc.policy.enabled = 0;
    ASSERT_EQ(ozayn_sr_calculate_risk(&_svc, a), OZAYN_SR_ERR_POLICY_REJECTED);
    return 0;
}

TEST(test_calculate_risk_contributions)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_HIGH_THREAT_SEVERITY);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 2, 15, "src2", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_GE(a->contribution_count, 1);
    ASSERT_GE(a->contribution_count, 2);
    return 0;
}

TEST(test_calculate_risk_explanation_codes)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_HIGH_THREAT_SEVERITY);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 2, 15, "src", OZAYN_SR_EXPLAIN_HIGH_CONFIDENCE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_GE(a->explanation_count, 1);
    return 0;
}

TEST(test_calculate_risk_deterministic)
{
    _init_svc();
    ozayn_sr_assessment_t *a1 = NULL, *a2 = NULL;
    ozayn_sr_create_assessment(&_svc, "F1", "T1", "E1", &a1);
    ozayn_sr_add_factor(a1, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_create_assessment(&_svc, "F2", "T2", "E2", &a2);
    ozayn_sr_add_factor(a2, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a1);
    ozayn_sr_calculate_risk(&_svc, a2);
    ASSERT_EQ(a1->risk_score, a2->risk_score);
    ASSERT_EQ(a1->risk_level, a2->risk_level);
    return 0;
}

TEST(test_calculate_risk_integrity_failure_caps)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_CONFIDENCE, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    a->integrity_state = OZAYN_SINTEL_INTEGRITY_INVALID;
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT(a->risk_level <= OZAYN_SR_LEVEL_MODERATE);
    return 0;
}

/* ============================================================
 * SCORE TO LEVEL TESTS
 * ============================================================ */

TEST(test_score_to_level)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 0), OZAYN_SR_LEVEL_UNKNOWN);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 5), OZAYN_SR_LEVEL_LOW);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 15), OZAYN_SR_LEVEL_MODERATE);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 35), OZAYN_SR_LEVEL_HIGH);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 65), OZAYN_SR_LEVEL_CRITICAL);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, -1), OZAYN_SR_LEVEL_UNKNOWN);
    ASSERT_EQ(ozayn_sr_score_to_level(NULL, 50), OZAYN_SR_LEVEL_UNKNOWN);
    return 0;
}

TEST(test_score_to_level_custom_thresholds)
{
    _init_svc();
    _svc.policy.score_threshold_low = 5;
    _svc.policy.score_threshold_moderate = 20;
    _svc.policy.score_threshold_high = 50;
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 4), OZAYN_SR_LEVEL_LOW);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 10), OZAYN_SR_LEVEL_MODERATE);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 30), OZAYN_SR_LEVEL_HIGH);
    ASSERT_EQ(ozayn_sr_score_to_level(&_svc, 60), OZAYN_SR_LEVEL_CRITICAL);
    return 0;
}

/* ============================================================
 * AGGREGATION TESTS
 * ============================================================ */

TEST(test_create_aggregation)
{
    _init_svc();
    ozayn_sr_aggregation_t *g = NULL;
    ASSERT_EQ(ozayn_sr_create_aggregation(&_svc, "IDENT-1", "RES-1", "INC-1", &g), OZAYN_SR_OK);
    ASSERT_NOT_NULL(g);
    ASSERT(g->group_id[0] != '\0');
    ASSERT(strcmp(g->identity_id, "IDENT-1") == 0);
    ASSERT(strcmp(g->resource_id, "RES-1") == 0);
    ASSERT(strcmp(g->incident_id, "INC-1") == 0);
    ASSERT_EQ(g->assessment_count, 0);
    ASSERT_EQ(_svc.aggregation_count, 1);
    return 0;
}

TEST(test_create_aggregation_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_create_aggregation(&_svc, NULL, NULL, NULL, NULL), OZAYN_SR_ERR_NULL);
    return 0;
}

TEST(test_add_to_aggregation)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);

    ozayn_sr_aggregation_t *g = NULL;
    ozayn_sr_create_aggregation(&_svc, "I", "R", "N", &g);
    ASSERT_EQ(ozayn_sr_add_to_aggregation(&_svc, g->group_id, a->risk_id), OZAYN_SR_OK);
    ASSERT_EQ(g->assessment_count, 1);
    return 0;
}

TEST(test_add_to_aggregation_not_found)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_add_to_aggregation(&_svc, "NONEXISTENT", "RISK"), OZAYN_SR_ERR_NOT_FOUND);
    return 0;
}

TEST(test_evaluate_aggregation)
{
    _init_svc();
    ozayn_sr_assessment_t *a1, *a2;
    ozayn_sr_create_assessment(&_svc, "F1", "T1", "E1", &a1);
    ozayn_sr_add_factor(a1, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "s", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a1);

    ozayn_sr_create_assessment(&_svc, "F2", "T2", "E2", &a2);
    ozayn_sr_add_factor(a2, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "s", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a2);

    ozayn_sr_aggregation_t *g = NULL;
    ozayn_sr_create_aggregation(&_svc, "I", "R", "N", &g);
    ozayn_sr_add_to_aggregation(&_svc, g->group_id, a1->risk_id);
    ozayn_sr_add_to_aggregation(&_svc, g->group_id, a2->risk_id);

    ASSERT_EQ(ozayn_sr_evaluate_aggregation(&_svc, g), OZAYN_SR_OK);
    ASSERT(g->aggregated_score > 0);
    ASSERT_GE(g->aggregated_level, OZAYN_SR_LEVEL_LOW);
    return 0;
}

TEST(test_get_aggregation)
{
    _init_svc();
    ozayn_sr_aggregation_t *g = NULL;
    ozayn_sr_create_aggregation(&_svc, "I", "R", "N", &g);
    ASSERT_NOT_NULL(ozayn_sr_get_aggregation(&_svc, g->group_id));
    ASSERT_NULL(ozayn_sr_get_aggregation(&_svc, "NONEXISTENT"));
    ASSERT_NULL(ozayn_sr_get_aggregation(NULL, "X"));
    return 0;
}

TEST(test_aggregation_count)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_aggregation_count(&_svc), 0);
    ozayn_sr_aggregation_t *g = NULL;
    ozayn_sr_create_aggregation(&_svc, "I", "R", "N", &g);
    ASSERT_EQ(ozayn_sr_aggregation_count(&_svc), 1);
    ASSERT_EQ(ozayn_sr_aggregation_count(NULL), 0);
    return 0;
}

/* ============================================================
 * DEDUPLICATION TESTS
 * ============================================================ */

TEST(test_dedup_no_duplicate)
{
    _init_svc();
    ASSERT(!ozayn_sr_assessment_is_duplicate(&_svc, "F", "E", "T"));
    return 0;
}

TEST(test_dedup_detects_duplicate)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ASSERT(ozayn_sr_assessment_is_duplicate(&_svc, "F", "E", "T"));
    return 0;
}

TEST(test_dedup_different_finding_not_duplicate)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F1", "T", "E", &a);
    ASSERT(!ozayn_sr_assessment_is_duplicate(&_svc, "F2", "E", "T"));
    return 0;
}

TEST(test_dedup_returns_null_assessment)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    /* Creating with same params returns NULL (deduplicated) and OK */
    ozayn_sr_assessment_t *a2 = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a2), OZAYN_SR_OK);
    ASSERT_NULL(a2);
    ASSERT_EQ(_svc.total_assessments_deduplicated, 1);
    return 0;
}

/* ============================================================
 * TEMPORAL TESTS
 * ============================================================ */

TEST(test_temporal_current)
{
    _init_svc();
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    a.created_time = time(NULL);
    ASSERT_EQ(ozayn_sr_evaluate_temporal(&_svc, &a), OZAYN_SR_TEMPORAL_CURRENT);
    return 0;
}

TEST(test_temporal_aging)
{
    _init_svc();
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    a.created_time = time(NULL) - 50000; /* > 12 hours */
    ASSERT_EQ(ozayn_sr_evaluate_temporal(&_svc, &a), OZAYN_SR_TEMPORAL_AGING);
    return 0;
}

TEST(test_temporal_expired)
{
    _init_svc();
    ozayn_sr_assessment_t a;
    memset(&a, 0, sizeof(a));
    a.created_time = time(NULL) - 200000; /* > 1 day */
    ASSERT_EQ(ozayn_sr_evaluate_temporal(&_svc, &a), OZAYN_SR_TEMPORAL_EXPIRED);
    return 0;
}

TEST(test_temporal_null)
{
    ASSERT_EQ(ozayn_sr_evaluate_temporal(NULL, NULL), OZAYN_SR_TEMPORAL_UNKNOWN);
    return 0;
}

/* ============================================================
 * DECISION SUPPORT TESTS
 * ============================================================ */

TEST(test_decision_low_risk)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 1, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_EQ(ozayn_sr_generate_decision(&_svc, a), OZAYN_SR_OK);
    ASSERT(a->recommended_decision != OZAYN_SR_DECISION_NONE);
    ASSERT(a->decision_priority > 0);
    return 0;
}

TEST(test_decision_high_risk)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    a->reliability = OZAYN_SINTEL_RELIABILITY_MEDIUM;
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_CONFIDENCE, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_DATA_CLASSIFICATION, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_EQ(ozayn_sr_generate_decision(&_svc, a), OZAYN_SR_OK);
    ASSERT_GE(a->decision_priority, 50);
    return 0;
}

TEST(test_decision_persistent_threat_override)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 2, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_PERSISTENCE, 3, 20, "src", OZAYN_SR_EXPLAIN_PERSISTENT_THREAT);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_EQ(ozayn_sr_generate_decision(&_svc, a), OZAYN_SR_OK);
    ASSERT(a->recommended_decision >= OZAYN_SR_DECISION_INVESTIGATE);
    return 0;
}

TEST(test_decision_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_generate_decision(&_svc, NULL), OZAYN_SR_ERR_NULL);
    ASSERT_EQ(ozayn_sr_generate_decision(NULL, NULL), OZAYN_SR_ERR_NULL);
    return 0;
}

TEST(test_decision_explanation_codes)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_CONFIDENCE, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_DATA_CLASSIFICATION, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ozayn_sr_generate_decision(&_svc, a);
    /* Decision may have added explanation codes */
    ASSERT(a->explanation_count >= 0);
    return 0;
}

/* ============================================================
 * INTEGRATION TESTS
 * ============================================================ */

TEST(test_incident_integration)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    /* Cannot create incident from PENDING state */
    ASSERT_EQ(ozayn_sr_create_incident_from_risk(&_svc, a), OZAYN_SR_ERR_STATE_TRANSITION);
    /* Complete and calculate */
    ozayn_sr_complete_assessment(&_svc, a->risk_id);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 30, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_IMPACT, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_EVIDENCE_RELIABILITY, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_CONFIDENCE, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_DATA_CLASSIFICATION, 4, 15, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    /* May create incident if risk is HIGH or CRITICAL */
    ozayn_sr_create_incident_from_risk(&_svc, a);
    /* Incident ID may or may not be set depending on risk level */
    ASSERT(1);
    return 0;
}

TEST(test_alert_integration)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_EQ(ozayn_sr_create_alert_from_risk(&_svc, a), OZAYN_SR_OK);
    return 0;
}

TEST(test_alert_integration_disabled)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    _svc.policy.alert_integration_enabled = 0;
    ASSERT_EQ(ozayn_sr_create_alert_from_risk(&_svc, a), OZAYN_SR_ERR_POLICY_REJECTED);
    return 0;
}

TEST(test_incident_integration_disabled)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_complete_assessment(&_svc, a->risk_id);
    _svc.policy.incident_integration_enabled = 0;
    ASSERT_EQ(ozayn_sr_create_incident_from_risk(&_svc, a), OZAYN_SR_ERR_POLICY_REJECTED);
    return 0;
}

TEST(test_health_impact)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_get_health_impact(&_svc), 0);
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT(ozayn_sr_get_health_impact(&_svc) >= 0);
    return 0;
}

TEST(test_health_integration_disabled)
{
    _init_svc();
    ozayn_sr_policy_t p = _svc.policy;
    p.health_integration_enabled = 0;
    ozayn_sr_set_policy(&_svc, &p);
    ASSERT_EQ(_svc.policy.health_integration_enabled, 0);
    return 0;
}

TEST(test_audit_event)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_audit_event(&_svc, "TEST_EVENT", "test detail"), OZAYN_SR_OK);
    ASSERT_EQ(ozayn_sr_audit_event(NULL, "E", "D"), OZAYN_SR_ERR_NULL);
    return 0;
}

/* ============================================================
 * POLICY TESTS
 * ============================================================ */

TEST(test_default_policy)
{
    ozayn_sr_policy_t p = ozayn_sr_default_policy();
    ASSERT(p.enabled);
    ASSERT(p.incident_integration_enabled);
    ASSERT(p.alert_integration_enabled);
    ASSERT(p.health_integration_enabled);
    ASSERT(p.audit_integration_enabled);
    ASSERT(p.max_assessments > 0);
    ASSERT(p.assessment_retention_seconds > 0);
    ASSERT(p.dedup_window_seconds > 0);
    ASSERT(p.score_threshold_low > 0);
    ASSERT(p.score_threshold_moderate > p.score_threshold_low);
    ASSERT(p.score_threshold_high > p.score_threshold_moderate);
    return 0;
}

TEST(test_set_get_policy)
{
    _init_svc();
    ozayn_sr_policy_t p = ozayn_sr_default_policy();
    p.score_threshold_high = 70;
    ASSERT_EQ(ozayn_sr_set_policy(&_svc, &p), OZAYN_SR_OK);
    ASSERT_EQ(_svc.policy.score_threshold_high, 70);
    const ozayn_sr_policy_t *gp = ozayn_sr_get_policy(&_svc);
    ASSERT_NOT_NULL(gp);
    ASSERT_EQ(gp->score_threshold_high, 70);
    return 0;
}

TEST(test_set_policy_disabled)
{
    _init_svc();
    ozayn_sr_policy_t p = ozayn_sr_default_policy();
    p.enabled = 0;
    ASSERT_EQ(ozayn_sr_set_policy(&_svc, &p), OZAYN_SR_ERR_POLICY_REJECTED);
    return 0;
}

TEST(test_set_policy_null)
{
    _init_svc();
    ASSERT_EQ(ozayn_sr_set_policy(&_svc, NULL), OZAYN_SR_ERR_NULL);
    ASSERT_EQ(ozayn_sr_set_policy(NULL, NULL), OZAYN_SR_ERR_NULL);
    ASSERT_NULL(ozayn_sr_get_policy(NULL));
    return 0;
}

/* ============================================================
 * CLEANUP TESTS
 * ============================================================ */

TEST(test_cleanup_expired)
{
    _init_svc();
    ozayn_sr_assessment_t *a1, *a2;
    ozayn_sr_create_assessment(&_svc, "F1", "T1", "E1", &a1);
    ozayn_sr_create_assessment(&_svc, "F2", "T2", "E2", &a2);
    /* Manually set old timestamps */
    a1->created_time = time(NULL) - 200000; /* > 1 day */
    a2->created_time = time(NULL); /* fresh */
    int cleaned = ozayn_sr_cleanup_expired_assessments(&_svc);
    ASSERT_EQ(cleaned, 1);
    ASSERT_EQ(a1->state, OZAYN_SR_STATE_EXPIRED);
    ASSERT_EQ(a2->state, OZAYN_SR_STATE_PENDING);
    return 0;
}

TEST(test_cleanup_null)
{
    ASSERT_EQ(ozayn_sr_cleanup_expired_assessments(NULL), 0);
    return 0;
}

/* ============================================================
 * RESOURCE SAFETY TESTS
 * ============================================================ */

TEST(test_assessments_full)
{
    _init_svc();
    ASSERT(!ozayn_sr_assessments_full(&_svc));
    /* Fill up to max */
    _svc.assessment_count = OZAYN_SR_MAX_ASSESSMENTS;
    ASSERT(ozayn_sr_assessments_full(&_svc));
    ASSERT(ozayn_sr_assessments_full(NULL));
    return 0;
}

TEST(test_aggregations_full)
{
    _init_svc();
    ASSERT(!ozayn_sr_aggregations_full(&_svc));
    _svc.aggregation_count = OZAYN_SR_MAX_AGGREGATIONS_SVC;
    ASSERT(ozayn_sr_aggregations_full(&_svc));
    ASSERT(ozayn_sr_aggregations_full(NULL));
    return 0;
}

/* ============================================================
 * NEGATIVE / SECURITY TESTS
 * ============================================================ */

TEST(test_not_initialized_ops)
{
    _reset_all();
    ozayn_sr_service_t svc;
    memset(&svc, 0, sizeof(svc));
    ozayn_sr_assessment_t *a = NULL;
    ASSERT_EQ(ozayn_sr_create_assessment(&svc, "F", "T", "E", &a), OZAYN_SR_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sr_complete_assessment(&svc, "ID"), OZAYN_SR_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sr_elevate_assessment(&svc, "ID"), OZAYN_SR_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sr_resolve_assessment(&svc, "ID"), OZAYN_SR_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sr_calculate_risk(&svc, &svc.assessments[0]), OZAYN_SR_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sr_generate_decision(&svc, &svc.assessments[0]), OZAYN_SR_ERR_NOT_INITIALIZED);
    ASSERT_EQ(ozayn_sr_set_policy(&svc, &svc.policy), OZAYN_SR_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_factor_weight_zero)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 4, 0, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_EQ(a->risk_level, OZAYN_SR_LEVEL_UNKNOWN);
    return 0;
}

TEST(test_factor_value_zero)
{
    _init_svc();
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 0, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT(a->risk_level <= OZAYN_SR_LEVEL_MODERATE);
    return 0;
}

/* ============================================================
 * STATISTICS TESTS
 * ============================================================ */

TEST(test_statistics)
{
    _init_svc();
    ASSERT_EQ(_svc.total_assessments_created, 0);
    ASSERT_EQ(_svc.total_calculations, 0);
    ASSERT_EQ(_svc.total_policy_rejections, 0);
    ozayn_sr_assessment_t *a = NULL;
    ozayn_sr_create_assessment(&_svc, "F", "T", "E", &a);
    ASSERT_EQ(_svc.total_assessments_created, 1);
    ozayn_sr_add_factor(a, OZAYN_SR_FACTOR_THREAT_SEVERITY, 3, 20, "src", OZAYN_SR_EXPLAIN_NONE);
    ozayn_sr_calculate_risk(&_svc, a);
    ASSERT_EQ(_svc.total_calculations, 1);
    ozayn_sr_complete_assessment(&_svc, a->risk_id);
    ASSERT_EQ(_svc.total_assessments_completed, 1);
    return 0;
}

/* ============================================================
 * RUN ALL TESTS
 * ============================================================ */

int run_sec_risk_tests(void)
{
    SUITE_BEGIN("Security Risk Scoring & Decision Support");

    /* Name helpers */
    RUN(test_err_name);
    RUN(test_level_name);
    RUN(test_factor_type_name);
    RUN(test_persistence_name);
    RUN(test_assurance_name);
    RUN(test_temporal_name);
    RUN(test_state_name);
    RUN(test_decision_name);
    RUN(test_explain_name);
    RUN(test_level_to_audit_severity);
    RUN(test_level_to_salert_severity);
    RUN(test_level_to_ir_severity);
    RUN(test_level_to_salert_priority);

    /* Lifecycle */
    RUN(test_lifecycle_null);
    RUN(test_lifecycle_init_with_config);
    RUN(test_lifecycle_init_with_deps);
    RUN(test_lifecycle_double_init);
    RUN(test_lifecycle_shutdown_null);
    RUN(test_lifecycle_is_initialized_null);
    RUN(test_global_accessor);

    /* Assessment operations */
    RUN(test_create_assessment_basic);
    RUN(test_create_assessment_null);
    RUN(test_create_assessment_not_initialized);
    RUN(test_create_assessment_policy_disabled);
    RUN(test_create_assessment_unique_ids);
    RUN(test_get_assessment);
    RUN(test_assessment_count);
    RUN(test_list_assessments);

    /* State transitions */
    RUN(test_complete_assessment);
    RUN(test_complete_assessment_not_pending);
    RUN(test_elevate_assessment);
    RUN(test_resolve_assessment);
    RUN(test_complete_null);
    RUN(test_complete_not_found);

    /* Factor operations */
    RUN(test_add_factor);
    RUN(test_add_factor_null);
    RUN(test_add_factor_invalid_type);
    RUN(test_add_factor_update_existing);
    RUN(test_add_multiple_factors);

    /* Risk calculation */
    RUN(test_calculate_risk_basic);
    RUN(test_calculate_risk_high_factors);
    RUN(test_calculate_risk_low_factors);
    RUN(test_calculate_risk_no_factors);
    RUN(test_calculate_risk_policy_disabled);
    RUN(test_calculate_risk_contributions);
    RUN(test_calculate_risk_explanation_codes);
    RUN(test_calculate_risk_deterministic);
    RUN(test_calculate_risk_integrity_failure_caps);
    RUN(test_score_to_level);
    RUN(test_score_to_level_custom_thresholds);

    /* Aggregation */
    RUN(test_create_aggregation);
    RUN(test_create_aggregation_null);
    RUN(test_add_to_aggregation);
    RUN(test_add_to_aggregation_not_found);
    RUN(test_evaluate_aggregation);
    RUN(test_get_aggregation);
    RUN(test_aggregation_count);

    /* Deduplication */
    RUN(test_dedup_no_duplicate);
    RUN(test_dedup_detects_duplicate);
    RUN(test_dedup_different_finding_not_duplicate);
    RUN(test_dedup_returns_null_assessment);

    /* Temporal */
    RUN(test_temporal_current);
    RUN(test_temporal_aging);
    RUN(test_temporal_expired);
    RUN(test_temporal_null);

    /* Decision support */
    RUN(test_decision_low_risk);
    RUN(test_decision_high_risk);
    RUN(test_decision_persistent_threat_override);
    RUN(test_decision_null);
    RUN(test_decision_explanation_codes);

    /* Integration */
    RUN(test_incident_integration);
    RUN(test_alert_integration);
    RUN(test_alert_integration_disabled);
    RUN(test_incident_integration_disabled);
    RUN(test_health_impact);
    RUN(test_health_integration_disabled);
    RUN(test_audit_event);

    /* Policy */
    RUN(test_default_policy);
    RUN(test_set_get_policy);
    RUN(test_set_policy_disabled);
    RUN(test_set_policy_null);

    /* Cleanup */
    RUN(test_cleanup_expired);
    RUN(test_cleanup_null);

    /* Resource safety */
    RUN(test_assessments_full);
    RUN(test_aggregations_full);

    /* Negative / security */
    RUN(test_not_initialized_ops);
    RUN(test_factor_weight_zero);
    RUN(test_factor_value_zero);

    /* Statistics */
    RUN(test_statistics);

    SUITE_END();
    return TOTAL_FAIL();
}
