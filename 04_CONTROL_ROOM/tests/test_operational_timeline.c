/*
 * test_operational_timeline.c — Section 04, Step 25
 * Runtime Event Correlation & Operational Timeline Foundation tests
 */

#include "../../tests/test_framework.h"
#include "../operational_timeline.h"
#include <string.h>

/* ============================================================
 * HELPERS
 * ============================================================ */

static ozayn_otl_event_t _make_event(uint64_t id,
                                     ozayn_otl_category_t cat,
                                     ozayn_otl_severity_t sev,
                                     const char *type_name,
                                     const char *src,
                                     const char *op_id,
                                     const char *req_id,
                                     const char *tgt,
                                     const char *desc) {
    ozayn_otl_event_t e;
    memset(&e, 0, sizeof(e));
    e.event_id = id;
    e.category = cat;
    e.severity = sev;
    e.state = OZAYN_OTL_EVT_NORMAL;
    if (type_name) strncpy(e.event_type_name, type_name, OZAYN_OTL_MAX_MSG_LEN - 1);
    if (src) strncpy(e.source_component_id, src, OZAYN_OTL_MAX_ID_LEN - 1);
    if (op_id) strncpy(e.operation_id, op_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (req_id) strncpy(e.request_id, req_id, OZAYN_OTL_MAX_ID_LEN - 1);
    if (tgt) strncpy(e.target_component_id, tgt, OZAYN_OTL_MAX_ID_LEN - 1);
    if (desc) strncpy(e.description, desc, OZAYN_OTL_MAX_MSG_LEN - 1);
    e.occurrence_time = 1000;
    e.ingestion_time = 1001;
    e.correlation_confidence = OZAYN_OTL_CORR_UNKNOWN;
    e.active = 1;
    return e;
}

static ozayn_otl_service_t _make_svc(void) {
    ozayn_otl_service_t svc;
    memset(&svc, 0, sizeof(svc));
    return svc;
}

/* ============================================================
 * LIFECYCLE TESTS
 * ============================================================ */

TEST(test_otl_init_null) {
    ASSERT_EQ(ozayn_otl_init(NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_init_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_otl_init(&svc), OZAYN_OTL_ERR_OK);
    ASSERT(svc.initialized);
    ASSERT_EQ(svc.event_count, 0);
    ASSERT_EQ(svc.timeline_count, 0);
    ASSERT_EQ(svc.edge_count, 0);
    return 0;
}

TEST(test_otl_init_double) {
    ozayn_otl_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_otl_init(&svc), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(ozayn_otl_init(&svc), OZAYN_OTL_ERR_ALREADY_INITIALIZED);
    return 0;
}

TEST(test_otl_shutdown_null) {
    ASSERT_EQ(ozayn_otl_shutdown(NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_shutdown_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_otl_shutdown(&svc), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_shutdown_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_otl_init(&svc), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(ozayn_otl_shutdown(&svc), OZAYN_OTL_ERR_OK);
    ASSERT(!svc.initialized);
    return 0;
}

TEST(test_otl_is_init_null) {
    ASSERT(!ozayn_otl_is_initialized(NULL));
    return 0;
}

TEST(test_otl_is_init_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ASSERT(!ozayn_otl_is_initialized(&svc));
    ozayn_otl_init(&svc);
    ASSERT(ozayn_otl_is_initialized(&svc));
    return 0;
}

/* ============================================================
 * NAME HELPER TESTS
 * ============================================================ */

TEST(test_otl_err_name_all) {
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_OK), "OK") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_NULL_PTR), "NULL_PTR") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_NOT_INITIALIZED), "NOT_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_ALREADY_INITIALIZED), "ALREADY_INITIALIZED") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_INVALID_ID), "INVALID_ID") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_NOT_FOUND), "NOT_FOUND") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_DUPLICATE), "DUPLICATE") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_FULL), "FULL") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_INVALID_STATE), "INVALID_STATE") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_INVALID_TRANSITION), "INVALID_TRANSITION") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_INVALID_EVENT), "INVALID_EVENT") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_CORRELATION_FAILED), "CORRELATION_FAILED") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_QUERY_INVALID), "QUERY_INVALID") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_QUERY_LIMIT), "QUERY_LIMIT") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_STORAGE_ERROR), "STORAGE_ERROR") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_SUBSYSTEM_UNAVAILABLE), "SUBSYSTEM_UNAVAILABLE") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_UNAUTHORIZED), "UNAUTHORIZED") == 0);
    ASSERT(strcmp(ozayn_otl_err_name(OZAYN_OTL_ERR_INTERNAL), "INTERNAL") == 0);
    return 0;
}

TEST(test_otl_category_name_all) {
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_SYSTEM), "SYSTEM") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_STARTUP), "STARTUP") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_SHUTDOWN), "SHUTDOWN") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_LIFECYCLE), "LIFECYCLE") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_COMPONENT), "COMPONENT") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_CAPABILITY), "CAPABILITY") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_OPERATION), "OPERATION") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_QUEUE), "QUEUE") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_SCHEDULER), "SCHEDULER") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_WORKFLOW), "WORKFLOW") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_PIPELINE), "PIPELINE") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_ADMISSION), "ADMISSION") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_ENFORCEMENT), "ENFORCEMENT") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_EXECUTION), "EXECUTION") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_RECONCILIATION), "RECONCILIATION") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_RESOURCE), "RESOURCE") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_DEVICE), "DEVICE") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_IO), "IO") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_SECURITY), "SECURITY") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_SAFETY), "SAFETY") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_DIAGNOSTIC), "DIAGNOSTIC") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_RECOVERY), "RECOVERY") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_CONFIGURATION), "CONFIGURATION") == 0);
    ASSERT(strcmp(ozayn_otl_category_name(OZAYN_OTL_CAT_ERROR), "ERROR") == 0);
    return 0;
}

TEST(test_otl_severity_name_all) {
    ASSERT(strcmp(ozayn_otl_severity_name(OZAYN_OTL_SEV_INFO), "INFO") == 0);
    ASSERT(strcmp(ozayn_otl_severity_name(OZAYN_OTL_SEV_LOW), "LOW") == 0);
    ASSERT(strcmp(ozayn_otl_severity_name(OZAYN_OTL_SEV_MEDIUM), "MEDIUM") == 0);
    ASSERT(strcmp(ozayn_otl_severity_name(OZAYN_OTL_SEV_HIGH), "HIGH") == 0);
    ASSERT(strcmp(ozayn_otl_severity_name(OZAYN_OTL_SEV_CRITICAL), "CRITICAL") == 0);
    return 0;
}

TEST(test_otl_relationship_name_all) {
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_NONE), "NONE") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_PARENT), "PARENT") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_CHILD), "CHILD") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_PRECEDES), "PRECEDES") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_FOLLOWS), "FOLLOWS") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_CAUSED_BY), "CAUSED_BY") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_RESULT_OF), "RESULT_OF") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_PART_OF), "PART_OF") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_RETRY_OF), "RETRY_OF") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_COMPENSATES), "COMPENSATES") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_RECONCILES), "RECONCILES") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_DEPENDS_ON), "DEPENDS_ON") == 0);
    ASSERT(strcmp(ozayn_otl_relationship_name(OZAYN_OTL_REL_AFFECTS), "AFFECTS") == 0);
    return 0;
}

TEST(test_otl_confidence_name_all) {
    ASSERT(strcmp(ozayn_otl_confidence_name(OZAYN_OTL_CORR_EXACT), "EXACT") == 0);
    ASSERT(strcmp(ozayn_otl_confidence_name(OZAYN_OTL_CORR_EXPLICIT), "EXPLICIT") == 0);
    ASSERT(strcmp(ozayn_otl_confidence_name(OZAYN_OTL_CORR_DERIVED), "DERIVED") == 0);
    ASSERT(strcmp(ozayn_otl_confidence_name(OZAYN_OTL_CORR_PARTIAL), "PARTIAL") == 0);
    ASSERT(strcmp(ozayn_otl_confidence_name(OZAYN_OTL_CORR_UNKNOWN), "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_otl_confidence_name(OZAYN_OTL_CORR_INVALID), "INVALID") == 0);
    return 0;
}

TEST(test_otl_tl_state_name_all) {
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_CREATED), "CREATED") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_ACTIVE), "ACTIVE") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_COMPLETED), "COMPLETED") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_FAILED), "FAILED") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_PARTIAL), "PARTIAL") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_CANCELLED), "CANCELLED") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_EXPIRED), "EXPIRED") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_UNKNOWN), "UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_otl_timeline_state_name(OZAYN_OTL_TL_UNAVAILABLE), "UNAVAILABLE") == 0);
    return 0;
}

TEST(test_otl_evt_state_name_all) {
    ASSERT(strcmp(ozayn_otl_event_state_name(OZAYN_OTL_EVT_NORMAL), "NORMAL") == 0);
    ASSERT(strcmp(ozayn_otl_event_state_name(OZAYN_OTL_EVT_DUPLICATE_DETECTED), "DUPLICATE_DETECTED") == 0);
    ASSERT(strcmp(ozayn_otl_event_state_name(OZAYN_OTL_EVT_OUT_OF_ORDER), "OUT_OF_ORDER") == 0);
    ASSERT(strcmp(ozayn_otl_event_state_name(OZAYN_OTL_EVT_LATE_ARRIVAL), "LATE_ARRIVAL") == 0);
    ASSERT(strcmp(ozayn_otl_event_state_name(OZAYN_OTL_EVT_INCONSISTENCY_DETECTED), "INCONSISTENCY_DETECTED") == 0);
    return 0;
}

TEST(test_otl_emit_type_name_all) {
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_TIMELINE_CREATED), "TIMELINE_CREATED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_TIMELINE_UPDATED), "TIMELINE_UPDATED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_TIMELINE_COMPLETED), "TIMELINE_COMPLETED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_TIMELINE_FAILED), "TIMELINE_FAILED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_TIMELINE_PARTIAL), "TIMELINE_PARTIAL") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_TIMELINE_EXPIRED), "TIMELINE_EXPIRED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_CORRELATION_STARTED), "CORRELATION_STARTED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_CORRELATED), "CORRELATED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_CORRELATION_PARTIAL), "CORRELATION_PARTIAL") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_CORRELATION_UNKNOWN), "CORRELATION_UNKNOWN") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_CORRELATION_INVALID), "CORRELATION_INVALID") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_DUPLICATE_DETECTED), "DUPLICATE_DETECTED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_OUT_OF_ORDER), "OUT_OF_ORDER") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_LATE_ARRIVAL), "LATE_ARRIVAL") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_INCONSISTENCY_DETECTED), "INCONSISTENCY_DETECTED") == 0);
    ASSERT(strcmp(ozayn_otl_emit_type_name(OZAYN_OTL_EVENT_RECONCILIATION_REQUIRED), "RECONCILIATION_REQUIRED") == 0);
    return 0;
}

/* ============================================================
 * SUBSYSTEM BINDING TESTS
 * ============================================================ */

TEST(test_otl_bind_null) {
    ASSERT_EQ(ozayn_otl_bind_subsystems(NULL, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_bind_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_subsystem_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    ASSERT_EQ(ozayn_otl_bind_subsystems(&svc, &bind), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_bind_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_subsystem_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    ASSERT_EQ(ozayn_otl_bind_subsystems(&svc, &bind), OZAYN_OTL_ERR_OK);
    return 0;
}

/* ============================================================
 * EVENT INGESTION TESTS
 * ============================================================ */

TEST(test_otl_event_ingest_null) {
    ASSERT_EQ(ozayn_otl_event_ingest(NULL, NULL, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_event_ingest_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    ASSERT_EQ(ozayn_otl_event_ingest(&svc, &e, NULL), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_event_ingest_inactive) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    e.active = 0;
    ASSERT_EQ(ozayn_otl_event_ingest(&svc, &e, NULL), OZAYN_OTL_ERR_INVALID_EVENT);
    return 0;
}

TEST(test_otl_event_ingest_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    uint64_t id = 0;
    ASSERT_EQ(ozayn_otl_event_ingest(&svc, &e, &id), OZAYN_OTL_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.event_count, 1);
    ASSERT_EQ(svc.stats.total_events_ingested, 1);
    ASSERT_EQ(svc.stats.current_events_stored, 1);
    return 0;
}

TEST(test_otl_event_ingest_simple_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t id = 0;
    ASSERT_EQ(ozayn_otl_event_ingest_simple(&svc, OZAYN_OTL_CAT_STARTUP, OZAYN_OTL_SEV_LOW, "boot", "sys", "op1", "req1", "tgt", "booting", 1000, &id), OZAYN_OTL_ERR_OK);
    ASSERT(id > 0);
    ASSERT_EQ(svc.event_count, 1);
    return 0;
}

TEST(test_otl_event_ingest_simple_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    uint64_t id = 0;
    ASSERT_EQ(ozayn_otl_event_ingest_simple(&svc, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "t", "s", "o", "r", "d", "d", 0, &id), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_event_ingest_multiple) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    for (uint64_t i = 0; i < 10; i++) {
        ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
        ASSERT_EQ(ozayn_otl_event_ingest(&svc, &e, NULL), OZAYN_OTL_ERR_OK);
    }
    ASSERT_EQ(svc.event_count, 10);
    ASSERT_EQ(svc.stats.total_events_ingested, 10);
    ASSERT_EQ(svc.stats.current_events_stored, 10);
    return 0;
}

TEST(test_otl_event_ingest_sequence_increments) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t id1 = 0, id2 = 0, id3 = 0;
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e3 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "c", "s", "o", "r", "d", "d");
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_event_ingest(&svc, &e3, &id3);
    ASSERT(id1 > 0);
    ASSERT(id2 > id1);
    ASSERT(id3 > id2);
    return 0;
}

TEST(test_otl_event_ingest_fixed_id) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(999, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &e, &id);
    ASSERT_EQ(id, 999);
    return 0;
}

TEST(test_otl_event_ingest_incr_not_assign) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(5, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &e, &id);
    ASSERT_EQ(id, 5);
    ozayn_otl_event_t e2 = _make_event(10, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    uint64_t id2 = 0;
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ASSERT_EQ(id2, 10);
    return 0;
}

/* ============================================================
 * EVENT GET TESTS
 * ============================================================ */

TEST(test_otl_event_get_null) {
    ASSERT_EQ(ozayn_otl_event_get(NULL, 1, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_event_get_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    const ozayn_otl_event_t *e = 0;
    ASSERT_EQ(ozayn_otl_event_get(&svc, 1, &e), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_event_get_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    const ozayn_otl_event_t *e = 0;
    ASSERT_EQ(ozayn_otl_event_get(&svc, 999, &e), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_event_get_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t ev = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "op1", "req1", "tgt", "desc");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &ev, &id);
    const ozayn_otl_event_t *got = 0;
    ASSERT_EQ(ozayn_otl_event_get(&svc, id, &got), OZAYN_OTL_ERR_OK);
    ASSERT(got != 0);
    ASSERT_EQ(got->event_id, id);
    ASSERT(got->active);
    return 0;
}

/* ============================================================
 * EVENT QUERY TESTS
 * ============================================================ */

TEST(test_otl_event_by_operation_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "op1", "r1", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "op2", "r1", "d", "d");
    ozayn_otl_event_t e3 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "c", "s", "op1", "r1", "d", "d");
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    ozayn_otl_event_ingest(&svc, &e3, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_operation(&svc, "op1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 2);
    return 0;
}

TEST(test_otl_event_by_operation_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_operation(&svc, "op1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(test_otl_event_by_request_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "req1", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "req2", "d", "d");
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_request(&svc, "req1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_event_by_correlation_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    uint64_t id1 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_set_correlation(&svc, id1, "corr1", OZAYN_OTL_CORR_EXACT);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_correlation(&svc, "corr1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_event_by_category_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_STARTUP, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SHUTDOWN, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_category(&svc, OZAYN_OTL_CAT_STARTUP, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_event_by_component_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "compA", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "compB", "o", "r", "d", "d");
    ozayn_otl_event_t e3 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "c", "s", "o", "r", "compA", "d");
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    ozayn_otl_event_ingest(&svc, &e3, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_component(&svc, "compA", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 2);
    return 0;
}

TEST(test_otl_event_by_severity_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_HIGH, "b", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e3 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_CRITICAL, "c", "s", "o", "r", "d", "d");
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    ozayn_otl_event_ingest(&svc, &e3, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_severity(&svc, OZAYN_OTL_SEV_HIGH, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 2);
    return 0;
}

TEST(test_otl_event_by_time_range_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    e1.occurrence_time = 100;
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    e2.occurrence_time = 200;
    ozayn_otl_event_t e3 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "c", "s", "o", "r", "d", "d");
    e3.occurrence_time = 300;
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    ozayn_otl_event_ingest(&svc, &e3, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_by_time_range(&svc, 150, 250, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_event_get_recent_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    for (uint64_t i = 0; i < 5; i++) {
        ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
        ozayn_otl_event_ingest(&svc, &e, NULL);
    }
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_recent(&svc, 3, results, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 3);
    return 0;
}

TEST(test_otl_event_get_recent_null) {
    ASSERT_EQ(ozayn_otl_event_get_recent(NULL, 5, NULL, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_event_get_recent_more_than_available) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    ozayn_otl_event_ingest(&svc, &e, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_event_get_recent(&svc, 100, results, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

/* ============================================================
 * DUPLICATE DETECTION TESTS
 * ============================================================ */

TEST(test_otl_duplicate_check_same_id) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "o", "r", "d", "d");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &e, &id);
    ASSERT(ozayn_otl_event_get_duplicate_check(&svc, id, "src", 0));
    return 0;
}

TEST(test_otl_duplicate_check_different_id) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "o", "r", "d", "d");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &e, &id);
    ASSERT(!ozayn_otl_event_get_duplicate_check(&svc, id + 1, "other", 99));
    return 0;
}

TEST(test_otl_duplicate_check_sequence) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "o", "r", "d", "d");
    e.source_sequence = 42;
    ozayn_otl_event_ingest(&svc, &e, NULL);
    ASSERT(ozayn_otl_event_get_duplicate_check(&svc, 0, "src", 42));
    ASSERT(!ozayn_otl_event_get_duplicate_check(&svc, 0, "src", 43));
    return 0;
}

/* ============================================================
 * EVENT MODIFICATION TESTS
 * ============================================================ */

TEST(test_otl_event_set_correlation_null) {
    ASSERT_EQ(ozayn_otl_event_set_correlation(NULL, 1, "c", OZAYN_OTL_CORR_EXACT), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_event_set_correlation_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "src", "o", "r", "d", "d");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &e, &id);
    ASSERT_EQ(ozayn_otl_event_set_correlation(&svc, id, "corr1", OZAYN_OTL_CORR_EXACT), OZAYN_OTL_ERR_OK);
    const ozayn_otl_event_t *got = 0;
    ozayn_otl_event_get(&svc, id, &got);
    ASSERT(strcmp(got->correlation_id, "corr1") == 0);
    ASSERT(got->has_correlation_id);
    ASSERT_EQ(got->correlation_confidence, OZAYN_OTL_CORR_EXACT);
    return 0;
}

TEST(test_otl_event_set_correlation_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_event_set_correlation(&svc, 999, "c", OZAYN_OTL_CORR_EXACT), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_event_set_parent_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ASSERT_EQ(ozayn_otl_event_set_parent(&svc, id2, id1, OZAYN_OTL_REL_CHILD), OZAYN_OTL_ERR_OK);
    const ozayn_otl_event_t *got = 0;
    ozayn_otl_event_get(&svc, id2, &got);
    ASSERT(got->has_parent);
    return 0;
}

TEST(test_otl_event_set_parent_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_event_set_parent(&svc, 999, 1, OZAYN_OTL_REL_CHILD), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_event_set_description_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    uint64_t id = 0;
    ozayn_otl_event_ingest(&svc, &e, &id);
    ASSERT_EQ(ozayn_otl_event_set_description(&svc, id, "new desc"), OZAYN_OTL_ERR_OK);
    const ozayn_otl_event_t *got = 0;
    ozayn_otl_event_get(&svc, id, &got);
    ASSERT(strcmp(got->description, "new desc") == 0);
    return 0;
}

TEST(test_otl_event_set_description_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_event_set_description(&svc, 999, "d"), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

/* ============================================================
 * RELATIONSHIP TESTS
 * ============================================================ */

TEST(test_otl_rel_add_null) {
    ASSERT_EQ(ozayn_otl_relationship_add(NULL, 1, 2, OZAYN_OTL_REL_PARENT, OZAYN_OTL_CORR_EXACT, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_rel_add_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    uint64_t edge_id = 0;
    ASSERT_EQ(ozayn_otl_relationship_add(&svc, id1, id2, OZAYN_OTL_REL_PARENT, OZAYN_OTL_CORR_EXACT, &edge_id), OZAYN_OTL_ERR_OK);
    ASSERT(svc.edge_count == 1);
    return 0;
}

TEST(test_otl_rel_add_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_relationship_add(&svc, 1, 2, OZAYN_OTL_REL_CHILD, OZAYN_OTL_CORR_EXACT, NULL), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_rel_get_by_event_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_relationship_add(&svc, id1, id2, OZAYN_OTL_REL_PARENT, OZAYN_OTL_CORR_EXACT, NULL);
    const ozayn_otl_edge_t *edges[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_relationship_get_by_event(&svc, id1, edges, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_rel_get_by_event_null) {
    ASSERT_EQ(ozayn_otl_relationship_get_by_event(NULL, 1, NULL, 0, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

/* ============================================================
 * TIMELINE TESTS
 * ============================================================ */

TEST(test_otl_tl_create_null) {
    ASSERT_EQ(ozayn_otl_timeline_create(NULL, NULL, NULL, NULL, NULL, NULL, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_tl_create_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    ASSERT_EQ(ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, NULL), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_tl_create_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ASSERT_EQ(ozayn_otl_timeline_create(&svc, "corr1", "op1", "req1", "wf1", "pl1", &tl_id), OZAYN_OTL_ERR_OK);
    ASSERT(tl_id > 0);
    ASSERT_EQ(svc.timeline_count, 1);
    ASSERT_EQ(svc.stats.total_timelines_created, 1);
    return 0;
}

TEST(test_otl_tl_create_duplicate) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, NULL), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, NULL), OZAYN_OTL_ERR_DUPLICATE);
    return 0;
}

TEST(test_otl_tl_add_event_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    uint64_t evt_id = 0;
    ozayn_otl_event_ingest(&svc, &e, &evt_id);
    ASSERT_EQ(ozayn_otl_timeline_add_event(&svc, tl_id, evt_id), OZAYN_OTL_ERR_OK);
    const ozayn_otl_timeline_t *tl = 0;
    ozayn_otl_timeline_get(&svc, tl_id, &tl);
    ASSERT_EQ(tl->event_ref_count, 1);
    ASSERT_EQ(tl->root_event_id, evt_id);
    ASSERT_EQ(tl->state, OZAYN_OTL_TL_ACTIVE);
    return 0;
}

TEST(test_otl_tl_add_event_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_timeline_add_event(&svc, 999, 1), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_tl_add_event_null) {
    ASSERT_EQ(ozayn_otl_timeline_add_event(NULL, 1, 2), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_tl_complete_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    ASSERT_EQ(ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_COMPLETED), OZAYN_OTL_ERR_OK);
    const ozayn_otl_timeline_t *tl = 0;
    ozayn_otl_timeline_get(&svc, tl_id, &tl);
    ASSERT_EQ(tl->state, OZAYN_OTL_TL_COMPLETED);
    ASSERT(tl->end_time > 0);
    ASSERT_EQ(svc.stats.current_active_timelines, 0);
    ASSERT_EQ(svc.stats.total_timelines_completed, 1);
    return 0;
}

TEST(test_otl_tl_complete_failed) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    ASSERT_EQ(ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_FAILED), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(svc.stats.total_timelines_failed, 1);
    return 0;
}

TEST(test_otl_tl_complete_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_timeline_complete(&svc, 999, OZAYN_OTL_TL_COMPLETED), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_tl_complete_already_done) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_COMPLETED);
    ASSERT_EQ(ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_COMPLETED), OZAYN_OTL_ERR_INVALID_STATE);
    return 0;
}

/* ============================================================
 * TIMELINE QUERY TESTS
 * ============================================================ */

TEST(test_otl_tl_get_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", "op1", "req1", "wf1", "pl1", &tl_id);
    const ozayn_otl_timeline_t *tl = 0;
    ASSERT_EQ(ozayn_otl_timeline_get(&svc, tl_id, &tl), OZAYN_OTL_ERR_OK);
    ASSERT(tl != 0);
    ASSERT_EQ(tl->timeline_id, tl_id);
    ASSERT(strcmp(tl->correlation_id, "corr1") == 0);
    ASSERT(strcmp(tl->operation_id, "op1") == 0);
    ASSERT(strcmp(tl->request_id, "req1") == 0);
    ASSERT(strcmp(tl->workflow_id, "wf1") == 0);
    ASSERT(strcmp(tl->pipeline_id, "pl1") == 0);
    return 0;
}

TEST(test_otl_tl_get_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    const ozayn_otl_timeline_t *tl = 0;
    ASSERT_EQ(ozayn_otl_timeline_get(&svc, 999, &tl), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_tl_get_null) {
    ASSERT_EQ(ozayn_otl_timeline_get(NULL, 1, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_tl_get_by_corr_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, NULL);
    ozayn_otl_timeline_create(&svc, "corr2", NULL, NULL, NULL, NULL, NULL);
    const ozayn_otl_timeline_t *tl = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_by_correlation(&svc, "corr1", &tl), OZAYN_OTL_ERR_OK);
    ASSERT(strcmp(tl->correlation_id, "corr1") == 0);
    return 0;
}

TEST(test_otl_tl_get_by_corr_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    const ozayn_otl_timeline_t *tl = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_by_correlation(&svc, "nope", &tl), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_tl_get_by_op_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_timeline_create(&svc, "c1", "op1", NULL, NULL, NULL, NULL);
    ozayn_otl_timeline_create(&svc, "c2", "op2", NULL, NULL, NULL, NULL);
    const ozayn_otl_timeline_t *tl = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_by_operation(&svc, "op1", &tl), OZAYN_OTL_ERR_OK);
    ASSERT(strcmp(tl->operation_id, "op1") == 0);
    return 0;
}

TEST(test_otl_tl_get_active_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl1 = 0, tl2 = 0;
    ozayn_otl_timeline_create(&svc, "c1", NULL, NULL, NULL, NULL, &tl1);
    ozayn_otl_timeline_create(&svc, "c2", NULL, NULL, NULL, NULL, &tl2);
    ozayn_otl_timeline_complete(&svc, tl1, OZAYN_OTL_TL_COMPLETED);
    const ozayn_otl_timeline_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_active(&svc, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

/* ============================================================
 * TIMELINE EVENT CHAIN TESTS
 * ============================================================ */

TEST(test_otl_tl_get_events_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_timeline_add_event(&svc, tl_id, id1);
    ozayn_otl_timeline_add_event(&svc, tl_id, id2);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_events(&svc, tl_id, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 2);
    return 0;
}

TEST(test_otl_tl_get_events_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_events(&svc, 999, results, 10, &count), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_tl_get_operation_chain_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_OPERATION, OZAYN_OTL_SEV_INFO, "a", "s", "op1", "req1", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_OPERATION, OZAYN_OTL_SEV_INFO, "b", "s", "op1", "req1", "d", "d");
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_operation_chain(&svc, "req1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 2);
    return 0;
}

TEST(test_otl_tl_get_workflow_chain_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_WORKFLOW, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    strncpy(e1.workflow_id, "wf1", OZAYN_OTL_MAX_ID_LEN - 1);
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_WORKFLOW, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    strncpy(e2.workflow_id, "wf2", OZAYN_OTL_MAX_ID_LEN - 1);
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_workflow_chain(&svc, "wf1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_tl_get_pipeline_chain_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_PIPELINE, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    strncpy(e1.pipeline_id, "pl1", OZAYN_OTL_MAX_ID_LEN - 1);
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_PIPELINE, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    strncpy(e2.pipeline_id, "pl2", OZAYN_OTL_MAX_ID_LEN - 1);
    ozayn_otl_event_ingest(&svc, &e1, NULL);
    ozayn_otl_event_ingest(&svc, &e2, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_pipeline_chain(&svc, "pl1", results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

/* ============================================================
 * CHILDREN / PREDECESSORS / SUCCESSORS
 * ============================================================ */

TEST(test_otl_tl_get_children_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_relationship_add(&svc, id1, id2, OZAYN_OTL_REL_CHILD, OZAYN_OTL_CORR_EXACT, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_children(&svc, id1, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_tl_get_predecessors_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_relationship_add(&svc, id1, id2, OZAYN_OTL_REL_FOLLOWS, OZAYN_OTL_CORR_EXACT, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_predecessors(&svc, id2, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_tl_get_successors_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_relationship_add(&svc, id1, id2, OZAYN_OTL_REL_PRECEDES, OZAYN_OTL_CORR_EXACT, NULL);
    const ozayn_otl_event_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_timeline_get_successors(&svc, id1, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

/* ============================================================
 * CONSISTENCY CHECK TESTS
 * ============================================================ */

TEST(test_otl_consistency_null) {
    ASSERT_EQ(ozayn_otl_consistency_check(NULL, 1, NULL, NULL, 0), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_consistency_not_init) {
    ozayn_otl_service_t svc = _make_svc();
    int consistent = 0;
    ASSERT_EQ(ozayn_otl_consistency_check(&svc, 1, &consistent, NULL, 0), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_consistency_not_found) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    int consistent = 0;
    ASSERT_EQ(ozayn_otl_consistency_check(&svc, 999, &consistent, NULL, 0), OZAYN_OTL_ERR_NOT_FOUND);
    return 0;
}

TEST(test_otl_consistency_created_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    int consistent = 0;
    char issue[256] = {0};
    ASSERT_EQ(ozayn_otl_consistency_check(&svc, tl_id, &consistent, issue, sizeof(issue)), OZAYN_OTL_ERR_OK);
    ASSERT(consistent);
    return 0;
}

TEST(test_otl_consistency_completed_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "corr1", NULL, NULL, NULL, NULL, &tl_id);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    uint64_t evt_id = 0;
    ozayn_otl_event_ingest(&svc, &e, &evt_id);
    ozayn_otl_timeline_add_event(&svc, tl_id, evt_id);
    ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_COMPLETED);
    int consistent = 0;
    ASSERT_EQ(ozayn_otl_consistency_check(&svc, tl_id, &consistent, NULL, 0), OZAYN_OTL_ERR_OK);
    ASSERT(consistent);
    return 0;
}

/* ============================================================
 * STATS TESTS
 * ============================================================ */

TEST(test_otl_stats_null) {
    ASSERT_EQ(ozayn_otl_stats_get(NULL, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_stats_initial) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_stats_t stats;
    ASSERT_EQ(ozayn_otl_stats_get(&svc, &stats), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(stats.total_events_ingested, 0);
    ASSERT_EQ(stats.total_timelines_created, 0);
    ASSERT_EQ(stats.total_timelines_completed, 0);
    ASSERT_EQ(stats.total_timelines_failed, 0);
    ASSERT_EQ(stats.total_correlations_formed, 0);
    ASSERT_EQ(stats.total_duplicates_detected, 0);
    ASSERT_EQ(stats.current_active_timelines, 0);
    ASSERT_EQ(stats.current_events_stored, 0);
    return 0;
}

TEST(test_otl_stats_after_ingest) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    for (uint64_t i = 0; i < 5; i++) {
        ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
        ozayn_otl_event_ingest(&svc, &e, NULL);
    }
    ozayn_otl_stats_t stats;
    ozayn_otl_stats_get(&svc, &stats);
    ASSERT_EQ(stats.total_events_ingested, 5);
    ASSERT_EQ(stats.current_events_stored, 5);
    return 0;
}

TEST(test_otl_stats_after_timeline) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "c1", NULL, NULL, NULL, NULL, &tl_id);
    ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_COMPLETED);
    ozayn_otl_stats_t stats;
    ozayn_otl_stats_get(&svc, &stats);
    ASSERT_EQ(stats.total_timelines_created, 1);
    ASSERT_EQ(stats.total_timelines_completed, 1);
    ASSERT_EQ(stats.current_active_timelines, 0);
    return 0;
}

/* ============================================================
 * COUNT TESTS
 * ============================================================ */

TEST(test_otl_event_count_null) {
    ASSERT_EQ(ozayn_otl_event_count(NULL), -1);
    return 0;
}

TEST(test_otl_event_count_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_event_count(&svc), 0);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    ozayn_otl_event_ingest(&svc, &e, NULL);
    ASSERT_EQ(ozayn_otl_event_count(&svc), 1);
    return 0;
}

TEST(test_otl_timeline_count_null) {
    ASSERT_EQ(ozayn_otl_timeline_count(NULL), -1);
    return 0;
}

TEST(test_otl_timeline_count_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_timeline_count(&svc), 0);
    ozayn_otl_timeline_create(&svc, "c1", NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(ozayn_otl_timeline_count(&svc), 1);
    return 0;
}

TEST(test_otl_active_tl_count_null) {
    ASSERT_EQ(ozayn_otl_active_timeline_count(NULL), -1);
    return 0;
}

TEST(test_otl_active_tl_count_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ASSERT_EQ(ozayn_otl_active_timeline_count(&svc), 0);
    uint64_t tl_id = 0;
    ozayn_otl_timeline_create(&svc, "c1", NULL, NULL, NULL, NULL, &tl_id);
    ASSERT_EQ(ozayn_otl_active_timeline_count(&svc), 1);
    ozayn_otl_timeline_complete(&svc, tl_id, OZAYN_OTL_TL_COMPLETED);
    ASSERT_EQ(ozayn_otl_active_timeline_count(&svc), 0);
    return 0;
}

/* ============================================================
 * SHUTDOWN DRAIN TESTS
 * ============================================================ */

TEST(test_otl_shutdown_drain_null) {
    ASSERT_EQ(ozayn_otl_shutdown_drain(NULL, NULL, 0, NULL), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_shutdown_drain_ok) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl1 = 0, tl2 = 0;
    ozayn_otl_timeline_create(&svc, "c1", NULL, NULL, NULL, NULL, &tl1);
    ozayn_otl_timeline_create(&svc, "c2", NULL, NULL, NULL, NULL, &tl2);
    ozayn_otl_timeline_complete(&svc, tl1, OZAYN_OTL_TL_COMPLETED);
    const ozayn_otl_timeline_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_shutdown_drain(&svc, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 1);
    return 0;
}

TEST(test_otl_shutdown_drain_empty) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    const ozayn_otl_timeline_t *results[10];
    uint64_t count = 0;
    ASSERT_EQ(ozayn_otl_shutdown_drain(&svc, results, 10, &count), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(count, 0);
    return 0;
}

/* ============================================================
 * RETENTION PRUNE TESTS
 * ============================================================ */

TEST(test_otl_prune_null) {
    uint64_t pruned = 0;
    ASSERT_EQ(ozayn_otl_retention_prune(NULL, 0, 0, &pruned), OZAYN_OTL_ERR_NULL_PTR);
    return 0;
}

TEST(test_otl_prune_by_count) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    for (uint64_t i = 0; i < 10; i++) {
        ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
        ozayn_otl_event_ingest(&svc, &e, NULL);
    }
    uint64_t pruned = 0;
    ASSERT_EQ(ozayn_otl_retention_prune(&svc, 5, 0, &pruned), OZAYN_OTL_ERR_OK);
    ASSERT(pruned > 0);
    return 0;
}

TEST(test_otl_prune_by_age) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    e.occurrence_time = 100;
    ozayn_otl_event_ingest(&svc, &e, NULL);
    uint64_t pruned = 0;
    ASSERT_EQ(ozayn_otl_retention_prune(&svc, 0, 1, &pruned), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(pruned, 1);
    return 0;
}

TEST(test_otl_prune_nothing) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    e.occurrence_time = time(0);
    ozayn_otl_event_ingest(&svc, &e, NULL);
    uint64_t pruned = 0;
    ASSERT_EQ(ozayn_otl_retention_prune(&svc, 100, 999999, &pruned), OZAYN_OTL_ERR_OK);
    ASSERT_EQ(pruned, 0);
    return 0;
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

TEST(test_otl_ingest_full) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    for (uint64_t i = 0; i < OZAYN_OTL_MAX_EVENTS; i++) {
        ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
        ASSERT_EQ(ozayn_otl_event_ingest(&svc, &e, NULL), OZAYN_OTL_ERR_OK);
    }
    ozayn_otl_event_t extra = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    ASSERT_EQ(ozayn_otl_event_ingest(&svc, &extra, NULL), OZAYN_OTL_ERR_FULL);
    return 0;
}

TEST(test_otl_tl_create_full) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    for (uint64_t i = 0; i < OZAYN_OTL_MAX_TIMELINES; i++) {
        char corr[32];
        snprintf(corr, sizeof(corr), "c%lu", (unsigned long)i);
        ASSERT_EQ(ozayn_otl_timeline_create(&svc, corr, NULL, NULL, NULL, NULL, NULL), OZAYN_OTL_ERR_OK);
    }
    ASSERT_EQ(ozayn_otl_timeline_create(&svc, "overflow", NULL, NULL, NULL, NULL, NULL), OZAYN_OTL_ERR_FULL);
    return 0;
}

TEST(test_otl_ops_after_shutdown) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_shutdown(&svc);
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    ASSERT_EQ(ozayn_otl_event_ingest(&svc, &e, NULL), OZAYN_OTL_ERR_NOT_INITIALIZED);
    const ozayn_otl_event_t *got = 0;
    ASSERT_EQ(ozayn_otl_event_get(&svc, 1, &got), OZAYN_OTL_ERR_NOT_INITIALIZED);
    uint64_t tl_id = 0;
    ASSERT_EQ(ozayn_otl_timeline_create(&svc, "c", NULL, NULL, NULL, NULL, &tl_id), OZAYN_OTL_ERR_NOT_INITIALIZED);
    return 0;
}

TEST(test_otl_auto_id_increments) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t id1 = 0, id2 = 0, id3 = 0;
    ozayn_otl_event_t e = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "test", "s", "o", "r", "d", "d");
    ozayn_otl_event_ingest(&svc, &e, &id1);
    ozayn_otl_event_ingest(&svc, &e, &id2);
    ozayn_otl_event_ingest(&svc, &e, &id3);
    ASSERT(id1 > 0);
    ASSERT(id2 > id1);
    ASSERT(id3 > id2);
    return 0;
}

/* ============================================================
 * MULTI-TIMELINE INTERLEAVE TESTS
 * ============================================================ */

TEST(test_otl_multi_timeline_interleave) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    uint64_t tl1 = 0, tl2 = 0;
    ozayn_otl_timeline_create(&svc, "c1", NULL, NULL, NULL, NULL, &tl1);
    ozayn_otl_timeline_create(&svc, "c2", NULL, NULL, NULL, NULL, &tl2);
    ozayn_otl_event_t ea = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t eb = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    uint64_t ida = 0, idb = 0;
    ozayn_otl_event_ingest(&svc, &ea, &ida);
    ozayn_otl_event_ingest(&svc, &eb, &idb);
    ozayn_otl_timeline_add_event(&svc, tl1, ida);
    ozayn_otl_timeline_add_event(&svc, tl2, idb);
    const ozayn_otl_event_t *r1[10], *r2[10];
    uint64_t c1 = 0, c2 = 0;
    ozayn_otl_timeline_get_events(&svc, tl1, r1, 10, &c1);
    ozayn_otl_timeline_get_events(&svc, tl2, r2, 10, &c2);
    ASSERT_EQ(c1, 1);
    ASSERT_EQ(c2, 1);
    ASSERT_EQ(r1[0]->event_id, ida);
    ASSERT_EQ(r2[0]->event_id, idb);
    return 0;
}

/* ============================================================
 * MULTI-EVENT CHAIN TESTS
 * ============================================================ */

TEST(test_otl_multi_event_chain) {
    ozayn_otl_service_t svc = _make_svc();
    ozayn_otl_init(&svc);
    ozayn_otl_event_t e1 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "a", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e2 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "b", "s", "o", "r", "d", "d");
    ozayn_otl_event_t e3 = _make_event(0, OZAYN_OTL_CAT_SYSTEM, OZAYN_OTL_SEV_INFO, "c", "s", "o", "r", "d", "d");
    uint64_t id1 = 0, id2 = 0, id3 = 0;
    ozayn_otl_event_ingest(&svc, &e1, &id1);
    ozayn_otl_event_ingest(&svc, &e2, &id2);
    ozayn_otl_event_ingest(&svc, &e3, &id3);
    ozayn_otl_relationship_add(&svc, id1, id2, OZAYN_OTL_REL_PRECEDES, OZAYN_OTL_CORR_EXACT, NULL);
    ozayn_otl_relationship_add(&svc, id2, id3, OZAYN_OTL_REL_PRECEDES, OZAYN_OTL_CORR_EXACT, NULL);
    const ozayn_otl_event_t *succ[10];
    uint64_t cnt = 0;
    ozayn_otl_timeline_get_successors(&svc, id1, succ, 10, &cnt);
    ASSERT_EQ(cnt, 1);
    ozayn_otl_timeline_get_successors(&svc, id2, succ, 10, &cnt);
    ASSERT_EQ(cnt, 1);
    ozayn_otl_timeline_get_successors(&svc, id3, succ, 10, &cnt);
    ASSERT_EQ(cnt, 0);
    return 0;
}

/* ============================================================
 * RUN SUITE
 * ============================================================ */

int run_cr_operational_timeline_tests(void) {
    int fail = 0;
    SUITE_BEGIN("operational_timeline");

    /* Lifecycle */
    RUN(test_otl_init_null);
    RUN(test_otl_init_ok);
    RUN(test_otl_init_double);
    RUN(test_otl_shutdown_null);
    RUN(test_otl_shutdown_not_init);
    RUN(test_otl_shutdown_ok);
    RUN(test_otl_is_init_null);
    RUN(test_otl_is_init_ok);

    /* Name helpers */
    RUN(test_otl_err_name_all);
    RUN(test_otl_category_name_all);
    RUN(test_otl_severity_name_all);
    RUN(test_otl_relationship_name_all);
    RUN(test_otl_confidence_name_all);
    RUN(test_otl_tl_state_name_all);
    RUN(test_otl_evt_state_name_all);
    RUN(test_otl_emit_type_name_all);

    /* Subsystem binding */
    RUN(test_otl_bind_null);
    RUN(test_otl_bind_not_init);
    RUN(test_otl_bind_ok);

    /* Event ingestion */
    RUN(test_otl_event_ingest_null);
    RUN(test_otl_event_ingest_not_init);
    RUN(test_otl_event_ingest_inactive);
    RUN(test_otl_event_ingest_ok);
    RUN(test_otl_event_ingest_simple_ok);
    RUN(test_otl_event_ingest_simple_not_init);
    RUN(test_otl_event_ingest_multiple);
    RUN(test_otl_event_ingest_sequence_increments);
    RUN(test_otl_event_ingest_fixed_id);
    RUN(test_otl_event_ingest_incr_not_assign);

    /* Event get */
    RUN(test_otl_event_get_null);
    RUN(test_otl_event_get_not_init);
    RUN(test_otl_event_get_not_found);
    RUN(test_otl_event_get_ok);

    /* Event queries */
    RUN(test_otl_event_by_operation_ok);
    RUN(test_otl_event_by_operation_not_found);
    RUN(test_otl_event_by_request_ok);
    RUN(test_otl_event_by_correlation_ok);
    RUN(test_otl_event_by_category_ok);
    RUN(test_otl_event_by_component_ok);
    RUN(test_otl_event_by_severity_ok);
    RUN(test_otl_event_by_time_range_ok);
    RUN(test_otl_event_get_recent_ok);
    RUN(test_otl_event_get_recent_null);
    RUN(test_otl_event_get_recent_more_than_available);

    /* Duplicate detection */
    RUN(test_otl_duplicate_check_same_id);
    RUN(test_otl_duplicate_check_different_id);
    RUN(test_otl_duplicate_check_sequence);

    /* Event modification */
    RUN(test_otl_event_set_correlation_null);
    RUN(test_otl_event_set_correlation_ok);
    RUN(test_otl_event_set_correlation_not_found);
    RUN(test_otl_event_set_parent_ok);
    RUN(test_otl_event_set_parent_not_found);
    RUN(test_otl_event_set_description_ok);
    RUN(test_otl_event_set_description_not_found);

    /* Relationships */
    RUN(test_otl_rel_add_null);
    RUN(test_otl_rel_add_ok);
    RUN(test_otl_rel_add_not_found);
    RUN(test_otl_rel_get_by_event_ok);
    RUN(test_otl_rel_get_by_event_null);

    /* Timeline lifecycle */
    RUN(test_otl_tl_create_null);
    RUN(test_otl_tl_create_not_init);
    RUN(test_otl_tl_create_ok);
    RUN(test_otl_tl_create_duplicate);
    RUN(test_otl_tl_add_event_ok);
    RUN(test_otl_tl_add_event_not_found);
    RUN(test_otl_tl_add_event_null);
    RUN(test_otl_tl_complete_ok);
    RUN(test_otl_tl_complete_failed);
    RUN(test_otl_tl_complete_not_found);
    RUN(test_otl_tl_complete_already_done);

    /* Timeline queries */
    RUN(test_otl_tl_get_ok);
    RUN(test_otl_tl_get_not_found);
    RUN(test_otl_tl_get_null);
    RUN(test_otl_tl_get_by_corr_ok);
    RUN(test_otl_tl_get_by_corr_not_found);
    RUN(test_otl_tl_get_by_op_ok);
    RUN(test_otl_tl_get_active_ok);

    /* Timeline event chains */
    RUN(test_otl_tl_get_events_ok);
    RUN(test_otl_tl_get_events_not_found);
    RUN(test_otl_tl_get_operation_chain_ok);
    RUN(test_otl_tl_get_workflow_chain_ok);
    RUN(test_otl_tl_get_pipeline_chain_ok);

    /* Children/predecessors/successors */
    RUN(test_otl_tl_get_children_ok);
    RUN(test_otl_tl_get_predecessors_ok);
    RUN(test_otl_tl_get_successors_ok);

    /* Consistency */
    RUN(test_otl_consistency_null);
    RUN(test_otl_consistency_not_init);
    RUN(test_otl_consistency_not_found);
    RUN(test_otl_consistency_created_ok);
    RUN(test_otl_consistency_completed_ok);

    /* Stats */
    RUN(test_otl_stats_null);
    RUN(test_otl_stats_initial);
    RUN(test_otl_stats_after_ingest);
    RUN(test_otl_stats_after_timeline);

    /* Counts */
    RUN(test_otl_event_count_null);
    RUN(test_otl_event_count_ok);
    RUN(test_otl_timeline_count_null);
    RUN(test_otl_timeline_count_ok);
    RUN(test_otl_active_tl_count_null);
    RUN(test_otl_active_tl_count_ok);

    /* Shutdown drain */
    RUN(test_otl_shutdown_drain_null);
    RUN(test_otl_shutdown_drain_ok);
    RUN(test_otl_shutdown_drain_empty);

    /* Retention prune */
    RUN(test_otl_prune_null);
    RUN(test_otl_prune_by_count);
    RUN(test_otl_prune_by_age);
    RUN(test_otl_prune_nothing);

    /* Edge cases */
    RUN(test_otl_ingest_full);
    RUN(test_otl_tl_create_full);
    RUN(test_otl_ops_after_shutdown);
    RUN(test_otl_auto_id_increments);
    RUN(test_otl_multi_timeline_interleave);
    RUN(test_otl_multi_event_chain);

    SUITE_END();
    fail = TOTAL_FAIL();
    return fail;
}
