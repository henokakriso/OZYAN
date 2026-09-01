#include "../test_framework.h"
#include "ozayn.h"
#include "diagnostics.h"

TEST(diagnostics_init) {
    ozayn_diagnostics_manager_t mgr = {0};
    ASSERT_EQ(ozayn_diagnostics_init(&mgr, 1), OZAYN_OK);
    ASSERT(ozayn_diagnostics_is_enabled(&mgr));
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_level_control) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    ozayn_diagnostics_set_level(&mgr, OZAYN_DIAG_LEVEL_DETAILED);
    ASSERT_EQ(ozayn_diagnostics_get_level(&mgr), OZAYN_DIAG_LEVEL_DETAILED);
    ozayn_diagnostics_set_level(&mgr, OZAYN_DIAG_LEVEL_TRACE);
    ASSERT_EQ(ozayn_diagnostics_get_level(&mgr), OZAYN_DIAG_LEVEL_TRACE);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_record_evidence) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    uint32_t id = ozayn_diagnostics_record_evidence(&mgr, OZAYN_DIAG_COMP_IPC,
                                                      OZAYN_DIAG_TARGET_IPC,
                                                      "REQ-001", "test evidence");
    ASSERT(id > 0);
    ASSERT_EQ(ozayn_diagnostics_evidence_count(&mgr), 1);
    const ozayn_evidence_t *e = ozayn_diagnostics_get_evidence(&mgr, id);
    ASSERT_NOT_NULL(e);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_add_finding) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    uint32_t id = ozayn_diagnostics_add_finding(&mgr, OZAYN_DIAG_COMP_SCHEDULER,
                                                   OZAYN_DIAG_SEV_WARNING,
                                                   "REQ-002", "observation", "cause",
                                                   OZAYN_DIAG_CONFIDENCE_HIGH);
    ASSERT(id > 0);
    ASSERT_EQ(ozayn_diagnostics_finding_count(&mgr), 1);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_timeline) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    uint32_t seq = ozayn_diagnostics_timeline_add(&mgr, OZAYN_DIAG_COMP_CORE,
                                                    "REQ-003", "timeline event");
    ASSERT(seq > 0);
    ASSERT_EQ(ozayn_diagnostics_timeline_count(&mgr), 1);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_session) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    uint32_t sid = ozayn_diagnostics_session_start(&mgr, OZAYN_DIAG_TARGET_IPC, "REQ-004");
    ASSERT(sid > 0);
    ASSERT_EQ(ozayn_diagnostics_session_count(&mgr), 1);
    ASSERT_EQ(ozayn_diagnostics_active_session_count(&mgr), 1);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_record_failure) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    ASSERT_EQ(ozayn_diagnostics_record_failure(&mgr, OZAYN_DIAG_COMP_SCHEDULER), OZAYN_OK);
    ASSERT_EQ(ozayn_diagnostics_record_failure(&mgr, OZAYN_DIAG_COMP_SCHEDULER), OZAYN_OK);
    ASSERT_EQ(ozayn_diagnostics_failure_count(&mgr, OZAYN_DIAG_COMP_SCHEDULER), 2);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_stats) {
    ozayn_diagnostics_manager_t mgr = {0};
    ozayn_diagnostics_init(&mgr, 1);
    ozayn_diagnostics_record_evidence(&mgr, OZAYN_DIAG_COMP_CORE,
                                        OZAYN_DIAG_TARGET_CORE, "REQ", "ev");
    ozayn_diag_stats_t s = ozayn_diagnostics_stats(&mgr);
    ASSERT_EQ(s.evidence_recorded, 1);
    ozayn_diagnostics_shutdown(&mgr);
    return 0;
}

TEST(diagnostics_level_names) {
    ASSERT_STR_EQ(ozayn_diag_level_name(OZAYN_DIAG_LEVEL_NORMAL), "NORMAL");
    ASSERT_STR_EQ(ozayn_diag_level_name(OZAYN_DIAG_LEVEL_DETAILED), "DETAILED");
    ASSERT_STR_EQ(ozayn_diag_level_name(OZAYN_DIAG_LEVEL_DEBUG), "DEBUG");
    ASSERT_STR_EQ(ozayn_diag_level_name(OZAYN_DIAG_LEVEL_TRACE), "TRACE");
    return 0;
}

TEST(diagnostics_confidence_names) {
    ASSERT_STR_EQ(ozayn_diag_confidence_name(OZAYN_DIAG_CONFIDENCE_NONE), "NONE");
    ASSERT_STR_EQ(ozayn_diag_confidence_name(OZAYN_DIAG_CONFIDENCE_HIGH), "HIGH");
    ASSERT_STR_EQ(ozayn_diag_confidence_name(OZAYN_DIAG_CONFIDENCE_CERTAIN), "CERTAIN");
    return 0;
}

int run_diagnostics_tests(void) {
    SUITE_BEGIN("Diagnostics");
    RUN(diagnostics_init);
    RUN(diagnostics_level_control);
    RUN(diagnostics_record_evidence);
    RUN(diagnostics_add_finding);
    RUN(diagnostics_timeline);
    RUN(diagnostics_session);
    RUN(diagnostics_record_failure);
    RUN(diagnostics_stats);
    RUN(diagnostics_level_names);
    RUN(diagnostics_confidence_names);
    SUITE_END();
    return _tf_suite_fail;
}
