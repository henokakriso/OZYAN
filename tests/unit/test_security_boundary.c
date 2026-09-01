#include "../test_framework.h"
#include "security_boundary.h"

TEST(security_boundary_init) {
    ozayn_security_boundary_manager_t mgr = {0};
    ASSERT_EQ(ozayn_security_boundary_init(&mgr, 1), 0);
    ASSERT(mgr.initialized);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_context_create) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx_id = ozayn_security_boundary_register_context(&mgr, "test-component",
                                                                 OZAYN_SB_TRUST_UNTRUSTED);
    ASSERT(ctx_id > 0);
    ASSERT_EQ(ozayn_security_boundary_context_count(&mgr), 1);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_check_deny_by_default) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx = ozayn_security_boundary_register_context(&mgr, "test",
                                                              OZAYN_SB_TRUST_UNTRUSTED);
    ozayn_security_check_result_t r = ozayn_security_boundary_check(&mgr, ctx,
                                                                      OZAYN_CAP_SECURITY_ADMIN);
    ASSERT(!r.allowed);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_grant_and_check) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx = ozayn_security_boundary_register_context(&mgr, "test",
                                                              OZAYN_SB_TRUST_UNTRUSTED);
    ASSERT_EQ(ozayn_security_boundary_grant_capability(&mgr, ctx, OZAYN_CAP_IPC_SEND), 0);
    ASSERT(ozayn_security_boundary_has_capability(&mgr, ctx, OZAYN_CAP_IPC_SEND));
    ozayn_security_check_result_t r = ozayn_security_boundary_check(&mgr, ctx,
                                                                      OZAYN_CAP_IPC_SEND);
    ASSERT(r.allowed);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_revoke) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx = ozayn_security_boundary_register_context(&mgr, "test",
                                                              OZAYN_SB_TRUST_UNTRUSTED);
    ozayn_security_boundary_grant_capability(&mgr, ctx, OZAYN_CAP_IPC_SEND);
    ASSERT_EQ(ozayn_security_boundary_revoke_capability(&mgr, ctx, OZAYN_CAP_IPC_SEND), 0);
    ASSERT(!ozayn_security_boundary_has_capability(&mgr, ctx, OZAYN_CAP_IPC_SEND));
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_report_violation) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    uint32_t ctx = ozayn_security_boundary_register_context(&mgr, "test",
                                                              OZAYN_SB_TRUST_UNTRUSTED);
    uint32_t vid = ozayn_security_boundary_report_violation(&mgr, ctx,
                                                              OZAYN_VIOLATION_CAPABILITY_DENIED,
                                                              OZAYN_SEC_SEV_HIGH, "test violation");
    ASSERT(vid > 0);
    ASSERT_EQ(ozayn_security_boundary_violation_count(&mgr), 1);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_stats) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    ozayn_security_boundary_stats_t s = ozayn_security_boundary_stats(&mgr);
    ASSERT_EQ(s.total_checks, 0);
    ASSERT_EQ(s.total_violations, 0);
    ASSERT_EQ(s.components_registered, 0);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

TEST(security_boundary_stats_after_register) {
    ozayn_security_boundary_manager_t mgr = {0};
    ozayn_security_boundary_init(&mgr, 1);
    ozayn_security_boundary_register_context(&mgr, "svc", OZAYN_SB_TRUST_CORE);
    ozayn_security_boundary_register_context(&mgr, "mod", OZAYN_SB_TRUST_SYSTEM);
    ozayn_security_boundary_stats_t s = ozayn_security_boundary_stats(&mgr);
    ASSERT_EQ(s.components_registered, 2);
    ozayn_security_boundary_shutdown(&mgr);
    return 0;
}

int run_security_boundary_tests(void) {
    SUITE_BEGIN("Security Boundary");
    RUN(security_boundary_init);
    RUN(security_context_create);
    RUN(security_check_deny_by_default);
    RUN(security_grant_and_check);
    RUN(security_revoke);
    RUN(security_report_violation);
    RUN(security_stats);
    RUN(security_boundary_stats_after_register);
    SUITE_END();
    return _tf_suite_fail;
}
