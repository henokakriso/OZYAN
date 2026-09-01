#include "../test_framework.h"
#include "registry.h"

TEST(registry_init) {
    ozayn_registry_manager_t mgr;
    ASSERT_EQ(ozayn_registry_init(&mgr, 1), OZAYN_OK);
    ASSERT(ozayn_registry_is_enabled(&mgr));
    ASSERT_EQ(ozayn_registry_count(&mgr), 0);
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(registry_register_service) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1");
    strcpy(reg.name, "Test Service");
    strcpy(reg.version, "1.0.0");
    strcpy(reg.endpoint, "/tmp/test.sock");
    strcpy(reg.provider, "test");
    reg.protocol_version = 1;
    ozayn_result_t r = ozayn_registry_register(&mgr, &reg, -1);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_registry_count(&mgr), 1);
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(registry_lookup) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1");
    strcpy(reg.name, "Test");
    strcpy(reg.version, "1.0");
    strcpy(reg.endpoint, "/tmp/test.sock");
    strcpy(reg.provider, "test");
    reg.protocol_version = 1;
    ozayn_registry_register(&mgr, &reg, -1);
    const ozayn_service_record_t *rec = ozayn_registry_lookup(&mgr, "svc1");
    ASSERT_NOT_NULL(rec);
    ASSERT_STR_EQ(rec->id, "svc1");
    ASSERT_NULL(ozayn_registry_lookup(&mgr, "nonexistent"));
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(registry_unregister) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1");
    strcpy(reg.name, "Test");
    strcpy(reg.version, "1.0");
    strcpy(reg.endpoint, "/tmp/test.sock");
    strcpy(reg.provider, "test");
    reg.protocol_version = 1;
    ozayn_registry_register(&mgr, &reg, -1);
    ASSERT_EQ(ozayn_registry_count(&mgr), 1);
    ozayn_result_t r = ozayn_registry_unregister(&mgr, "svc1");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_registry_count(&mgr), 0);
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(registry_find_by_capability) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1");
    strcpy(reg.name, "Test");
    strcpy(reg.version, "1.0");
    strcpy(reg.endpoint, "/tmp/test.sock");
    strcpy(reg.provider, "test");
    strcpy(reg.capabilities[0], "audio.playback");
    reg.capability_count = 1;
    reg.protocol_version = 1;
    ozayn_registry_register(&mgr, &reg, -1);
    const ozayn_service_record_t *rec = ozayn_registry_find_by_capability(&mgr, "audio.playback");
    ASSERT_NOT_NULL(rec);
    ASSERT_NULL(ozayn_registry_find_by_capability(&mgr, "nonexistent"));
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(registry_update_state) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1");
    strcpy(reg.name, "Test");
    strcpy(reg.version, "1.0");
    strcpy(reg.endpoint, "/tmp/test.sock");
    strcpy(reg.provider, "test");
    reg.protocol_version = 1;
    ozayn_registry_register(&mgr, &reg, -1);
    ozayn_result_t r = ozayn_registry_update_state(&mgr, "svc1", OZAYN_SVC_DEGRADED);
    ASSERT_EQ(r, OZAYN_OK);
    const ozayn_service_record_t *rec = ozayn_registry_lookup(&mgr, "svc1");
    ASSERT_EQ(rec->state, OZAYN_SVC_DEGRADED);
    ozayn_registry_shutdown(&mgr);
    return 0;
}

TEST(registry_service_state_names) {
    ASSERT_STR_EQ(ozayn_service_state_name(OZAYN_SVC_REGISTERING), "REGISTERING");
    ASSERT_STR_EQ(ozayn_service_state_name(OZAYN_SVC_READY), "READY");
    ASSERT_STR_EQ(ozayn_service_state_name(OZAYN_SVC_DEGRADED), "DEGRADED");
    ASSERT_STR_EQ(ozayn_service_state_name(OZAYN_SVC_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_service_state_name(OZAYN_SVC_OFFLINE), "OFFLINE");
    ASSERT_STR_EQ(ozayn_service_state_name(OZAYN_SVC_STOPPING), "STOPPING");
    return 0;
}

TEST(registry_list) {
    ozayn_registry_manager_t mgr;
    ozayn_registry_init(&mgr, 1);
    ozayn_service_registration_t reg = {0};
    strcpy(reg.id, "svc1"); strcpy(reg.name, "S1"); strcpy(reg.version, "1.0");
    strcpy(reg.endpoint, "/tmp/s1.sock"); strcpy(reg.provider, "test");
    reg.protocol_version = 1;
    ozayn_registry_register(&mgr, &reg, -1);
    strcpy(reg.id, "svc2"); strcpy(reg.name, "S2");
    strcpy(reg.endpoint, "/tmp/s2.sock");
    ozayn_registry_register(&mgr, &reg, -1);
    const ozayn_service_record_t *out[4] = {0};
    int n = ozayn_registry_list(&mgr, out, 4);
    ASSERT_EQ(n, 2);
    ozayn_registry_shutdown(&mgr);
    return 0;
}

int run_registry_tests(void) {
    SUITE_BEGIN("Registry");
    RUN(registry_init);
    RUN(registry_register_service);
    RUN(registry_lookup);
    RUN(registry_unregister);
    RUN(registry_find_by_capability);
    RUN(registry_update_state);
    RUN(registry_service_state_names);
    RUN(registry_list);
    SUITE_END();
    return _tf_suite_fail;
}
