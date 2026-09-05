#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_service.c — Section 02 Step 32: System Service & Background Process Information Abstraction Tests.
 *
 * Tests service discovery initialization, shutdown, enumeration, lookup,
 * type/state names, and error handling. Read-only — no service control.
 */

/* --- Initialization --- */

TEST(service_init_basic) {
    ozayn_result_t r = ozayn_service_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_init_idempotent) {
    ozayn_service_init();
    ozayn_result_t r = ozayn_service_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_service_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(service_is_available_before_init) {
    int avail = ozayn_service_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(service_is_available_after_init) {
    ozayn_service_init();
    int avail = ozayn_service_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_service_shutdown();
    return 0;
}

/* --- Count --- */

TEST(service_count_before_init) {
    int count = ozayn_service_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(service_count_after_init) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    ASSERT(count >= 0);
    ozayn_service_shutdown();
    return 0;
}

/* --- Get Info --- */

TEST(service_get_info_null) {
    ozayn_service_init();
    ozayn_result_t r = ozayn_service_get_info(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_get_info_before_init) {
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_get_info(0, &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(service_get_info_negative_index) {
    ozayn_service_init();
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_get_info(-1, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_get_info_index_out_of_range) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_get_info(count + 100, &info);
    ASSERT(r != OZAYN_OK);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_get_info_valid) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    if (count <= 0) {
        ozayn_service_shutdown();
        return 0;
    }
    OzaynServiceInfo info;
    memset(&info, 0, sizeof(info));
    ozayn_result_t r = ozayn_service_get_info(0, &info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(info.available, 1);
    ASSERT(info.id[0] != '\0');
    ASSERT(info.name[0] != '\0');
    ozayn_service_shutdown();
    return 0;
}

TEST(service_get_info_enumerate_all) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    for (int i = 0; i < count; i++) {
        OzaynServiceInfo info;
        memset(&info, 0, sizeof(info));
        ozayn_result_t r = ozayn_service_get_info(i, &info);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT_EQ(info.available, 1);
        ASSERT(info.id[0] != '\0');
    }
    ozayn_service_shutdown();
    return 0;
}

/* --- Find --- */

TEST(service_find_null) {
    ozayn_service_init();
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_find(NULL, &info);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_find_empty) {
    ozayn_service_init();
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_find("", &info);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_find_null_info) {
    ozayn_service_init();
    ozayn_result_t r = ozayn_service_find("test", NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_find_before_init) {
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_find("test", &info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(service_find_nonexistent) {
    ozayn_service_init();
    OzaynServiceInfo info;
    ozayn_result_t r = ozayn_service_find("ozayn_nonexistent_service_xyz", &info);
    ASSERT(r != OZAYN_OK);
    ozayn_service_shutdown();
    return 0;
}

TEST(service_find_existing) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    if (count <= 0) {
        ozayn_service_shutdown();
        return 0;
    }
    /* Get first service's ID and try to find it */
    OzaynServiceInfo info;
    ozayn_service_get_info(0, &info);
    OzaynServiceInfo found;
    memset(&found, 0, sizeof(found));
    ozayn_result_t r = ozayn_service_find(info.id, &found);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(found.available, 1);
    ASSERT(strcmp(found.id, info.id) == 0);
    ozayn_service_shutdown();
    return 0;
}

/* --- Type Names --- */

TEST(service_type_name_unknown) {
    const char *name = ozayn_sys_service_type_name(OZAYN_SERVICE_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(service_type_name_system) {
    const char *name = ozayn_sys_service_type_name(OZAYN_SERVICE_SYSTEM);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "System") == 0);
    return 0;
}

TEST(service_type_name_user) {
    const char *name = ozayn_sys_service_type_name(OZAYN_SERVICE_USER);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "User") == 0);
    return 0;
}

TEST(service_type_name_other) {
    const char *name = ozayn_sys_service_type_name(OZAYN_SERVICE_OTHER);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Other") == 0);
    return 0;
}

TEST(service_type_name_invalid) {
    const char *name = ozayn_sys_service_type_name(9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

/* --- State Names --- */

TEST(service_state_name_unknown) {
    const char *name = ozayn_sys_service_state_name(OZAYN_SERVICE_STATE_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(service_state_name_running) {
    const char *name = ozayn_sys_service_state_name(OZAYN_SERVICE_STATE_RUNNING);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Running") == 0);
    return 0;
}

TEST(service_state_name_stopped) {
    const char *name = ozayn_sys_service_state_name(OZAYN_SERVICE_STATE_STOPPED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Stopped") == 0);
    return 0;
}

TEST(service_state_name_paused) {
    const char *name = ozayn_sys_service_state_name(OZAYN_SERVICE_STATE_PAUSED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Paused") == 0);
    return 0;
}

TEST(service_state_name_disabled) {
    const char *name = ozayn_sys_service_state_name(OZAYN_SERVICE_STATE_DISABLED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Disabled") == 0);
    return 0;
}

TEST(service_state_name_invalid) {
    const char *name = ozayn_sys_service_state_name(9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

/* --- String Validation --- */

TEST(service_strings_null_terminated) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    for (int i = 0; i < count; i++) {
        OzaynServiceInfo info;
        ozayn_service_get_info(i, &info);
        ASSERT(info.id[OZAYN_MAX_SERVICE_ID - 1] == '\0');
        ASSERT(info.name[OZAYN_MAX_SERVICE_NAME - 1] == '\0');
        ASSERT(info.description[OZAYN_MAX_SERVICE_DESC - 1] == '\0');
    }
    ozayn_service_shutdown();
    return 0;
}

TEST(service_valid_state_values) {
    ozayn_service_init();
    int count = ozayn_service_get_count();
    for (int i = 0; i < count; i++) {
        OzaynServiceInfo info;
        ozayn_service_get_info(i, &info);
        ASSERT(info.state >= OZAYN_SERVICE_STATE_UNKNOWN &&
               info.state <= OZAYN_SERVICE_STATE_OTHER);
        ASSERT(info.type >= OZAYN_SERVICE_UNKNOWN &&
               info.type <= OZAYN_SERVICE_OTHER);
    }
    ozayn_service_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(service_shutdown_basic) {
    ozayn_service_init();
    ozayn_service_shutdown();
    return 0;
}

TEST(service_shutdown_idempotent) {
    ozayn_service_init();
    ozayn_service_shutdown();
    ozayn_service_shutdown();
    return 0;
}

TEST(service_shutdown_before_init) {
    ozayn_service_shutdown();
    return 0;
}

/* --- After Shutdown --- */

TEST(service_query_after_shutdown) {
    ozayn_service_init();
    ozayn_service_shutdown();

    ASSERT_EQ(ozayn_service_is_available(), 0);
    ASSERT_EQ(ozayn_service_get_count(), 0);

    OzaynServiceInfo info;
    ASSERT(ozayn_service_get_info(0, &info) != OZAYN_OK);
    ASSERT(ozayn_service_find("test", &info) != OZAYN_OK);

    return 0;
}

/* --- Test Suite --- */

int run_system_service_tests(void) {
    SUITE_BEGIN("System Service & Background Process Information Abstraction (Step 32)");

    /* Lifecycle */
    RUN(service_init_basic);
    RUN(service_init_idempotent);

    /* Availability */
    RUN(service_is_available_before_init);
    RUN(service_is_available_after_init);

    /* Count */
    RUN(service_count_before_init);
    RUN(service_count_after_init);

    /* Get Info */
    RUN(service_get_info_null);
    RUN(service_get_info_before_init);
    RUN(service_get_info_negative_index);
    RUN(service_get_info_index_out_of_range);
    RUN(service_get_info_valid);
    RUN(service_get_info_enumerate_all);

    /* Find */
    RUN(service_find_null);
    RUN(service_find_empty);
    RUN(service_find_null_info);
    RUN(service_find_before_init);
    RUN(service_find_nonexistent);
    RUN(service_find_existing);

    /* Type Names */
    RUN(service_type_name_unknown);
    RUN(service_type_name_system);
    RUN(service_type_name_user);
    RUN(service_type_name_other);
    RUN(service_type_name_invalid);

    /* State Names */
    RUN(service_state_name_unknown);
    RUN(service_state_name_running);
    RUN(service_state_name_stopped);
    RUN(service_state_name_paused);
    RUN(service_state_name_disabled);
    RUN(service_state_name_invalid);

    /* String Validation */
    RUN(service_strings_null_terminated);
    RUN(service_valid_state_values);

    /* Shutdown */
    RUN(service_shutdown_basic);
    RUN(service_shutdown_idempotent);
    RUN(service_shutdown_before_init);
    RUN(service_query_after_shutdown);

    SUITE_END();
    return FAILED();
}
