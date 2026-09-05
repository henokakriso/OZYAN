#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_sys_security.c — Section 02 Step 33: System Security & Firewall State Abstraction Tests.
 *
 * Tests security state initialization, shutdown, firewall detection,
 * state names, and error handling. Read-only — no security modification.
 */

/* --- Initialization --- */

TEST(syssec_init_basic) {
    ozayn_result_t r = ozayn_sys_security_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_sys_security_shutdown();
    return 0;
}

TEST(syssec_init_idempotent) {
    ozayn_sys_security_init();
    ozayn_result_t r = ozayn_sys_security_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_sys_security_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(syssec_is_available_before_init) {
    int avail = ozayn_sys_security_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(syssec_is_available_after_init) {
    ozayn_sys_security_init();
    int avail = ozayn_sys_security_is_available();
    ASSERT_EQ(avail, 1);
    ozayn_sys_security_shutdown();
    return 0;
}

/* --- Get Info --- */

TEST(syssec_get_info_null) {
    ozayn_sys_security_init();
    ozayn_result_t r = ozayn_sys_security_get_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_sys_security_shutdown();
    return 0;
}

TEST(syssec_get_info_before_init) {
    OzaynSecurityInfo info;
    ozayn_result_t r = ozayn_sys_security_get_info(&info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(syssec_get_info_valid) {
    ozayn_sys_security_init();
    OzaynSecurityInfo info;
    memset(&info, 0, sizeof(info));
    ozayn_result_t r = ozayn_sys_security_get_info(&info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(info.available, 1);
    /* Firewall state must be a valid enum */
    ASSERT(info.firewall_state >= OZAYN_SECURITY_UNKNOWN &&
           info.firewall_state <= OZAYN_SECURITY_UNAVAILABLE);
    ozayn_sys_security_shutdown();
    return 0;
}

/* --- Firewall State --- */

TEST(syssec_firewall_state_before_init) {
    OzaynSecurityState state = ozayn_sys_security_get_firewall_state();
    ASSERT_EQ(state, OZAYN_SECURITY_UNKNOWN);
    return 0;
}

TEST(syssec_firewall_state_valid) {
    ozayn_sys_security_init();
    OzaynSecurityState state = ozayn_sys_security_get_firewall_state();
    ASSERT(state >= OZAYN_SECURITY_UNKNOWN && state <= OZAYN_SECURITY_UNAVAILABLE);
    ozayn_sys_security_shutdown();
    return 0;
}

TEST(syssec_firewall_name_not_empty) {
    ozayn_sys_security_init();
    OzaynSecurityInfo info;
    ozayn_sys_security_get_info(&info);
    if (info.firewall_state_available) {
        ASSERT(info.firewall_name[0] != '\0');
        ASSERT(strlen(info.firewall_name) < OZAYN_MAX_SECURITY_NAME);
    }
    ozayn_sys_security_shutdown();
    return 0;
}

/* --- State Names --- */

TEST(syssec_state_name_unknown) {
    const char *name = ozayn_sys_security_state_name(OZAYN_SECURITY_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

TEST(syssec_state_name_enabled) {
    const char *name = ozayn_sys_security_state_name(OZAYN_SECURITY_ENABLED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Enabled") == 0);
    return 0;
}

TEST(syssec_state_name_disabled) {
    const char *name = ozayn_sys_security_state_name(OZAYN_SECURITY_DISABLED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Disabled") == 0);
    return 0;
}

TEST(syssec_state_name_unavailable) {
    const char *name = ozayn_sys_security_state_name(OZAYN_SECURITY_UNAVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unavailable") == 0);
    return 0;
}

TEST(syssec_state_name_invalid) {
    const char *name = ozayn_sys_security_state_name(9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

/* --- Information Validation --- */

TEST(syssec_strings_null_terminated) {
    ozayn_sys_security_init();
    OzaynSecurityInfo info;
    ozayn_sys_security_get_info(&info);
    ASSERT(info.firewall_name[OZAYN_MAX_SECURITY_NAME - 1] == '\0');
    ozayn_sys_security_shutdown();
    return 0;
}

TEST(syssec_consistency) {
    ozayn_sys_security_init();
    OzaynSecurityInfo info;
    ozayn_sys_security_get_info(&info);
    /* If firewall_state_available is 0, state should be UNKNOWN */
    if (!info.firewall_state_available) {
        ASSERT_EQ(info.firewall_state, OZAYN_SECURITY_UNKNOWN);
    }
    /* If antivirus_state_available is 0, state should be UNKNOWN */
    if (!info.antivirus_state_available) {
        ASSERT_EQ(info.antivirus_state, OZAYN_SECURITY_UNKNOWN);
    }
    ozayn_sys_security_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(syssec_shutdown_basic) {
    ozayn_sys_security_init();
    ozayn_sys_security_shutdown();
    return 0;
}

TEST(syssec_shutdown_idempotent) {
    ozayn_sys_security_init();
    ozayn_sys_security_shutdown();
    ozayn_sys_security_shutdown();
    return 0;
}

TEST(syssec_shutdown_before_init) {
    ozayn_sys_security_shutdown();
    return 0;
}

/* --- After Shutdown --- */

TEST(syssec_query_after_shutdown) {
    ozayn_sys_security_init();
    ozayn_sys_security_shutdown();

    ASSERT_EQ(ozayn_sys_security_is_available(), 0);

    OzaynSecurityInfo info;
    ASSERT(ozayn_sys_security_get_info(&info) != OZAYN_OK);

    ASSERT_EQ(ozayn_sys_security_get_firewall_state(), OZAYN_SECURITY_UNKNOWN);

    return 0;
}

/* --- Test Suite --- */

int run_sys_security_tests(void) {
    SUITE_BEGIN("System Security & Firewall State Abstraction (Step 33)");

    /* Lifecycle */
    RUN(syssec_init_basic);
    RUN(syssec_init_idempotent);

    /* Availability */
    RUN(syssec_is_available_before_init);
    RUN(syssec_is_available_after_init);

    /* Get Info */
    RUN(syssec_get_info_null);
    RUN(syssec_get_info_before_init);
    RUN(syssec_get_info_valid);

    /* Firewall State */
    RUN(syssec_firewall_state_before_init);
    RUN(syssec_firewall_state_valid);
    RUN(syssec_firewall_name_not_empty);

    /* State Names */
    RUN(syssec_state_name_unknown);
    RUN(syssec_state_name_enabled);
    RUN(syssec_state_name_disabled);
    RUN(syssec_state_name_unavailable);
    RUN(syssec_state_name_invalid);

    /* Information Validation */
    RUN(syssec_strings_null_terminated);
    RUN(syssec_consistency);

    /* Shutdown */
    RUN(syssec_shutdown_basic);
    RUN(syssec_shutdown_idempotent);
    RUN(syssec_shutdown_before_init);
    RUN(syssec_query_after_shutdown);

    SUITE_END();
    return FAILED();
}
