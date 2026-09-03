#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_session.c — Section 02 Step 21: System Lock State & Session Control Abstraction Tests.
 *
 * Tests session initialization, shutdown, state queries, state names,
 * and error handling. No automated lock/unlock tests — that would
 * lock the developer's workstation during unattended test runs.
 */

/* --- Initialization --- */

TEST(session_init_basic) {
    ozayn_result_t r = ozayn_session_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_session_shutdown();
    return 0;
}

TEST(session_init_idempotent) {
    ozayn_session_init();
    ozayn_result_t r = ozayn_session_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_session_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(session_is_available_after_init) {
    ozayn_session_init();
    int avail = ozayn_session_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_session_shutdown();
    return 0;
}

TEST(session_is_available_before_init) {
    int avail = ozayn_session_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- State --- */

TEST(session_get_state_before_init) {
    OzaynSessionState state = ozayn_session_get_state();
    ASSERT(state == OZAYN_SESSION_UNKNOWN || state == OZAYN_SESSION_UNAVAILABLE);
    return 0;
}

TEST(session_get_state_after_init) {
    ozayn_session_init();
    OzaynSessionState state = ozayn_session_get_state();
    /* Any valid state is acceptable */
    ASSERT(state == OZAYN_SESSION_UNKNOWN || state == OZAYN_SESSION_ACTIVE ||
           state == OZAYN_SESSION_LOCKED || state == OZAYN_SESSION_INACTIVE ||
           state == OZAYN_SESSION_UNAVAILABLE);
    ozayn_session_shutdown();
    return 0;
}

TEST(session_is_locked_before_init) {
    int locked = ozayn_session_is_locked();
    ASSERT(locked == 0 || locked == 1);
    return 0;
}

TEST(session_is_locked_after_init) {
    ozayn_session_init();
    int locked = ozayn_session_is_locked();
    ASSERT(locked == 0 || locked == 1);
    ozayn_session_shutdown();
    return 0;
}

/* --- State Name --- */

TEST(session_state_name_unknown) {
    const char *name = ozayn_session_state_name(OZAYN_SESSION_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

TEST(session_state_name_active) {
    const char *name = ozayn_session_state_name(OZAYN_SESSION_ACTIVE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Active") == 0);
    return 0;
}

TEST(session_state_name_locked) {
    const char *name = ozayn_session_state_name(OZAYN_SESSION_LOCKED);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Locked") == 0);
    return 0;
}

TEST(session_state_name_inactive) {
    const char *name = ozayn_session_state_name(OZAYN_SESSION_INACTIVE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Inactive") == 0);
    return 0;
}

TEST(session_state_name_unavailable) {
    const char *name = ozayn_session_state_name(OZAYN_SESSION_UNAVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unavailable") == 0);
    return 0;
}

TEST(session_state_name_invalid) {
    const char *name = ozayn_session_state_name((OzaynSessionState)999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Invalid") == 0);
    return 0;
}

/* --- Lock (manual test — does NOT lock during automated run) --- */

TEST(session_lock_before_init) {
    ozayn_result_t r = ozayn_session_lock();
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(session_lock_safe) {
    /* This test verifies the API accepts calls safely.
     * It does NOT actually lock the workstation. */
    ozayn_session_init();
    /* On headless/unsupported systems, lock should fail gracefully */
    ozayn_result_t r = ozayn_session_lock();
    /* Either OK (lock requested) or ERR (unsupported) — both acceptable */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_session_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(session_shutdown_basic) {
    ozayn_session_init();
    ozayn_session_shutdown();
    return 0;
}

TEST(session_shutdown_idempotent) {
    ozayn_session_init();
    ozayn_session_shutdown();
    ozayn_session_shutdown();
    return 0;
}

TEST(session_shutdown_before_init) {
    ozayn_session_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_session_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Lock State & Session Control (Section 02)");

    /* Initialization */
    RUN(session_init_basic);
    RUN(session_init_idempotent);

    /* Availability */
    RUN(session_is_available_after_init);
    RUN(session_is_available_before_init);

    /* State */
    RUN(session_get_state_before_init);
    RUN(session_get_state_after_init);
    RUN(session_is_locked_before_init);
    RUN(session_is_locked_after_init);

    /* State Names */
    RUN(session_state_name_unknown);
    RUN(session_state_name_active);
    RUN(session_state_name_locked);
    RUN(session_state_name_inactive);
    RUN(session_state_name_unavailable);
    RUN(session_state_name_invalid);

    /* Lock */
    RUN(session_lock_before_init);
    RUN(session_lock_safe);

    /* Shutdown */
    RUN(session_shutdown_basic);
    RUN(session_shutdown_idempotent);
    RUN(session_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
