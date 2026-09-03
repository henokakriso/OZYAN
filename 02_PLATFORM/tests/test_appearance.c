#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_appearance.c — Section 02 Step 23: System Theme & Appearance Abstraction Tests.
 *
 * Tests appearance initialization, shutdown, queries, name helpers,
 * and error handling. Read-only — no theme modification.
 */

/* --- Initialization --- */

TEST(appearance_init_basic) {
    ozayn_result_t r = ozayn_appearance_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_appearance_shutdown();
    return 0;
}

TEST(appearance_init_idempotent) {
    ozayn_appearance_init();
    ozayn_result_t r = ozayn_appearance_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_appearance_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(appearance_is_available_after_init) {
    ozayn_appearance_init();
    int avail = ozayn_appearance_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_appearance_shutdown();
    return 0;
}

TEST(appearance_is_available_before_init) {
    int avail = ozayn_appearance_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Appearance --- */

TEST(appearance_get_before_init) {
    OzaynAppearance app = ozayn_appearance_get();
    ASSERT(app == OZAYN_APPEARANCE_UNKNOWN);
    return 0;
}

TEST(appearance_get_after_init) {
    ozayn_appearance_init();
    OzaynAppearance app = ozayn_appearance_get();
    /* Any valid state is acceptable */
    ASSERT(app == OZAYN_APPEARANCE_UNKNOWN ||
           app == OZAYN_APPEARANCE_LIGHT ||
           app == OZAYN_APPEARANCE_DARK);
    ozayn_appearance_shutdown();
    return 0;
}

/* --- Name --- */

TEST(appearance_name_unknown) {
    const char *name = ozayn_appearance_name(OZAYN_APPEARANCE_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

TEST(appearance_name_light) {
    const char *name = ozayn_appearance_name(OZAYN_APPEARANCE_LIGHT);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Light") == 0);
    return 0;
}

TEST(appearance_name_dark) {
    const char *name = ozayn_appearance_name(OZAYN_APPEARANCE_DARK);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Dark") == 0);
    return 0;
}

TEST(appearance_name_invalid) {
    const char *name = ozayn_appearance_name((OzaynAppearance)999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Invalid") == 0);
    return 0;
}

/* --- Shutdown --- */

TEST(appearance_shutdown_basic) {
    ozayn_appearance_init();
    ozayn_appearance_shutdown();
    return 0;
}

TEST(appearance_shutdown_idempotent) {
    ozayn_appearance_init();
    ozayn_appearance_shutdown();
    ozayn_appearance_shutdown();
    return 0;
}

TEST(appearance_shutdown_before_init) {
    ozayn_appearance_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_appearance_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Theme & Appearance (Section 02)");

    /* Initialization */
    RUN(appearance_init_basic);
    RUN(appearance_init_idempotent);

    /* Availability */
    RUN(appearance_is_available_after_init);
    RUN(appearance_is_available_before_init);

    /* Appearance */
    RUN(appearance_get_before_init);
    RUN(appearance_get_after_init);

    /* Name */
    RUN(appearance_name_unknown);
    RUN(appearance_name_light);
    RUN(appearance_name_dark);
    RUN(appearance_name_invalid);

    /* Shutdown */
    RUN(appearance_shutdown_basic);
    RUN(appearance_shutdown_idempotent);
    RUN(appearance_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
