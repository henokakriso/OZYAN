#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_power.c — Section 02 Step 13: Power & Battery Information Abstraction Tests.
 *
 * Tests power initialization, shutdown, availability, battery information,
 * and error handling. Works on both laptop and desktop systems.
 *
 * Desktop systems without batteries produce valid test results.
 * No power modification or control is performed.
 */

/* --- Power Initialization --- */

TEST(power_init_basic) {
    ozayn_result_t r = ozayn_power_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_power_shutdown();
    return 0;
}

TEST(power_init_idempotent) {
    ozayn_power_init();
    ozayn_result_t r = ozayn_power_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_power_shutdown();
    return 0;
}

/* --- Power Availability --- */

TEST(power_is_available_after_init) {
    ozayn_power_init();
    int avail = ozayn_power_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_power_shutdown();
    return 0;
}

TEST(power_is_available_before_init) {
    int avail = ozayn_power_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Power Information --- */

TEST(power_get_info_after_init) {
    ozayn_power_init();
    OzaynPowerInfo info;
    ozayn_result_t r = ozayn_power_get_info(&info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(info.available == 0 || info.available == 1);
    ASSERT(info.has_battery == 0 || info.has_battery == 1);
    ozayn_power_shutdown();
    return 0;
}

TEST(power_get_info_null) {
    ozayn_power_init();
    ozayn_result_t r = ozayn_power_get_info(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_power_shutdown();
    return 0;
}

TEST(power_get_info_before_init) {
    OzaynPowerInfo info;
    ozayn_result_t r = ozayn_power_get_info(&info);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Battery Presence --- */

TEST(power_has_battery) {
    ozayn_power_init();
    int has = ozayn_power_has_battery();
    ASSERT(has == 0 || has == 1);
    ozayn_power_shutdown();
    return 0;
}

/* --- Battery Percentage --- */

TEST(power_battery_percent_range) {
    ozayn_power_init();
    int percent = ozayn_power_get_battery_percent();
    /* -1 means unknown, otherwise 0-100 */
    ASSERT(percent == -1 || (percent >= 0 && percent <= 100));
    ozayn_power_shutdown();
    return 0;
}

TEST(power_battery_percent_no_battery) {
    ozayn_power_init();
    if (!ozayn_power_has_battery()) {
        int percent = ozayn_power_get_battery_percent();
        ASSERT(percent == -1);
    }
    ozayn_power_shutdown();
    return 0;
}

/* --- Charging State --- */

TEST(power_is_charging) {
    ozayn_power_init();
    int charging = ozayn_power_is_charging();
    ASSERT(charging == 0 || charging == 1);
    ozayn_power_shutdown();
    return 0;
}

/* --- Plugged In State --- */

TEST(power_is_plugged_in) {
    ozayn_power_init();
    int plugged = ozayn_power_is_plugged_in();
    ASSERT(plugged == 0 || plugged == 1);
    ozayn_power_shutdown();
    return 0;
}

/* --- Power State Constants --- */

TEST(power_state_constants) {
    ASSERT_EQ(OZAYN_POWER_UNKNOWN, 0);
    ASSERT(OZAYN_POWER_BATTERY != OZAYN_POWER_UNKNOWN);
    ASSERT(OZAYN_POWER_CHARGING != OZAYN_POWER_UNKNOWN);
    ASSERT(OZAYN_POWER_AC_POWER != OZAYN_POWER_UNKNOWN);
    ASSERT(OZAYN_POWER_NO_BATTERY != OZAYN_POWER_UNKNOWN);
    return 0;
}

/* --- Power Shutdown --- */

TEST(power_shutdown_basic) {
    ozayn_power_init();
    ozayn_power_shutdown();
    return 0;
}

TEST(power_shutdown_idempotent) {
    ozayn_power_init();
    ozayn_power_shutdown();
    ozayn_power_shutdown();
    return 0;
}

TEST(power_shutdown_before_init) {
    ozayn_power_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_power_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Power & Battery Information Abstraction (Section 02)");

    RUN(power_init_basic);
    RUN(power_init_idempotent);
    RUN(power_is_available_after_init);
    RUN(power_is_available_before_init);
    RUN(power_get_info_after_init);
    RUN(power_get_info_null);
    RUN(power_get_info_before_init);
    RUN(power_has_battery);
    RUN(power_battery_percent_range);
    RUN(power_battery_percent_no_battery);
    RUN(power_is_charging);
    RUN(power_is_plugged_in);
    RUN(power_state_constants);
    RUN(power_shutdown_basic);
    RUN(power_shutdown_idempotent);
    RUN(power_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
