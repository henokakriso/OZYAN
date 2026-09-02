#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_time.c — Section 02 Step 17: System Time & Date Abstraction Tests.
 *
 * Tests time initialization, shutdown, timestamps, date/time retrieval,
 * sleep, and error handling. Read-only — no clock modification.
 */

/* --- Time Initialization --- */

TEST(time_init_basic) {
    ozayn_result_t r = ozayn_time_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_init_idempotent) {
    ozayn_time_init();
    ozayn_result_t r = ozayn_time_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_time_shutdown();
    return 0;
}

/* --- Time Availability --- */

TEST(time_is_available_after_init) {
    ozayn_time_init();
    int avail = ozayn_time_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_is_available_before_init) {
    int avail = ozayn_time_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Unix Timestamps --- */

TEST(time_unix_seconds) {
    ozayn_time_init();
    int64_t seconds = ozayn_time_unix_seconds();
    ASSERT(seconds > 0);
    /* Should be after year 2020 */
    ASSERT(seconds > 1577836800);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_unix_milliseconds) {
    ozayn_time_init();
    int64_t ms = ozayn_time_unix_milliseconds();
    ASSERT(ms > 0);
    /* Should be after year 2020 */
    ASSERT(ms > 1577836800000LL);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_unix_microseconds) {
    ozayn_time_init();
    int64_t us = ozayn_time_unix_microseconds();
    ASSERT(us > 0);
    /* Should be after year 2020 */
    ASSERT(us > 1577836800000000LL);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_timestamp_consistency) {
    ozayn_time_init();
    int64_t sec = ozayn_time_unix_seconds();
    int64_t ms = ozayn_time_unix_milliseconds();
    int64_t us = ozayn_time_unix_microseconds();

    /* ms should be approximately sec * 1000 */
    int64_t diff_ms = ms - sec * 1000;
    ASSERT(diff_ms >= -1 && diff_ms <= 1000);

    /* us should be approximately ms * 1000 */
    int64_t diff_us = us - ms * 1000;
    ASSERT(diff_us >= -1 && diff_us <= 1000);

    ozayn_time_shutdown();
    return 0;
}

/* --- Local Date/Time --- */

TEST(time_get_local) {
    ozayn_time_init();
    OzaynDateTime dt;
    memset(&dt, 0, sizeof(dt));
    ozayn_result_t r = ozayn_time_get_local(&dt);
    ASSERT_EQ(r, OZAYN_OK);

    /* Validate ranges */
    ASSERT(dt.year >= 2020);
    ASSERT(dt.month >= 1 && dt.month <= 12);
    ASSERT(dt.day >= 1 && dt.day <= 31);
    ASSERT(dt.hour >= 0 && dt.hour <= 23);
    ASSERT(dt.minute >= 0 && dt.minute <= 59);
    ASSERT(dt.second >= 0 && dt.second <= 59);
    ASSERT(dt.millisecond >= 0 && dt.millisecond <= 999);

    ozayn_time_shutdown();
    return 0;
}

TEST(time_get_local_null) {
    ozayn_time_init();
    ozayn_result_t r = ozayn_time_get_local(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_get_local_before_init) {
    OzaynDateTime dt;
    ozayn_result_t r = ozayn_time_get_local(&dt);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- UTC Date/Time --- */

TEST(time_get_utc) {
    ozayn_time_init();
    OzaynDateTime dt;
    memset(&dt, 0, sizeof(dt));
    ozayn_result_t r = ozayn_time_get_utc(&dt);
    ASSERT_EQ(r, OZAYN_OK);

    /* Validate ranges */
    ASSERT(dt.year >= 2020);
    ASSERT(dt.month >= 1 && dt.month <= 12);
    ASSERT(dt.day >= 1 && dt.day <= 31);
    ASSERT(dt.hour >= 0 && dt.hour <= 23);
    ASSERT(dt.minute >= 0 && dt.minute <= 59);
    ASSERT(dt.second >= 0 && dt.second <= 59);
    ASSERT(dt.millisecond >= 0 && dt.millisecond <= 999);
    ASSERT_EQ(dt.utc_offset_minutes, 0);

    ozayn_time_shutdown();
    return 0;
}

TEST(time_get_utc_null) {
    ozayn_time_init();
    ozayn_result_t r = ozayn_time_get_utc(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_get_utc_before_init) {
    OzaynDateTime dt;
    ozayn_result_t r = ozayn_time_get_utc(&dt);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Local vs UTC --- */

TEST(time_local_vs_utc_offset) {
    ozayn_time_init();
    OzaynDateTime local_dt, utc_dt;
    memset(&local_dt, 0, sizeof(local_dt));
    memset(&utc_dt, 0, sizeof(utc_dt));

    ozayn_time_get_local(&local_dt);
    ozayn_time_get_utc(&utc_dt);

    /* If timezone is not UTC, offset should be non-zero */
    if (local_dt.utc_offset_minutes != 0) {
        ASSERT(local_dt.utc_offset_minutes >= -720 && local_dt.utc_offset_minutes <= 720);
    }

    ozayn_time_shutdown();
    return 0;
}

/* --- Sleep --- */

TEST(time_sleep_basic) {
    ozayn_time_init();
    ozayn_result_t r = ozayn_time_sleep_ms(10);
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_sleep_zero) {
    ozayn_time_init();
    ozayn_result_t r = ozayn_time_sleep_ms(0);
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_time_shutdown();
    return 0;
}

TEST(time_sleep_before_init) {
    ozayn_result_t r = ozayn_time_sleep_ms(10);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Time Shutdown --- */

TEST(time_shutdown_basic) {
    ozayn_time_init();
    ozayn_time_shutdown();
    return 0;
}

TEST(time_shutdown_idempotent) {
    ozayn_time_init();
    ozayn_time_shutdown();
    ozayn_time_shutdown();
    return 0;
}

TEST(time_shutdown_before_init) {
    ozayn_time_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_time_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Time & Date Abstraction (Section 02)");

    RUN(time_init_basic);
    RUN(time_init_idempotent);
    RUN(time_is_available_after_init);
    RUN(time_is_available_before_init);
    RUN(time_unix_seconds);
    RUN(time_unix_milliseconds);
    RUN(time_unix_microseconds);
    RUN(time_timestamp_consistency);
    RUN(time_get_local);
    RUN(time_get_local_null);
    RUN(time_get_local_before_init);
    RUN(time_get_utc);
    RUN(time_get_utc_null);
    RUN(time_get_utc_before_init);
    RUN(time_local_vs_utc_offset);
    RUN(time_sleep_basic);
    RUN(time_sleep_zero);
    RUN(time_sleep_before_init);
    RUN(time_shutdown_basic);
    RUN(time_shutdown_idempotent);
    RUN(time_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
