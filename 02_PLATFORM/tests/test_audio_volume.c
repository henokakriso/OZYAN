#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_audio_volume.c — Section 02 Step 20: System Audio Volume & Mute Abstraction Tests.
 *
 * Tests volume/mute initialization, queries, control, and error handling.
 * Restores original volume/mute state after testing.
 * Safe for headless environments — reports unavailable rather than failing.
 */

/* --- Initialization --- */

TEST(audio_volume_init_basic) {
    ozayn_result_t r = ozayn_audio_volume_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_init_idempotent) {
    ozayn_audio_volume_init();
    ozayn_result_t r = ozayn_audio_volume_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_audio_volume_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(audio_volume_is_available_after_init) {
    ozayn_audio_volume_init();
    int avail = ozayn_audio_volume_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_is_available_before_init) {
    int avail = ozayn_audio_volume_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Volume Query --- */

TEST(audio_volume_get_null) {
    ozayn_audio_volume_init();
    ozayn_result_t r = ozayn_audio_volume_get(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_get_before_init) {
    int vol;
    ozayn_result_t r = ozayn_audio_volume_get(&vol);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(audio_volume_get_valid_range) {
    ozayn_audio_volume_init();
    if (!ozayn_audio_volume_is_available()) {
        ozayn_audio_volume_shutdown();
        return 0;
    }
    int vol;
    ozayn_result_t r = ozayn_audio_volume_get(&vol);
    if (r == OZAYN_OK) {
        ASSERT(vol >= 0 && vol <= 100);
    }
    ozayn_audio_volume_shutdown();
    return 0;
}

/* --- Volume Set --- */

TEST(audio_volume_set_invalid_negative) {
    ozayn_audio_volume_init();
    ozayn_result_t r = ozayn_audio_volume_set(-1);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_set_invalid_over) {
    ozayn_audio_volume_init();
    ozayn_result_t r = ozayn_audio_volume_set(101);
    ASSERT(r != OZAYN_OK);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_set_before_init) {
    ozayn_result_t r = ozayn_audio_volume_set(50);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(audio_volume_set_restore) {
    ozayn_audio_volume_init();
    if (!ozayn_audio_volume_is_available()) {
        ozayn_audio_volume_shutdown();
        return 0;
    }

    /* Save original volume */
    int orig_vol;
    ozayn_result_t r = ozayn_audio_volume_get(&orig_vol);
    if (r != OZAYN_OK) {
        ozayn_audio_volume_shutdown();
        return 0;
    }

    /* Set and verify */
    r = ozayn_audio_volume_set(50);
    if (r == OZAYN_OK) {
        int check_vol;
        ozayn_audio_volume_get(&check_vol);
        /* Allow ±1 for rounding */
        ASSERT(check_vol >= 49 && check_vol <= 51);
    }

    /* Restore original */
    ozayn_audio_volume_set(orig_vol);
    ozayn_audio_volume_shutdown();
    return 0;
}

/* --- Mute Control --- */

TEST(audio_volume_is_muted_null) {
    ozayn_audio_volume_init();
    ozayn_result_t r = ozayn_audio_volume_is_muted(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_is_muted_before_init) {
    int muted;
    ozayn_result_t r = ozayn_audio_volume_is_muted(&muted);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(audio_volume_set_muted_before_init) {
    ozayn_result_t r = ozayn_audio_volume_set_muted(1);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(audio_volume_toggle_before_init) {
    ozayn_result_t r = ozayn_audio_volume_toggle_mute();
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(audio_volume_mute_restore) {
    ozayn_audio_volume_init();
    if (!ozayn_audio_volume_is_available()) {
        ozayn_audio_volume_shutdown();
        return 0;
    }

    /* Save original mute state */
    int orig_muted;
    ozayn_result_t r = ozayn_audio_volume_is_muted(&orig_muted);
    if (r != OZAYN_OK) {
        ozayn_audio_volume_shutdown();
        return 0;
    }

    /* Mute and verify */
    r = ozayn_audio_volume_set_muted(1);
    if (r == OZAYN_OK) {
        int check_muted;
        ozayn_audio_volume_is_muted(&check_muted);
        ASSERT_EQ(check_muted, 1);
    }

    /* Unmute and verify */
    r = ozayn_audio_volume_set_muted(0);
    if (r == OZAYN_OK) {
        int check_muted;
        ozayn_audio_volume_is_muted(&check_muted);
        ASSERT_EQ(check_muted, 0);
    }

    /* Restore original */
    ozayn_audio_volume_set_muted(orig_muted);
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_toggle_restore) {
    ozayn_audio_volume_init();
    if (!ozayn_audio_volume_is_available()) {
        ozayn_audio_volume_shutdown();
        return 0;
    }

    /* Save original mute state */
    int orig_muted;
    ozayn_result_t r = ozayn_audio_volume_is_muted(&orig_muted);
    if (r != OZAYN_OK) {
        ozayn_audio_volume_shutdown();
        return 0;
    }

    /* Toggle and verify state changed */
    r = ozayn_audio_volume_toggle_mute();
    if (r == OZAYN_OK) {
        int check_muted;
        ozayn_audio_volume_is_muted(&check_muted);
        ASSERT(check_muted != orig_muted);

        /* Toggle again to restore */
        ozayn_audio_volume_toggle_mute();
        ozayn_audio_volume_is_muted(&check_muted);
        ASSERT_EQ(check_muted, orig_muted);
    }

    /* Restore original */
    ozayn_audio_volume_set_muted(orig_muted);
    ozayn_audio_volume_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(audio_volume_shutdown_basic) {
    ozayn_audio_volume_init();
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_shutdown_idempotent) {
    ozayn_audio_volume_init();
    ozayn_audio_volume_shutdown();
    ozayn_audio_volume_shutdown();
    return 0;
}

TEST(audio_volume_shutdown_before_init) {
    ozayn_audio_volume_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_audio_volume_tests(void) {
    int failed = 0;
    SUITE_BEGIN("System Audio Volume & Mute (Section 02)");

    /* Initialization */
    RUN(audio_volume_init_basic);
    RUN(audio_volume_init_idempotent);

    /* Availability */
    RUN(audio_volume_is_available_after_init);
    RUN(audio_volume_is_available_before_init);

    /* Volume Query */
    RUN(audio_volume_get_null);
    RUN(audio_volume_get_before_init);
    RUN(audio_volume_get_valid_range);

    /* Volume Set */
    RUN(audio_volume_set_invalid_negative);
    RUN(audio_volume_set_invalid_over);
    RUN(audio_volume_set_before_init);
    RUN(audio_volume_set_restore);

    /* Mute Control */
    RUN(audio_volume_is_muted_null);
    RUN(audio_volume_is_muted_before_init);
    RUN(audio_volume_set_muted_before_init);
    RUN(audio_volume_toggle_before_init);
    RUN(audio_volume_mute_restore);
    RUN(audio_volume_toggle_restore);

    /* Shutdown */
    RUN(audio_volume_shutdown_basic);
    RUN(audio_volume_shutdown_idempotent);
    RUN(audio_volume_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
