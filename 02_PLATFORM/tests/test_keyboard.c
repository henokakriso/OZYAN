#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_keyboard.c — Section 02 Step 08: Keyboard & Input Event Abstraction Tests.
 *
 * Tests keyboard initialization, shutdown, availability, key mapping,
 * key names, event polling, and error handling. Works in headless environments.
 *
 * Event polling and key state tests are only verified for API correctness.
 * No physical keyboard interaction is required for automated tests.
 */

/* --- Keyboard Initialization --- */

TEST(keyboard_init_basic) {
    ozayn_result_t r = ozayn_keyboard_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_keyboard_shutdown();
    return 0;
}

TEST(keyboard_init_idempotent) {
    ozayn_input_init();
    ozayn_keyboard_init();
    ozayn_result_t r = ozayn_keyboard_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

/* --- Keyboard Availability --- */

TEST(keyboard_is_available_after_init) {
    ozayn_input_init();
    ozayn_keyboard_init();
    int avail = ozayn_keyboard_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_is_available_before_init) {
    ozayn_keyboard_shutdown();
    int avail = ozayn_keyboard_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

/* --- Key State --- */

TEST(keyboard_is_key_down_before_init) {
    int r = ozayn_keyboard_is_key_down(OZAYN_KEY_A);
    ASSERT_EQ(r, -1);
    return 0;
}

TEST(keyboard_is_key_down_unknown_key) {
    ozayn_input_init();
    ozayn_keyboard_init();
    int r = ozayn_keyboard_is_key_down(OZAYN_KEY_UNKNOWN);
    ASSERT_EQ(r, -1);
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_is_key_down_valid_key) {
    ozayn_input_init();
    ozayn_keyboard_init();
    if (ozayn_keyboard_is_available()) {
        int r = ozayn_keyboard_is_key_down(OZAYN_KEY_A);
        ASSERT(r == 0 || r == 1 || r == -1);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_is_key_down_letters) {
    ozayn_input_init();
    ozayn_keyboard_init();
    if (ozayn_keyboard_is_available()) {
        /* Spot-check a few letter keys — should not crash */
        int r;
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_A);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_Z);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_M);
        ASSERT(r == 0 || r == 1 || r == -1);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_is_key_down_digits) {
    ozayn_input_init();
    ozayn_keyboard_init();
    if (ozayn_keyboard_is_available()) {
        int r;
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_0);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_9);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_5);
        ASSERT(r == 0 || r == 1 || r == -1);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_is_key_down_function_keys) {
    ozayn_input_init();
    ozayn_keyboard_init();
    if (ozayn_keyboard_is_available()) {
        int r;
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_F1);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_F12);
        ASSERT(r == 0 || r == 1 || r == -1);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_is_key_down_modifier_keys) {
    ozayn_input_init();
    ozayn_keyboard_init();
    if (ozayn_keyboard_is_available()) {
        int r;
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_SHIFT);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_CTRL);
        ASSERT(r == 0 || r == 1 || r == -1);
        r = ozayn_keyboard_is_key_down(OZAYN_KEY_ALT);
        ASSERT(r == 0 || r == 1 || r == -1);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

/* --- Key Names --- */

TEST(keyboard_key_name_known_keys) {
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_A), "A");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_Z), "Z");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_0), "0");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_9), "9");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_ESCAPE), "Escape");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_ENTER), "Enter");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_SPACE), "Space");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_SHIFT), "Shift");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_CTRL), "Ctrl");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_ALT), "Alt");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_UP), "Up");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_DOWN), "Down");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_LEFT), "Left");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_RIGHT), "Right");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_F1), "F1");
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_F12), "F12");
    return 0;
}

TEST(keyboard_key_name_unknown) {
    ASSERT_STR_EQ(ozayn_key_name(OZAYN_KEY_UNKNOWN), "Unknown");
    ASSERT_STR_EQ(ozayn_key_name((OzaynKey)999), "Unknown");
    return 0;
}

TEST(keyboard_key_name_never_null) {
    for (int i = 0; i < OZAYN_KEY_COUNT; i++) {
        const char *name = ozayn_key_name((OzaynKey)i);
        ASSERT(name != NULL);
    }
    return 0;
}

/* --- Event Polling --- */

TEST(keyboard_poll_event_null) {
    ozayn_result_t r = ozayn_keyboard_poll_event(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    return 0;
}

TEST(keyboard_poll_event_before_init) {
    OzaynInputEvent event;
    ozayn_result_t r = ozayn_keyboard_poll_event(&event);
    ASSERT_EQ(r, OZAYN_ERR);
    return 0;
}

TEST(keyboard_poll_event_no_event) {
    ozayn_input_init();
    ozayn_keyboard_init();
    OzaynInputEvent event;
    memset(&event, 0xFF, sizeof(event));
    ozayn_result_t r = ozayn_keyboard_poll_event(&event);
    /* No event available is a normal result */
    if (r == OZAYN_OK) {
        ASSERT(event.type == OZAYN_INPUT_EVENT_KEY_DOWN || event.type == OZAYN_INPUT_EVENT_KEY_UP);
    } else {
        ASSERT_EQ(r, OZAYN_ERR);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_poll_event_fields_zeroed) {
    ozayn_input_init();
    ozayn_keyboard_init();
    OzaynInputEvent event;
    memset(&event, 0xFF, sizeof(event));
    ozayn_keyboard_poll_event(&event);
    /* If no event, fields should be zeroed/reset */
    if (event.type == OZAYN_INPUT_EVENT_NONE) {
        ASSERT_EQ(event.key, OZAYN_KEY_UNKNOWN);
        ASSERT_EQ(event.modifiers, 0u);
    }
    ozayn_keyboard_shutdown();
    ozayn_input_shutdown();
    return 0;
}

/* --- Keyboard Shutdown --- */

TEST(keyboard_shutdown_basic) {
    ozayn_input_init();
    ozayn_keyboard_init();
    ozayn_keyboard_shutdown();
    ASSERT_EQ(ozayn_keyboard_is_available(), 0);
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_shutdown_idempotent) {
    ozayn_input_init();
    ozayn_keyboard_init();
    ozayn_keyboard_shutdown();
    ozayn_keyboard_shutdown();
    ASSERT_EQ(ozayn_keyboard_is_available(), 0);
    ozayn_input_shutdown();
    return 0;
}

TEST(keyboard_shutdown_before_init) {
    ozayn_keyboard_shutdown();
    ASSERT_EQ(ozayn_keyboard_is_available(), 0);
    return 0;
}

/* --- Modifier Constants --- */

TEST(keyboard_modifier_constants) {
    ASSERT_EQ(OZAYN_MOD_SHIFT, 1);
    ASSERT_EQ(OZAYN_MOD_CTRL, 2);
    ASSERT_EQ(OZAYN_MOD_ALT, 4);
    return 0;
}

/* --- Key Enumeration Range --- */

TEST(keyboard_key_enum_range) {
    ASSERT_EQ(OZAYN_KEY_UNKNOWN, 0);
    ASSERT_EQ(OZAYN_KEY_A, 1);
    ASSERT(OZAYN_KEY_COUNT >= 60);
    return 0;
}

int run_keyboard_tests(void) {
    SUITE_BEGIN("Keyboard & Input Event Abstraction (Section 02)");
    RUN(keyboard_init_basic);
    RUN(keyboard_init_idempotent);
    RUN(keyboard_is_available_after_init);
    RUN(keyboard_is_available_before_init);
    RUN(keyboard_is_key_down_before_init);
    RUN(keyboard_is_key_down_unknown_key);
    RUN(keyboard_is_key_down_valid_key);
    RUN(keyboard_is_key_down_letters);
    RUN(keyboard_is_key_down_digits);
    RUN(keyboard_is_key_down_function_keys);
    RUN(keyboard_is_key_down_modifier_keys);
    RUN(keyboard_key_name_known_keys);
    RUN(keyboard_key_name_unknown);
    RUN(keyboard_key_name_never_null);
    RUN(keyboard_poll_event_null);
    RUN(keyboard_poll_event_before_init);
    RUN(keyboard_poll_event_no_event);
    RUN(keyboard_poll_event_fields_zeroed);
    RUN(keyboard_shutdown_basic);
    RUN(keyboard_shutdown_idempotent);
    RUN(keyboard_shutdown_before_init);
    RUN(keyboard_modifier_constants);
    RUN(keyboard_key_enum_range);
    SUITE_END();
    return _tf_suite_fail;
}
