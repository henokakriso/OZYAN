#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_system_event.c — Section 02 Step 29: System Event & Hardware Change Notification Abstraction Tests.
 *
 * Tests system event initialization, shutdown, lifecycle, polling, type names,
 * and error handling. Read-only — no system modification.
 */

/* --- Initialization --- */

TEST(system_event_init_basic) {
    ozayn_result_t r = ozayn_system_event_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_init_idempotent) {
    ozayn_system_event_init();
    ozayn_result_t r = ozayn_system_event_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_system_event_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(system_event_is_available_before_init) {
    int avail = ozayn_system_event_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(system_event_is_available_after_init) {
    ozayn_system_event_init();
    int avail = ozayn_system_event_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_system_event_shutdown();
    return 0;
}

/* --- Lifecycle --- */

TEST(system_event_start_before_init) {
    ozayn_result_t r = ozayn_system_event_start();
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(system_event_start_basic) {
    ozayn_system_event_init();
    ozayn_result_t r = ozayn_system_event_start();
    /* May succeed or fail depending on inotify availability */
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);
    ozayn_system_event_stop();
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_start_idempotent) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    ozayn_result_t r = ozayn_system_event_start();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_system_event_stop();
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_stop_before_init) {
    ozayn_result_t r = ozayn_system_event_stop();
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(system_event_stop_basic) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    ozayn_result_t r = ozayn_system_event_stop();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_is_running_before_init) {
    int running = ozayn_system_event_is_running();
    ASSERT_EQ(running, 0);
    return 0;
}

TEST(system_event_is_running_after_start) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    int running = ozayn_system_event_is_running();
    ASSERT(running == 0 || running == 1);
    ozayn_system_event_stop();
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_is_running_after_stop) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    ozayn_system_event_stop();
    int running = ozayn_system_event_is_running();
    ASSERT_EQ(running, 0);
    ozayn_system_event_shutdown();
    return 0;
}

/* --- Polling --- */

TEST(system_event_poll_null) {
    ozayn_system_event_init();
    ozayn_result_t r = ozayn_system_event_poll(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_poll_before_init) {
    OzaynSystemEvent event;
    ozayn_result_t r = ozayn_system_event_poll(&event);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(system_event_poll_when_not_started) {
    ozayn_system_event_init();
    OzaynSystemEvent event;
    ozayn_result_t r = ozayn_system_event_poll(&event);
    /* Should return error since monitoring not started */
    ASSERT(r != OZAYN_OK);
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_poll_no_event) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    OzaynSystemEvent event;
    /* Poll multiple times — should eventually return no event */
    for (int i = 0; i < 10; i++) {
        ozayn_system_event_poll(&event);
    }
    /* After polling, event should be in safe state */
    ASSERT(event.type == OZAYN_SYSTEM_EVENT_NONE || event.available == 0 || event.available == 1);
    ozayn_system_event_stop();
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_poll_after_stop) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    ozayn_system_event_stop();
    OzaynSystemEvent event;
    ozayn_result_t r = ozayn_system_event_poll(&event);
    /* Should return error since monitoring stopped */
    ASSERT(r != OZAYN_OK);
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_poll_repeatedly) {
    ozayn_system_event_init();
    ozayn_system_event_start();
    /* Repeated polling must not crash or block */
    for (int i = 0; i < 100; i++) {
        OzaynSystemEvent event;
        ozayn_system_event_poll(&event);
    }
    ozayn_system_event_stop();
    ozayn_system_event_shutdown();
    return 0;
}

/* --- Event Type Names --- */

TEST(system_event_type_name_none) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_NONE);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_device_connected) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_DEVICE_CONNECTED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_device_disconnected) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_DEVICE_DISCONNECTED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_display_changed) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_DISPLAY_CHANGED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_network_changed) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_NETWORK_CHANGED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_power_changed) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_POWER_CHANGED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_audio_changed) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_AUDIO_CHANGED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_session_changed) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_SESSION_CHANGED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_bluetooth_changed) {
    const char *name = ozayn_system_event_type_name(OZAYN_SYSTEM_EVENT_BLUETOOTH_CHANGED);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

TEST(system_event_type_name_invalid) {
    const char *name = ozayn_system_event_type_name((OzaynSystemEventType)9999);
    ASSERT(name != NULL);
    ASSERT(strlen(name) > 0);
    return 0;
}

/* --- Shutdown --- */

TEST(system_event_shutdown_basic) {
    ozayn_system_event_init();
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_shutdown_idempotent) {
    ozayn_system_event_init();
    ozayn_system_event_shutdown();
    ozayn_system_event_shutdown();
    return 0;
}

TEST(system_event_shutdown_before_init) {
    ozayn_system_event_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_system_event_tests(void) {
    SUITE_BEGIN("System Event & Hardware Change Notification Abstraction (Step 29)");

    /* Lifecycle */
    RUN(system_event_init_basic);
    RUN(system_event_init_idempotent);

    /* Availability */
    RUN(system_event_is_available_before_init);
    RUN(system_event_is_available_after_init);

    /* Lifecycle Control */
    RUN(system_event_start_before_init);
    RUN(system_event_start_basic);
    RUN(system_event_start_idempotent);
    RUN(system_event_stop_before_init);
    RUN(system_event_stop_basic);
    RUN(system_event_is_running_before_init);
    RUN(system_event_is_running_after_start);
    RUN(system_event_is_running_after_stop);

    /* Polling */
    RUN(system_event_poll_null);
    RUN(system_event_poll_before_init);
    RUN(system_event_poll_when_not_started);
    RUN(system_event_poll_no_event);
    RUN(system_event_poll_after_stop);
    RUN(system_event_poll_repeatedly);

    /* Type Names */
    RUN(system_event_type_name_none);
    RUN(system_event_type_name_device_connected);
    RUN(system_event_type_name_device_disconnected);
    RUN(system_event_type_name_display_changed);
    RUN(system_event_type_name_network_changed);
    RUN(system_event_type_name_power_changed);
    RUN(system_event_type_name_audio_changed);
    RUN(system_event_type_name_session_changed);
    RUN(system_event_type_name_bluetooth_changed);
    RUN(system_event_type_name_invalid);

    /* Shutdown */
    RUN(system_event_shutdown_basic);
    RUN(system_event_shutdown_idempotent);
    RUN(system_event_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
