#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_notification.c — Section 02 Step 14: Notification System Abstraction Tests.
 *
 * Tests notification initialization, shutdown, availability, sending,
 * and error handling. Works on headless systems.
 *
 * If no notification service is available, tests verify graceful handling.
 * No spam or excessive notifications are sent during automated tests.
 */

/* --- Notification Initialization --- */

TEST(notif_init_basic) {
    ozayn_result_t r = ozayn_notification_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_init_idempotent) {
    ozayn_notification_init();
    ozayn_result_t r = ozayn_notification_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_notification_shutdown();
    return 0;
}

/* --- Notification Availability --- */

TEST(notif_is_available_after_init) {
    ozayn_notification_init();
    int avail = ozayn_notification_is_available();
    ASSERT(avail == 0 || avail == 1);
    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_is_available_before_init) {
    int avail = ozayn_notification_is_available();
    ASSERT(avail == 0);
    return 0;
}

/* --- Notification Send --- */

TEST(notif_send_valid) {
    ozayn_notification_init();
    OzaynNotification notif;
    memset(&notif, 0, sizeof(notif));
    strncpy(notif.title, "OZAYN Test", sizeof(notif.title) - 1);
    strncpy(notif.message, "Test notification from OZAYN", sizeof(notif.message) - 1);

    /* Send may fail on headless systems, which is acceptable */
    ozayn_result_t r = ozayn_notification_send(&notif);
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_send_empty_title) {
    ozayn_notification_init();
    OzaynNotification notif;
    memset(&notif, 0, sizeof(notif));
    strncpy(notif.message, "Message without title", sizeof(notif.message) - 1);

    ozayn_result_t r = ozayn_notification_send(&notif);
    ASSERT(r != OZAYN_OK);

    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_send_empty_message) {
    ozayn_notification_init();
    OzaynNotification notif;
    memset(&notif, 0, sizeof(notif));
    strncpy(notif.title, "Title only", sizeof(notif.title) - 1);

    /* Empty message is allowed — some notifications just show title */
    ozayn_result_t r = ozayn_notification_send(&notif);
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_send_null) {
    ozayn_notification_init();
    ozayn_result_t r = ozayn_notification_send(NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_send_oversized_title) {
    ozayn_notification_init();
    OzaynNotification notif;
    memset(&notif, 0, sizeof(notif));
    memset(notif.title, 'A', sizeof(notif.title) - 1);
    notif.title[sizeof(notif.title) - 1] = '\0';
    strncpy(notif.message, "Message", sizeof(notif.message) - 1);

    /* Oversized title may be truncated or fail gracefully */
    ozayn_result_t r = ozayn_notification_send(&notif);
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_send_oversized_message) {
    ozayn_notification_init();
    OzaynNotification notif;
    memset(&notif, 0, sizeof(notif));
    strncpy(notif.title, "Title", sizeof(notif.title) - 1);
    memset(notif.message, 'B', sizeof(notif.message) - 1);
    notif.message[sizeof(notif.message) - 1] = '\0';

    /* Oversized message may be truncated or fail gracefully */
    ozayn_result_t r = ozayn_notification_send(&notif);
    ASSERT(r == OZAYN_OK || r == OZAYN_ERR);

    ozayn_notification_shutdown();
    return 0;
}

/* --- Notification After Shutdown --- */

TEST(notif_send_after_shutdown) {
    ozayn_notification_init();
    ozayn_notification_shutdown();

    OzaynNotification notif;
    memset(&notif, 0, sizeof(notif));
    strncpy(notif.title, "Title", sizeof(notif.title) - 1);
    strncpy(notif.message, "Message", sizeof(notif.message) - 1);

    ozayn_result_t r = ozayn_notification_send(&notif);
    ASSERT(r != OZAYN_OK);
    return 0;
}

/* --- Notification Shutdown --- */

TEST(notif_shutdown_basic) {
    ozayn_notification_init();
    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_shutdown_idempotent) {
    ozayn_notification_init();
    ozayn_notification_shutdown();
    ozayn_notification_shutdown();
    return 0;
}

TEST(notif_shutdown_before_init) {
    ozayn_notification_shutdown();
    return 0;
}

/* --- Test Suite --- */

int run_notification_tests(void) {
    int failed = 0;
    SUITE_BEGIN("Notification System Abstraction (Section 02)");

    RUN(notif_init_basic);
    RUN(notif_init_idempotent);
    RUN(notif_is_available_after_init);
    RUN(notif_is_available_before_init);
    RUN(notif_send_valid);
    RUN(notif_send_empty_title);
    RUN(notif_send_empty_message);
    RUN(notif_send_null);
    RUN(notif_send_oversized_title);
    RUN(notif_send_oversized_message);
    RUN(notif_send_after_shutdown);
    RUN(notif_shutdown_basic);
    RUN(notif_shutdown_idempotent);
    RUN(notif_shutdown_before_init);

    SUITE_END();
    return FAILED();
}
