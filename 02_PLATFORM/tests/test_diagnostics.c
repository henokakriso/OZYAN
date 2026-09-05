#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_diagnostics.c — Section 02 Step 34: System Diagnostics & Health Information Abstraction Tests.
 *
 * Tests diagnostics initialization, shutdown, run, enumeration, result validation,
 * component lookup, and error handling. Read-only — no system modification.
 */

/* --- Initialization --- */

TEST(diag_init_basic) {
    ozayn_result_t r = ozayn_sys_diag_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_init_idempotent) {
    ozayn_sys_diag_init();
    ozayn_result_t r = ozayn_sys_diag_init();
    ASSERT_EQ(r, OZAYN_OK);
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- Availability --- */

TEST(diag_is_available_before_init) {
    int avail = ozayn_sys_diag_is_available();
    ASSERT_EQ(avail, 0);
    return 0;
}

TEST(diag_is_available_after_init) {
    ozayn_sys_diag_init();
    int avail = ozayn_sys_diag_is_available();
    ASSERT_EQ(avail, 1);
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- Run --- */

TEST(diag_run_before_init) {
    int count = ozayn_sys_diag_run();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(diag_run_returns_results) {
    ozayn_sys_diag_init();
    int count = ozayn_sys_diag_run();
    ASSERT(count > 0);
    ASSERT_EQ(count, ozayn_sys_diag_get_count());
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- Count --- */

TEST(diag_count_before_init) {
    int count = ozayn_sys_diag_get_count();
    ASSERT_EQ(count, 0);
    return 0;
}

TEST(diag_count_after_run) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    int count = ozayn_sys_diag_get_count();
    ASSERT(count > 0);
    ASSERT(count <= OZAYN_DIAGNOSTIC_COMPONENT_COUNT);
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- Get Result --- */

TEST(diag_get_result_null) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    ozayn_result_t r = ozayn_sys_diag_get_result(0, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_get_result_before_init) {
    OzaynDiagnosticResult result;
    ozayn_result_t r = ozayn_sys_diag_get_result(0, &result);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(diag_get_result_negative_index) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    OzaynDiagnosticResult result;
    ozayn_result_t r = ozayn_sys_diag_get_result(-1, &result);
    ASSERT(r != OZAYN_OK);
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_get_result_index_out_of_range) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    int count = ozayn_sys_diag_get_count();
    OzaynDiagnosticResult result;
    ozayn_result_t r = ozayn_sys_diag_get_result(count + 100, &result);
    ASSERT(r != OZAYN_OK);
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_get_result_valid) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    int count = ozayn_sys_diag_get_count();
    ASSERT(count > 0);
    OzaynDiagnosticResult result;
    memset(&result, 0, sizeof(result));
    ozayn_result_t r = ozayn_sys_diag_get_result(0, &result);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(result.state >= OZAYN_DIAGNOSTIC_UNKNOWN &&
           result.state <= OZAYN_DIAGNOSTIC_ERROR);
    ASSERT(result.component >= OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM &&
           result.component < OZAYN_DIAGNOSTIC_COMPONENT_COUNT);
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_get_result_all_components) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    int count = ozayn_sys_diag_get_count();
    for (int i = 0; i < count; i++) {
        OzaynDiagnosticResult result;
        memset(&result, 0, sizeof(result));
        ozayn_result_t r = ozayn_sys_diag_get_result(i, &result);
        ASSERT_EQ(r, OZAYN_OK);
        ASSERT(result.name[0] != '\0');
        ASSERT(result.message[0] != '\0');
    }
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- Get Component --- */

TEST(diag_get_component_null) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    ozayn_result_t r = ozayn_sys_diag_get_component(OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM, NULL);
    ASSERT_EQ(r, OZAYN_ERR_NULL);
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_get_component_before_init) {
    OzaynDiagnosticResult result;
    ozayn_result_t r = ozayn_sys_diag_get_component(OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM, &result);
    ASSERT(r != OZAYN_OK);
    return 0;
}

TEST(diag_get_component_valid) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    OzaynDiagnosticResult result;
    memset(&result, 0, sizeof(result));
    ozayn_result_t r = ozayn_sys_diag_get_component(OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM, &result);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(result.component, OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM);
    ASSERT(result.state >= OZAYN_DIAGNOSTIC_UNKNOWN &&
           result.state <= OZAYN_DIAGNOSTIC_ERROR);
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- State Names --- */

TEST(diag_state_name_unknown) {
    const char *name = ozayn_sys_diag_state_name(OZAYN_DIAGNOSTIC_UNKNOWN);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

TEST(diag_state_name_ok) {
    const char *name = ozayn_sys_diag_state_name(OZAYN_DIAGNOSTIC_OK);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "OK") == 0);
    return 0;
}

TEST(diag_state_name_warning) {
    const char *name = ozayn_sys_diag_state_name(OZAYN_DIAGNOSTIC_WARNING);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Warning") == 0);
    return 0;
}

TEST(diag_state_name_unavailable) {
    const char *name = ozayn_sys_diag_state_name(OZAYN_DIAGNOSTIC_UNAVAILABLE);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unavailable") == 0);
    return 0;
}

TEST(diag_state_name_error) {
    const char *name = ozayn_sys_diag_state_name(OZAYN_DIAGNOSTIC_ERROR);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Error") == 0);
    return 0;
}

TEST(diag_state_name_invalid) {
    const char *name = ozayn_sys_diag_state_name(9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

/* --- Component Names --- */

TEST(diag_component_name_platform) {
    const char *name = ozayn_sys_diag_component_name(OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Platform") == 0);
    return 0;
}

TEST(diag_component_name_all) {
    for (int c = 0; c < OZAYN_DIAGNOSTIC_COMPONENT_COUNT; c++) {
        const char *name = ozayn_sys_diag_component_name((OzaynDiagnosticComponent)c);
        ASSERT(name != NULL);
        ASSERT(strlen(name) > 0);
    }
    return 0;
}

TEST(diag_component_name_invalid) {
    const char *name = ozayn_sys_diag_component_name(9999);
    ASSERT(name != NULL);
    ASSERT(strcmp(name, "Unknown") == 0);
    return 0;
}

/* --- String Validation --- */

TEST(diag_strings_null_terminated) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    int count = ozayn_sys_diag_get_count();
    for (int i = 0; i < count; i++) {
        OzaynDiagnosticResult result;
        ozayn_sys_diag_get_result(i, &result);
        ASSERT(result.name[OZAYN_MAX_DIAG_NAME - 1] == '\0');
        ASSERT(result.message[OZAYN_MAX_DIAG_MSG - 1] == '\0');
    }
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- Shutdown --- */

TEST(diag_shutdown_basic) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_shutdown_idempotent) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_shutdown();
    ozayn_sys_diag_shutdown();
    return 0;
}

TEST(diag_shutdown_before_init) {
    ozayn_sys_diag_shutdown();
    return 0;
}

/* --- After Shutdown --- */

TEST(diag_query_after_shutdown) {
    ozayn_sys_diag_init();
    ozayn_sys_diag_run();
    ozayn_sys_diag_shutdown();

    ASSERT_EQ(ozayn_sys_diag_is_available(), 0);
    ASSERT_EQ(ozayn_sys_diag_get_count(), 0);
    ASSERT_EQ(ozayn_sys_diag_run(), 0);

    OzaynDiagnosticResult result;
    ASSERT(ozayn_sys_diag_get_result(0, &result) != OZAYN_OK);
    ASSERT(ozayn_sys_diag_get_component(OZAYN_DIAGNOSTIC_COMPONENT_PLATFORM, &result) != OZAYN_OK);

    return 0;
}

/* --- Test Suite --- */

int run_sys_diagnostics_tests(void) {
    SUITE_BEGIN("System Diagnostics & Health Information Abstraction (Step 34)");

    /* Lifecycle */
    RUN(diag_init_basic);
    RUN(diag_init_idempotent);

    /* Availability */
    RUN(diag_is_available_before_init);
    RUN(diag_is_available_after_init);

    /* Run */
    RUN(diag_run_before_init);
    RUN(diag_run_returns_results);

    /* Count */
    RUN(diag_count_before_init);
    RUN(diag_count_after_run);

    /* Get Result */
    RUN(diag_get_result_null);
    RUN(diag_get_result_before_init);
    RUN(diag_get_result_negative_index);
    RUN(diag_get_result_index_out_of_range);
    RUN(diag_get_result_valid);
    RUN(diag_get_result_all_components);

    /* Get Component */
    RUN(diag_get_component_null);
    RUN(diag_get_component_before_init);
    RUN(diag_get_component_valid);

    /* State Names */
    RUN(diag_state_name_unknown);
    RUN(diag_state_name_ok);
    RUN(diag_state_name_warning);
    RUN(diag_state_name_unavailable);
    RUN(diag_state_name_error);
    RUN(diag_state_name_invalid);

    /* Component Names */
    RUN(diag_component_name_platform);
    RUN(diag_component_name_all);
    RUN(diag_component_name_invalid);

    /* String Validation */
    RUN(diag_strings_null_terminated);

    /* Shutdown */
    RUN(diag_shutdown_basic);
    RUN(diag_shutdown_idempotent);
    RUN(diag_shutdown_before_init);
    RUN(diag_query_after_shutdown);

    SUITE_END();
    return FAILED();
}
