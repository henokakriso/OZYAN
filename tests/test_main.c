/*
 * test_main.c — OZAYN Core Test Runner.
 *
 * Runs all unit, integration, and system tests.
 * Exit code: 0 = all pass, 1 = any failure.
 */

#include "test_framework.h"
#include <stdio.h>

/* Unit test declarations */
extern int run_events_tests(void);
extern int run_dependency_tests(void);
extern int run_lifecycle_tests(void);
extern int run_security_tests(void);
extern int run_reload_tests(void);
extern int run_perf_tests(void);
extern int run_defense_tests(void);
extern int run_cb_tests(void);
extern int run_rl_tests(void);
extern int run_ht_tests(void);
extern int run_cl_tests(void);
extern int run_cv_tests(void);
extern int run_version_tests(void);
extern int run_release_tests(void);
extern int run_logger_tests(void);
extern int run_tasks_tests(void);
extern int run_commands_tests(void);
extern int run_recovery_tests(void);
extern int run_resource_tests(void);
extern int run_scheduler_tests(void);
extern int run_monitoring_tests(void);
extern int run_diagnostics_tests(void);
extern int run_security_boundary_tests(void);
extern int run_state_manager_tests(void);
extern int run_service_lifecycle_tests(void);
extern int run_platform_tests(void);
extern int run_ipc_tests(void);
extern int run_registry_tests(void);
extern int run_modules_tests(void);
extern int run_plugins_tests(void);
extern int run_processes_tests(void);
extern int run_perf_mgr_tests(void);
extern int run_core_api_tests(void);
extern int run_config_mgr_tests(void);

/* Section 02 — Platform Detection tests */
extern int run_platform_detect_tests(void);
extern int run_platform_info_tests(void);
extern int run_filesystem_tests(void);
extern int run_process_tests(void);
extern int run_display_tests(void);
extern int run_window_tests(void);
extern int run_input_tests(void);
extern int run_keyboard_tests(void);
extern int run_camera_tests(void);
extern int run_microphone_tests(void);
extern int run_audio_output_tests(void);
extern int run_network_tests(void);
extern int run_power_tests(void);
extern int run_notification_tests(void);
extern int run_clipboard_tests(void);
extern int run_environment_tests(void);
extern int run_time_tests(void);
extern int run_application_tests(void);
extern int run_permissions_tests(void);
extern int run_audio_volume_tests(void);
extern int run_session_tests(void);
extern int run_brightness_tests(void);
extern int run_appearance_tests(void);
extern int run_font_tests(void);
extern int run_sensors_tests(void);
extern int run_storage_tests(void);
extern int run_peripheral_tests(void);
extern int run_bluetooth_tests(void);
extern int run_system_event_tests(void);
extern int run_resource_monitoring_tests(void);
extern int run_network_config_tests(void);
extern int run_system_service_tests(void);
extern int run_sys_security_tests(void);
extern int run_sys_diagnostics_tests(void);
extern int run_platform_capabilities_tests(void);

/* Section 03 — Secure Data Layer tests */
extern int run_data_classification_tests(void);
extern int run_secure_data_object_tests(void);
extern int run_storage_provider_tests(void);
extern int run_storage_provider_local_tests(void);
extern int run_protection_provider_tests(void);
extern int run_protection_provider_sodium_tests(void);
extern int run_key_management_tests(void);

/* Failure mode test declarations */
extern int run_failure_tests(void);

/* Regression test declarations */
extern int run_regression_tests(void);

/* Integration test declarations */
extern int run_startup_shutdown_tests(void);
extern int run_service_integration_tests(void);

/* System test declarations */
extern int run_full_lifecycle_tests(void);

int main(void) {
    int total_pass = 0;
    int total_fail = 0;
    int suite_pass, suite_fail;

    printf("\n");
    printf("  ======================================================\n");
    printf("  OZAYN CORE TEST SUITE\n");
    printf("  Version: 0.1 (Genesis)\n");
    printf("  ======================================================\n");

    /* Unit tests */
    printf("\n  --- UNIT TESTS ---");
    suite_fail = run_events_tests();       suite_pass = 11 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_dependency_tests();   suite_pass = 11 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_lifecycle_tests();    suite_pass = 9  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_security_tests();     suite_pass = 16 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_reload_tests();       suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_perf_tests();         suite_pass = 15 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_defense_tests();      suite_pass = 13 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_cb_tests();           suite_pass = 8  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_rl_tests();           suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_ht_tests();           suite_pass = 8  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_cl_tests();           suite_pass = 9  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_cv_tests();           suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_version_tests();      suite_pass = 16 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_release_tests();      suite_pass = 13 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_logger_tests();       suite_pass = 7  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_tasks_tests();        suite_pass = 11 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_commands_tests();     suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_recovery_tests();     suite_pass = 9  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_resource_tests();     suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_scheduler_tests();    suite_pass = 7  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_monitoring_tests();   suite_pass = 11 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_diagnostics_tests();  suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_security_boundary_tests(); suite_pass = 8 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_state_manager_tests(); suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_service_lifecycle_tests(); suite_pass = 7 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_platform_tests();     suite_pass = 8  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_ipc_tests();          suite_pass = 7  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_registry_tests();     suite_pass = 8  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_modules_tests();      suite_pass = 6  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_plugins_tests();      suite_pass = 6  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_processes_tests();    suite_pass = 7  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_perf_mgr_tests();     suite_pass = 11 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_core_api_tests();     suite_pass = 12 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_config_mgr_tests();   suite_pass = 6  - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_platform_detect_tests(); suite_pass = 8 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_platform_info_tests(); suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_filesystem_tests();  suite_pass = 40 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_process_tests();     suite_pass = 26 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_display_tests();     suite_pass = 26 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_window_tests();      suite_pass = 26 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_input_tests();       suite_pass = 23 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_keyboard_tests();    suite_pass = 23 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_camera_tests();      suite_pass = 29 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_microphone_tests();  suite_pass = 26 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_audio_output_tests();  suite_pass = 27 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_network_tests();       suite_pass = 23 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_power_tests();         suite_pass = 16 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_notification_tests();  suite_pass = 14 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_clipboard_tests();     suite_pass = 19 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_environment_tests();   suite_pass = 24 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_time_tests();          suite_pass = 21 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_application_tests();   suite_pass = 29 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_permissions_tests();   suite_pass = 30 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_audio_volume_tests();  suite_pass = 20 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_session_tests();       suite_pass = 19 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_brightness_tests();    suite_pass = 17 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_appearance_tests();    suite_pass = 13 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_font_tests();          suite_pass = 19 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_sensors_tests();       suite_pass = 22 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_storage_tests();       suite_pass = 18 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_peripheral_tests();    suite_pass = 25 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_bluetooth_tests();     suite_pass = 24 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_system_event_tests();  suite_pass = 31 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_resource_monitoring_tests(); suite_pass = 24 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_network_config_tests();   suite_pass = 22 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_system_service_tests();  suite_pass = 35 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_sys_security_tests();    suite_pass = 21 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_sys_diagnostics_tests();  suite_pass = 31 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_platform_capabilities_tests(); suite_pass = 34 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;

    /* Section 03 — Secure Data Layer tests */
    printf("\n  --- SECTION 03 TESTS ---");
    suite_fail = run_data_classification_tests();  suite_pass = 56 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_secure_data_object_tests();   suite_pass = 54 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_storage_provider_tests();      suite_pass = 36 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_storage_provider_local_tests(); suite_pass = 45 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_protection_provider_tests();    suite_pass = 58 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_protection_provider_sodium_tests(); suite_pass = 42 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_key_management_tests();              suite_pass = 40 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;

    /* Failure mode tests */
    printf("\n  --- FAILURE MODE TESTS ---");
    suite_fail = run_failure_tests();      suite_pass = 10 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;

    /* Regression tests */
    printf("\n  --- REGRESSION TESTS ---");
    suite_fail = run_regression_tests();   suite_pass = 11 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;

    /* Integration tests */
    printf("\n  --- INTEGRATION TESTS ---");
    suite_fail = run_startup_shutdown_tests();    suite_pass = 6 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;
    suite_fail = run_service_integration_tests(); suite_pass = 6 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;

    /* System tests */
    printf("\n  --- SYSTEM TESTS ---");
    suite_fail = run_full_lifecycle_tests();      suite_pass = 5 - suite_fail; total_pass += suite_pass; total_fail += suite_fail;

    /* Summary */
    int total_tests = total_pass + total_fail;
    printf("\n  ======================================================\n");
    printf("  TOTAL: %d/%d passed", total_pass, total_tests);
    if (total_fail > 0) {
        printf(" (%d FAILED)", total_fail);
    } else {
        printf(" -- ALL PASS");
    }
    printf("\n  ======================================================\n\n");

    return total_fail > 0 ? 1 : 0;
}
