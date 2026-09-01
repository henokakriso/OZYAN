#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_process.c — Section 02 Step 04: Process Management Abstraction Tests.
 *
 * Tests process start, status, info, terminate, wait, and close.
 * Uses /usr/bin/sleep as the test child process.
 */

/* --- Process Start --- */

TEST(process_start_basic) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_result_t r = ozayn_process_start("/usr/bin/sleep", args, &proc);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT(proc.pid > 0);
    ozayn_process_close(&proc);
    return 0;
}

TEST(process_start_returns_pid) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ASSERT(proc.pid > 0);
    ozayn_process_close(&proc);
    return 0;
}

TEST(process_start_running_flag) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ASSERT_EQ(proc.running, 1);
    ozayn_process_close(&proc);
    return 0;
}

/* --- Process Is Running --- */

TEST(process_is_running_check) {
    OzaynProcess proc;
    const char *args[] = {"3", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ASSERT_EQ(ozayn_process_is_running(&proc), 1);
    ozayn_process_close(&proc);
    return 0;
}

TEST(process_is_running_after_terminate) {
    OzaynProcess proc;
    const char *args[] = {"5", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ozayn_process_terminate(&proc);
    ozayn_process_wait(&proc, 2000);
    ASSERT_EQ(ozayn_process_is_running(&proc), 0);
    ozayn_process_close(&proc);
    return 0;
}

/* --- Process Info --- */

TEST(process_info_running) {
    OzaynProcess proc;
    const char *args[] = {"3", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);

    OzaynProcessInfo info;
    ozayn_result_t r = ozayn_proc_get_info(&proc, &info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(info.pid, proc.pid);
    ASSERT_EQ(info.state, OZAYN_PROC_STATE_RUNNING);

    ozayn_process_close(&proc);
    return 0;
}

TEST(process_info_after_exit) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ozayn_process_wait(&proc, 3000);

    OzaynProcessInfo info;
    ozayn_result_t r = ozayn_proc_get_info(&proc, &info);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(info.state, OZAYN_PROC_STATE_EXITED);

    ozayn_process_close(&proc);
    return 0;
}

/* --- Process Terminate --- */

TEST(process_terminate_basic) {
    OzaynProcess proc;
    const char *args[] = {"10", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ASSERT_EQ(ozayn_process_terminate(&proc), OZAYN_OK);
    ozayn_process_wait(&proc, 2000);
    ozayn_process_close(&proc);
    return 0;
}

/* --- Process Wait --- */

TEST(process_wait_exits) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ozayn_result_t r = ozayn_process_wait(&proc, 5000);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(proc.running, 0);
    ozayn_process_close(&proc);
    return 0;
}

TEST(process_wait_timeout) {
    OzaynProcess proc;
    const char *args[] = {"10", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ozayn_result_t r = ozayn_process_wait(&proc, 50);
    /* Should timeout, process still running */
    ASSERT_EQ(proc.running, 1);
    ozayn_process_terminate(&proc);
    ozayn_process_wait(&proc, 2000);
    ozayn_process_close(&proc);
    (void)r;
    return 0;
}

/* --- Process Close --- */

TEST(process_close_cleans) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ozayn_process_close(&proc);
    ASSERT_EQ(proc.pid, 0);
    ASSERT_EQ(proc.running, 0);
    return 0;
}

TEST(process_close_idempotent) {
    OzaynProcess proc;
    const char *args[] = {"1", NULL};
    ozayn_process_start("/usr/bin/sleep", args, &proc);
    ozayn_process_close(&proc);
    ozayn_process_close(&proc);
    ASSERT_EQ(proc.pid, 0);
    return 0;
}

/* --- Error Handling --- */

TEST(process_start_null_program) {
    OzaynProcess proc;
    ASSERT_EQ(ozayn_process_start(NULL, NULL, &proc), OZAYN_ERR_NULL);
    return 0;
}

TEST(process_start_empty_program) {
    OzaynProcess proc;
    ASSERT_EQ(ozayn_process_start("", NULL, &proc), OZAYN_ERR);
    return 0;
}

TEST(process_start_null_proc) {
    ASSERT_EQ(ozayn_process_start("/usr/bin/sleep", NULL, NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(process_start_invalid_exec) {
    OzaynProcess proc;
    ASSERT_EQ(ozayn_process_start("/nonexistent_program_xyz", NULL, &proc), OZAYN_ERR);
    return 0;
}

TEST(process_is_running_null) {
    ASSERT_EQ(ozayn_process_is_running(NULL), 0);
    return 0;
}

TEST(process_is_running_zero_pid) {
    OzaynProcess proc;
    memset(&proc, 0, sizeof(proc));
    ASSERT_EQ(ozayn_process_is_running(&proc), 0);
    return 0;
}

TEST(process_info_null) {
    OzaynProcessInfo info;
    ASSERT_EQ(ozayn_proc_get_info(NULL, &info), OZAYN_ERR_NULL);
    return 0;
}

TEST(process_info_null_info) {
    OzaynProcess proc;
    memset(&proc, 0, sizeof(proc));
    ASSERT_EQ(ozayn_proc_get_info(&proc, NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(process_terminate_null) {
    ASSERT_EQ(ozayn_process_terminate(NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(process_terminate_not_running) {
    OzaynProcess proc;
    memset(&proc, 0, sizeof(proc));
    ASSERT_EQ(ozayn_process_terminate(&proc), OZAYN_ERR);
    return 0;
}

TEST(process_wait_null) {
    ASSERT_EQ(ozayn_process_wait(NULL, 100), OZAYN_ERR_NULL);
    return 0;
}

TEST(process_wait_zero_pid) {
    OzaynProcess proc;
    memset(&proc, 0, sizeof(proc));
    ASSERT_EQ(ozayn_process_wait(&proc, 100), OZAYN_ERR);
    return 0;
}

TEST(process_close_null) {
    ozayn_process_close(NULL);
    return 0;
}

/* --- Multiple Processes --- */

TEST(process_multiple_concurrent) {
    OzaynProcess p1, p2;
    const char *args1[] = {"3", NULL};
    const char *args2[] = {"3", NULL};

    ozayn_process_start("/usr/bin/sleep", args1, &p1);
    ozayn_process_start("/usr/bin/sleep", args2, &p2);

    ASSERT(p1.pid != p2.pid);
    ASSERT_EQ(ozayn_process_is_running(&p1), 1);
    ASSERT_EQ(ozayn_process_is_running(&p2), 1);

    ozayn_process_close(&p1);
    ozayn_process_close(&p2);
    return 0;
}

int run_process_tests(void) {
    SUITE_BEGIN("Process Management (Section 02)");
    RUN(process_start_basic);
    RUN(process_start_returns_pid);
    RUN(process_start_running_flag);
    RUN(process_is_running_check);
    RUN(process_is_running_after_terminate);
    RUN(process_info_running);
    RUN(process_info_after_exit);
    RUN(process_terminate_basic);
    RUN(process_wait_exits);
    RUN(process_wait_timeout);
    RUN(process_close_cleans);
    RUN(process_close_idempotent);
    RUN(process_start_null_program);
    RUN(process_start_empty_program);
    RUN(process_start_null_proc);
    RUN(process_start_invalid_exec);
    RUN(process_is_running_null);
    RUN(process_is_running_zero_pid);
    RUN(process_info_null);
    RUN(process_info_null_info);
    RUN(process_terminate_null);
    RUN(process_terminate_not_running);
    RUN(process_wait_null);
    RUN(process_wait_zero_pid);
    RUN(process_close_null);
    RUN(process_multiple_concurrent);
    SUITE_END();
    return _tf_suite_fail;
}
