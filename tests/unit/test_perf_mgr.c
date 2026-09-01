#include "../test_framework.h"
#include "perf_mgr.h"

TEST(perf_init) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = {
        .snapshot_interval_ms = 0,
        .max_snapshots = 16,
        .startup_timeout_ms = 5000,
        .auto_cpu_check = 0,
        .auto_memory_check = 0,
    };
    ASSERT_EQ(ozayn_perf_init(&mgr, &cfg), 0);
    ASSERT(mgr.initialized);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_startup_timing) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ozayn_perf_startup_begin(&mgr);
    ozayn_perf_startup_end(&mgr);
    uint64_t dur = ozayn_perf_startup_duration_us(&mgr);
    ASSERT(dur >= 0);
    double ms = ozayn_perf_startup_duration_ms(&mgr);
    ASSERT(ms >= 0.0);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_snapshot_collect) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ozayn_perf_snapshot_t snap = {0};
    ASSERT_EQ(ozayn_perf_snapshot_collect(&mgr, &snap), 0);
    ASSERT(snap.timestamp_us > 0);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_snapshot_store) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ASSERT_EQ(ozayn_perf_snapshot_store(&mgr), 0);
    ASSERT_EQ(ozayn_perf_snapshot_count(&mgr), 1);
    const ozayn_perf_snapshot_t *latest = ozayn_perf_snapshot_latest(&mgr);
    ASSERT_NOT_NULL(latest);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_bench_register) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ASSERT_EQ(ozayn_perf_bench_register(&mgr, "test.bench"), 0);
    ASSERT_EQ(ozayn_perf_bench_count(&mgr), 1);
    const ozayn_perf_benchmark_t *b = ozayn_perf_bench_find(&mgr, "test.bench");
    ASSERT_NOT_NULL(b);
    ASSERT_NULL(ozayn_perf_bench_find(&mgr, "nonexistent"));
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_bench_run) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ozayn_perf_bench_register(&mgr, "bench1");
    ASSERT_EQ(ozayn_perf_bench_begin(&mgr, "bench1"), 0);
    ASSERT_EQ(ozayn_perf_bench_record(&mgr, "bench1", 1000), 0);
    ASSERT_EQ(ozayn_perf_bench_record(&mgr, "bench1", 2000), 0);
    ASSERT_EQ(ozayn_perf_bench_end(&mgr, "bench1"), 0);
    const ozayn_perf_benchmark_t *b = ozayn_perf_bench_find(&mgr, "bench1");
    ASSERT_NOT_NULL(b);
    ASSERT_EQ(b->iterations, 2);
    ASSERT(b->min_us == 1000);
    ASSERT(b->max_us == 2000);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_bench_state_names) {
    ASSERT_STR_EQ(ozayn_perf_bench_state_name(OZAYN_PERF_BENCH_IDLE), "IDLE");
    ASSERT_STR_EQ(ozayn_perf_bench_state_name(OZAYN_PERF_BENCH_RUNNING), "RUNNING");
    ASSERT_STR_EQ(ozayn_perf_bench_state_name(OZAYN_PERF_BENCH_COMPLETED), "COMPLETED");
    ASSERT_STR_EQ(ozayn_perf_bench_state_name(OZAYN_PERF_BENCH_FAILED), "FAILED");
    ASSERT_STR_EQ(ozayn_perf_bench_state_name(OZAYN_PERF_BENCH_CANCELLED), "CANCELLED");
    return 0;
}

TEST(perf_threshold_names) {
    ASSERT_STR_EQ(ozayn_perf_threshold_severity_name(OZAYN_PERF_THRESH_WARNING), "WARNING");
    ASSERT_STR_EQ(ozayn_perf_threshold_severity_name(OZAYN_PERF_THRESH_CRITICAL), "CRITICAL");
    return 0;
}

TEST(perf_threshold_register) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ASSERT_EQ(ozayn_perf_threshold_register(&mgr, "cpu", 80.0, 95.0), 0);
    ASSERT_EQ(mgr.threshold_count, 1);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

TEST(perf_elapsed_us) {
    struct timespec t1 = { .tv_sec = 1, .tv_nsec = 0 };
    struct timespec t2 = { .tv_sec = 2, .tv_nsec = 0 };
    uint64_t us = ozayn_perf_elapsed_us(&t1, &t2);
    ASSERT_EQ(us, 1000000);
    return 0;
}

TEST(perf_stats) {
    ozayn_perf_manager_t mgr;
    ozayn_perf_config_t cfg = { .snapshot_interval_ms = 0, .max_snapshots = 16 };
    ozayn_perf_init(&mgr, &cfg);
    ozayn_perf_stats_t s = ozayn_perf_stats(&mgr);
    ASSERT_EQ(s.snapshot_count, 0);
    ASSERT_EQ(s.benchmark_count, 0);
    ozayn_perf_shutdown(&mgr);
    return 0;
}

int run_perf_mgr_tests(void) {
    SUITE_BEGIN("Performance Manager");
    RUN(perf_init);
    RUN(perf_startup_timing);
    RUN(perf_snapshot_collect);
    RUN(perf_snapshot_store);
    RUN(perf_bench_register);
    RUN(perf_bench_run);
    RUN(perf_bench_state_names);
    RUN(perf_threshold_names);
    RUN(perf_threshold_register);
    RUN(perf_elapsed_us);
    RUN(perf_stats);
    SUITE_END();
    return _tf_suite_fail;
}
