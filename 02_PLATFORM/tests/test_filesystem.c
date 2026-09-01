#include "../../tests/test_framework.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>

/*
 * test_filesystem.c — Section 02 Step 03: Filesystem Abstraction Tests.
 *
 * Tests all filesystem operations in a temporary directory.
 * Cleans up after itself.
 */

#define TEST_FS_BASE "/tmp/ozayn_fs_test"
#define TEST_FS_DIR  TEST_FS_BASE "/subdir"

static void cleanup_test_dir(void) {
    remove(TEST_FS_BASE "/copy.txt");
    remove(TEST_FS_BASE "/move.txt");
    remove(TEST_FS_BASE "/append.txt");
    remove(TEST_FS_BASE "/binary.dat");
    remove(TEST_FS_BASE "/readme.txt");
    remove(TEST_FS_DIR  "/nested.txt");
    rmdir(TEST_FS_DIR);
    rmdir(TEST_FS_BASE);
}

/* --- Directory Operations --- */

TEST(fs_dir_creation) {
    cleanup_test_dir();
    ozayn_result_t r = ozayn_fs_mkdir(TEST_FS_DIR);
    ASSERT_EQ(r, OZAYN_OK);
    return 0;
}

TEST(fs_dir_exists) {
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_DIR), 1);
    return 0;
}

TEST(fs_dir_detection) {
    ASSERT_EQ(ozayn_fs_is_dir(TEST_FS_DIR), 1);
    ASSERT_EQ(ozayn_fs_is_file(TEST_FS_DIR), 0);
    return 0;
}

TEST(fs_dir_already_exists) {
    ozayn_result_t r = ozayn_fs_mkdir(TEST_FS_DIR);
    ASSERT_EQ(r, OZAYN_OK);
    return 0;
}

/* --- File Write & Existence --- */

TEST(fs_file_write) {
    const char *data = "OZAYN FILESYSTEM TEST\nSection 02\nStep 03\n";
    int64_t written = ozayn_fs_write(TEST_FS_BASE "/readme.txt", data, strlen(data));
    ASSERT_EQ(written, (int64_t)strlen(data));
    return 0;
}

TEST(fs_file_exists) {
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_BASE "/readme.txt"), 1);
    return 0;
}

TEST(fs_file_is_file) {
    ASSERT_EQ(ozayn_fs_is_file(TEST_FS_BASE "/readme.txt"), 1);
    ASSERT_EQ(ozayn_fs_is_dir(TEST_FS_BASE "/readme.txt"), 0);
    return 0;
}

TEST(fs_file_size) {
    const char *data = "OZAYN FILESYSTEM TEST\nSection 02\nStep 03\n";
    int64_t size = ozayn_fs_size(TEST_FS_BASE "/readme.txt");
    ASSERT_EQ(size, (int64_t)strlen(data));
    return 0;
}

/* --- File Read --- */

TEST(fs_file_read) {
    const char *expected = "OZAYN FILESYSTEM TEST\nSection 02\nStep 03\n";
    char buf[256] = {0};
    int64_t n = ozayn_fs_read(TEST_FS_BASE "/readme.txt", buf, sizeof(buf));
    ASSERT_EQ(n, (int64_t)strlen(expected));
    ASSERT_STR_EQ(buf, expected);
    return 0;
}

/* --- File Append --- */

TEST(fs_file_append) {
    const char *extra = "Appended line\n";
    int64_t appended = ozayn_fs_append(TEST_FS_BASE "/append.txt", extra, strlen(extra));
    ASSERT_EQ(appended, (int64_t)strlen(extra));
    return 0;
}

TEST(fs_file_append_to_existing) {
    const char *line1 = "Line 1\n";
    const char *line2 = "Line 2\n";
    ozayn_fs_write(TEST_FS_BASE "/append.txt", line1, strlen(line1));
    ozayn_fs_append(TEST_FS_BASE "/append.txt", line2, strlen(line2));

    char buf[256] = {0};
    int64_t n = ozayn_fs_read(TEST_FS_BASE "/append.txt", buf, sizeof(buf));
    ASSERT_EQ(n, (int64_t)(strlen(line1) + strlen(line2)));
    ASSERT_STR_EQ(buf, "Line 1\nLine 2\n");
    return 0;
}

/* --- Binary Data --- */

TEST(fs_binary_write_read) {
    unsigned char bindata[8] = {0x00, 0x01, 0x7F, 0x80, 0xFF, 0x42, 0xDE, 0xAD};
    int64_t written = ozayn_fs_write(TEST_FS_BASE "/binary.dat", bindata, 8);
    ASSERT_EQ(written, (int64_t)8);

    unsigned char readbuf[8] = {0};
    int64_t n = ozayn_fs_read(TEST_FS_BASE "/binary.dat", readbuf, 8);
    ASSERT_EQ(n, (int64_t)8);

    for (int i = 0; i < 8; i++) {
        ASSERT_EQ(readbuf[i], bindata[i]);
    }
    return 0;
}

/* --- File Copy --- */

TEST(fs_file_copy) {
    ozayn_result_t r = ozayn_fs_copy(TEST_FS_BASE "/readme.txt", TEST_FS_BASE "/copy.txt");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_BASE "/copy.txt"), 1);
    ASSERT_EQ(ozayn_fs_size(TEST_FS_BASE "/copy.txt"), ozayn_fs_size(TEST_FS_BASE "/readme.txt"));
    return 0;
}

TEST(fs_copy_preserves_content) {
    char buf[256] = {0};
    int64_t n = ozayn_fs_read(TEST_FS_BASE "/copy.txt", buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "OZAYN FILESYSTEM TEST\nSection 02\nStep 03\n");
    (void)n;
    return 0;
}

/* --- File Move --- */

TEST(fs_file_move) {
    ozayn_result_t r = ozayn_fs_move(TEST_FS_BASE "/copy.txt", TEST_FS_BASE "/move.txt");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_BASE "/move.txt"), 1);
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_BASE "/copy.txt"), 0);
    return 0;
}

/* --- File Removal --- */

TEST(fs_file_removal) {
    ozayn_result_t r = ozayn_fs_remove(TEST_FS_BASE "/move.txt");
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_BASE "/move.txt"), 0);
    return 0;
}

/* --- Directory Removal --- */

TEST(fs_dir_removal) {
    ozayn_result_t r = ozayn_fs_rmdir(TEST_FS_DIR);
    ASSERT_EQ(r, OZAYN_OK);
    ASSERT_EQ(ozayn_fs_exists(TEST_FS_DIR), 0);
    return 0;
}

/* --- Error Handling --- */

TEST(fs_null_path_exists) {
    ASSERT_EQ(ozayn_fs_exists(NULL), 0);
    return 0;
}

TEST(fs_null_path_is_file) {
    ASSERT_EQ(ozayn_fs_is_file(NULL), 0);
    return 0;
}

TEST(fs_null_path_is_dir) {
    ASSERT_EQ(ozayn_fs_is_dir(NULL), 0);
    return 0;
}

TEST(fs_null_path_mkdir) {
    ASSERT_EQ(ozayn_fs_mkdir(NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_null_path_rmdir) {
    ASSERT_EQ(ozayn_fs_rmdir(NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_null_path_remove) {
    ASSERT_EQ(ozayn_fs_remove(NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_null_path_size) {
    ASSERT_EQ(ozayn_fs_size(NULL), -1);
    return 0;
}

TEST(fs_null_path_read) {
    char buf[16];
    ASSERT_EQ(ozayn_fs_read(NULL, buf, sizeof(buf)), -1);
    return 0;
}

TEST(fs_null_buffer_read) {
    ASSERT_EQ(ozayn_fs_read("/nonexistent", NULL, 16), -1);
    return 0;
}

TEST(fs_null_path_write) {
    ASSERT_EQ(ozayn_fs_write(NULL, "x", 1), -1);
    return 0;
}

TEST(fs_null_data_write) {
    ASSERT_EQ(ozayn_fs_write("/tmp/ozayn_fs_test/null.txt", NULL, 1), -1);
    return 0;
}

TEST(fs_null_path_append) {
    ASSERT_EQ(ozayn_fs_append(NULL, "x", 1), -1);
    return 0;
}

TEST(fs_null_data_append) {
    ASSERT_EQ(ozayn_fs_append("/tmp/ozayn_fs_test/null.txt", NULL, 1), -1);
    return 0;
}

TEST(fs_null_source_copy) {
    ASSERT_EQ(ozayn_fs_copy(NULL, "/tmp/x"), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_null_dest_copy) {
    ASSERT_EQ(ozayn_fs_copy("/tmp/x", NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_null_source_move) {
    ASSERT_EQ(ozayn_fs_move(NULL, "/tmp/x"), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_null_dest_move) {
    ASSERT_EQ(ozayn_fs_move("/tmp/x", NULL), OZAYN_ERR_NULL);
    return 0;
}

TEST(fs_nonexistent_file_read) {
    char buf[16];
    ASSERT_EQ(ozayn_fs_read("/nonexistent_file_ozayn_test", buf, sizeof(buf)), -1);
    return 0;
}

TEST(fs_nonexistent_file_size) {
    ASSERT_EQ(ozayn_fs_size("/nonexistent_file_ozayn_test"), -1);
    return 0;
}

TEST(fs_nonexistent_copy_source) {
    ASSERT_EQ(ozayn_fs_copy("/nonexistent_file_ozayn_test", "/tmp/x"), OZAYN_ERR);
    return 0;
}

TEST(fs_empty_path_exists) {
    ASSERT_EQ(ozayn_fs_exists(""), 0);
    return 0;
}

TEST(fs_nonexistent_remove) {
    ASSERT_EQ(ozayn_fs_remove("/nonexistent_file_ozayn_test"), OZAYN_ERR);
    return 0;
}

TEST(fs_nonexistent_rmdir) {
    ASSERT_EQ(ozayn_fs_rmdir("/nonexistent_dir_ozayn_test"), OZAYN_ERR);
    return 0;
}

int run_filesystem_tests(void) {
    SUITE_BEGIN("Filesystem Abstraction (Section 02)");
    RUN(fs_dir_creation);
    RUN(fs_dir_exists);
    RUN(fs_dir_detection);
    RUN(fs_dir_already_exists);
    RUN(fs_file_write);
    RUN(fs_file_exists);
    RUN(fs_file_is_file);
    RUN(fs_file_size);
    RUN(fs_file_read);
    RUN(fs_file_append);
    RUN(fs_file_append_to_existing);
    RUN(fs_binary_write_read);
    RUN(fs_file_copy);
    RUN(fs_copy_preserves_content);
    RUN(fs_file_move);
    RUN(fs_file_removal);
    RUN(fs_dir_removal);
    RUN(fs_null_path_exists);
    RUN(fs_null_path_is_file);
    RUN(fs_null_path_is_dir);
    RUN(fs_null_path_mkdir);
    RUN(fs_null_path_rmdir);
    RUN(fs_null_path_remove);
    RUN(fs_null_path_size);
    RUN(fs_null_path_read);
    RUN(fs_null_buffer_read);
    RUN(fs_null_path_write);
    RUN(fs_null_data_write);
    RUN(fs_null_path_append);
    RUN(fs_null_data_append);
    RUN(fs_null_source_copy);
    RUN(fs_null_dest_copy);
    RUN(fs_null_source_move);
    RUN(fs_null_dest_move);
    RUN(fs_nonexistent_file_read);
    RUN(fs_nonexistent_file_size);
    RUN(fs_nonexistent_copy_source);
    RUN(fs_empty_path_exists);
    RUN(fs_nonexistent_remove);
    RUN(fs_nonexistent_rmdir);
    cleanup_test_dir();
    SUITE_END();
    return _tf_suite_fail;
}
