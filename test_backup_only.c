#include "tests/test_framework.h"

extern int run_backup_tests(void);

int main(void) {
    printf("\n  ======================================================\n");
    printf("  BACKUP TEST RUNNER\n");
    printf("  ======================================================\n\n");
    run_backup_tests();
    return FAILED() ? 1 : 0;
}
