#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP(ms) usleep((ms) * 1000)
#endif

/*
 * process_child.c — Test child process for OZAYN process management tests.
 *
 * Usage: process_child [sleep_ms]
 *
 * Prints PID, sleeps, then exits with code 0.
 * If an argument is provided, it is used as sleep duration in milliseconds.
 */

int main(int argc, char *argv[]) {
    uint32_t sleep_ms = 200;
    if (argc > 1) {
        sleep_ms = (uint32_t)atoi(argv[1]);
    }

    printf("CHILD PID=%d SLEEP=%u\n",
#ifdef _WIN32
           (int)GetCurrentProcessId(),
#else
           (int)getpid(),
#endif
           sleep_ms);

    SLEEP(sleep_ms);
    return 0;
}
