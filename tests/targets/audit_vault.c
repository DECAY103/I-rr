#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__linux__)
#error "audit_vault.c requires Linux (fork, pipe, getrandom, and waitpid semantics)."
#else
#include <sys/random.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
typedef struct audit_frame {
    char local_buffer[16];
    char metadata_shadow[24];
    uint32_t frame_guard;
} audit_frame_t;

static int write_all(int fd, const void *buffer, size_t size) {
    const unsigned char *cursor = (const unsigned char *) buffer;

    while (size > 0) {
        ssize_t written = write(fd, cursor, size);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += (size_t) written;
        size -= (size_t) written;
    }
    return 0;
}

static int read_all(int fd, void *buffer, size_t size) {
    unsigned char *cursor = (unsigned char *) buffer;

    while (size > 0) {
        ssize_t nread = read(fd, cursor, size);
        if (nread == 0) {
            return -1;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += (size_t) nread;
        size -= (size_t) nread;
    }
    return 0;
}

static long elapsed_ms(const struct timespec *start, const struct timespec *end) {
    long seconds = (long) (end->tv_sec - start->tv_sec);
    long nanos = end->tv_nsec - start->tv_nsec;

    return seconds * 1000L + nanos / 1000000L;
}

static int audit_logger(int read_fd) {
    uint32_t session_id = 0;
    uint8_t token = 0;
    uint16_t payload_size = 0;
    char incoming[96];
    struct timespec start;
    struct timespec finish;
    audit_frame_t frame;
    useconds_t delay_us;

    memset(&frame, 0, sizeof(frame));
    frame.frame_guard = 0xC0DEFACEu;

    if (read_all(read_fd, &session_id, sizeof(session_id)) != 0 ||
            read_all(read_fd, &token, sizeof(token)) != 0 ||
            read_all(read_fd, &payload_size, sizeof(payload_size)) != 0) {
        perror("audit_logger: read header");
        return 1;
    }

    if (payload_size == 0 || payload_size > sizeof(incoming)) {
        fprintf(stderr, "audit_logger: invalid payload size %u\n", payload_size);
        return 1;
    }
    if (read_all(read_fd, incoming, payload_size) != 0) {
        perror("audit_logger: read payload");
        return 1;
    }
    incoming[payload_size - 1] = '\0';

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        return 1;
    }

    delay_us = (token % 2u == 0u) ? 50000u : 200000u;
    if (usleep(delay_us) != 0) {
        perror("usleep");
        return 1;
    }

    /*
     * Stack-frame stress point:
     * "incoming" came from the pipe, but this local 16-byte buffer lives on
     * the child stack. strcpy() crosses a classic memory-safety boundary and
     * can corrupt adjacent stack-frame state when the parent sends the long
     * payload on the rare 0xDE token path.
     */
    strcpy(frame.local_buffer, incoming);

    if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0) {
        perror("clock_gettime");
        return 1;
    }

    printf("[audit-logger] Session ID: 0x%08x\n", session_id);
    printf("[audit-logger] Security Token: 0x%02x\n", token);
    printf("[audit-logger] Processing Time: %ld ms\n", elapsed_ms(&start, &finish));
    printf("[audit-logger] Frame Guard After Copy: 0x%08x\n", frame.frame_guard);
    printf("[audit-logger] Stored Log Preview: %.24s\n", frame.local_buffer);
    fflush(stdout);
    return 0;
}

int main(void) {
    static const char normal_message[] = "SAFELOG!";
    static const char malicious_message[] =
        "AUDIT_OVERRUN_PAYLOAD::root=1::action=exfiltrate::tag=DEMO";
    int pipefd[2];
    pid_t child;
    uint32_t session_id = 0;
    uint8_t token = 0;
    uint16_t payload_size;
    const char *message;
    int status;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }

    if (child == 0) {
        close(pipefd[1]);
        status = audit_logger(pipefd[0]);
        close(pipefd[0]);
        return status;
    }

    close(pipefd[0]);

    if (getrandom(&session_id, sizeof(session_id), 0) != (ssize_t) sizeof(session_id)) {
        perror("getrandom(session_id)");
        close(pipefd[1]);
        waitpid(child, NULL, 0);
        return 1;
    }
    if (getrandom(&token, sizeof(token), 0) != (ssize_t) sizeof(token)) {
        perror("getrandom(token)");
        close(pipefd[1]);
        waitpid(child, NULL, 0);
        return 1;
    }

    message = (token == 0xDEu) ? malicious_message : normal_message;
    payload_size = (uint16_t) (strlen(message) + 1u);

    /*
     * Syscall-boundary stress points for EchoRun:
     * - getrandom() makes the session ID and token non-deterministic.
     * - write() and read() on the pipe force kernel-mediated IPC between the
     *   parent front-end and child logger, creating visible scheduling gaps.
     * - waitpid(WNOHANG) below turns the child sleep into a timing-sensitive
     *   race, so even/odd tokens change whether the parent observes the child
     *   as "already done" or "still running".
     */
    if (write_all(pipefd[1], &session_id, sizeof(session_id)) != 0 ||
            write_all(pipefd[1], &token, sizeof(token)) != 0 ||
            write_all(pipefd[1], &payload_size, sizeof(payload_size)) != 0 ||
            write_all(pipefd[1], message, payload_size) != 0) {
        perror("write_all");
        close(pipefd[1]);
        waitpid(child, NULL, 0);
        return 1;
    }
    close(pipefd[1]);

    printf("[front-end] Session ID: 0x%08x\n", session_id);
    printf("[front-end] Security Token: 0x%02x\n", token);
    printf("[front-end] Payload Path: %s\n", token == 0xDEu ? "malicious-overflow" : "normal");

    usleep(100000u);
    {
        pid_t wait_rc = waitpid(child, &status, WNOHANG);
        if (wait_rc == 0) {
            printf("[front-end] Race Observation: logger still running after 100 ms\n");
            waitpid(child, &status, 0);
        } else if (wait_rc < 0) {
            perror("waitpid");
            return 1;
        } else {
            printf("[front-end] Race Observation: logger finished before 100 ms\n");
        }
    }

    /*
     * Context-switching note for a professor:
     * fork() creates two schedulable processes sharing the initial address
     * space snapshot, so the demo bounces between parent/child execution while
     * the kernel arbitrates pipe I/O, sleep wakeups, and waitpid() results.
     */
    if (WIFSIGNALED(status)) {
        printf("[front-end] Child terminated from signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }
    if (!WIFEXITED(status)) {
        fprintf(stderr, "[front-end] Child ended unexpectedly\n");
        return 1;
    }

    printf("[front-end] Child exit code: %d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status);
}
#endif
