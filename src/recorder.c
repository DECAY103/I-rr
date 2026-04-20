#define _GNU_SOURCE

#include "echorun.h"
#include "syscall_table.h"
#include "trace_reader.h"

#ifdef __linux__
#include <errno.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef struct flight_buffer {
    trace_event_t *events;
    size_t capacity;
    size_t count;
    size_t head;
} flight_buffer_t;

typedef struct syscall_entry {
    long nr;
    uint64_t args[6];
} syscall_entry_t;

typedef struct tracee_state {
    pid_t pid;
    int in_syscall;
    syscall_entry_t entry;
} tracee_state_t;

#define MAX_TRACEES 256
static tracee_state_t tracees[MAX_TRACEES];
static size_t tracee_count = 0;

static tracee_state_t *get_tracee(pid_t pid) {
    for (size_t i = 0; i < tracee_count; i++) {
        if (tracees[i].pid == pid) return &tracees[i];
    }
    if (tracee_count < MAX_TRACEES) {
        tracees[tracee_count].pid = pid;
        tracees[tracee_count].in_syscall = 0;
        return &tracees[tracee_count++];
    }
    return NULL;
}

static int tracee_read_memory(pid_t pid, uint64_t addr, void *buf, size_t len) {
    size_t copied = 0;
    unsigned char *dst = (unsigned char *) buf;

    while (copied < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *) (uintptr_t) (addr + copied), NULL);
        if (word == -1 && errno != 0) {
            return -1;
        }
        size_t chunk = sizeof(word);
        if (chunk > len - copied) {
            chunk = len - copied;
        }
        memcpy(dst + copied, &word, chunk);
        copied += chunk;
    }
    return 0;
}

static int syscall_payload_descriptor(long syscall_nr, const syscall_entry_t *entry, long retval, uint64_t *addr, uint32_t *size) {
    switch (syscall_nr) {
        case SYS_pipe:
        case SYS_pipe2:
            if (retval == 0) {
                *addr = entry->args[0];
                *size = sizeof(int) * 2;
                return 1;
            }
            return 0;
        case SYS_read:
        case SYS_write:
            if (retval <= 0) {
                return 0;
            }
            *addr = entry->args[1];
            *size = (uint32_t) retval;
            return 1;
        case SYS_getrandom:
            if (retval <= 0) {
                return 0;
            }
            *addr = entry->args[0];
            *size = (uint32_t) retval;
            return 1;
        case SYS_clock_gettime:
            *addr = entry->args[1];
            *size = (uint32_t) sizeof(struct timespec);
            return 1;
        case SYS_gettimeofday:
            *addr = entry->args[0];
            *size = (uint32_t) sizeof(struct timeval);
            return 1;
        default:
            return 0;
    }
}

static void flight_buffer_init(flight_buffer_t *buffer, size_t capacity) {
    memset(buffer, 0, sizeof(*buffer));
    buffer->capacity = capacity;
    if (capacity > 0) {
        buffer->events = calloc(capacity, sizeof(trace_event_t));
    }
}

static void flight_buffer_push(flight_buffer_t *buffer, const trace_event_t *event) {
    if (buffer->capacity == 0 || buffer->events == NULL) {
        return;
    }

    if (buffer->count < buffer->capacity) {
        size_t slot = (buffer->head + buffer->count) % buffer->capacity;
        trace_event_clone(&buffer->events[slot], event);
        buffer->count++;
        return;
    }

    trace_event_release(&buffer->events[buffer->head]);
    trace_event_clone(&buffer->events[buffer->head], event);
    buffer->head = (buffer->head + 1) % buffer->capacity;
}

static int flight_buffer_flush(trace_writer_t *writer, const flight_buffer_t *buffer) {
    size_t i;
    for (i = 0; i < buffer->count; ++i) {
        size_t slot = (buffer->head + i) % buffer->capacity;
        if (trace_writer_write_event(writer, &buffer->events[slot]) != 0) {
            return -1;
        }
    }
    return 0;
}

static void flight_buffer_destroy(flight_buffer_t *buffer) {
    size_t i;
    for (i = 0; i < buffer->capacity; ++i) {
        trace_event_release(&buffer->events[i]);
    }
    free(buffer->events);
}

static int emit_event(trace_writer_t *writer, flight_buffer_t *flight, const trace_event_t *event, int flight_mode) {
    if (flight_mode) {
        flight_buffer_push(flight, event);
        return 0;
    }
    return trace_writer_write_event(writer, event);
}

int recorder_run(char *const argv[], const recorder_options_t *options) {
    pid_t child;
    int status = 0;
    uint64_t seq_idx = 0;
    trace_writer_t writer;
    flight_buffer_t flight;
    trace_file_header_t file_header;

    if (argv == NULL || argv[0] == NULL || options == NULL || options->output_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    flight_buffer_init(&flight, options->flight_mode ? options->flight_capacity : 0);

    child = fork();
    if (child == -1) {
        flight_buffer_destroy(&flight);
        return -1;
    }

    if (child == 0) {
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[0], argv);
        _exit(127);
    }

    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL, (void *) (uintptr_t) (PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE));

    trace_default_file_header(&file_header, (uint32_t) child, argv[0]);
    if (trace_writer_open(&writer, options->output_path, &file_header) != 0) {
        flight_buffer_destroy(&flight);
        return -1;
    }

    tracee_count = 0;
    get_tracee(child);

    {
        trace_proc_event_record_t proc_record;
        trace_event_t proc_event;
        memset(&proc_record, 0, sizeof(proc_record));
        memset(&proc_event, 0, sizeof(proc_event));
        proc_record.header.seq_idx = seq_idx++;
        proc_record.header.type = TRACE_EVENT_PROC_EVENT;
        proc_record.header.record_size = sizeof(proc_record);
        proc_record.header.pid = (uint32_t) child;
        proc_record.proc_kind = PROC_EVENT_EXEC;
        proc_event.header = proc_record.header;
        proc_event.record.proc_event = proc_record;
        emit_event(&writer, &flight, &proc_event, options->flight_mode);
    }

    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    for (;;) {
        trace_proc_event_record_t proc_record;
        trace_event_t event;
        struct user_regs_struct regs;
        int wait_rc;

        wait_rc = waitpid(-1, &status, __WALL);
        if (wait_rc == -1) {
            if (errno == ECHILD) break;
            continue;
        }

        pid_t event_pid = wait_rc;
        tracee_state_t *tstate = get_tracee(event_pid);
        if (!tstate) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            trace_event_t proc_event;
            memset(&proc_record, 0, sizeof(proc_record));
            memset(&proc_event, 0, sizeof(proc_event));
            proc_record.header.seq_idx = seq_idx++;
            proc_record.header.type = TRACE_EVENT_PROC_EVENT;
            proc_record.header.record_size = sizeof(proc_record);
            proc_record.header.pid = (uint32_t) event_pid;
            proc_record.proc_kind = PROC_EVENT_EXIT;
            proc_record.status_code = WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status);
            proc_event.header = proc_record.header;
            proc_event.record.proc_event = proc_record;
            emit_event(&writer, &flight, &proc_event, options->flight_mode);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
            continue;
        }

        int sig = WSTOPSIG(status);
        int event_type = status >> 16;
        if (event_type == PTRACE_EVENT_FORK || event_type == PTRACE_EVENT_VFORK || event_type == PTRACE_EVENT_CLONE) {
            unsigned long new_pid;
            ptrace(PTRACE_GETEVENTMSG, event_pid, NULL, &new_pid);
            get_tracee((pid_t)new_pid);
            ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            ptrace(PTRACE_GETREGS, event_pid, NULL, &regs);
            if (!tstate->in_syscall) {
                tstate->in_syscall = 1;
                tstate->entry.nr = (long) regs.orig_rax;
                tstate->entry.args[0] = regs.rdi;
                tstate->entry.args[1] = regs.rsi;
                tstate->entry.args[2] = regs.rdx;
                tstate->entry.args[3] = regs.r10;
                tstate->entry.args[4] = regs.r8;
                tstate->entry.args[5] = regs.r9;
                ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
                continue;
            }

            tstate->in_syscall = 0;
            memset(&event, 0, sizeof(event));
            event.header.seq_idx = seq_idx++;
            event.header.type = TRACE_EVENT_SYSCALL_EXIT;
            event.header.record_size = sizeof(trace_syscall_exit_record_t);
            event.header.pid = (uint32_t) event_pid;
            event.record.syscall_exit.header = event.header;
            event.record.syscall_exit.syscall_nr = (int32_t) tstate->entry.nr;
            event.record.syscall_exit.syscall_class = (int32_t) syscall_table_classify(tstate->entry.nr);
            event.record.syscall_exit.retval = (int64_t) regs.rax;
            memcpy(event.record.syscall_exit.args, tstate->entry.args, sizeof(tstate->entry.args));

            {
                uint32_t payload_size = 0;
                if (syscall_payload_descriptor(tstate->entry.nr, &tstate->entry, (long) regs.rax,
                        &event.record.syscall_exit.inject_addr, &payload_size)) {
                    event.header.payload_size = payload_size;
                    event.record.syscall_exit.header.payload_size = payload_size;
                    event.record.syscall_exit.header.flags |= TRACE_EVENT_HAS_PAYLOAD;
                    event.header.flags |= TRACE_EVENT_HAS_PAYLOAD;
                    event.payload = malloc(event.header.payload_size);
                    if (event.payload != NULL) {
                        tracee_read_memory(event_pid, event.record.syscall_exit.inject_addr, event.payload, event.header.payload_size);
                    }
                }
            }

            event.record.syscall_exit.header = event.header;
            emit_event(&writer, &flight, &event, options->flight_mode);
            trace_event_release(&event);
            ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
            continue;
        }

        memset(&event, 0, sizeof(event));
        event.header.seq_idx = seq_idx++;
        event.header.type = TRACE_EVENT_SIGNAL;
        event.header.record_size = sizeof(trace_signal_record_t);
        event.header.pid = (uint32_t) event_pid;
        event.record.signal.header = event.header;
        event.record.signal.signal_no = sig;
        emit_event(&writer, &flight, &event, options->flight_mode);
        ptrace(PTRACE_SYSCALL, event_pid, NULL, (void*)(uintptr_t)((sig == SIGSTOP || sig == SIGTRAP || sig == SIGCHLD) ? 0 : sig));
    }

    if (options->flight_mode) {
        flight_buffer_flush(&writer, &flight);
    }

    flight_buffer_destroy(&flight);
    trace_writer_close(&writer);
    return 0;
}



#else
int recorder_run(char *const argv[], const recorder_options_t *options) {
    (void) argv;
    (void) options;
    return -1;
}
#endif
