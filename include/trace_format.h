#ifndef ECHORUN_TRACE_FORMAT_H
#define ECHORUN_TRACE_FORMAT_H

#include <stdint.h>

#define ECHOTRACE_MAGIC "ECHOTRC"
#define ECHOTRACE_VERSION 1U

enum trace_event_type {
    TRACE_EVENT_SYSCALL_EXIT = 1,
    TRACE_EVENT_SIGNAL = 2,
    TRACE_EVENT_PROC_EVENT = 3,
    TRACE_EVENT_IPC_DATA = 4
};

enum proc_event_kind {
    PROC_EVENT_EXEC = 1,
    PROC_EVENT_EXIT = 2,
    PROC_EVENT_STOP = 3,
    PROC_EVENT_CHECKPOINT = 4
};

enum trace_event_flags {
    TRACE_EVENT_HAS_PAYLOAD = 1U << 0,
    TRACE_EVENT_FLIGHT_RECORDER = 1U << 1,
    TRACE_EVENT_DIVERGENCE = 1U << 2
};

#pragma pack(push, 1)
typedef struct trace_file_header {
    char magic[8];
    uint16_t version;
    uint16_t header_size;
    uint32_t pointer_width;
    uint32_t arch_tag;
    uint32_t pid;
    uint32_t flags;
    uint64_t start_time_ns;
    char command[256];
} trace_file_header_t;

typedef struct trace_event_header {
    uint64_t seq_idx;
    uint16_t type;
    uint16_t record_size;
    uint32_t payload_size;
    uint32_t flags;
    uint32_t pid;
} trace_event_header_t;

typedef struct trace_syscall_exit_record {
    trace_event_header_t header;
    int32_t syscall_nr;
    int32_t syscall_class;
    int64_t retval;
    uint64_t args[6];
    uint64_t inject_addr;
    uint64_t aux_value;
} trace_syscall_exit_record_t;

typedef struct trace_signal_record {
    trace_event_header_t header;
    int32_t signal_no;
    int32_t signal_code;
    int64_t signal_errno;
    uint64_t fault_addr;
} trace_signal_record_t;

typedef struct trace_proc_event_record {
    trace_event_header_t header;
    int32_t proc_kind;
    int32_t status_code;
    uint64_t ip;
    uint64_t sp;
    uint64_t metadata;
} trace_proc_event_record_t;
#pragma pack(pop)

typedef struct trace_event {
    trace_event_header_t header;
    union {
        trace_syscall_exit_record_t syscall_exit;
        trace_signal_record_t signal;
        trace_proc_event_record_t proc_event;
    } record;
    uint8_t *payload;
} trace_event_t;

#endif
