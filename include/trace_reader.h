#ifndef ECHORUN_TRACE_READER_H
#define ECHORUN_TRACE_READER_H

#include <stdio.h>
#include <stdint.h>
#include "trace_format.h"

typedef struct trace_writer {
    FILE *fp;
    trace_file_header_t header;
    uint64_t event_count;
} trace_writer_t;

typedef struct trace_reader {
    FILE *fp;
    trace_file_header_t header;
    uint64_t event_count;
} trace_reader_t;

void trace_default_file_header(trace_file_header_t *header, uint32_t pid, const char *command);

int trace_writer_open(trace_writer_t *writer, const char *path, const trace_file_header_t *header);
int trace_writer_write_event(trace_writer_t *writer, const trace_event_t *event);
int trace_writer_write_syscall_exit(trace_writer_t *writer, const trace_syscall_exit_record_t *record, const void *payload);
int trace_writer_write_signal(trace_writer_t *writer, const trace_signal_record_t *record);
int trace_writer_write_proc_event(trace_writer_t *writer, const trace_proc_event_record_t *record);
int trace_writer_close(trace_writer_t *writer);

int trace_reader_open(trace_reader_t *reader, const char *path);
int trace_reader_next(trace_reader_t *reader, trace_event_t *event);
int trace_reader_seek_seq(trace_reader_t *reader, uint64_t seq_idx, trace_event_t *event);
void trace_reader_rewind(trace_reader_t *reader);
void trace_reader_close(trace_reader_t *reader);

void trace_event_reset(trace_event_t *event);
void trace_event_release(trace_event_t *event);
int trace_event_clone(trace_event_t *dst, const trace_event_t *src);

#endif
