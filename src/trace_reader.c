#include "trace_reader.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int trace_validate_header(const trace_file_header_t *header) {
    if (memcmp(header->magic, ECHOTRACE_MAGIC, 7) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (header->version != ECHOTRACE_VERSION) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

void trace_default_file_header(trace_file_header_t *header, uint32_t pid, const char *command) {
    memset(header, 0, sizeof(*header));
    memcpy(header->magic, ECHOTRACE_MAGIC, 7);
    header->version = ECHOTRACE_VERSION;
    header->header_size = (uint16_t) sizeof(*header);
    header->pointer_width = (uint32_t) sizeof(void *);
    header->arch_tag = 0x3E;
    header->pid = pid;
    header->flags = 0;
    header->start_time_ns = (uint64_t) time(NULL) * 1000000000ULL;
    if (command != NULL) {
        snprintf(header->command, sizeof(header->command), "%s", command);
    }
}

void trace_event_reset(trace_event_t *event) {
    memset(event, 0, sizeof(*event));
}

void trace_event_release(trace_event_t *event) {
    free(event->payload);
    event->payload = NULL;
}

int trace_event_clone(trace_event_t *dst, const trace_event_t *src) {
    trace_event_release(dst);
    memcpy(dst, src, sizeof(*dst));
    dst->payload = NULL;
    if (src->header.payload_size > 0 && src->payload != NULL) {
        dst->payload = (uint8_t *) malloc(src->header.payload_size);
        if (dst->payload == NULL) {
            return -1;
        }
        memcpy(dst->payload, src->payload, src->header.payload_size);
    }
    return 0;
}

int trace_writer_open(trace_writer_t *writer, const char *path, const trace_file_header_t *header) {
    memset(writer, 0, sizeof(*writer));
    writer->fp = fopen(path, "wb");
    if (writer->fp == NULL) {
        return -1;
    }
    writer->header = *header;
    if (fwrite(&writer->header, sizeof(writer->header), 1, writer->fp) != 1) {
        fclose(writer->fp);
        writer->fp = NULL;
        return -1;
    }
    return 0;
}

int trace_writer_write_event(trace_writer_t *writer, const trace_event_t *event) {
    if (writer == NULL || writer->fp == NULL || event == NULL) {
        errno = EINVAL;
        return -1;
    }

    switch (event->header.type) {
        case TRACE_EVENT_SYSCALL_EXIT:
            if (fwrite(&event->record.syscall_exit, sizeof(event->record.syscall_exit), 1, writer->fp) != 1) {
                return -1;
            }
            break;
        case TRACE_EVENT_SIGNAL:
            if (fwrite(&event->record.signal, sizeof(event->record.signal), 1, writer->fp) != 1) {
                return -1;
            }
            break;
        case TRACE_EVENT_PROC_EVENT:
            if (fwrite(&event->record.proc_event, sizeof(event->record.proc_event), 1, writer->fp) != 1) {
                return -1;
            }
            break;
        default:
            errno = EINVAL;
            return -1;
    }

    if (event->header.payload_size > 0 && event->payload != NULL) {
        if (fwrite(event->payload, event->header.payload_size, 1, writer->fp) != 1) {
            return -1;
        }
    }
    writer->event_count++;
    return 0;
}

int trace_writer_write_syscall_exit(trace_writer_t *writer, const trace_syscall_exit_record_t *record, const void *payload) {
    trace_event_t event;
    trace_event_reset(&event);
    event.header = record->header;
    event.record.syscall_exit = *record;
    event.payload = (uint8_t *) payload;
    return trace_writer_write_event(writer, &event);
}

int trace_writer_write_signal(trace_writer_t *writer, const trace_signal_record_t *record) {
    trace_event_t event;
    trace_event_reset(&event);
    event.header = record->header;
    event.record.signal = *record;
    return trace_writer_write_event(writer, &event);
}

int trace_writer_write_proc_event(trace_writer_t *writer, const trace_proc_event_record_t *record) {
    trace_event_t event;
    trace_event_reset(&event);
    event.header = record->header;
    event.record.proc_event = *record;
    return trace_writer_write_event(writer, &event);
}

int trace_writer_close(trace_writer_t *writer) {
    int rc = 0;
    if (writer != NULL && writer->fp != NULL) {
        rc = fclose(writer->fp);
        writer->fp = NULL;
    }
    return rc;
}

int trace_reader_open(trace_reader_t *reader, const char *path) {
    memset(reader, 0, sizeof(*reader));
    reader->fp = fopen(path, "rb");
    if (reader->fp == NULL) {
        return -1;
    }
    if (fread(&reader->header, sizeof(reader->header), 1, reader->fp) != 1) {
        fclose(reader->fp);
        reader->fp = NULL;
        return -1;
    }
    if (trace_validate_header(&reader->header) != 0) {
        fclose(reader->fp);
        reader->fp = NULL;
        return -1;
    }
    return 0;
}

static int trace_reader_read_payload(trace_reader_t *reader, trace_event_t *event) {
    if (event->header.payload_size == 0) {
        return 0;
    }
    event->payload = (uint8_t *) malloc(event->header.payload_size);
    if (event->payload == NULL) {
        return -1;
    }
    if (fread(event->payload, event->header.payload_size, 1, reader->fp) != 1) {
        trace_event_release(event);
        return -1;
    }
    return 0;
}

int trace_reader_next(trace_reader_t *reader, trace_event_t *event) {
    trace_event_release(event);

    trace_event_header_t header;
    if (fread(&header, sizeof(header), 1, reader->fp) != 1) {
        return feof(reader->fp) ? 1 : -1;
    }

    if (fseek(reader->fp, -(long) sizeof(header), SEEK_CUR) != 0) {
        return -1;
    }

    memset(event, 0, sizeof(*event));
    switch (header.type) {
        case TRACE_EVENT_SYSCALL_EXIT:
            if (fread(&event->record.syscall_exit, sizeof(event->record.syscall_exit), 1, reader->fp) != 1) {
                return -1;
            }
            event->header = event->record.syscall_exit.header;
            break;
        case TRACE_EVENT_SIGNAL:
            if (fread(&event->record.signal, sizeof(event->record.signal), 1, reader->fp) != 1) {
                return -1;
            }
            event->header = event->record.signal.header;
            break;
        case TRACE_EVENT_PROC_EVENT:
            if (fread(&event->record.proc_event, sizeof(event->record.proc_event), 1, reader->fp) != 1) {
                return -1;
            }
            event->header = event->record.proc_event.header;
            break;
        default:
            errno = EINVAL;
            return -1;
    }

    reader->event_count++;
    return trace_reader_read_payload(reader, event);
}

int trace_reader_seek_seq(trace_reader_t *reader, uint64_t seq_idx, trace_event_t *event) {
    trace_reader_rewind(reader);
    for (;;) {
        int rc = trace_reader_next(reader, event);
        if (rc != 0) {
            return rc;
        }
        if (event->header.seq_idx == seq_idx) {
            return 0;
        }
    }
}

void trace_reader_rewind(trace_reader_t *reader) {
    if (reader != NULL && reader->fp != NULL) {
        fseek(reader->fp, (long) sizeof(reader->header), SEEK_SET);
        reader->event_count = 0;
    }
}

void trace_reader_close(trace_reader_t *reader) {
    if (reader != NULL && reader->fp != NULL) {
        fclose(reader->fp);
        reader->fp = NULL;
    }
}
