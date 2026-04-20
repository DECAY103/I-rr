#include "echorun.h"
#include "trace_reader.h"
#include "syscall_table.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct event_cache {
    trace_event_t *events;
    size_t count;
    size_t capacity;
} event_cache_t;

static const char *event_color(const trace_event_t *event) {
    switch (event->header.type) {
        case TRACE_EVENT_SIGNAL:
            return "#ef4444";
        case TRACE_EVENT_PROC_EVENT:
            return "#0f766e";
        case TRACE_EVENT_SYSCALL_EXIT:
            switch ((syscall_kind_t) event->record.syscall_exit.syscall_class) {
                case SYSCALL_KIND_NON_DET:
                    return "#34d399";
                case SYSCALL_KIND_SIDE_EFFECT:
                    return "#166534";
                case SYSCALL_KIND_DETERMINISTIC:
                default:
                    return "#475569";
            }
        default:
            return "#64748b";
    }
}

static int cache_push(event_cache_t *cache, const trace_event_t *event) {
    if (cache->count == cache->capacity) {
        size_t next = cache->capacity == 0 ? 64 : cache->capacity * 2;
        trace_event_t *grown = realloc(cache->events, next * sizeof(*grown));
        if (grown == NULL) {
            return -1;
        }
        cache->events = grown;
        cache->capacity = next;
    }
    memset(&cache->events[cache->count], 0, sizeof(trace_event_t));
    if (trace_event_clone(&cache->events[cache->count], event) != 0) {
        return -1;
    }
    cache->count++;
    return 0;
}

static void cache_free(event_cache_t *cache) {
    size_t i;
    for (i = 0; i < cache->count; ++i) {
        trace_event_release(&cache->events[i]);
    }
    free(cache->events);
}

static int load_events(trace_reader_t *reader, event_cache_t *cache) {
    trace_event_t event;
    int rc;

    trace_event_reset(&event);
    while ((rc = trace_reader_next(reader, &event)) == 0) {
        if (cache_push(cache, &event) != 0) {
            trace_event_release(&event);
            return -1;
        }
        trace_event_release(&event);
    }
    return rc == 1 ? 0 : -1;
}

static int write_svg(const char *path, const event_cache_t *cache, unsigned width, unsigned height, const divergence_report_t *report) {
    FILE *fp;
    size_t i;

    if (path == NULL) {
        return 0;
    }
    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    fprintf(fp, "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%u\" height=\"%u\" viewBox=\"0 0 %u %u\">\n",
        width, height, width, height);
    fprintf(fp, "<rect width=\"100%%\" height=\"100%%\" rx=\"24\" fill=\"#f5f7f6\"/>\n");
    fprintf(fp, "<line x1=\"40\" y1=\"%u\" x2=\"%u\" y2=\"%u\" stroke=\"#cbd5d1\" stroke-width=\"2\"/>\n",
        height / 2, width - 40, height / 2);

    for (i = 0; i < cache->count; ++i) {
        double x = cache->count == 0 ? 40.0 : ((double) cache->events[i].header.seq_idx / (double) cache->count) * (double) (width - 80) + 40.0;
        const char *fill = event_color(&cache->events[i]);
        if (report != NULL && report->reason[0] != '\0' && cache->events[i].header.seq_idx == report->seq_idx) {
            fill = "#dc2626";
        }
        fprintf(fp, "<rect x=\"%.2f\" y=\"%u\" width=\"6\" height=\"40\" rx=\"3\" fill=\"%s\"/>\n",
            x, (height / 2) - 20, fill);
    }

    if (report != NULL && report->reason[0] != '\0') {
        fprintf(fp, "<text x=\"40\" y=\"40\" font-family=\"Inter, sans-serif\" font-size=\"18\" fill=\"#991b1b\">Divergence at seq %llu: %s</text>\n",
            (unsigned long long) report->seq_idx, report->reason);
    }
    fprintf(fp, "</svg>\n");
    fclose(fp);
    return 0;
}

static int write_summary_json(const char *path, const event_cache_t *cache, const trace_file_header_t *header, const divergence_report_t *report) {
    FILE *fp;
    size_t i;
    size_t nondet = 0;
    size_t signals = 0;

    if (path == NULL) {
        return 0;
    }
    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    for (i = 0; i < cache->count; ++i) {
        if (cache->events[i].header.type == TRACE_EVENT_SIGNAL) {
            signals++;
        }
        if (cache->events[i].header.type == TRACE_EVENT_SYSCALL_EXIT &&
                cache->events[i].record.syscall_exit.syscall_class == SYSCALL_KIND_NON_DET) {
            nondet++;
        }
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"command\": \"%s\",\n", header->command);
    fprintf(fp, "  \"totalEvents\": %llu,\n", (unsigned long long) cache->count);
    fprintf(fp, "  \"nonDetEvents\": %llu,\n", (unsigned long long) nondet);
    fprintf(fp, "  \"signalEvents\": %llu,\n", (unsigned long long) signals);
    fprintf(fp, "  \"divergence\": {\n");
    fprintf(fp, "    \"seq\": %llu,\n", (unsigned long long) report->seq_idx);
    fprintf(fp, "    \"reason\": \"%s\"\n", report->reason);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"events\": [\n");
    for (i = 0; i < cache->count; ++i) {
        const trace_event_t *event = &cache->events[i];
        fprintf(fp, "    {\"seq\": %llu, \"type\": %u, \"payload\": %u, \"syscall\": %d}%s\n",
            (unsigned long long) event->header.seq_idx,
            event->header.type,
            event->header.payload_size,
            event->header.type == TRACE_EVENT_SYSCALL_EXIT ? event->record.syscall_exit.syscall_nr : -1,
            (i + 1 == cache->count) ? "" : ",");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

static int diff_traces(const char *lhs_path, const char *rhs_path, divergence_report_t *report) {
    trace_reader_t lhs;
    trace_reader_t rhs;
    trace_event_t left;
    trace_event_t right;
    int left_rc;
    int right_rc;

    if (rhs_path == NULL) {
        return 0;
    }

    memset(report, 0, sizeof(*report));
    if (trace_reader_open(&lhs, lhs_path) != 0 || trace_reader_open(&rhs, rhs_path) != 0) {
        return -1;
    }

    trace_event_reset(&left);
    trace_event_reset(&right);
    for (;;) {
        left_rc = trace_reader_next(&lhs, &left);
        right_rc = trace_reader_next(&rhs, &right);
        if (left_rc != 0 || right_rc != 0) {
            break;
        }
        if (left.header.type != right.header.type ||
                left.header.payload_size != right.header.payload_size ||
                (left.header.type == TRACE_EVENT_SYSCALL_EXIT &&
                 left.record.syscall_exit.syscall_nr != right.record.syscall_exit.syscall_nr) ||
                (left.header.payload_size > 0 &&
                 right.header.payload_size > 0 &&
                 memcmp(left.payload, right.payload, left.header.payload_size) != 0)) {
            report->seq_idx = left.header.seq_idx;
            snprintf(report->reason, sizeof(report->reason), "trace diff mismatch");
            break;
        }
    }
    trace_event_release(&left);
    trace_event_release(&right);
    trace_reader_close(&lhs);
    trace_reader_close(&rhs);
    return 0;
}

int visualiser_run(const visualiser_options_t *options, divergence_report_t *report) {
    trace_reader_t reader;
    event_cache_t cache;

    memset(&cache, 0, sizeof(cache));
    if (trace_reader_open(&reader, options->input_path) != 0) {
        return -1;
    }

    if (load_events(&reader, &cache) != 0) {
        trace_reader_close(&reader);
        cache_free(&cache);
        return -1;
    }

    if (options->diff_path != NULL) {
        diff_traces(options->input_path, options->diff_path, report);
    }
    write_svg(options->svg_path, &cache, options->width, options->height, report);
    write_summary_json(options->summary_path, &cache, &reader.header, report);

    cache_free(&cache);
    trace_reader_close(&reader);
    return 0;
}
