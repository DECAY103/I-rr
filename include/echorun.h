#ifndef ECHORUN_H
#define ECHORUN_H

#include <stddef.h>
#include <stdint.h>

typedef struct recorder_options {
    const char *output_path;
    size_t flight_capacity;
    int flight_mode;
} recorder_options_t;

typedef struct divergence_report {
    uint64_t seq_idx;
    long expected_syscall;
    long observed_syscall;
    long long expected_retval;
    long long observed_retval;
    char reason[160];
} divergence_report_t;

typedef struct replayer_options {
    const char *input_path;
    size_t checkpoint_every;
    int interactive;
} replayer_options_t;

typedef struct visualiser_options {
    const char *input_path;
    const char *svg_path;
    const char *summary_path;
    const char *diff_path;
    unsigned width;
    unsigned height;
} visualiser_options_t;

int recorder_run(char *const argv[], const recorder_options_t *options);
int replayer_run(char *const argv[], const replayer_options_t *options, divergence_report_t *report);
int visualiser_run(const visualiser_options_t *options, divergence_report_t *report);

#endif
