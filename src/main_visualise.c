#include "echorun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s <trace.echotrace> [--svg out.svg] [--summary out.json] [--diff other.echotrace]\n", argv0);
}

int main(int argc, char **argv) {
    visualiser_options_t options;
    divergence_report_t report;
    int i;

    memset(&options, 0, sizeof(options));
    memset(&report, 0, sizeof(report));
    options.width = 1440;
    options.height = 320;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    options.input_path = argv[1];
    for (i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--svg") == 0 && i + 1 < argc) {
            options.svg_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--summary") == 0 && i + 1 < argc) {
            options.summary_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--diff") == 0 && i + 1 < argc) {
            options.diff_path = argv[++i];
            continue;
        }
    }

    if (visualiser_run(&options, &report) != 0) {
        if (report.reason[0] != '\0') {
            fprintf(stderr, "diff divergence at seq %llu: %s\n",
                (unsigned long long) report.seq_idx, report.reason);
        }
        return 1;
    }
    return 0;
}
