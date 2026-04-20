#include "echorun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s -i <trace.echotrace> [--repl] [--checkpoint-every N] -- <target> [args...]\n", argv0);
}

int main(int argc, char **argv) {
    replayer_options_t options;
    divergence_report_t report;
    int sep = -1;
    int i;

    memset(&options, 0, sizeof(options));
    memset(&report, 0, sizeof(report));
    options.checkpoint_every = 8;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) {
            sep = i + 1;
            break;
        }
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            options.input_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--repl") == 0) {
            options.interactive = 1;
            continue;
        }
        if (strcmp(argv[i], "--checkpoint-every") == 0 && i + 1 < argc) {
            options.checkpoint_every = (size_t) strtoull(argv[++i], NULL, 10);
            continue;
        }
    }

    if (options.input_path == NULL || sep == -1 || sep >= argc) {
        usage(argv[0]);
        return 1;
    }

    if (replayer_run(&argv[sep], &options, &report) != 0) {
        if (report.reason[0] != '\0') {
            fprintf(stderr, "divergence at seq %llu: %s\n",
                (unsigned long long) report.seq_idx, report.reason);
        }
        return 1;
    }
    return 0;
}
