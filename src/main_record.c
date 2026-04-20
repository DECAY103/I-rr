#include "echorun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s -o <trace.echotrace> [--flight N] -- <target> [args...]\n", argv0);
}

int main(int argc, char **argv) {
    recorder_options_t options;
    int sep = -1;
    int i;

    memset(&options, 0, sizeof(options));
    options.flight_capacity = 256;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) {
            sep = i + 1;
            break;
        }
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            options.output_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--flight") == 0 && i + 1 < argc) {
            options.flight_mode = 1;
            options.flight_capacity = (size_t) strtoull(argv[++i], NULL, 10);
            continue;
        }
    }

    if (options.output_path == NULL || sep == -1 || sep >= argc) {
        usage(argv[0]);
        return 1;
    }
    return recorder_run(&argv[sep], &options) == 0 ? 0 : 1;
}
