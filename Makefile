CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS ?= -Iinclude
LDFLAGS ?=

COMMON_SRCS = src/trace_reader.c src/syscall_table.c
RECORDER_SRCS = $(COMMON_SRCS) src/recorder.c src/main_record.c
REPLAYER_SRCS = $(COMMON_SRCS) src/replayer.c src/main_replay.c
VISUALISER_SRCS = $(COMMON_SRCS) src/visualiser.c src/main_visualise.c

TARGETS = bin/echorun-record bin/echorun-replay bin/echorun-visualise \
	bin/hello_world bin/getrandom_demo bin/file_reader bin/counter_loop

.PHONY: all clean test ui

all: $(TARGETS)

bin:
	mkdir -p bin

bin/echorun-record: $(RECORDER_SRCS) | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(RECORDER_SRCS) $(LDFLAGS)

bin/echorun-replay: $(REPLAYER_SRCS) | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(REPLAYER_SRCS) $(LDFLAGS)

bin/echorun-visualise: $(VISUALISER_SRCS) | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(VISUALISER_SRCS) $(LDFLAGS)

bin/hello_world: tests/targets/hello_world.c | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

bin/getrandom_demo: tests/targets/getrandom_demo.c | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

bin/file_reader: tests/targets/file_reader.c | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

bin/counter_loop: tests/targets/counter_loop.c | bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

test: all
	bash tests/run_validation.sh

ui:
	@echo "Run: python3 -m http.server 8000"
	@echo "Then open: http://localhost:8000/ui/"
	@echo "Serve from the project root so the UI can read ./out artifacts."

clean:
	rm -rf bin traces out
