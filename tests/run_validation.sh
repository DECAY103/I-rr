#!/usr/bin/env bash
set -euo pipefail

mkdir -p traces out

echo "== Test 1: Hello World =="
./bin/echorun-record -o traces/hello.echotrace -- ./bin/hello_world | tee out/hello.record.txt
./bin/echorun-replay -i traces/hello.echotrace -- ./bin/hello_world | tee out/hello.replay.txt
./bin/echorun-visualise traces/hello.echotrace --svg out/hello.svg --summary out/hello.json

echo "== Test 2: getrandom capture =="
./bin/echorun-record -o traces/getrandom.echotrace -- ./bin/getrandom_demo | tee out/getrandom.record.txt
./bin/echorun-replay -i traces/getrandom.echotrace -- ./bin/getrandom_demo | tee out/getrandom.replay.txt
cmp out/getrandom.record.txt out/getrandom.replay.txt
./bin/echorun-visualise traces/getrandom.echotrace --svg out/getrandom.svg --summary out/getrandom.json

echo "== Test 3: Divergence detection =="
printf "alpha\n" > out/sample.txt
./bin/echorun-record -o traces/file.echotrace -- ./bin/file_reader out/sample.txt | tee out/file.record.txt
printf "beta\n" > out/sample.txt
set +e
./bin/echorun-replay -i traces/file.echotrace -- ./bin/file_reader out/sample.txt 2>&1 | tee out/file.replay.txt
replay_rc=${PIPESTATUS[0]}
set -e
if [ "$replay_rc" -eq 0 ]; then
  echo "expected divergence but replay succeeded" >&2
  exit 1
fi
./bin/echorun-visualise traces/file.echotrace --svg out/file.svg --summary out/file.json

echo "== Test 4: Time-travel goto =="
./bin/echorun-record -o traces/counter.echotrace -- ./bin/counter_loop | tee out/counter.record.txt
./bin/echorun-visualise traces/counter.echotrace --svg out/counter.svg --summary out/counter.json
printf "step\ngoto 8\ncontinue\nquit\n" | ./bin/echorun-replay -i traces/counter.echotrace --repl -- ./bin/counter_loop 2>&1 | tee out/counter.repl.txt || true

echo "validation complete"
