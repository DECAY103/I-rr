const TESTS = [
  {
    id: "hello",
    title: "Hello World",
    label: "Test 1",
    target: "./bin/hello_world",
    intent: "Smoke test for recording and replaying write(2) output.",
    trace: "traces/hello.echotrace",
    commands: [
      "./bin/echorun-record -o traces/hello.echotrace -- ./bin/hello_world",
      "./bin/echorun-replay -i traces/hello.echotrace -- ./bin/hello_world",
      "./bin/echorun-visualise traces/hello.echotrace --svg out/hello.svg --summary out/hello.json"
    ],
    logs: [
      { label: "record", path: "../out/hello.record.txt" },
      { label: "replay", path: "../out/hello.replay.txt" }
    ],
    summaryPath: "../out/hello.json",
    svgPath: "../out/hello.svg"
  },
  {
    id: "getrandom",
    title: "getrandom capture",
    label: "Test 2",
    target: "./bin/getrandom_demo",
    intent: "Confirms non-deterministic getrandom(2) bytes are captured and replayed.",
    trace: "traces/getrandom.echotrace",
    commands: [
      "./bin/echorun-record -o traces/getrandom.echotrace -- ./bin/getrandom_demo",
      "./bin/echorun-replay -i traces/getrandom.echotrace -- ./bin/getrandom_demo",
      "cmp out/getrandom.record.txt out/getrandom.replay.txt"
    ],
    logs: [
      { label: "record", path: "../out/getrandom.record.txt" },
      { label: "replay", path: "../out/getrandom.replay.txt" }
    ],
    summaryPath: "../out/getrandom.json",
    svgPath: "../out/getrandom.svg"
  },
  {
    id: "file",
    title: "Divergence detection",
    label: "Test 3",
    target: "./bin/file_reader out/sample.txt",
    intent: "Records one file state, mutates the file, then verifies replay reports divergence.",
    trace: "traces/file.echotrace",
    commands: [
      "printf \"alpha\\n\" > out/sample.txt",
      "./bin/echorun-record -o traces/file.echotrace -- ./bin/file_reader out/sample.txt",
      "printf \"beta\\n\" > out/sample.txt",
      "./bin/echorun-replay -i traces/file.echotrace -- ./bin/file_reader out/sample.txt"
    ],
    logs: [
      { label: "record", path: "../out/file.record.txt" },
      { label: "replay", path: "../out/file.replay.txt" }
    ],
    summaryPath: "../out/file.json",
    svgPath: "../out/file.svg",
    expectsDivergence: true
  },
  {
    id: "counter",
    title: "Time-travel goto",
    label: "Test 4",
    target: "./bin/counter_loop",
    intent: "Exercises checkpoint creation and the replay REPL commands: step, goto, continue.",
    trace: "traces/counter.echotrace",
    commands: [
      "./bin/echorun-record -o traces/counter.echotrace -- ./bin/counter_loop",
      "./bin/echorun-visualise traces/counter.echotrace --svg out/counter.svg --summary out/counter.json",
      "printf \"step\\ngoto 8\\ncontinue\\nquit\\n\" | ./bin/echorun-replay -i traces/counter.echotrace --repl -- ./bin/counter_loop"
    ],
    logs: [
      { label: "record", path: "../out/counter.record.txt" },
      { label: "repl", path: "../out/counter.repl.txt" }
    ],
    summaryPath: "../out/counter.json",
    svgPath: "../out/counter.svg"
  }
];

const EVENT_TYPES = {
  1: "syscall",
  2: "signal",
  3: "process"
};

const SYSCALL_NAMES = {
  0: "read",
  1: "write",
  3: "close",
  5: "fstat",
  9: "mmap",
  10: "mprotect",
  11: "munmap",
  12: "brk",
  17: "pread64",
  21: "access",
  59: "execve",
  158: "arch_prctl",
  218: "set_tid_address",
  257: "openat",
  273: "set_robust_list",
  302: "prlimit64",
  318: "getrandom",
  334: "rseq"
};

function classNames(...parts) {
  return parts.filter(Boolean).join(" ");
}

async function fetchText(path) {
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) {
      return "";
    }
    return await response.text();
  } catch (error) {
    return "";
  }
}

async function fetchJson(path) {
  const text = await fetchText(path);
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    return null;
  }
}

function useArtifacts() {
  const [state, setState] = React.useState({ loading: true, tests: [] });

  React.useEffect(() => {
    let cancelled = false;

    async function load() {
      const tests = await Promise.all(
        TESTS.map(async (test) => {
          const [summary, ...logs] = await Promise.all([
            fetchJson(test.summaryPath),
            ...test.logs.map((log) => fetchText(log.path))
          ]);

          return {
            ...test,
            summary,
            logs: test.logs.map((log, index) => ({ ...log, text: logs[index] }))
          };
        })
      );

      if (!cancelled) {
        setState({ loading: false, tests });
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

function statusFor(test) {
  const replayLog = test.logs.find((log) => log.label === "replay" || log.label === "repl")?.text || "";
  const recordLog = test.logs.find((log) => log.label === "record")?.text || "";

  if (!test.summary) {
    return { label: "Waiting for artifacts", tone: "bg-white/70 text-ink/60" };
  }
  if (test.expectsDivergence) {
    return replayLog.includes("divergence")
      ? { label: "Divergence detected", tone: "bg-lavender text-ink" }
      : { label: "Needs rerun", tone: "bg-red-100 text-red-800" };
  }
  if (test.id === "getrandom" && recordLog && recordLog === replayLog) {
    return { label: "Replay matched", tone: "bg-mint text-ink" };
  }
  if (recordLog) {
    return { label: "Artifacts ready", tone: "bg-mint text-ink" };
  }
  return { label: "Summary ready", tone: "bg-mint text-ink" };
}

function SectionLabel({ children, className = "" }) {
  return (
    <p className={classNames("text-xs font-bold uppercase tracking-[0.28em]", className)}>
      {children}
    </p>
  );
}

function ShellCard({ children, className = "", style }) {
  return (
    <section className={classNames("rounded-[2rem] border border-white/60 bg-white/95 p-5 shadow-float sm:p-6", className)} style={style}>
      {children}
    </section>
  );
}

function CommandList() {
  return (
    <ShellCard className="bg-ink text-white">
      <SectionLabel className="text-mint/70">How to Run</SectionLabel>
      <h2 className="mt-3 text-3xl font-bold tracking-[-0.05em]">Terminal first, UI second.</h2>
      <div className="mt-5 grid gap-3 text-sm text-white/75">
        {[
          "make",
          "make test",
          "python3 -m http.server 8000",
          "Open http://localhost:8000/ui/"
        ].map((command, index) => (
          <div key={command} className="flex gap-3 rounded-2xl bg-white/10 p-3">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-mint text-xs font-bold text-ink">
              {index + 1}
            </span>
            <code className="pt-1 font-mono text-[0.8rem] leading-5 text-white">{command}</code>
          </div>
        ))}
      </div>
      <p className="mt-5 text-sm leading-6 text-white/55">
        Serve from the project root, not from inside <code className="font-mono">ui/</code>, so the browser can fetch <code className="font-mono">out/*.json</code>, <code className="font-mono">out/*.svg</code>, and terminal log files.
      </p>
    </ShellCard>
  );
}

function Metric({ label, value }) {
  return (
    <div className="rounded-2xl bg-shell/75 px-4 py-3">
      <p className="text-xs uppercase tracking-[0.18em] text-ink/40">{label}</p>
      <p className="mt-2 text-2xl font-bold tracking-[-0.05em]">{value}</p>
    </div>
  );
}

function eventColor(event) {
  if (event.type === 2) {
    return "#ef4444";
  }
  if (event.type === 3) {
    return "#0f766e";
  }
  if (event.payload > 0) {
    return "#B2F2BB";
  }
  return "#1A1A1A";
}

function Timeline({ events = [] }) {
  const visible = events.slice(0, 90);

  if (events.length === 0) {
    return (
      <div className="rounded-[1.5rem] border border-dashed border-ink/20 bg-shell/60 p-5 text-sm text-ink/50">
        No timeline yet. Run <code className="font-mono">make test</code> to create visualizer output.
      </div>
    );
  }

  return (
    <div className="rounded-[1.5rem] bg-ink p-4">
      <div className="flex h-28 items-center gap-1 overflow-hidden">
        {visible.map((event) => (
          <div
            key={event.seq}
            title={`seq ${event.seq}: ${EVENT_TYPES[event.type] || "event"} ${SYSCALL_NAMES[event.syscall] || event.syscall}`}
            className="min-w-[5px] flex-1 rounded-full"
            style={{
              height: `${Math.max(18, Math.min(92, event.payload ? 38 + event.payload / 10 : 28))}%`,
              background: eventColor(event)
            }}
          />
        ))}
      </div>
      <div className="mt-4 flex flex-wrap gap-3 text-xs text-white/55">
        <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-mint"></span>payload</span>
        <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-white"></span>syscall</span>
        <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-red-500"></span>signal</span>
        <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded-full bg-teal-700"></span>process</span>
      </div>
    </div>
  );
}

function TerminalBlock({ logs }) {
  const hasText = logs.some((log) => (log.text || "").trim());

  if (!hasText) {
    return (
      <pre className="min-h-[9rem] overflow-auto rounded-[1.5rem] bg-ink p-4 font-mono text-xs leading-6 text-white/45">
Run make test to populate out/*.txt terminal logs.
      </pre>
    );
  }

  return (
    <div className="grid gap-3">
      {logs.map((log) => (
        <div key={log.label} className="overflow-hidden rounded-[1.5rem] bg-ink">
          <div className="flex items-center justify-between border-b border-white/10 px-4 py-2">
            <span className="text-xs uppercase tracking-[0.2em] text-white/45">{log.label}</span>
            <span className="text-xs text-white/35">{log.path.replace("../", "")}</span>
          </div>
          <pre className="max-h-48 overflow-auto p-4 font-mono text-xs leading-6 text-mint">
{log.text || "(no output)"}
          </pre>
        </div>
      ))}
    </div>
  );
}

function TestCard({ test, index }) {
  const status = statusFor(test);
  const summary = test.summary;
  const events = summary?.events || [];
  const payloadEvents = events.filter((event) => event.payload > 0).length;
  const topSyscalls = events
    .filter((event) => event.syscall >= 0)
    .slice(-6)
    .map((event) => SYSCALL_NAMES[event.syscall] || `sys_${event.syscall}`)
    .join(" -> ");

  return (
    <ShellCard className="animate-fade-up" style={{ animationDelay: `${index * 80}ms` }}>
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start">
        <div className="xl:w-[28rem]">
          <div className="flex flex-wrap items-center gap-3">
            <SectionLabel className="text-ink/35">{test.label}</SectionLabel>
            <span className={classNames("rounded-full px-3 py-1 text-xs font-bold", status.tone)}>
              {status.label}
            </span>
          </div>
          <h3 className="mt-3 text-3xl font-bold tracking-[-0.05em]">{test.title}</h3>
          <p className="mt-3 text-sm leading-6 text-ink/55">{test.intent}</p>
          <p className="mt-4 rounded-2xl bg-shell/80 px-4 py-3 font-mono text-xs text-ink/70">{test.target}</p>

          <div className="mt-4 grid grid-cols-3 gap-3">
            <Metric label="events" value={summary?.totalEvents ?? "-"} />
            <Metric label="payloads" value={payloadEvents || "-"} />
            <Metric label="signals" value={summary?.signalEvents ?? "-"} />
          </div>
        </div>

        <div className="grid flex-1 gap-4">
          <Timeline events={events} />
          {summary ? (
            <img
              src={test.svgPath}
              alt={`${test.title} SVG timeline`}
              className="w-full rounded-[1.5rem] border border-ink/10 bg-white"
              onError={(event) => {
                event.currentTarget.style.display = "none";
              }}
            />
          ) : null}
          <div className="grid gap-4 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
            <div className="rounded-[1.5rem] bg-shell/70 p-4">
              <p className="text-xs uppercase tracking-[0.2em] text-ink/35">Commands</p>
              <div className="mt-3 grid gap-2">
                {test.commands.map((command) => (
                  <code key={command} className="block rounded-xl bg-white/75 px-3 py-2 font-mono text-xs leading-5 text-ink/70">
                    {command}
                  </code>
                ))}
              </div>
              <p className="mt-4 text-xs leading-5 text-ink/45">
                Recent syscall tail: {topSyscalls || "not available"}
              </p>
            </div>
            <TerminalBlock logs={test.logs} />
          </div>
        </div>
      </div>
    </ShellCard>
  );
}

function App() {
  const { loading, tests } = useArtifacts();
  const readyCount = tests.filter((test) => test.summary).length;
  const totalEvents = tests.reduce((sum, test) => sum + (test.summary?.totalEvents || 0), 0);
  const divergenceSeen = tests.some((test) => test.logs.some((log) => log.text.includes("divergence")));

  return (
    <div className="relative min-h-screen overflow-hidden">


      <main className="relative mx-auto flex min-h-screen max-w-7xl flex-col gap-5 px-4 py-6 sm:px-6 lg:px-8">
        <header className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_24rem]">
          <ShellCard className="animate-fade-up bg-white/70">
            <SectionLabel className="text-ink/35">EchoRun Output Viewer</SectionLabel>
            <h1 className="mt-4 max-w-4xl text-4xl font-bold leading-none tracking-[-0.07em] sm:text-6xl">
              C execution traces, terminal logs, and visualizer summaries in one place.
            </h1>
            <p className="mt-5 max-w-2xl text-sm leading-6 text-ink/55">
              Run the validation suite first. The C tools write traces into <code className="font-mono">traces/</code> and dashboard artifacts into <code className="font-mono">out/</code>; this UI reads those files directly.
            </p>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              <Metric label="ready tests" value={loading ? "..." : `${readyCount}/4`} />
              <Metric label="trace events" value={loading ? "..." : totalEvents} />
              <Metric label="divergence" value={divergenceSeen ? "seen" : "none"} />
            </div>
          </ShellCard>
          <CommandList />
        </header>

        <section className="grid gap-5">
          {(tests.length ? tests : TESTS).map((test, index) => (
            <TestCard key={test.id} test={test} index={index} />
          ))}
        </section>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
