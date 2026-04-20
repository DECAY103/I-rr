// =======================
// SVG Icons (Flat Design)
// =======================
const IconDatabase = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M3 5V19A9 3 0 0 0 21 19V5"></path><path d="M3 12A9 3 0 0 0 21 12"></path></svg>;
const IconFile = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>;
const IconTerminal = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>;
const IconPlay = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>;
const IconCode = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>;
const IconActivity = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>;
const IconCopy = ({ className }) => <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>;

// =======================
// Config
// =======================
const TESTS = [
  { id: "hello", title: "Hello World", target: "./bin/hello_world", summaryPath: "../out/hello.json", logs: [{ label: "record", path: "../out/hello.record.txt" }, { label: "replay", path: "../out/hello.replay.txt" }] },
  { id: "getrandom", title: "getrandom capture", target: "./bin/getrandom_demo", summaryPath: "../out/getrandom.json", logs: [{ label: "record", path: "../out/getrandom.record.txt" }, { label: "replay", path: "../out/getrandom.replay.txt" }] },
  { id: "file", title: "Divergence detection", target: "./bin/file_reader out/sample.txt", summaryPath: "../out/file.json", expectsDivergence: true, logs: [{ label: "record", path: "../out/file.record.txt" }, { label: "replay", path: "../out/file.replay.txt" }] },
  { id: "counter", title: "Time-travel goto", target: "./bin/counter_loop", summaryPath: "../out/counter.json", logs: [{ label: "record", path: "../out/counter.record.txt" }, { label: "repl", path: "../out/counter.repl.txt" }] },
  { id: "audit", title: "Audit Vault Multi-Process", target: "./bin/audit_vault", summaryPath: "../out/audit.json", logs: [{ label: "record", path: "../out/audit.record.txt" }, { label: "replay", path: "../out/audit.replay.txt" }] }
];

const SYSCALL_NAMES = { 0: "read", 1: "write", 3: "close", 5: "fstat", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk", 17: "pread64", 21: "access", 56: "clone", 59: "execve", 61: "wait4", 158: "arch_prctl", 218: "set_tid_address", 219: "restart_syscall", 230: "nanosleep", 257: "openat", 273: "set_robust_list", 293: "pipe2", 302: "prlimit64", 318: "getrandom", 334: "rseq" };

// Colors logic based on prompt
function getEventColor(event) {
  if (event.syscall === 318) return "bg-emerald-500 border-emerald-600"; // non-det
  if (event.syscall === 1 || event.syscall === 0) return "bg-amber-500 border-amber-600"; // side-effect
  if (event.type === 2) return "bg-red-500 border-red-600"; // signal
  if (event.type === 3) return "bg-slate-700 border-slate-800"; // process event
  return "bg-slate-400 border-slate-500"; // default det
}

function getEventColorCoreHex(event) {
    if (event.syscall === 318) return "#10b981"; // emerald
    if (event.syscall === 1 || event.syscall === 0) return "#f59e0b"; // amber
    if (event.type === 2) return "#ef4444"; // red
    if (event.type === 3) return "#334155"; // slate-700
    return "#94a3b8"; // slate-400
}

function extractDivergenceMessage(logs) {
    for (const log of logs) {
        if (!log.text) continue;
        const match = log.text.match(/(divergence at seq \d+: .*)/i);
        if (match) return match[1];
    }
    return "divergence observed";
}

// =======================
// Data Loading Hook
// =======================
function useArtifacts() {
  const [state, setState] = React.useState({ loading: true, tests: [] });
  React.useEffect(() => {
    let cancelled = false;
    async function load() {
      const db = await Promise.all(TESTS.map(async (test) => {
        let summary = null;
        try { const r = await fetch(test.summaryPath, { cache: "no-store" }); if(r.ok) summary = await r.json(); } catch(e){}
        const logs = await Promise.all(test.logs.map(async (log) => {
            let text = "";
            try { const r = await fetch(log.path, { cache: "no-store"}); if(r.ok) text = await r.text(); } catch(e){}
            return { ...log, text };
        }));
        return { ...test, summary, logs };
      }));
      if (!cancelled) setState({ loading: false, tests: db });
    }
    load();
    return () => { cancelled = true; };
  }, []);
  return state;
}

// =======================
// Components
// =======================
function App() {
  const { loading, tests } = useArtifacts();
  const [activeTestId, setActiveTestId] = React.useState("hello");
  const [selectedSeq, setSelectedSeq] = React.useState(null);
  const [activeTab, setActiveTab] = React.useState("record");

  const rowRefs = React.useRef({});

  if (loading) {
      return <div className="flex h-screen items-center justify-center font-bold text-slate-500 uppercase tracking-widest text-sm">LOADING ARTIFACTS...</div>;
  }

  const activeTest = tests.find(t => t.id === activeTestId);
  const events = activeTest?.summary?.events || [];
  const selectedEvent = events.find(e => e.seq === selectedSeq);

  const scrollToSeq = (seq) => {
      setSelectedSeq(seq);
      if (rowRefs.current[seq]) {
          rowRefs.current[seq].scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
  };

  // Divergence logic
  let divergenceSeq = -1;
  let divergenceMsg = "";
  if (activeTest.summary && activeTest.summary.divergence && activeTest.summary.divergence.seq !== undefined && activeTest.summary.divergence.reason !== "") {
    divergenceSeq = activeTest.summary.divergence.seq;
  }
  const replayLogText = activeTest.logs.find(l => l.label === "replay" || l.label === "repl")?.text || "";
  if (replayLogText.includes("divergence")) {
     const match = replayLogText.match(/divergence at seq (\d+)/);
     if (match) divergenceSeq = parseInt(match[1]);
     divergenceMsg = extractDivergenceMessage(activeTest.logs);
  }

  return (
    <div className="flex h-screen w-full bg-slate-50 overflow-hidden text-sm">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-300 bg-white flex flex-col shrink-0 z-20 shadow-[1px_0_10px_rgba(0,0,0,0.02)]">
        <div className="p-5 border-b border-slate-300 font-bold flex items-center gap-3 text-slate-800 tracking-tight text-lg">
           <IconDatabase className="w-5 h-5 text-blue-600" /> EchoRun
        </div>
        <div className="flex-1 overflow-y-auto">
            <div className="p-3 text-[10px] uppercase font-bold text-slate-400 tracking-widest">Test Targets</div>
            {tests.map(test => {
                const isActive = test.id === activeTestId;
                const hasSummary = !!test.summary;
                return (
                    <button 
                        key={test.id}
                        onClick={() => { setActiveTestId(test.id); setSelectedSeq(null); setActiveTab(test.logs[0].label); }}
                        className={`w-full text-left px-5 py-4 border-b border-slate-100 flex flex-col gap-1 transition-colors ${isActive ? 'bg-blue-600 text-white' : 'hover:bg-slate-50 text-slate-700'}`}
                    >
                        <div className="font-bold truncate">{test.title}</div>
                        <div className={`text-[10px] font-bold uppercase tracking-wider ${isActive ? 'text-blue-200' : 'text-slate-400'}`}>
                           {hasSummary ? `${test.summary.totalEvents} events` : <span className="text-red-400">MISSING ARTIFACT</span>}
                        </div>
                    </button>
                );
            })}
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="flex-1 flex flex-col min-w-0 bg-white">
        {!activeTest.summary ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-500 bg-slate-50">
                <IconActivity className="w-12 h-12 mb-4 opacity-30 text-slate-400" />
                <h2 className="text-xl font-bold pb-2 mb-2">Artifact Missing</h2>
                <p>Run <code className="bg-slate-200 px-1.5 py-0.5 rounded text-slate-800 border border-slate-300 shadow-sm mx-1">make test</code> to generate traces</p>
            </div>
        ) : (
            <>
                {/* Header Strip */}
                <div className="bg-white border-b border-slate-300 px-6 py-4 shrink-0 flex items-center justify-between">
                    <div>
                        <h1 className="font-bold text-xl text-slate-800">{activeTest.title}</h1>
                        <div className="text-slate-400 font-mono text-xs mt-1">{activeTest.target}</div>
                    </div>
                </div>

                {/* Execution Strip (Timeline) */}
                <div className="bg-slate-50 border-b border-slate-300 p-4 shrink-0 shadow-inner">
                    <div className="text-[10px] font-bold text-slate-500 mb-3 uppercase tracking-widest flex items-center justify-between">
                        <span>Timeline Execution Strip</span>
                        <div className="flex gap-4">
                            <span className="flex items-center gap-1.5"><span className="w-2 h-2 bg-slate-400 block"></span> Deterministic</span>
                            <span className="flex items-center gap-1.5"><span className="w-2 h-2 bg-emerald-500 block"></span> Non-Deterministic</span>
                            <span className="flex items-center gap-1.5"><span className="w-2 h-2 bg-amber-500 block"></span> Side-Effect</span>
                        </div>
                    </div>
                    <div className="flex gap-[2px] overflow-x-auto pb-2 custom-scrollbar">
                        {events.map((event) => {
                            const isSelected = selectedSeq === event.seq;
                            return (
                                <button 
                                    key={event.seq} 
                                    onClick={() => scrollToSeq(event.seq)}
                                    title={`Seq ${event.seq}: ${SYSCALL_NAMES[event.syscall] || 'Event'}`}
                                    className={`h-8 min-w-[12px] flex-1 border ${getEventColor(event)} ${isSelected ? 'ring-2 ring-blue-600 ring-offset-[3px] ring-offset-slate-50 z-10' : 'opacity-80 hover:opacity-100 hover:scale-110 transition-transform'}`}
                                ></button>
                            );
                        })}
                    </div>
                </div>

                {/* Work Area Split */}
                <div className="flex-1 flex overflow-hidden">
                    {/* Divergence Diff Table */}
                    <div className="flex-1 flex flex-col bg-white overflow-hidden relative mr-[-1px]">
                         <div className="grid grid-cols-2 bg-slate-800 text-slate-300 text-[10px] uppercase tracking-widest font-bold shrink-0">
                             <div className="p-2 px-4 border-r border-slate-600 flex items-center gap-2"><IconFile className="w-3 h-3 text-emerald-400" /> Record Path (JSON)</div>
                             <div className="p-2 px-4 flex items-center gap-2"><IconPlay className="w-3 h-3 text-blue-400" /> Replay Path (Live)</div>
                         </div>
                         <div className="flex-1 overflow-y-auto custom-scrollbar p-2 space-y-[1px] bg-slate-50">
                             {events.map(event => {
                                 const isSelected = selectedSeq === event.seq;
                                 const isDivergence = divergenceSeq === event.seq;
                                 const isPostDivergence = divergenceSeq !== -1 && event.seq > divergenceSeq;
                                 const eventName = event.type === 2 ? "SIGNAL" : event.type === 3 ? "PROCESS" : (SYSCALL_NAMES[event.syscall] || `syscall(${event.syscall})`);
                                 
                                 return (
                                     <div key={event.seq} 
                                          ref={el => rowRefs.current[event.seq] = el}
                                          className={`grid grid-cols-[1fr_1px_1fr] text-xs cursor-pointer ${isSelected ? 'bg-blue-100 border border-blue-300 shadow-sm z-10 relative' : 'hover:bg-slate-100 border border-transparent bg-white'} ${isDivergence && !isSelected ? 'border-red-500 bg-red-50 z-10 relative' : ''}`}
                                          onClick={() => setSelectedSeq(event.seq)}>
                                         <div className="p-2 flex gap-3 items-center">
                                            <span className="text-slate-400 font-mono w-8 text-right block">#{event.seq}</span>
                                            <span className="font-bold w-24" style={{color: getEventColorCoreHex(event)}}>{eventName}</span>
                                            {event.payload > 0 && <span className="text-[10px] uppercase font-bold text-slate-500 bg-slate-100 px-1.5 rounded border border-slate-200">pay: {event.payload}</span>}
                                         </div>
                                         <div className="bg-slate-200"></div>
                                         <div className={`p-2 flex gap-3 items-center ${isDivergence ? 'bg-red-500 text-white font-bold' : isPostDivergence ? 'text-slate-300 bg-slate-100/50' : ''}`}>
                                            {isDivergence ? (
                                                <span className="px-2">{divergenceMsg || 'EXPECTATION MISMATCH CAUGHT'}</span>
                                            ) : isPostDivergence ? (
                                                <span className="px-2 italic">(Execution Aborted)</span>
                                            ) : (
                                                <>
                                                    <span className={isDivergence ? 'text-red-200 font-mono w-8 text-right block' : 'text-slate-400 font-mono w-8 text-right block'}>#{event.seq}</span>
                                                    <span className={`font-bold w-24 ${isDivergence ? 'text-white' : ''}`} style={(!isDivergence) ? {color: getEventColorCoreHex(event)} : {}}>{eventName}</span>
                                                    {event.payload > 0 && <span className={`text-[10px] uppercase font-bold border rounded px-1.5 ${isDivergence ? 'bg-red-600 text-red-200 border-red-400' : 'text-slate-500 bg-slate-100 border-slate-200'}`}>pay: {event.payload}</span>}
                                                </>
                                            )}
                                         </div>
                                     </div>
                                 );
                             })}
                         </div>
                    </div>

                    {/* Right Panel Layout */}
                    <div className="w-[360px] flex flex-col bg-white border-l border-slate-300 shrink-0 shadow-[-5px_0_15px_rgba(0,0,0,0.02)] z-10">
                        {/* Payload Inspector */}
                        <div className="flex-1 flex flex-col overflow-hidden">
                            <div className="bg-slate-100 p-2 text-[10px] font-bold uppercase text-slate-500 tracking-widest border-b border-slate-300 shrink-0 flex items-center justify-center gap-2">
                                <IconCode className="w-3.5 h-3.5 text-slate-400" /> Payload & Arg Inspector
                            </div>
                            <div className="p-5 overflow-y-auto custom-scrollbar flex-1 bg-white">
                                {selectedEvent ? (
                                    <div className="space-y-6">
                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <div className="text-[10px] text-slate-400 uppercase font-bold tracking-widest border-b border-slate-100 pb-1 mb-2">Sequence ID</div>
                                                <div className="font-mono text-2xl text-slate-800">{selectedEvent.seq}</div>
                                            </div>
                                            <div>
                                                <div className="text-[10px] text-slate-400 uppercase font-bold tracking-widest border-b border-slate-100 pb-1 mb-2">Syscall ID</div>
                                                <div className="font-mono text-2xl text-slate-800 bg-slate-50 inline-block px-2">{selectedEvent.syscall}</div>
                                            </div>
                                        </div>
                                        <div>
                                            <div className="text-[10px] text-slate-400 uppercase font-bold tracking-widest border-b border-slate-100 pb-1 mb-2">Execution Target</div>
                                            <div className="font-mono border border-slate-300 bg-slate-50 px-3 py-1.5 inline-block text-slate-700 font-bold">
                                                {selectedEvent.type === 2 ? 'OS_SIGNAL' : selectedEvent.type === 3 ? 'OS_PROCESS' : (SYSCALL_NAMES[selectedEvent.syscall] || `syscall_${selectedEvent.syscall}`)}()
                                            </div>
                                        </div>
                                        <div>
                                            <div className="text-[10px] text-slate-400 uppercase font-bold tracking-widest border-b border-slate-100 pb-1 mb-2">Intercepted Buffer</div>
                                            {selectedEvent.payload > 0 ? (
                                                <div className="border border-slate-300 bg-slate-800 text-slate-100 p-3 font-mono text-xs relative group shadow-sm flex items-center justify-between">
                                                    <span>{selectedEvent.payload} bytes of static memory</span>
                                                    <button className="p-1.5 bg-slate-700 hover:bg-slate-600 rounded text-slate-200 transition-colors border border-slate-600" title="Copy Data">
                                                        <IconCopy className="w-3.5 h-3.5" />
                                                    </button>
                                                </div>
                                            ) : (
                                                <div className="text-slate-400 italic text-xs">No active payloads bound to arguments.</div>
                                            )}
                                        </div>
                                    </div>
                                ) : (
                                    <div className="flex flex-col items-center justify-center h-full text-slate-400 gap-3 opacity-60">
                                        <IconDatabase className="w-8 h-8" />
                                        <div className="italic text-xs font-mono">Select timeline block...</div>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Terminal Logs */}
                        <div className="h-64 flex flex-col bg-slate-900 shrink-0">
                            <div className="flex bg-[#0f172a] text-[10px] tracking-widest shrink-0">
                                {activeTest.logs.map(log => (
                                    <button 
                                        key={log.label}
                                        onClick={() => setActiveTab(log.label)}
                                        className={`px-4 py-2 uppercase font-bold flex items-center justify-center gap-2 flex-1 border-t-2 ${activeTab === log.label ? 'bg-slate-900 text-white border-blue-500' : 'text-slate-500 border-transparent hover:text-slate-300 hover:bg-slate-800'}`}
                                    >
                                        <IconTerminal className="w-3 h-3" /> {log.label}
                                    </button>
                                ))}
                            </div>
                            <div className="flex-1 overflow-y-auto p-4 term-scroll">
                                {activeTest.logs.map(log => {
                                    if (log.label !== activeTab) return null;
                                    if (!log.text) return <div key={log.label} className="text-slate-600 font-mono text-xs italic">Waiting for execution...</div>;
                                    
                                    const lines = log.text.split('\n');
                                    return (
                                        <pre key={log.label} className="font-mono text-xs leading-5 text-slate-300 m-0 p-0 break-all whitespace-pre-wrap">
                                            {lines.map((line, i) => {
                                                if (line.toLowerCase().includes('divergence') || line.toLowerCase().includes('error')) {
                                                    return <div key={i} className="text-red-400 font-bold bg-red-950/30 px-1 border-l-2 border-red-500 -ml-1 inline-block">{line}</div>;
                                                }
                                                return <div key={i}>{line}</div>;
                                            })}
                                        </pre>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            </>
        )}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
