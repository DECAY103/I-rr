import re

with open('src/recorder.c', 'r') as f:
    content = f.read()

run_new = """int recorder_run(char *const argv[], const recorder_options_t *options) {
    pid_t child;
    int status = 0;
    uint64_t seq_idx = 0;
    trace_writer_t writer;
    flight_buffer_t flight;
    trace_file_header_t file_header;

    if (argv == NULL || argv[0] == NULL || options == NULL || options->output_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    flight_buffer_init(&flight, options->flight_mode ? options->flight_capacity : 0);

    child = fork();
    if (child == -1) {
        flight_buffer_destroy(&flight);
        return -1;
    }

    if (child == 0) {
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(argv[0], argv);
        _exit(127);
    }

    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, NULL, (void *) (uintptr_t) (PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE));

    trace_default_file_header(&file_header, (uint32_t) child, argv[0]);
    if (trace_writer_open(&writer, options->output_path, &file_header) != 0) {
        flight_buffer_destroy(&flight);
        return -1;
    }

    tracee_count = 0;
    get_tracee(child);

    {
        trace_proc_event_record_t proc_record;
        trace_event_t proc_event;
        memset(&proc_record, 0, sizeof(proc_record));
        memset(&proc_event, 0, sizeof(proc_event));
        proc_record.header.seq_idx = seq_idx++;
        proc_record.header.type = TRACE_EVENT_PROC_EVENT;
        proc_record.header.record_size = sizeof(proc_record);
        proc_record.header.pid = (uint32_t) child;
        proc_record.proc_kind = PROC_EVENT_EXEC;
        proc_event.header = proc_record.header;
        proc_event.record.proc_event = proc_record;
        emit_event(&writer, &flight, &proc_event, options->flight_mode);
    }

    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    for (;;) {
        trace_proc_event_record_t proc_record;
        trace_event_t event;
        struct user_regs_struct regs;
        int wait_rc;

        wait_rc = waitpid(-1, &status, __WALL);
        if (wait_rc == -1) {
            if (errno == ECHILD) break;
            continue;
        }

        pid_t event_pid = wait_rc;
        tracee_state_t *tstate = get_tracee(event_pid);
        if (!tstate) continue;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            trace_event_t proc_event;
            memset(&proc_record, 0, sizeof(proc_record));
            memset(&proc_event, 0, sizeof(proc_event));
            proc_record.header.seq_idx = seq_idx++;
            proc_record.header.type = TRACE_EVENT_PROC_EVENT;
            proc_record.header.record_size = sizeof(proc_record);
            proc_record.header.pid = (uint32_t) event_pid;
            proc_record.proc_kind = PROC_EVENT_EXIT;
            proc_record.status_code = WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status);
            proc_event.header = proc_record.header;
            proc_event.record.proc_event = proc_record;
            emit_event(&writer, &flight, &proc_event, options->flight_mode);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
            continue;
        }

        int sig = WSTOPSIG(status);
        int event_type = status >> 16;
        if (event_type == PTRACE_EVENT_FORK || event_type == PTRACE_EVENT_VFORK || event_type == PTRACE_EVENT_CLONE) {
            unsigned long new_pid;
            ptrace(PTRACE_GETEVENTMSG, event_pid, NULL, &new_pid);
            get_tracee((pid_t)new_pid);
            ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            ptrace(PTRACE_GETREGS, event_pid, NULL, &regs);
            if (!tstate->in_syscall) {
                tstate->in_syscall = 1;
                tstate->entry.nr = (long) regs.orig_rax;
                tstate->entry.args[0] = regs.rdi;
                tstate->entry.args[1] = regs.rsi;
                tstate->entry.args[2] = regs.rdx;
                tstate->entry.args[3] = regs.r10;
                tstate->entry.args[4] = regs.r8;
                tstate->entry.args[5] = regs.r9;
                ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
                continue;
            }

            tstate->in_syscall = 0;
            memset(&event, 0, sizeof(event));
            event.header.seq_idx = seq_idx++;
            event.header.type = TRACE_EVENT_SYSCALL_EXIT;
            event.header.record_size = sizeof(trace_syscall_exit_record_t);
            event.header.pid = (uint32_t) event_pid;
            event.record.syscall_exit.header = event.header;
            event.record.syscall_exit.syscall_nr = (int32_t) tstate->entry.nr;
            event.record.syscall_exit.syscall_class = (int32_t) syscall_table_classify(tstate->entry.nr);
            event.record.syscall_exit.retval = (int64_t) regs.rax;
            memcpy(event.record.syscall_exit.args, tstate->entry.args, sizeof(tstate->entry.args));

            {
                uint32_t payload_size = 0;
                if (syscall_payload_descriptor(tstate->entry.nr, &tstate->entry, (long) regs.rax,
                        &event.record.syscall_exit.inject_addr, &payload_size)) {
                    event.header.payload_size = payload_size;
                    event.record.syscall_exit.header.payload_size = payload_size;
                    event.record.syscall_exit.header.flags |= TRACE_EVENT_HAS_PAYLOAD;
                    event.header.flags |= TRACE_EVENT_HAS_PAYLOAD;
                    event.payload = malloc(event.header.payload_size);
                    if (event.payload != NULL) {
                        tracee_read_memory(event_pid, event.record.syscall_exit.inject_addr, event.payload, event.header.payload_size);
                    }
                }
            }

            event.record.syscall_exit.header = event.header;
            emit_event(&writer, &flight, &event, options->flight_mode);
            trace_event_release(&event);
            ptrace(PTRACE_SYSCALL, event_pid, NULL, NULL);
            continue;
        }

        memset(&event, 0, sizeof(event));
        event.header.seq_idx = seq_idx++;
        event.header.type = TRACE_EVENT_SIGNAL;
        event.header.record_size = sizeof(trace_signal_record_t);
        event.header.pid = (uint32_t) event_pid;
        event.record.signal.header = event.header;
        event.record.signal.signal_no = sig;
        emit_event(&writer, &flight, &event, options->flight_mode);
        ptrace(PTRACE_SYSCALL, event_pid, NULL, (void*)(uintptr_t)((sig == SIGSTOP) ? 0 : sig));
    }

    if (options->flight_mode) {
        flight_buffer_flush(&writer, &flight);
    }

    flight_buffer_destroy(&flight);
    trace_writer_close(&writer);
    return 0;
}
"""

content = re.sub(r'int recorder_run\(char \*const argv\[\], const recorder_options_t \*options\) \{.*return 0;\n\}', run_new, content, flags=re.DOTALL)

with open('src/recorder.c', 'w') as f:
    f.write(content)
