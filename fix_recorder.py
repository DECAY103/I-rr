with open('src/recorder.c', 'r') as f:
    content = f.read()

s1 = """typedef struct tracee_state {
    pid_t pid;
    int in_syscall;
    syscall_entry_t entry;
} tracee_state_t;

#define MAX_TRACEES 256
static tracee_state_t tracees[MAX_TRACEES];
static size_t tracee_count = 0;

static tracee_state_t *get_tracee(pid_t pid) {
    for (size_t i = 0; i < tracee_count; i++) {
        if (tracees[i].pid == pid) return &tracees[i];
    }
    if (tracee_count < MAX_TRACEES) {
        tracees[tracee_count].pid = pid;
        tracees[tracee_count].in_syscall = 0;
        return &tracees[tracee_count++];
    }
    return NULL;
}

typedef struct syscall_entry {"""

s2 = """typedef struct syscall_entry {
    long nr;
    uint64_t args[6];
} syscall_entry_t;

typedef struct tracee_state {
    pid_t pid;
    int in_syscall;
    syscall_entry_t entry;
} tracee_state_t;

#define MAX_TRACEES 256
static tracee_state_t tracees[MAX_TRACEES];
static size_t tracee_count = 0;

static tracee_state_t *get_tracee(pid_t pid) {
    for (size_t i = 0; i < tracee_count; i++) {
        if (tracees[i].pid == pid) return &tracees[i];
    }
    if (tracee_count < MAX_TRACEES) {
        tracees[tracee_count].pid = pid;
        tracees[tracee_count].in_syscall = 0;
        return &tracees[tracee_count++];
    }
    return NULL;
}"""

content = content.replace(s1, s2)

with open('src/recorder.c', 'w') as f:
    f.write(content)
