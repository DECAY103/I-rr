#include "syscall_table.h"

#ifdef __linux__
#include <sys/syscall.h>
#endif

syscall_kind_t syscall_table_classify(long syscall_nr) {
    switch (syscall_nr) {
#ifdef __linux__
        case SYS_read:
        case SYS_getrandom:
        case SYS_clock_gettime:
        case SYS_gettimeofday:
        case SYS_time:
        case SYS_getpid:
        case SYS_getppid:
            return SYSCALL_KIND_NON_DET;
        case SYS_write:
        case SYS_writev:
        case SYS_open:
        case SYS_openat:
        case SYS_close:
        case SYS_unlink:
        case SYS_unlinkat:
        case SYS_rename:
        case SYS_renameat:
        case SYS_renameat2:
        case SYS_mkdir:
        case SYS_rmdir:
        case SYS_execve:
        case SYS_exit:
        case SYS_exit_group:
        case SYS_pipe:
        case SYS_pipe2:
        case SYS_shmget:
        case SYS_shmat:
        case SYS_shmdt:
        case SYS_fork:
        case SYS_vfork:
        case SYS_clone:
            return SYSCALL_KIND_SIDE_EFFECT;
#endif
        default:
            return SYSCALL_KIND_DETERMINISTIC;
    }
}

const char *syscall_table_kind_name(syscall_kind_t kind) {
    switch (kind) {
        case SYSCALL_KIND_NON_DET:
            return "NON_DET";
        case SYSCALL_KIND_DETERMINISTIC:
            return "DETERMINISTIC";
        case SYSCALL_KIND_SIDE_EFFECT:
            return "SIDE_EFFECT";
        default:
            return "UNKNOWN";
    }
}
