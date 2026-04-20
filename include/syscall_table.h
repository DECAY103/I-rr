#ifndef ECHORUN_SYSCALL_TABLE_H
#define ECHORUN_SYSCALL_TABLE_H

typedef enum syscall_kind {
    SYSCALL_KIND_NON_DET = 0,
    SYSCALL_KIND_DETERMINISTIC = 1,
    SYSCALL_KIND_SIDE_EFFECT = 2
} syscall_kind_t;

syscall_kind_t syscall_table_classify(long syscall_nr);
const char *syscall_table_kind_name(syscall_kind_t kind);

#endif
