#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "syscalls_table.h"

typedef struct {
    unsigned long long num;
    unsigned long long rdi;
    unsigned long long rsi;
    unsigned long long rdx;
    unsigned long long r10;
    unsigned long long r8;
    unsigned long long r9;
    unsigned long long ret;
} syscall_entry_t;

typedef struct {
    syscall_entry_t *entries;
    size_t count;
    size_t capacity;
} syscall_log_t;

void init_syscall_log(syscall_log_t *log) {
    log->entries = NULL;
    log->count = 0;
    log->capacity = 0;
}

int append_syscall(syscall_log_t *log, syscall_entry_t entry) {
    if (log->count >= log->capacity) {
        size_t new_capacity = log->capacity + 1;

        syscall_entry_t *new_entries =
            realloc(log->entries, new_capacity * sizeof(syscall_entry_t));
        if (new_entries == NULL) {
            perror("cannot allocate memory for syscall_log");
            return -1;
        }

        log->entries = new_entries;
        log->capacity = new_capacity;
    }

    log->entries[log->count] = entry;
    log->count++;

    return 0;
}

void free_syscall_log(syscall_log_t *log) {
    if (log->entries) {
        free(log->entries);
        log->entries = NULL;
    }

    log->count = 0;
    log->capacity = 0;
}

const char *get_syscall_name(unsigned long long syscall_num) {
    size_t count = sizeof(syscalls_table) / sizeof(syscalls_table[0]);

    for (size_t i = 0; i < count; i++) {
        if (syscalls_table[i].number == syscall_num) {
            return syscalls_table[i].name;
        }
    }

    return "unknown";
}

int main(int argc, char *argv[]) {
    syscall_log_t log;
    init_syscall_log(&log);

    pid_t tracer_pid;

    tracer_pid = fork();
    if (tracer_pid < 0) {
        perror("cannot create a tracer process.");
        exit(EXIT_FAILURE);
    } else if (tracer_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("PTRACE_TRACEME failed.");
            exit(EXIT_FAILURE);
        }
        execvp(argv[1], &argv[1]);
    }

    int status;
    bool in_syscall = false;
    struct user_regs_struct regs;

    // Skip the first syscall (execve)
    waitpid(tracer_pid, &status, 0);
    ptrace(PTRACE_SYSCALL, tracer_pid, NULL, NULL);

    while (1) {
        waitpid(tracer_pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        if (ptrace(PTRACE_GETREGS, tracer_pid, NULL, &regs) == -1) {
            perror("PTRACE_GETREGS failed.");
            exit(EXIT_FAILURE);
        }

        if (in_syscall == false) {
            syscall_entry_t entry = {
                .num = regs.orig_rax,
                .rdi = regs.rdi,
                .rsi = regs.rsi,
                .rdx = regs.rdx,
                .r10 = regs.r10,
                .r8 = regs.r8,
                .r9 = regs.r9,
            };

            if (append_syscall(&log, entry) == -1) {
                perror("cannot append the syscall to the log");
                exit(EXIT_FAILURE);
            }

            in_syscall = true;
        } else {
            log.entries[log.count - 1].ret = regs.rax;

            in_syscall = false;
        }

        if (ptrace(PTRACE_SYSCALL, tracer_pid, NULL, NULL) == -1) {
            perror("PTRACE_SYSCALL failed.");
            exit(EXIT_FAILURE);
        }
    }

    for (size_t i = 0; i < log.capacity; i++) {
        printf("syscall: %s [%lld] (", get_syscall_name(log.entries[i].num),
               log.entries[i].num);
        printf("0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx",
               log.entries[i].rdi, log.entries[i].rsi, log.entries[i].rdx,
               log.entries[i].r10, log.entries[i].r8, log.entries[i].r9);
        printf(")\n");

        if (i == log.capacity - 1) {
            continue;
        }
        printf(" -> return = 0x%llx\n\n", log.entries[i].ret);
    }

    free_syscall_log(&log);

    return 0;
}
