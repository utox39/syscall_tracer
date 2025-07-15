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
    pid_t tracee_pid;

    tracee_pid = fork();
    if (tracee_pid < 0) {
        perror("cannot create a tracee process.");
        exit(EXIT_FAILURE);
    } else if (tracee_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("PTRACE_TRACEME failed.");
            exit(EXIT_FAILURE);
        }
        execvp(argv[1], &argv[1]);
    }

    printf("\n--------------\n\n");

    int status;
    bool in_syscall = false;
    struct user_regs_struct regs;

    // Skip the first syscall (execve)
    waitpid(tracee_pid, &status, 0);
    ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);

    while (1) {
        waitpid(tracee_pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        if (ptrace(PTRACE_GETREGS, tracee_pid, NULL, &regs) == -1) {
            perror("PTRACE_GETREGS failed.");
            exit(EXIT_FAILURE);
        }

        if (in_syscall == false) {
            printf("syscall: %s [%lld] (", get_syscall_name(regs.orig_rax),
                   regs.orig_rax);
            printf("0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx", regs.rdi,
                   regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
            printf(")\n");
            in_syscall = true;
        } else {
            printf(" -> return = 0x%llx\n\n", regs.rax);
            in_syscall = false;
        }

        if (ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL) == -1) {
            perror("PTRACE_SYSCALL failed.");
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
