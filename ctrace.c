#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <sys/ptrace.h>

#include "ctrace.h"

#define DEFAULT_FORMAT "%ld(?)"

#define handle_error(msg) { perror(msg); exit(EXIT_FAILURE); }


static long safe_ptrace(enum __ptrace_request request, pid_t pid,
        void *addr, void *data) {
    long ret;
    if ((ret = ptrace(request, pid, addr, data)) == -1) {
        handle_error("ptrace");
    }

    return ret;
}

static void *read_addr(pid_t pid, uint64_t addr, size_t size) {
    char *s = calloc(size + 1, sizeof(char));
    size_t i = 0;
    long ret;
    while (i < size) {
        ret = safe_ptrace(PTRACE_PEEKDATA, pid, (void *) (addr + i), NULL);
        memcpy((s + i), &ret, i + sizeof(long) > size ? size - i
                : sizeof(long));

        i += sizeof(long);
    }

    s[size] = '\0';

    return ((void *) s);
}

void parse_syscall(pid_t pid, syscall_t *syscall, uint64_t args[6]) {

    fprintf(stderr, "%s(", syscall->name);

    for (uint8_t i = 0; i < syscall->n_params; i++) {
        uint64_t val = args[i];
        switch (syscall->params[i])  {
            default:
                fprintf(stderr, "<unimpl>");
                break;
        }

        if ((i + 1) != syscall->n_params) {
            fprintf(stderr, ", ");
        }
    }

    fprintf(stderr, ")");
}

syscall_t *find_syscall(uint64_t nr) {
    for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscall_t); i++) {
        syscall_t *syscall = (syscalls + i);
        if (syscall->nr == nr) {
            return syscall;
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cmd> [args...]\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (!pid) {
        safe_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], (argv + 1));
        perror("exec");
    } else if (pid > 0) {
        fprintf(stderr, "pid: %d\n", pid);
        int status;
        struct __ptrace_syscall_info info;
        size_t size = sizeof(info);
        if (waitpid(pid, &status, 0) == -1) {
            handle_error("waitpid");
        }
        safe_ptrace(PTRACE_SETOPTIONS, pid, NULL,
                (void *) PTRACE_O_TRACESYSGOOD);
        safe_ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        do {
            if (waitpid(pid, &status, 0) == -1) {
                handle_error("waitpid");
            }
            if (WIFSTOPPED(status)) {
                safe_ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *) size, &info);
                syscall_t *syscall;
                switch (info.op) {
                    case PTRACE_SYSCALL_INFO_ENTRY:
                        if (!(syscall = find_syscall(info.entry.nr))) {
                            fprintf(stderr, DEFAULT_FORMAT, info.entry.nr);
                        } else {
                            parse_syscall(pid, syscall, info.entry.args);
                        }
                        break;
                    case PTRACE_SYSCALL_INFO_EXIT:
                        fprintf(stderr, " = %ld%s\n", info.exit.rval,
                                info.exit.is_error ? " [ERR]" : "");
                        break;
                    case PTRACE_SYSCALL_INFO_SECCOMP:
                        if (!(syscall = find_syscall(info.seccomp.nr))) {
                            fprintf(stderr, DEFAULT_FORMAT, info.seccomp.nr);
                        } else {
                            parse_syscall(pid, syscall, info.seccomp.args);
                        }
                        break;
                    default:
                        break;
                }

                safe_ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        fprintf(stderr, "\ntracer exit\n");
        return 0;
    } else {
        perror("fork");
    }

    return EXIT_FAILURE;
}
