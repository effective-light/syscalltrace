#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/syscall.h>

#define DEFAULT_FORMAT "syscall(%d, ...)"

#define handle_error(msg) { perror(msg); exit(EXIT_FAILURE); }


static long safe_ptrace(enum __ptrace_request request, pid_t pid,
        void *addr, void *data) {
    long ret;
    if ((ret = ptrace(request, pid, addr, data)) == -1) {
        handle_error("ptrace");
    }

    return ret;
}

static char *read_string(uint64_t addr, pid_t pid, size_t size) {
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

    return s;
}

static int parse_syscall(uint64_t nr, uint64_t args[6], pid_t pid) {

    int ret = 1;
    char *s = NULL;

    switch (nr) {
        case SYS_read:
            s = read_string(args[1], pid, args[2]);
            printf("read(%ld, \"%s\", %ld)", args[0], s, args[2]);
            break;
        case SYS_write:
            s = read_string(args[1], pid, args[2]);
            printf("write(%ld, \"%s\", %ld)", args[0], s, args[2]);
            break;
        default:
            ret = 0;
    }

    free(s);

    return ret;
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
        printf("pid: %d\n", pid);
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
                switch (info.op) {
                    case PTRACE_SYSCALL_INFO_ENTRY:
                        if (!parse_syscall(info.entry.nr, info.entry.args,
                                    pid)) {
                            printf(DEFAULT_FORMAT, info.entry.nr);
                        }
                        break;
                    case PTRACE_SYSCALL_INFO_EXIT:
                        printf(" = %ld%s\n", info.exit.rval,
                                info.exit.is_error ? " [ERR]" : "");
                        break;
                    case PTRACE_SYSCALL_INFO_SECCOMP:
                        printf(DEFAULT_FORMAT, info.seccomp.nr);
                        break;
                    default:
                        break;
                }

                safe_ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        printf("\ntracer exit\n");
        return 0;
    } else {
        perror("fork");
    }

    return EXIT_FAILURE;
}
