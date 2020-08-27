#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


static long safe_ptrace(enum __ptrace_request request, pid_t pid,
        void *addr, void *data) {
    long ret;
    if ((ret = ptrace(request, pid, addr, data)) == -1) {
        perror("ptrace");
        exit(EXIT_FAILURE);
    }

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
        raise(SIGSTOP);
        execvp(argv[1], (argv + 1));
        perror("exec");
    } else if (pid > 0) {
        safe_ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        printf("pid: %d\n", pid);
        int status;
        do {
            if (waitpid(pid, &status, WCONTINUED) == -1) {
                perror("waitpid");
                return EXIT_FAILURE;
            }
            if (WIFSTOPPED(status)) {
                // TODO: read syscall
                if (kill(pid, SIGCONT) == -1) {
                    perror("kill");
                    return EXIT_FAILURE;
                }
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        printf("tracer exit\n");
        return 0;
    } else {
        perror("fork");
    }

    return EXIT_FAILURE;
}
