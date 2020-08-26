#include <errno.h>
#include <stdio.h>

#include <sys/ptrace.h>

#include <sys/types.h>
#include <unistd.h>


int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cmd> [args...]", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (!pid) {
        // PTRACE_TRACEME
        execvp(argv[1], (argv + 1));
        perror("exec");
    } else if (pid > 0) {
        // ptrace
        return 0;
    } else {
        perror("fork");
    }

    return 1;
}
