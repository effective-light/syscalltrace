#include <errno.h>
#include <stdio.h>

#include <sys/ptrace.h>

#include <sys/types.h>
#include <unistd.h>


int main(int argc, char **argv) {

    pid_t pid = fork();
    if (!pid) {
        // PTRACE_TRACEME
        execvp(argv[0], argv);
        perror("exec");
    } else if (pid > 0) {
        // ptrace
        return 0;
    } else {
        perror("fork");
    }

    return 1;
}
