#include <errno.h>
#include <inttypes.h>
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
#define __print(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

static _Bool is_struct(param_t param) {
    switch (param) {
        case STRUCT___AIO_SIGSET_PTR:
        case STRUCT_CLONE_ARGS_PTR:
        case STRUCT_COMPAT_SIGACTION_PTR:
        case STRUCT_EPOLL_EVENT_PTR:
        case STRUCT_FILE_HANDLE_PTR:
        case STRUCT_GETCPU_CACHE_PTR:
        case STRUCT_GS_CB_PTR:
        case STRUCT_IOCB_PTR:
        case STRUCT_IOCB_PTR_PTR:
        case STRUCT_IO_EVENT_PTR:
        case STRUCT_IO_URING_PARAMS_PTR:
        case STRUCT_IOVEC_PTR:
        case STRUCT___KERNEL_ITIMERSPEC_PTR:
        case STRUCT___KERNEL_OLD_ITIMERVAL_PTR:
        case STRUCT___KERNEL_OLD_TIMEVAL_PTR:
        case STRUCT___KERNEL_TIMESPEC_PTR:
        case STRUCT___KERNEL_TIMEX_PTR:
        case STRUCT_KEXEC_SEGMENT_PTR:
        case STRUCT_LINUX_DIRENT64_PTR:
        case STRUCT_LINUX_DIRENT_PTR:
        case STRUCT_MMAP_ARG_STRUCT_PTR:
        case STRUCT_MMSGHDR_PTR:
        case STRUCT_MOUNT_ATTR_PTR:
        case STRUCT_MQ_ATTR_PTR:
        case STRUCT_MSGBUF_PTR:
        case STRUCT_MSQID_DS_PTR:
        case STRUCT_NEW_UTSNAME_PTR:
        case STRUCT_OLD_ITIMERSPEC32_PTR:
        case STRUCT___OLD_KERNEL_STAT_PTR:
        case STRUCT_OLD_LINUX_DIRENT_PTR:
        case STRUCT_OLDOLD_UTSNAME_PTR:
        case STRUCT_OLD_SIGACTION_PTR:
        case STRUCT_OLD_TIMESPEC32_PTR:
        case STRUCT_OLD_TIMEVAL32_PTR:
        case STRUCT_OLD_TIMEX32_PTR:
        case STRUCT_OLD_UTIMBUF32_PTR:
        case STRUCT_OLD_UTSNAME_PTR:
        case STRUCT_OPEN_HOW_PTR:
        case STRUCT_OSF_DIRENT_PTR:
        case STRUCT_OSF_SIGACTION_PTR:
        case STRUCT_OSF_STATFS64_PTR:
        case STRUCT_OSF_STATFS_PTR:
        case STRUCT_OSF_STAT_PTR:
        case STRUCT_PERF_EVENT_ATTR_PTR:
        case STRUCT_POLLFD_PTR:
        case STRUCT_RLIMIT64_PTR:
        case STRUCT_RLIMIT_PTR:
        case STRUCT_ROBUST_LIST_HEAD_PTR:
        case STRUCT_ROBUST_LIST_HEAD_PTR_PTR:
        case STRUCT_RSEQ_PTR:
        case STRUCT_RTAS_ARGS_PTR:
        case STRUCT_RUSAGE32_PTR:
        case STRUCT_RUSAGE_PTR:
        case STRUCT_SCHED_ATTR_PTR:
        case STRUCT_SCHED_PARAM_PTR:
        case STRUCT_SEL_ARG_STRUCT_PTR:
        case STRUCT_SEMBUF_PTR:
        case STRUCT_SHMID_DS_PTR:
        case STRUCT_SIGACTION_PTR:
        case STRUCT_SIG_DBG_OP_PTR:
        case STRUCT_SIGEVENT_PTR:
        case STRUCT_SIGINFO_PTR:
        case STRUCT_SIGSTACK_PTR:
        case STRUCT_SOCKADDR_PTR:
        case STRUCT_STAT64_PTR:
        case STRUCT_STATFS64_PTR:
        case STRUCT_STATFS_PTR:
        case STRUCT_STAT_PTR:
        case STRUCT_STATX_PTR:
        case STRUCT_SYSINFO_PTR:
        case STRUCT_TIMEVAL32_PTR:
        case STRUCT_TIMEX32_PTR:
        case STRUCT_TIMEZONE_PTR:
        case STRUCT_TMS_PTR:
        case STRUCT_UCONTEXT_PTR:
        case STRUCT_USER_DESC_PTR:
        case STRUCT_USER_MSGHDR_PTR:
        case STRUCT_USTAT_PTR:
        case STRUCT_UTIMBUF_PTR:
        case STRUCT_VM86_STRUCT_PTR:
            return 1;
        default:
            return 0;
    }
}

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

static char *read_str(pid_t pid, uint64_t addr) {
    size_t size = sizeof(long);
    char *buf = calloc(size, sizeof(char));
    long ret;

    for (size_t i = 0;; i++) {
        size_t len = i * sizeof(long);
        ret = safe_ptrace(PTRACE_PEEKDATA, pid, (void *) (addr + len), NULL);
        if (len >= size) {
            size *= 2;
            buf = realloc(buf, size * sizeof(char));
            if (!buf) {
                exit(EXIT_FAILURE);
            }
        }
        memcpy((buf + len), &ret, sizeof(long));
        for (uint8_t j = 0; j < sizeof(long); j++) {
            char c = *(((char *) &ret) + j);
            if (!c) {
                goto END;
            }
        }
    }

END:
    return buf;
}

static syscall_t *find_syscall(uint64_t nr) {
    for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscall_t); i++) {
        syscall_t *syscall = (syscalls + i);
        if (syscall->nr == nr) {
            return syscall;
        }
    }

    return NULL;
}

static void parse_syscall(pid_t pid, uint64_t nr, uint64_t args[6]) {
    syscall_t *syscall = find_syscall(nr);
    char *s;

    if (!syscall) {
        __print(DEFAULT_FORMAT, nr);
        return;
    }

    __print("%s(", syscall->name);

    for (uint8_t i = 0; i < syscall->n_params; i++) {
        uint64_t val = args[i];
        param_t param = syscall->params[i];
        if (is_struct(param)) {
            __print("{");
        }
        switch (param)  {
            case INT:
                __print("%d", (int) val);
                break;
            case __S32:
                __print("%" PRId32, (int32_t) val);
                break;
            case LONG:
                __print("%ld", (long) val);
                break;
            case UINT:
            case UNSIGNED_INT:
                __print("%u", (unsigned int) val);
                break;
            case UNSIGNED_LONG:
                __print("%lu", (unsigned long) val);
                break;
            case __U32:
            case U32:
                __print("%" PRIu32, (uint32_t) val);
                break;
            case __U64:
            case U64:
                __print("%" PRIu64, val);
                break;
            case CHAR_PTR:
                s = read_str(pid, val);
                __print("\"");
                for (char *i = s; *i; i++) {
                    char c = *i;
                    _Bool escape = 1;
                    switch (c) {
                        case '\a':
                            c = 'a';
                            break;
                        case '\b':
                            c = 'b';
                            break;
                        case '\f':
                            c = 'f';
                            break;
                        case '\n':
                            c = 'n';
                            break;
                        case '\r':
                            c = 'r';
                            break;
                        case '\t':
                            c = 't';
                            break;
                        case '\v':
                            c = 'v';
                            break;
                        case 0x1A:
                            __print("\\0x1a");
                            goto INNER_LOOP_END;
                        case 0x1B:
                            __print("\\0x1b");
                            goto INNER_LOOP_END;
                        default:
                            escape = 0;
                            break;
                    }
                    if (escape) {
                        __print("\\");
                    }
                    __print("%c", c);
INNER_LOOP_END:
                    continue;
                }
                __print("\"");
                free(s);
                break;
            case VOID_PTR:
            case VOID_PTR_PTR:
                if (!val) {
                    __print("NULL");
                } else {
                    __print("%#" PRIxPTR, (uintptr_t) val);
                }
                break;
            default:
                __print("<unimpl>");
                break;
        }

        if (is_struct(param)) {
            __print("}");
        }

        if ((i + 1) != syscall->n_params) {
            __print(", ");
        }
    }

    __print(")");
}


int main(int argc, char **argv) {
    if (argc < 2) {
        __print("Usage: %s <cmd> [args...]\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();
    if (!pid) {
        safe_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], (argv + 1));
        perror("exec");
    } else if (pid > 0) {
        __print("pid: %d\n", pid);
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
                        parse_syscall(pid, info.entry.nr, info.entry.args);
                        break;
                    case PTRACE_SYSCALL_INFO_EXIT:
                        __print(" = %ld%s\n", info.exit.rval,
                                info.exit.is_error ? " [ERR]" : "");
                        break;
                    case PTRACE_SYSCALL_INFO_SECCOMP:
                        parse_syscall(pid, info.seccomp.nr, info.seccomp.args);
                        break;
                    default:
                        break;
                }

                safe_ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        __print("\ntracer exit\n");
        return 0;
    } else {
        perror("fork");
    }

    return EXIT_FAILURE;
}
