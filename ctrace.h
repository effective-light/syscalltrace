#ifndef _CTRACE_H_
#define _CTRACE_H_

#include <stdint.h>
#include <unistd.h>

#include <sys/syscall.h>

#define STRUCT_N_PARAMS_MAX 16

#if INTPTR_MAX == INT32_MAX
#define __32BIT__
#elif INTPTR_MAX != INT64_MAX
#error Unknown pointer size or missing size macros!
#endif


typedef enum param_types {
    AIO_CONTEXT_T,
    AIO_CONTEXT_T_PTR,
    CAP_USER_DATA_T,
    CAP_USER_HEADER_T,
    CHAR_PTR,
    CHAR_PTR_PTR,
    CLOCKID_T,
    ENUM_PL_CODE,
    FD_SET_PTR,
    GID_T,
    GID_T_PTR,
    INT,
    INT_PTR,
    __KERNEL_OLD_TIME_T_PTR,
    KEY_SERIAL_T,
    KEY_T,
    LOFF_T,
    LOFF_T_PTR,
    LONG,
    LONG_PTR,
    MQD_T,
    OFF_T,
    OFF_T_PTR,
    OLD_GID_T,
    OLD_GID_T_PTR,
    OLD_SIGSET_T,
    OLD_SIGSET_T_PTR,
    OLD_TIME32_T_PTR,
    OLD_UID_T,
    OLD_UID_T_PTR,
    PID_T,
    QID_T,
    RWF_T,
    __S32,
    __SIGHANDLER_T,
    SIGINFO_T_PTR,
    SIGSET_T_PTR,
    SIZE_T,
    SIZE_T_PTR,
    STACK_T_PTR,
    STRUCT___AIO_SIGSET_PTR,
    STRUCT_CLONE_ARGS_PTR,
    STRUCT_COMPAT_SIGACTION_PTR,
    STRUCT_EPOLL_EVENT_PTR,
    STRUCT_FILE_HANDLE_PTR,
    STRUCT_GETCPU_CACHE_PTR,
    STRUCT_GS_CB_PTR,
    STRUCT_IOCB_PTR,
    STRUCT_IOCB_PTR_PTR,
    STRUCT_IO_EVENT_PTR,
    STRUCT_IO_URING_PARAMS_PTR,
    STRUCT_IOVEC_PTR,
    STRUCT___KERNEL_ITIMERSPEC_PTR,
    STRUCT___KERNEL_OLD_ITIMERVAL_PTR,
    STRUCT___KERNEL_OLD_TIMEVAL_PTR,
    STRUCT___KERNEL_TIMESPEC_PTR,
    STRUCT___KERNEL_TIMEX_PTR,
    STRUCT_KEXEC_SEGMENT_PTR,
    STRUCT_LINUX_DIRENT64_PTR,
    STRUCT_LINUX_DIRENT_PTR,
    STRUCT_MMAP_ARG_STRUCT_PTR,
    STRUCT_MMSGHDR_PTR,
    STRUCT_MOUNT_ATTR_PTR,
    STRUCT_MQ_ATTR_PTR,
    STRUCT_MSGBUF_PTR,
    STRUCT_MSQID_DS_PTR,
    STRUCT_NEW_UTSNAME_PTR,
    STRUCT_OLD_ITIMERSPEC32_PTR,
    STRUCT___OLD_KERNEL_STAT_PTR,
    STRUCT_OLD_LINUX_DIRENT_PTR,
    STRUCT_OLDOLD_UTSNAME_PTR,
    STRUCT_OLD_SIGACTION_PTR,
    STRUCT_OLD_TIMESPEC32_PTR,
    STRUCT_OLD_TIMEVAL32_PTR,
    STRUCT_OLD_TIMEX32_PTR,
    STRUCT_OLD_UTIMBUF32_PTR,
    STRUCT_OLD_UTSNAME_PTR,
    STRUCT_OPEN_HOW_PTR,
    STRUCT_OSF_DIRENT_PTR,
    STRUCT_OSF_SIGACTION_PTR,
    STRUCT_OSF_STATFS64_PTR,
    STRUCT_OSF_STATFS_PTR,
    STRUCT_OSF_STAT_PTR,
    STRUCT_PERF_EVENT_ATTR_PTR,
    STRUCT_POLLFD_PTR,
    STRUCT_RLIMIT64_PTR,
    STRUCT_RLIMIT_PTR,
    STRUCT_ROBUST_LIST_HEAD_PTR,
    STRUCT_ROBUST_LIST_HEAD_PTR_PTR,
    STRUCT_RSEQ_PTR,
    STRUCT_RTAS_ARGS_PTR,
    STRUCT_RUSAGE32_PTR,
    STRUCT_RUSAGE_PTR,
    STRUCT_SCHED_ATTR_PTR,
    STRUCT_SCHED_PARAM_PTR,
    STRUCT_SEL_ARG_STRUCT_PTR,
    STRUCT_SEMBUF_PTR,
    STRUCT_SHMID_DS_PTR,
    STRUCT_SIGACTION_PTR,
    STRUCT_SIG_DBG_OP_PTR,
    STRUCT_SIGEVENT_PTR,
    STRUCT_SIGINFO_PTR,
    STRUCT_SIGSTACK_PTR,
    STRUCT_SOCKADDR_PTR,
    STRUCT_STAT64_PTR,
    STRUCT_STATFS64_PTR,
    STRUCT_STATFS_PTR,
    STRUCT_STAT_PTR,
    STRUCT_STATX_PTR,
    STRUCT_SYSINFO_PTR,
    STRUCT_TIMEVAL32_PTR,
    STRUCT_TIMEX32_PTR,
    STRUCT_TIMEZONE_PTR,
    STRUCT_TMS_PTR,
    STRUCT_UCONTEXT_PTR,
    STRUCT_USER_DESC_PTR,
    STRUCT_USER_MSGHDR_PTR,
    STRUCT_USTAT_PTR,
    STRUCT_UTIMBUF_PTR,
    STRUCT_VM86_STRUCT_PTR,
    TIMER_T,
    TIMER_T_PTR,
    __U32,
    U32,
    __U32_PTR,
    U32_PTR,
    __U64,
    U64,
    U64_PTR,
    UID_T,
    UID_T_PTR,
    UINT,
    UINTPTR_T,
    UMODE_T,
    UNION_BPF_ATTR_PTR,
    UNION_PL_ARGS_PTR,
    UNSIGNED,
    UNSIGNED_CHAR_PTR,
    UNSIGNED_INT,
    UNSIGNED_INT_PTR,
    UNSIGNED_LONG,
    UNSIGNED_LONG_PTR,
    UNSIGNED_PTR,
    UTRAP_ENTRY_T,
    UTRAP_HANDLER_T,
    UTRAP_HANDLER_T_PTR,
    VOID_PTR,
    VOID_PTR_PTR
} param_t;

typedef struct syscall_s {
    char *name;
    uint8_t n_params;
    param_t params[6];
} syscall_t;

typedef struct named_param_s {
    param_t type;
    char *name;
} named_param_t;

typedef struct struct_s {
    char *name;
    uint8_t n_params;
    named_param_t params[STRUCT_N_PARAMS_MAX];
} struct_t;

syscall_t syscalls[] = {
#ifdef SYS_accept
    [SYS_accept] = {
        .name = "accept",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_accept4
    [SYS_accept4] = {
        .name = "accept4",
        .n_params = 4,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR, INT}
    },
#endif
#ifdef SYS_access
    [SYS_access] = {
        .name = "access",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_acct
    [SYS_acct] = {
        .name = "acct",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_add_key
    [SYS_add_key] = {
        .name = "add_key",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T, KEY_SERIAL_T}
    },
#endif
#ifdef SYS_adjtimex
    [SYS_adjtimex] = {
        .name = "adjtimex",
        .n_params = 1,
#ifdef __32BIT__
        .params = {STRUCT_OLD_TIMEX32_PTR}
#else
        .params = {STRUCT___KERNEL_TIMEX_PTR}
#endif
    },
#endif
#ifdef SYS_old_adjtimex
    [SYS_old_adjtimex] = {
        .name = "old_adjtimex",
        .n_params = 1,
        .params = {STRUCT_TIMEX32_PTR}
    },
#endif
#ifdef SYS_alarm
    [SYS_alarm] = {
        .name = "alarm",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_arc_gettls
    [SYS_arc_gettls] = {
        .name = "arc_gettls",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_arch_prctl
    [SYS_arch_prctl] = {
        .name = "arch_prctl",
        .n_params = 2,
        .params = {INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_arc_settls
    [SYS_arc_settls] = {
        .name = "arc_settls",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_arc_usr_cmpxchg
    [SYS_arc_usr_cmpxchg] = {
        .name = "arc_usr_cmpxchg",
        .n_params = 3,
        .params = {INT_PTR, INT, INT}
    },
#endif
#ifdef SYS_bdflush
    [SYS_bdflush] = {
        .name = "bdflush",
        .n_params = 2,
        .params = {INT, LONG}
    },
#endif
#ifdef SYS_bind
    [SYS_bind] = {
        .name = "bind",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT}
    },
#endif
#ifdef SYS_bpf
    [SYS_bpf] = {
        .name = "bpf",
        .n_params = 3,
        .params = {INT, UNION_BPF_ATTR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_brk
    [SYS_brk] = {
        .name = "brk",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_cachectl
    [SYS_cachectl] = {
        .name = "cachectl",
        .n_params = 3,
        .params = {CHAR_PTR, INT, INT}
    },
#endif
#ifdef SYS_cacheflush
    [SYS_cacheflush] = {
        .name = "cacheflush",
        .n_params = 3,
        .params = {VOID_PTR, UNSIGNED_LONG, INT}
    },
#endif
#ifdef SYS_capget
    [SYS_capget] = {
        .name = "capget",
        .n_params = 2,
        .params = {CAP_USER_HEADER_T, CAP_USER_DATA_T}
    },
#endif
#ifdef SYS_capset
    [SYS_capset] = {
        .name = "capset",
        .n_params = 2,
        .params = {CAP_USER_HEADER_T, CAP_USER_DATA_T}
    },
#endif
#ifdef SYS_chdir
    [SYS_chdir] = {
        .name = "chdir",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_chmod
    [SYS_chmod] = {
        .name = "chmod",
        .n_params = 2,
        .params = {CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_chown
    [SYS_chown] = {
        .name = "chown",
        .n_params = 3,
        .params = {CHAR_PTR, OLD_UID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_chown32
    [SYS_chown32] = {
        .name = "chown32",
        .n_params = 3,
        .params = {CHAR_PTR, UID_T, GID_T}
    },
#endif
#ifdef SYS_chroot
    [SYS_chroot] = {
        .name = "chroot",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_clock_adjtime
    [SYS_clock_adjtime] = {
        .name = "clock_adjtime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMEX32_PTR}
    },
#endif
#ifdef SYS_clock_adjtime64
    [SYS_clock_adjtime64] = {
        .name = "clock_adjtime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMEX_PTR}
    },
#endif
#ifdef SYS_clock_getres
    [SYS_clock_getres] = {
        .name = "clock_getres",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_getres_time64
    [SYS_clock_getres_time64] = {
        .name = "clock_getres",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clock_gettime
    [SYS_clock_gettime] = {
        .name = "clock_gettime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_gettime64
    [SYS_clock_gettime64] = {
        .name = "clock_gettime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clock_nanosleep
    [SYS_clock_nanosleep] = {
        .name = "clock_nanosleep",
        .n_params = 4,
        .params = {CLOCKID_T, INT, STRUCT_OLD_TIMESPEC32_PTR,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_nanosleep_time64
    [SYS_clock_nanosleep_time64] = {
        .name = "clock_nanosleep",
        .n_params = 4,
        .params = {CLOCKID_T, INT, STRUCT___KERNEL_TIMESPEC_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clock_settime
    [SYS_clock_settime] = {
        .name = "clock_settime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_settime64
    [SYS_clock_settime64] = {
        .name = "clock_settime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clone
    [SYS_clone] = {
        .name = "clone",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, INT_PTR, UNSIGNED_LONG,
            INT_PTR}
    },
#endif
#ifdef SYS_clone3
    [SYS_clone3] = {
        .name = "clone3",
        .n_params = 2,
        .params = {STRUCT_CLONE_ARGS_PTR, SIZE_T}
    },
#endif
#ifdef SYS_close
    [SYS_close] = {
        .name = "close",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_close_range
    [SYS_close_range] = {
        .name = "close_range",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_connect
    [SYS_connect] = {
        .name = "connect",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT}
    },
#endif
#ifdef SYS_copy_file_range
    [SYS_copy_file_range] = {
        .name = "copy_file_range",
        .n_params = 6,
        .params = {INT, LOFF_T_PTR, INT, LOFF_T_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_creat
    [SYS_creat] = {
        .name = "creat",
        .n_params = 2,
        .params = {CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_sys_debug_setcontext
    [SYS_sys_debug_setcontext] = {
        .name = "sys_debug_setcontext",
        .n_params = 3,
        .params = {STRUCT_UCONTEXT_PTR, INT, STRUCT_SIG_DBG_OP_PTR}
    },
#endif
#ifdef SYS_delete_module
    [SYS_delete_module] = {
        .name = "delete_module",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_dup
    [SYS_dup] = {
        .name = "dup",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_dup2
    [SYS_dup2] = {
        .name = "dup2",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_dup3
    [SYS_dup3] = {
        .name = "dup3",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_epoll_create
    [SYS_epoll_create] = {
        .name = "epoll_create",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_epoll_create1
    [SYS_epoll_create1] = {
        .name = "epoll_create1",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_epoll_ctl
    [SYS_epoll_ctl] = {
        .name = "epoll_ctl",
        .n_params = 4,
        .params = {INT, INT, INT, STRUCT_EPOLL_EVENT_PTR}
    },
#endif
#ifdef SYS_epoll_pwait
    [SYS_epoll_pwait] = {
        .name = "epoll_pwait",
        .n_params = 6,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT, INT, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_epoll_pwait2
    [SYS_epoll_pwait2] = {
        .name = "epoll_pwait2",
        .n_params = 6,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT,
            STRUCT___KERNEL_TIMESPEC_PTR, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_epoll_wait
    [SYS_epoll_wait] = {
        .name = "epoll_wait",
        .n_params = 4,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT, INT}
    },
#endif
#ifdef SYS_eventfd
    [SYS_eventfd] = {
        .name = "eventfd",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_eventfd2
    [SYS_eventfd2] = {
        .name = "eventfd2",
        .n_params = 2,
        .params = {UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_execve
    [SYS_execve] = {
        .name = "execve",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR_PTR, CHAR_PTR_PTR}
    },
#endif
#ifdef SYS_execveat
    [SYS_execveat] = {
        .name = "execveat",
        .n_params = 5,
        .params = {INT, CHAR_PTR, CHAR_PTR_PTR, CHAR_PTR_PTR, INT}
    },
#endif
#ifdef SYS_exit
    [SYS_exit] = {
        .name = "exit",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_exit_group
    [SYS_exit_group] = {
        .name = "exit_group",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_faccessat
    [SYS_faccessat] = {
        .name = "faccessat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_faccessat2
    [SYS_faccessat2] = {
        .name = "faccessat2",
        .n_params = 4,
        .params = {INT, CHAR_PTR, INT, INT}
    },
#endif
#ifdef SYS_fadvise64
    [SYS_fadvise64] = {
        .name = "fadvise64",
#ifdef __i386__
        .n_params = 5,
        .params = {INT, UNSIGNED_INT, UNSIGNED_INT, SIZE_T, INT}
#else
        .n_params = 4,
        .params = {INT, LOFF_T, SIZE_T, INT}
#endif
    },
#endif
#ifdef SYS_fadvise64_64
    [SYS_fadvise64_64] = {
        .name = "fadvise64_64",
#if defined(__nds32__) || defined(__csky__)
        .n_params = 4,
        .params = {INT, INT, LOFF_T, LOFF_T}
#elif defined(__i386__)
        .n_params = 6,
        .params = {INT, __U32, __U32, __U32, __U32, INT}
#else
        .n_params = 4,
        .params = {INT, LOFF_T, LOFF_T, INT}
#endif
    },
#endif
#ifdef SYS_fallocate
    [SYS_fallocate] = {
        .name = "fallocate",
#ifdef __i386__
        .n_params = 6,
        .params = {INT, INT, UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_INT,
            UNSIGNED_INT}
#else
        .n_params = 4,
        .params = {INT, INT, LOFF_T, LOFF_T}
#endif
    },
#endif
#ifdef SYS_fanotify_init
    [SYS_fanotify_init] = {
        .name = "fanotify_init",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fanotify_mark
    [SYS_fanotify_mark] = {
        .name = "fanotify_mark",
        .n_params = 5,
        .params = {INT, UNSIGNED_INT, __U64, INT, CHAR_PTR}
    },
#endif
#ifdef SYS_fchdir
    [SYS_fchdir] = {
        .name = "fchdir",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_fchmod
    [SYS_fchmod] = {
        .name = "fchmod",
        .n_params = 2,
        .params = {UNSIGNED_INT, UMODE_T}
    },
#endif
#ifdef SYS_fchmodat
    [SYS_fchmodat] = {
        .name = "fchmodat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_fchown
    [SYS_fchown] = {
        .name = "fchown",
        .n_params = 3,
        .params = {UNSIGNED_INT, OLD_UID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_fchown32
    [SYS_fchown32] = {
        .name = "fchown32",
        .n_params = 3,
        .params = {UNSIGNED_INT, UID_T, GID_T}
    },
#endif
#ifdef SYS_fchownat
    [SYS_fchownat] = {
        .name = "fchownat",
        .n_params = 5,
        .params = {INT, CHAR_PTR, UID_T, GID_T, INT}
    },
#endif
#ifdef SYS_fcntl
    [SYS_fcntl] = {
        .name = "fcntl",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_fcntl64
    [SYS_fcntl64] = {
        .name = "fcntl64",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_fdatasync
    [SYS_fdatasync] = {
        .name = "fdatasync",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_fgetxattr
    [SYS_fgetxattr] = {
        .name = "fgetxattr",
        .n_params = 4,
        .params = {INT, CHAR_PTR, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_finit_module
    [SYS_finit_module] = {
        .name = "finit_module",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_flistxattr
    [SYS_flistxattr] = {
        .name = "flistxattr",
        .n_params = 3,
        .params = {INT, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_flock
    [SYS_flock] = {
        .name = "flock",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fork
    [SYS_fork] = {
        .name = "fork",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_fp_udfiex_crtl
    [SYS_fp_udfiex_crtl] = {
        .name = "fp_udfiex_crtl",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fremovexattr
    [SYS_fremovexattr] = {
        .name = "fremovexattr",
        .n_params = 2,
        .params = {INT, CHAR_PTR}
    },
#endif
#ifdef SYS_fsconfig
    [SYS_fsconfig] = {
        .name = "fsconfig",
        .n_params = 5,
        .params = {INT, UNSIGNED_INT, CHAR_PTR, VOID_PTR, INT}
    },
#endif
#ifdef SYS_fsetxattr
    [SYS_fsetxattr] = {
        .name = "fsetxattr",
        .n_params = 5,
        .params = {INT, CHAR_PTR, VOID_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_fsmount
    [SYS_fsmount] = {
        .name = "fsmount",
        .n_params = 3,
        .params = {INT, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fsopen
    [SYS_fsopen] = {
        .name = "fsopen",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fspick
    [SYS_fspick] = {
        .name = "fspick",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_oldfstat
    [SYS_oldfstat] = {
        .name = "oldfstat",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT___OLD_KERNEL_STAT_PTR}
    },
#endif
#ifdef SYS_fstat64
    [SYS_fstat64] = {
        .name = "fstat64",
        .n_params = 2,
        .params = {UNSIGNED_LONG, STRUCT_STAT64_PTR}
    },
#endif
#ifdef SYS_fstatat64
    [SYS_fstatat64] = {
        .name = "fstatat64",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT_STAT64_PTR, INT}
    },
#endif
#ifdef SYS_fstatfs
    [SYS_fstatfs] = {
        .name = "fstatfs",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_STATFS_PTR}
    },
#endif
#ifdef SYS_fstatfs64
    [SYS_fstatfs64] = {
        .name = "fstatfs64",
        .n_params = 3,
        .params = {UNSIGNED_INT, SIZE_T, STRUCT_STATFS64_PTR}
    },
#endif
#ifdef SYS_fsync
    [SYS_fsync] = {
        .name = "fsync",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_ftruncate
    [SYS_ftruncate] = {
        .name = "ftruncate",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_ftruncate64
    [SYS_ftruncate64] = {
        .name = "ftruncate64",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 4,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG}
#elif defined(__i386__)
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_LONG, UNSIGNED_LONG}
#else
        .n_params = 2,
        .params = {UNSIGNED_INT, LOFF_T}
#endif
    },
#endif
#ifdef SYS_futex
    [SYS_futex] = {
        .name = "futex",
        .n_params = 6,
        .params = {U32_PTR, INT, U32, STRUCT_OLD_TIMESPEC32_PTR, U32_PTR, U32}
    },
#endif
#ifdef SYS_futex_time64
    [SYS_futex_time64] = {
        .name = "futex",
        .n_params = 6,
        .params = {U32_PTR, INT, U32, STRUCT___KERNEL_TIMESPEC_PTR, U32_PTR,
            U32}
    },
#endif
#ifdef SYS_futimesat
    [SYS_futimesat] = {
        .name = "futimesat",
        .n_params = 3,
#ifdef __32BIT__
        .params = {UNSIGNED_INT, CHAR_PTR, STRUCT_OLD_TIMEVAL32_PTR}
#else
        .params = {INT, CHAR_PTR, STRUCT___KERNEL_OLD_TIMEVAL_PTR}
#endif
    },
#endif
#ifdef SYS_getcpu
    [SYS_getcpu] = {
        .name = "getcpu",
        .n_params = 3,
        .params = {UNSIGNED_PTR, UNSIGNED_PTR, STRUCT_GETCPU_CACHE_PTR}
    },
#endif
#ifdef SYS_getcwd
    [SYS_getcwd] = {
        .name = "getcwd",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_getdents
    [SYS_getdents] = {
        .name = "getdents",
        .n_params = 3,
        .params = {UNSIGNED_INT, STRUCT_LINUX_DIRENT_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_getdents64
    [SYS_getdents64] = {
        .name = "getdents64",
        .n_params = 3,
        .params = {UNSIGNED_INT, STRUCT_LINUX_DIRENT64_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_getdomainname
    [SYS_getdomainname] = {
        .name = "getdomainname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_getdtablesize
    [SYS_getdtablesize] = {
        .name = "getdtablesize",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getegid
    [SYS_getegid] = {
        .name = "getegid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getegid32
    [SYS_getegid32] = {
        .name = "getegid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_geteuid
    [SYS_geteuid] = {
        .name = "geteuid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_geteuid32
    [SYS_geteuid32] = {
        .name = "geteuid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getgid
    [SYS_getgid] = {
        .name = "getgid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getgid32
    [SYS_getgid32] = {
        .name = "getgid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getgroups
    [SYS_getgroups] = {
        .name = "getgroups",
        .n_params = 2,
        .params = {INT, OLD_GID_T_PTR}
    },
#endif
#ifdef SYS_getgroups32
    [SYS_getgroups32] = {
        .name = "getgroups32",
        .n_params = 2,
        .params = {INT, GID_T_PTR}
    },
#endif
#ifdef SYS_gethostname
    [SYS_gethostname] = {
        .name = "gethostname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_getitimer
    [SYS_getitimer] = {
        .name = "getitimer",
        .n_params = 2,
        .params = {INT, STRUCT___KERNEL_OLD_ITIMERVAL_PTR}
    },
#endif
#ifdef SYS_get_mempolicy
    [SYS_get_mempolicy] = {
        .name = "get_mempolicy",
        .n_params = 5,
        .params = {INT_PTR, UNSIGNED_LONG_PTR, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_old_getpagesize
    [SYS_old_getpagesize] = {
        .name = "old_getpagesize",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpagesize
    [SYS_getpagesize] = {
        .name = "getpagesize",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpeername
    [SYS_getpeername] = {
        .name = "getpeername",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_getpgid
    [SYS_getpgid] = {
        .name = "getpgid",
        .n_params = 1,
        .params = {PID_T}
    },
#endif
#ifdef SYS_getpgrp
    [SYS_getpgrp] = {
        .name = "getpgrp",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpid
    [SYS_getpid] = {
        .name = "getpid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getppid
    [SYS_getppid] = {
        .name = "getppid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpriority
    [SYS_getpriority] = {
        .name = "getpriority",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_getrandom
    [SYS_getrandom] = {
        .name = "getrandom",
        .n_params = 3,
        .params = {CHAR_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_getresgid
    [SYS_getresgid] = {
        .name = "getresgid",
        .n_params = 3,
        .params = {OLD_GID_T_PTR, OLD_GID_T_PTR, OLD_GID_T_PTR}
    },
#endif
#ifdef SYS_getresgid32
    [SYS_getresgid32] = {
        .name = "getresgid32",
        .n_params = 3,
        .params = {GID_T_PTR, GID_T_PTR, GID_T_PTR}
    },
#endif
#ifdef SYS_getresuid
    [SYS_getresuid] = {
        .name = "getresuid",
        .n_params = 3,
        .params = {OLD_UID_T_PTR, OLD_UID_T_PTR, OLD_UID_T_PTR}
    },
#endif
#ifdef SYS_getresuid32
    [SYS_getresuid32] = {
        .name = "getresuid32",
        .n_params = 3,
        .params = {UID_T_PTR, UID_T_PTR, UID_T_PTR}
    },
#endif
#ifdef SYS_getrlimit
    [SYS_getrlimit] = {
#ifdef __bfin__
        .name = "old_getrlimit",
#else
        .name = "getrlimit",
#endif
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_RLIMIT_PTR}
    },
#endif
#ifdef SYS_get_robust_list
    [SYS_get_robust_list] = {
        .name = "get_robust_list",
        .n_params = 3,
        .params = {INT, STRUCT_ROBUST_LIST_HEAD_PTR_PTR, SIZE_T_PTR}
    },
#endif
#ifdef SYS_getrusage
    [SYS_getrusage] = {
        .name = "getrusage",
        .n_params = 2,
        .params = {INT, STRUCT_RUSAGE_PTR}
    },
#endif
#ifdef SYS_getsid
    [SYS_getsid] = {
        .name = "getsid",
        .n_params = 1,
        .params = {PID_T}
    },
#endif
#ifdef SYS_getsockname
    [SYS_getsockname] = {
        .name = "getsockname",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_getsockopt
    [SYS_getsockopt] = {
        .name = "getsockopt",
        .n_params = 5,
        .params = {INT, INT, INT, CHAR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_get_thread_area
    [SYS_get_thread_area] = {
        .name = "get_thread_area",
        .n_params = 1,
        .params = {STRUCT_USER_DESC_PTR}
    },
#endif
#ifdef SYS_gettid
    [SYS_gettid] = {
        .name = "gettid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_gettimeofday
    [SYS_gettimeofday] = {
        .name = "gettimeofday",
        .n_params = 2,
        .params = {STRUCT___KERNEL_OLD_TIMEVAL_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_getuid
    [SYS_getuid] = {
        .name = "getuid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getuid32
    [SYS_getuid32] = {
        .name = "getuid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getxattr
    [SYS_getxattr] = {
        .name = "getxattr",
        .n_params = 4,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_getxgid
    [SYS_getxgid] = {
        .name = "getxgid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getxpid
    [SYS_getxpid] = {
        .name = "getxpid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getxuid
    [SYS_getxuid] = {
        .name = "getxuid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_init_module
    [SYS_init_module] = {
        .name = "init_module",
        .n_params = 3,
        .params = {VOID_PTR, UNSIGNED_LONG, CHAR_PTR}
    },
#endif
#ifdef SYS_inotify_add_watch
    [SYS_inotify_add_watch] = {
        .name = "inotify_add_watch",
        .n_params = 3,
        .params = {INT, CHAR_PTR, U32}
    },
#endif
#ifdef SYS_inotify_init
    [SYS_inotify_init] = {
        .name = "inotify_init",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_inotify_init1
    [SYS_inotify_init1] = {
        .name = "inotify_init1",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_inotify_rm_watch
    [SYS_inotify_rm_watch] = {
        .name = "inotify_rm_watch",
        .n_params = 2,
        .params = {INT, __S32}
    },
#endif
#ifdef SYS_io_cancel
    [SYS_io_cancel] = {
        .name = "io_cancel",
        .n_params = 3,
        .params = {AIO_CONTEXT_T, STRUCT_IOCB_PTR, STRUCT_IO_EVENT_PTR}
    },
#endif
#ifdef SYS_ioctl
    [SYS_ioctl] = {
        .name = "ioctl",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_io_destroy
    [SYS_io_destroy] = {
        .name = "io_destroy",
        .n_params = 1,
        .params = {AIO_CONTEXT_T}
    },
#endif
#ifdef SYS_io_getevents
    [SYS_io_getevents] = {
        .name = "io_getevents",
        .n_params = 5,
#ifdef __32BIT__
        .params = {__U32, __S32, __S32, STRUCT_IO_EVENT_PTR,
            STRUCT_OLD_TIMESPEC32_PTR}
#else
        .params = {AIO_CONTEXT_T, LONG, LONG, STRUCT_IO_EVENT_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR}
#endif
    },
#endif
#ifdef SYS_ioperm
    [SYS_ioperm] = {
        .name = "ioperm",
        .n_params = 3,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, INT}
    },
#endif
#ifdef SYS_io_pgetevents
    [SYS_io_pgetevents] = {
        .name = "io_pgetevents",
        .n_params = 6,
        .params = {AIO_CONTEXT_T, LONG, LONG, STRUCT_IO_EVENT_PTR,
            STRUCT_OLD_TIMESPEC32_PTR, STRUCT___AIO_SIGSET_PTR}
    },
#endif
#ifdef SYS_io_pgetevents_time64
    [SYS_io_pgetevents_time64] = {
        .name = "io_pgetevents",
        .n_params = 6,
        .params = {AIO_CONTEXT_T, LONG, LONG, STRUCT_IO_EVENT_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR, STRUCT___AIO_SIGSET_PTR}
    },
#endif
#ifdef SYS_iopl
    [SYS_iopl] = {
        .name = "iopl",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_ioprio_get
    [SYS_ioprio_get] = {
        .name = "ioprio_get",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_ioprio_set
    [SYS_ioprio_set] = {
        .name = "ioprio_set",
        .n_params = 3,
        .params = {INT, INT, INT}
    },
#endif
#ifdef SYS_io_setup
    [SYS_io_setup] = {
        .name = "io_setup",
        .n_params = 2,
        .params = {UNSIGNED, AIO_CONTEXT_T_PTR}
    },
#endif
#ifdef SYS_io_submit
    [SYS_io_submit] = {
        .name = "io_submit",
        .n_params = 3,
        .params = {AIO_CONTEXT_T, LONG, STRUCT_IOCB_PTR_PTR}
    },
#endif
#ifdef SYS_io_uring_enter
    [SYS_io_uring_enter] = {
        .name = "io_uring_enter",
        .n_params = 6,
        .params = {UNSIGNED_INT, U32, U32, U32, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_io_uring_register
    [SYS_io_uring_register] = {
        .name = "io_uring_register",
        .n_params = 4,
        .params = {UNSIGNED_INT, UNSIGNED_INT, VOID_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_io_uring_setup
    [SYS_io_uring_setup] = {
        .name = "io_uring_setup",
        .n_params = 2,
        .params = {U32, STRUCT_IO_URING_PARAMS_PTR}
    },
#endif
#ifdef SYS_ipc
    [SYS_ipc] = {
        .name = "ipc",
#ifdef __s390__
        .n_params = 5,
        .params = {UINT, INT, UNSIGNED_LONG, UNSIGNED_LONG, VOID_PTR}
#else
        .n_params = 6,
        .params = {UNSIGNED_INT, INT, UNSIGNED_LONG, UNSIGNED_LONG, VOID_PTR,
            LONG}
#endif
    },
#endif
#ifdef SYS_kcmp
    [SYS_kcmp] = {
        .name = "kcmp",
        .n_params = 5,
        .params = {PID_T, PID_T, INT, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_kern_features
    [SYS_kern_features] = {
        .name = "kern_features",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_kexec_file_load
    [SYS_kexec_file_load] = {
        .name = "kexec_file_load",
        .n_params = 5,
        .params = {INT, INT, UNSIGNED_LONG, CHAR_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_kexec_load
    [SYS_kexec_load] = {
        .name = "kexec_load",
        .n_params = 4,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, STRUCT_KEXEC_SEGMENT_PTR,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_keyctl
    [SYS_keyctl] = {
        .name = "keyctl",
        .n_params = 5,
        .params = {INT, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_kill
    [SYS_kill] = {
        .name = "kill",
        .n_params = 2,
        .params = {PID_T, INT}
    },
#endif
#ifdef SYS_lchown
    [SYS_lchown] = {
        .name = "lchown",
        .n_params = 3,
        .params = {CHAR_PTR, OLD_UID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_lchown32
    [SYS_lchown32] = {
        .name = "lchown32",
        .n_params = 3,
        .params = {CHAR_PTR, UID_T, GID_T}
    },
#endif
#ifdef SYS_lgetxattr
    [SYS_lgetxattr] = {
        .name = "lgetxattr",
        .n_params = 4,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_link
    [SYS_link] = {
        .name = "link",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_linkat
    [SYS_linkat] = {
        .name = "linkat",
        .n_params = 5,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_listen
    [SYS_listen] = {
        .name = "listen",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_listxattr
    [SYS_listxattr] = {
        .name = "listxattr",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_llistxattr
    [SYS_llistxattr] = {
        .name = "llistxattr",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_llseek
    [SYS_llseek] = {
        .name = "llseek",
        .n_params = 5,
#if defined(__mips__) && defined(__32BIT__)
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_INT, LOFF_T_PTR,
            UNSIGNED_INT}
#else
        .params = {UNSIGNED_INT, UNSIGNED_LONG, UNSIGNED_LONG, LOFF_T_PTR,
            UNSIGNED_INT}
#endif
    },
#endif
#ifdef SYS__llseek
    [SYS__llseek] = {
        .name = "_llseek",
        .n_params = 5,
        .params = {UNSIGNED_INT, UNSIGNED_LONG, UNSIGNED_LONG, LOFF_T_PTR,
            UNSIGNED_INT}
    },
#endif
#ifdef SYS_lremovexattr
    [SYS_lremovexattr] = {
        .name = "lremovexattr",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_lseek
    [SYS_lseek] = {
        .name = "lseek",
        .n_params = 3,
        .params = {UNSIGNED_INT, OFF_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_lsetxattr
    [SYS_lsetxattr] = {
        .name = "lsetxattr",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_oldlstat
    [SYS_oldlstat] = {
        .name = "oldlstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT___OLD_KERNEL_STAT_PTR}
    },
#endif
#ifdef SYS_lstat64
    [SYS_lstat64] = {
        .name = "lstat64",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT64_PTR}
    },
#endif
#ifdef SYS_madvise
    [SYS_madvise] = {
        .name = "madvise",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, INT}
    },
#endif
#ifdef SYS_mbind
    [SYS_mbind] = {
        .name = "mbind",
        .n_params = 6,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG_PTR, UNSIGNED_LONG, UNSIGNED_INT}
    },
#endif
#ifdef SYS_membarrier
    [SYS_membarrier] = {
        .name = "membarrier",
        .n_params = 3,
        .params = {INT, UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_memfd_create
    [SYS_memfd_create] = {
        .name = "memfd_create",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_memory_ordering
    [SYS_memory_ordering] = {
        .name = "memory_ordering",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_migrate_pages
    [SYS_migrate_pages] = {
        .name = "migrate_pages",
        .n_params = 4,
        .params = {PID_T, UNSIGNED_LONG, UNSIGNED_LONG_PTR, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_mincore
    [SYS_mincore] = {
        .name = "mincore",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, UNSIGNED_CHAR_PTR}
    },
#endif
#ifdef SYS_mkdir
    [SYS_mkdir] = {
        .name = "mkdir",
        .n_params = 2,
        .params = {CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_mkdirat
    [SYS_mkdirat] = {
        .name = "mkdirat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_mknod
    [SYS_mknod] = {
        .name = "mknod",
        .n_params = 3,
        .params = {CHAR_PTR, UMODE_T, UNSIGNED}
    },
#endif
#ifdef SYS_mknodat
    [SYS_mknodat] = {
        .name = "mknodat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, UMODE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_mlock
    [SYS_mlock] = {
        .name = "mlock",
        .n_params = 2,
        .params = {UNSIGNED_LONG, SIZE_T}
    },
#endif
#ifdef SYS_mlock2
    [SYS_mlock2] = {
        .name = "mlock2",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, INT}
    },
#endif
#ifdef SYS_mlockall
    [SYS_mlockall] = {
        .name = "mlockall",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_mmap
    [SYS_mmap] = {
        .name = "mmap",
#if defined(__s390__) || defined(__s390x__) || defined(__m68k__) \
        || defined(__i386__) || defined(__arm__)
        .n_params = 1,
        .params = {STRUCT_MMAP_ARG_STRUCT_PTR}
#elif defined(__mips__)
        .n_params = 6,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG, OFF_T}
#else
        .n_params = 6,
        .params = {VOID_PTR, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
#endif
    },
#endif
#ifdef SYS_mmap2
    [SYS_mmap2] = {
        .name = "mmap2",
        .n_params = 6,
#if defined(__mips__) || defined(__xtensa__) || defined(__AVR__) \
        || defined(__microblaze__) || defined(__m68k__) || defined(__i386__) \
        || defined(__bfin__) || defined(__ia64__)
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
#else
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG, OFF_T}
#endif
    },
#endif
#ifdef SYS_modify_ldt
    [SYS_modify_ldt] = {
        .name = "modify_ldt",
        .n_params = 3,
        .params = {INT, VOID_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_mount
    [SYS_mount] = {
        .name = "mount",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, CHAR_PTR, UNSIGNED_LONG, VOID_PTR}
    },
#endif
#ifdef SYS_mount_setattr
    [SYS_mount_setattr] = {
        .name = "mount_setattr",
        .n_params = 5,
        .params = {INT, CHAR_PTR, UNSIGNED_INT, STRUCT_MOUNT_ATTR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_move_mount
    [SYS_move_mount] = {
        .name = "move_mount",
        .n_params = 5,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_move_pages
    [SYS_move_pages] = {
        .name = "move_pages",
        .n_params = 6,
        .params = {PID_T, UNSIGNED_LONG, VOID_PTR_PTR, INT_PTR, INT_PTR, INT}
    },
#endif
#ifdef SYS_mprotect
    [SYS_mprotect] = {
        .name = "mprotect",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_mq_getsetattr
    [SYS_mq_getsetattr] = {
        .name = "mq_getsetattr",
        .n_params = 3,
        .params = {MQD_T, STRUCT_MQ_ATTR_PTR, STRUCT_MQ_ATTR_PTR}
    },
#endif
#ifdef SYS_mq_notify
    [SYS_mq_notify] = {
        .name = "mq_notify",
        .n_params = 2,
        .params = {MQD_T, STRUCT_SIGEVENT_PTR}
    },
#endif
#ifdef SYS_mq_open
    [SYS_mq_open] = {
        .name = "mq_open",
        .n_params = 4,
        .params = {CHAR_PTR, INT, UMODE_T, STRUCT_MQ_ATTR_PTR}
    },
#endif
#ifdef SYS_mq_timedreceive
    [SYS_mq_timedreceive] = {
        .name = "mq_timedreceive",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, UNSIGNED_INT, UNSIGNED_INT_PTR,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_mq_timedreceive_time64
    [SYS_mq_timedreceive_time64] = {
        .name = "mq_timedreceive",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, SIZE_T, UNSIGNED_INT_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_mq_timedsend
    [SYS_mq_timedsend] = {
        .name = "mq_timedsend",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, UNSIGNED_INT, UNSIGNED_INT,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_mq_timedsend_time64
    [SYS_mq_timedsend_time64] = {
        .name = "mq_timedsend",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, SIZE_T, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_mq_unlink
    [SYS_mq_unlink] = {
        .name = "mq_unlink",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_mremap
    [SYS_mremap] = {
        .name = "mremap",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_msgctl
    [SYS_msgctl] = {
        .name = "msgctl",
        .n_params = 3,
        .params = {INT, INT, STRUCT_MSQID_DS_PTR}
    },
#endif
#ifdef SYS_msgget
    [SYS_msgget] = {
        .name = "msgget",
        .n_params = 2,
        .params = {KEY_T, INT}
    },
#endif
#ifdef SYS_msgrcv
    [SYS_msgrcv] = {
        .name = "msgrcv",
        .n_params = 5,
        .params = {INT, STRUCT_MSGBUF_PTR, SIZE_T, LONG, INT}
    },
#endif
#ifdef SYS_msgsnd
    [SYS_msgsnd] = {
        .name = "msgsnd",
        .n_params = 4,
        .params = {INT, STRUCT_MSGBUF_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_msync
    [SYS_msync] = {
        .name = "msync",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, INT}
    },
#endif
#ifdef SYS_munlock
    [SYS_munlock] = {
        .name = "munlock",
        .n_params = 2,
        .params = {UNSIGNED_LONG, SIZE_T}
    },
#endif
#ifdef SYS_munlockall
    [SYS_munlockall] = {
        .name = "munlockall",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_munmap
    [SYS_munmap] = {
        .name = "munmap",
        .n_params = 2,
        .params = {UNSIGNED_LONG, SIZE_T}
    },
#endif
#ifdef SYS_name_to_handle_at
    [SYS_name_to_handle_at] = {
        .name = "name_to_handle_at",
        .n_params = 5,
        .params = {INT, CHAR_PTR, STRUCT_FILE_HANDLE_PTR, INT_PTR, INT}
    },
#endif
#ifdef SYS_nanosleep
    [SYS_nanosleep] = {
        .name = "nanosleep",
        .n_params = 2,
#ifdef __32BIT__
        .params = {STRUCT_OLD_TIMESPEC32_PTR, STRUCT_OLD_TIMESPEC32_PTR}
#else
        .params = {STRUCT___KERNEL_TIMESPEC_PTR, STRUCT___KERNEL_TIMESPEC_PTR}
#endif
    },
#endif
#ifdef SYS_fstat
    [SYS_fstat] = {
        .name = "fstat",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_STAT_PTR}
    },
#endif
#ifdef SYS_newfstatat
    [SYS_newfstatat] = {
        .name = "newfstatat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT_STAT_PTR, INT}
    },
#endif
#ifdef SYS_lstat
    [SYS_lstat] = {
        .name = "lstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT_PTR}
    },
#endif
#ifdef SYS_stat
    [SYS_stat] = {
        .name = "stat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT_PTR}
    },
#endif
#ifdef SYS_uname
    [SYS_uname] = {
        .name = "uname",
        .n_params = 1,
        .params = {STRUCT_NEW_UTSNAME_PTR}
    },
#endif
#ifdef SYS_nice
    [SYS_nice] = {
        .name = "nice",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_ni_syscall
    [SYS_ni_syscall] = {
        .name = "ni_syscall",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_readdir
    [SYS_readdir] = {
        .name = "readdir",
        .n_params = 3,
        .params = {UNSIGNED_INT, STRUCT_OLD_LINUX_DIRENT_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS__newselect
    [SYS__newselect] = {
        .name = "_newselect",
        .n_params = 1,
        .params = {STRUCT_SEL_ARG_STRUCT_PTR}
    },
#endif
#ifdef SYS_oldumount
    [SYS_oldumount] = {
        .name = "oldumount",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_oldolduname
    [SYS_oldolduname] = {
        .name = "oldolduname",
        .n_params = 1,
        .params = {STRUCT_OLDOLD_UTSNAME_PTR}
    },
#endif
#ifdef SYS_open
    [SYS_open] = {
        .name = "open",
        .n_params = 3,
        .params = {CHAR_PTR, INT, UMODE_T}
    },
#endif
#ifdef SYS_openat
    [SYS_openat] = {
        .name = "openat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, INT, UMODE_T}
    },
#endif
#ifdef SYS_openat2
    [SYS_openat2] = {
        .name = "openat2",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT_OPEN_HOW_PTR, SIZE_T}
    },
#endif
#ifdef SYS_open_by_handle_at
    [SYS_open_by_handle_at] = {
        .name = "open_by_handle_at",
        .n_params = 3,
        .params = {INT, STRUCT_FILE_HANDLE_PTR, INT}
    },
#endif
#ifdef SYS_open_tree
    [SYS_open_tree] = {
        .name = "open_tree",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UNSIGNED}
    },
#endif
#ifdef SYS_osf_fstat
    [SYS_osf_fstat] = {
        .name = "osf_fstat",
        .n_params = 2,
        .params = {INT, STRUCT_OSF_STAT_PTR}
    },
#endif
#ifdef SYS_osf_fstatfs
    [SYS_osf_fstatfs] = {
        .name = "osf_fstatfs",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_OSF_STATFS_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_fstatfs64
    [SYS_osf_fstatfs64] = {
        .name = "osf_fstatfs64",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_OSF_STATFS64_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_getdirentries
    [SYS_osf_getdirentries] = {
        .name = "osf_getdirentries",
        .n_params = 4,
        .params = {UNSIGNED_INT, STRUCT_OSF_DIRENT_PTR, UNSIGNED_INT, LONG_PTR}
    },
#endif
#ifdef SYS_osf_getdomainname
    [SYS_osf_getdomainname] = {
        .name = "osf_getdomainname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_osf_getrusage
    [SYS_osf_getrusage] = {
        .name = "osf_getrusage",
        .n_params = 2,
        .params = {INT, STRUCT_RUSAGE32_PTR}
    },
#endif
#ifdef SYS_osf_getsysinfo
    [SYS_osf_getsysinfo] = {
        .name = "osf_getsysinfo",
        .n_params = 5,
        .params = {UNSIGNED_LONG, VOID_PTR, UNSIGNED_LONG, INT_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_gettimeofday
    [SYS_osf_gettimeofday] = {
        .name = "osf_gettimeofday",
        .n_params = 2,
        .params = {STRUCT_TIMEVAL32_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_osf_lstat
    [SYS_osf_lstat] = {
        .name = "osf_lstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_OSF_STAT_PTR}
    },
#endif
#ifdef SYS_osf_mount
    [SYS_osf_mount] = {
        .name = "osf_mount",
        .n_params = 4,
        .params = {UNSIGNED_LONG, CHAR_PTR, INT, VOID_PTR}
    },
#endif
#ifdef SYS_osf_proplist_syscall
    [SYS_osf_proplist_syscall] = {
        .name = "osf_proplist_syscall",
        .n_params = 2,
        .params = {ENUM_PL_CODE, UNION_PL_ARGS_PTR}
    },
#endif
#ifdef SYS_osf_select
    [SYS_osf_select] = {
        .name = "osf_select",
        .n_params = 5,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT_TIMEVAL32_PTR}
    },
#endif
#ifdef SYS_osf_set_program_attributes
    [SYS_osf_set_program_attributes] = {
        .name = "osf_set_program_attributes",
        .n_params = 4,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_setsysinfo
    [SYS_osf_setsysinfo] = {
        .name = "osf_setsysinfo",
        .n_params = 5,
        .params = {UNSIGNED_LONG, VOID_PTR, UNSIGNED_LONG, INT_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_settimeofday
    [SYS_osf_settimeofday] = {
        .name = "osf_settimeofday",
        .n_params = 2,
        .params = {STRUCT_TIMEVAL32_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_osf_sigprocmask
    [SYS_osf_sigprocmask] = {
        .name = "osf_sigprocmask",
        .n_params = 2,
        .params = {INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_sigstack
    [SYS_osf_sigstack] = {
        .name = "osf_sigstack",
        .n_params = 2,
        .params = {STRUCT_SIGSTACK_PTR, STRUCT_SIGSTACK_PTR}
    },
#endif
#ifdef SYS_osf_stat
    [SYS_osf_stat] = {
        .name = "osf_stat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_OSF_STAT_PTR}
    },
#endif
#ifdef SYS_osf_statfs
    [SYS_osf_statfs] = {
        .name = "osf_statfs",
        .n_params = 3,
        .params = {CHAR_PTR, STRUCT_OSF_STATFS_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_statfs64
    [SYS_osf_statfs64] = {
        .name = "osf_statfs64",
        .n_params = 3,
        .params = {CHAR_PTR, STRUCT_OSF_STATFS64_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_sysinfo
    [SYS_osf_sysinfo] = {
        .name = "osf_sysinfo",
        .n_params = 3,
        .params = {INT, CHAR_PTR, LONG}
    },
#endif
#ifdef SYS_osf_usleep_thread
    [SYS_osf_usleep_thread] = {
        .name = "osf_usleep_thread",
        .n_params = 2,
        .params = {STRUCT_TIMEVAL32_PTR, STRUCT_TIMEVAL32_PTR}
    },
#endif
#ifdef SYS_osf_utimes
    [SYS_osf_utimes] = {
        .name = "osf_utimes",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_TIMEVAL32_PTR}
    },
#endif
#ifdef SYS_osf_utsname
    [SYS_osf_utsname] = {
        .name = "osf_utsname",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_osf_wait4
    [SYS_osf_wait4] = {
        .name = "osf_wait4",
        .n_params = 4,
        .params = {PID_T, INT_PTR, INT, STRUCT_RUSAGE32_PTR}
    },
#endif
#ifdef SYS_pause
    [SYS_pause] = {
        .name = "pause",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_pciconfig_iobase
    [SYS_pciconfig_iobase] = {
        .name = "pciconfig_iobase",
        .n_params = 3,
        .params = {LONG, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pciconfig_read
    [SYS_pciconfig_read] = {
        .name = "pciconfig_read",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            VOID_PTR}
    },
#endif
#ifdef SYS_pciconfig_write
    [SYS_pciconfig_write] = {
        .name = "pciconfig_write",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            VOID_PTR}
    },
#endif
#ifdef SYS_perf_event_open
    [SYS_perf_event_open] = {
        .name = "perf_event_open",
        .n_params = 5,
        .params = {STRUCT_PERF_EVENT_ATTR_PTR, PID_T, INT, INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_personality
    [SYS_personality] = {
        .name = "personality",
        .n_params = 1,
#if (defined(__mips__) && defined(__32BIT__)) || defined(__sparc64__)
        .params = {UNSIGNED_LONG}
#else
        .params = {UNSIGNED_INT}
#endif
    },
#endif
#ifdef SYS_pidfd_getfd
    [SYS_pidfd_getfd] = {
        .name = "pidfd_getfd",
        .n_params = 3,
        .params = {INT, INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_pidfd_open
    [SYS_pidfd_open] = {
        .name = "pidfd_open",
        .n_params = 2,
        .params = {PID_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_pidfd_send_signal
    [SYS_pidfd_send_signal] = {
        .name = "pidfd_send_signal",
        .n_params = 4,
        .params = {INT, INT, SIGINFO_T_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_pipe
    [SYS_pipe] = {
        .name = "pipe",
#if defined(__alpha__) || defined(__sparc__)
        .n_params = 0,
        .params = {}
#else
        .n_params = 1,
        .params = {INT_PTR}
#endif
    },
#endif
#ifdef SYS_pipe2
    [SYS_pipe2] = {
        .name = "pipe2",
        .n_params = 2,
        .params = {INT_PTR, INT}
    },
#endif
#ifdef SYS_pivot_root
    [SYS_pivot_root] = {
        .name = "pivot_root",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_pkey_alloc
    [SYS_pkey_alloc] = {
        .name = "pkey_alloc",
        .n_params = 2,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pkey_free
    [SYS_pkey_free] = {
        .name = "pkey_free",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_pkey_mprotect
    [SYS_pkey_mprotect] = {
        .name = "pkey_mprotect",
        .n_params = 4,
        .params = {UNSIGNED_LONG, SIZE_T, UNSIGNED_LONG, INT}
    },
#endif
#ifdef SYS_poll
    [SYS_poll] = {
        .name = "poll",
        .n_params = 3,
        .params = {STRUCT_POLLFD_PTR, UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_ppoll
    [SYS_ppoll] = {
        .name = "ppoll",
        .n_params = 5,
        .params = {STRUCT_POLLFD_PTR, UNSIGNED_INT, STRUCT_OLD_TIMESPEC32_PTR,
            SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_ppoll_time64
    [SYS_ppoll_time64] = {
        .name = "ppoll",
        .n_params = 5,
        .params = {STRUCT_POLLFD_PTR, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_prctl
    [SYS_prctl] = {
        .name = "prctl",
        .n_params = 5,
        .params = {INT, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pread64
    [SYS_pread64] = {
        .name = "pread64",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 6,
        .params = {UNSIGNED_LONG, CHAR_PTR, SIZE_T, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
#elif defined(__i386__)
        .n_params = 5,
        .params = {UNSIGNED_INT, CHAR_PTR, U32, U32, U32}
#else
        .n_params = 4,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T, LOFF_T}
#endif
    },
#endif
#ifdef SYS_preadv
    [SYS_preadv] = {
        .name = "preadv",
        .n_params = 5,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_preadv2
    [SYS_preadv2] = {
        .name = "preadv2",
        .n_params = 6,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG, RWF_T}
    },
#endif
#ifdef SYS_prlimit64
    [SYS_prlimit64] = {
        .name = "prlimit64",
        .n_params = 4,
        .params = {PID_T, UNSIGNED_INT, STRUCT_RLIMIT64_PTR,
            STRUCT_RLIMIT64_PTR}
    },
#endif
#ifdef SYS_process_madvise
    [SYS_process_madvise] = {
        .name = "process_madvise",
        .n_params = 5,
        .params = {INT, STRUCT_IOVEC_PTR, SIZE_T, INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_process_vm_readv
    [SYS_process_vm_readv] = {
        .name = "process_vm_readv",
        .n_params = 6,
        .params = {PID_T, STRUCT_IOVEC_PTR, UNSIGNED_LONG, STRUCT_IOVEC_PTR,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_process_vm_writev
    [SYS_process_vm_writev] = {
        .name = "process_vm_writev",
        .n_params = 6,
        .params = {PID_T, STRUCT_IOVEC_PTR, UNSIGNED_LONG, STRUCT_IOVEC_PTR,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pselect6
    [SYS_pselect6] = {
        .name = "pselect6",
        .n_params = 6,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT_OLD_TIMESPEC32_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_pselect6_time64
    [SYS_pselect6_time64] = {
        .name = "pselect6",
        .n_params = 6,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_ptrace
    [SYS_ptrace] = {
        .name = "ptrace",
        .n_params = 4,
        .params = {LONG, LONG, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pwrite64
    [SYS_pwrite64] = {
        .name = "pwrite64",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 6,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T, U32, U64, U64}
#elif defined(__i386__)
        .n_params = 5,
        .params = {UNSIGNED_INT, CHAR_PTR, U32, U32, U32}
#else
        .n_params = 4,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T, LOFF_T}
#endif
    },
#endif
#ifdef SYS_pwritev
    [SYS_pwritev] = {
        .name = "pwritev",
        .n_params = 5,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pwritev2
    [SYS_pwritev2] = {
        .name = "pwritev2",
        .n_params = 6,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG, RWF_T}
    },
#endif
#ifdef SYS_quotactl
    [SYS_quotactl] = {
        .name = "quotactl",
        .n_params = 4,
        .params = {UNSIGNED_INT, CHAR_PTR, QID_T, VOID_PTR}
    },
#endif
#ifdef SYS_read
    [SYS_read] = {
        .name = "read",
        .n_params = 3,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_readahead
    [SYS_readahead] = {
        .name = "readahead",
#ifdef __i386__
        .n_params = 4,
        .params = {INT, UNSIGNED_INT, UNSIGNED_INT, SIZE_T}
#else
        .n_params = 3,
        .params = {INT, LOFF_T, SIZE_T}
#endif
    },
#endif
#ifdef SYS_readlink
    [SYS_readlink] = {
        .name = "readlink",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_readlinkat
    [SYS_readlinkat] = {
        .name = "readlinkat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_readv
    [SYS_readv] = {
        .name = "readv",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_reboot
    [SYS_reboot] = {
        .name = "reboot",
        .n_params = 4,
        .params = {INT, INT, UNSIGNED_INT, VOID_PTR}
    },
#endif
#ifdef SYS_recv
    [SYS_recv] = {
        .name = "recv",
        .n_params = 4,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_recvfrom
    [SYS_recvfrom] = {
        .name = "recvfrom",
        .n_params = 6,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT, STRUCT_SOCKADDR_PTR,
            INT_PTR}
    },
#endif
#ifdef SYS_recvmmsg
    [SYS_recvmmsg] = {
        .name = "recvmmsg",
        .n_params = 5,
        .params = {INT, STRUCT_MMSGHDR_PTR, UNSIGNED_INT, UNSIGNED_INT,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_recvmmsg_time64
    [SYS_recvmmsg_time64] = {
        .name = "recvmmsg",
        .n_params = 5,
        .params = {INT, STRUCT_MMSGHDR_PTR, UNSIGNED_INT, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_recvmsg
    [SYS_recvmsg] = {
        .name = "recvmsg",
        .n_params = 3,
        .params = {INT, STRUCT_USER_MSGHDR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_remap_file_pages
    [SYS_remap_file_pages] = {
        .name = "remap_file_pages",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_removexattr
    [SYS_removexattr] = {
        .name = "removexattr",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_rename
    [SYS_rename] = {
        .name = "rename",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_renameat
    [SYS_renameat] = {
        .name = "renameat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR}
    },
#endif
#ifdef SYS_renameat2
    [SYS_renameat2] = {
        .name = "renameat2",
        .n_params = 5,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_request_key
    [SYS_request_key] = {
        .name = "request_key",
        .n_params = 4,
        .params = {CHAR_PTR, CHAR_PTR, CHAR_PTR, KEY_SERIAL_T}
    },
#endif
#ifdef SYS_restart_syscall
    [SYS_restart_syscall] = {
        .name = "restart_syscall",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_riscv_flush_icache
    [SYS_riscv_flush_icache] = {
        .name = "riscv_flush_icache",
        .n_params = 3,
        .params = {UINTPTR_T, UINTPTR_T, UINTPTR_T}
    },
#endif
#ifdef SYS_rmdir
    [SYS_rmdir] = {
        .name = "rmdir",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_rseq
    [SYS_rseq] = {
        .name = "rseq",
        .n_params = 4,
        .params = {STRUCT_RSEQ_PTR, U32, INT, U32}
    },
#endif
#ifdef SYS_rtas
    [SYS_rtas] = {
        .name = "rtas",
        .n_params = 1,
        .params = {STRUCT_RTAS_ARGS_PTR}
    },
#endif
#ifdef SYS_rt_sigaction
    [SYS_rt_sigaction] = {
        .name = "rt_sigaction",
        .n_params = 4,
        .params = {INT, STRUCT_SIGACTION_PTR, STRUCT_SIGACTION_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigpending
    [SYS_rt_sigpending] = {
        .name = "rt_sigpending",
        .n_params = 2,
        .params = {SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigprocmask
    [SYS_rt_sigprocmask] = {
        .name = "rt_sigprocmask",
        .n_params = 4,
        .params = {INT, SIGSET_T_PTR, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigqueueinfo
    [SYS_rt_sigqueueinfo] = {
        .name = "rt_sigqueueinfo",
        .n_params = 3,
        .params = {PID_T, INT, SIGINFO_T_PTR}
    },
#endif
#ifdef SYS_rt_sigreturn
    [SYS_rt_sigreturn] = {
        .name = "rt_sigreturn",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_rt_sigsuspend
    [SYS_rt_sigsuspend] = {
        .name = "rt_sigsuspend",
        .n_params = 2,
        .params = {SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigtimedwait
    [SYS_rt_sigtimedwait] = {
        .name = "rt_sigtimedwait",
        .n_params = 4,
        .params = {SIGSET_T_PTR, SIGINFO_T_PTR, STRUCT_OLD_TIMESPEC32_PTR,
            SIZE_T}
    },
#endif
#ifdef SYS_rt_sigtimedwait_time64
    [SYS_rt_sigtimedwait_time64] = {
        .name = "rt_sigtimedwait",
        .n_params = 4,
        .params = {SIGSET_T_PTR, SIGINFO_T_PTR, STRUCT___KERNEL_TIMESPEC_PTR,
            SIZE_T}
    },
#endif
#ifdef SYS_rt_tgsigqueueinfo
    [SYS_rt_tgsigqueueinfo] = {
        .name = "rt_tgsigqueueinfo",
        .n_params = 4,
        .params = {PID_T, PID_T, INT, SIGINFO_T_PTR}
    },
#endif
#ifdef SYS_s390_guarded_storage
    [SYS_s390_guarded_storage] = {
        .name = "s390_guarded_storage",
        .n_params = 2,
        .params = {INT, STRUCT_GS_CB_PTR}
    },
#endif
#ifdef SYS_s390_pci_mmio_read
    [SYS_s390_pci_mmio_read] = {
        .name = "s390_pci_mmio_read",
        .n_params = 3,
        .params = {UNSIGNED_LONG, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_s390_pci_mmio_write
    [SYS_s390_pci_mmio_write] = {
        .name = "s390_pci_mmio_write",
        .n_params = 3,
        .params = {UNSIGNED_LONG, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_s390_runtime_instr
    [SYS_s390_runtime_instr] = {
        .name = "s390_runtime_instr",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_s390_sthyi
    [SYS_s390_sthyi] = {
        .name = "s390_sthyi",
        .n_params = 4,
        .params = {UNSIGNED_LONG, VOID_PTR, U64_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_sched_getaffinity
    [SYS_sched_getaffinity] = {
        .name = "sched_getaffinity",
        .n_params = 3,
        .params = {PID_T, UNSIGNED_INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_sched_getattr
    [SYS_sched_getattr] = {
        .name = "sched_getattr",
        .n_params = 4,
        .params = {PID_T, STRUCT_SCHED_ATTR_PTR, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sched_getparam
    [SYS_sched_getparam] = {
        .name = "sched_getparam",
        .n_params = 2,
        .params = {PID_T, STRUCT_SCHED_PARAM_PTR}
    },
#endif
#ifdef SYS_sched_get_priority_max
    [SYS_sched_get_priority_max] = {
        .name = "sched_get_priority_max",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sched_get_priority_min
    [SYS_sched_get_priority_min] = {
        .name = "sched_get_priority_min",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sched_getscheduler
    [SYS_sched_getscheduler] = {
        .name = "sched_getscheduler",
        .n_params = 1,
        .params = {PID_T}
    },
#endif
#ifdef SYS_sched_rr_get_interval
    [SYS_sched_rr_get_interval] = {
        .name = "sched_rr_get_interval",
        .n_params = 2,
        .params = {PID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_sched_rr_get_interval_time64
    [SYS_sched_rr_get_interval_time64] = {
        .name = "sched_rr_get_interval",
        .n_params = 2,
        .params = {PID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_sched_setaffinity
    [SYS_sched_setaffinity] = {
        .name = "sched_setaffinity",
        .n_params = 3,
        .params = {PID_T, UNSIGNED_INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_sched_setattr
    [SYS_sched_setattr] = {
        .name = "sched_setattr",
        .n_params = 3,
        .params = {PID_T, STRUCT_SCHED_ATTR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sched_setparam
    [SYS_sched_setparam] = {
        .name = "sched_setparam",
        .n_params = 2,
        .params = {PID_T, STRUCT_SCHED_PARAM_PTR}
    },
#endif
#ifdef SYS_sched_setscheduler
    [SYS_sched_setscheduler] = {
        .name = "sched_setscheduler",
        .n_params = 3,
        .params = {PID_T, INT, STRUCT_SCHED_PARAM_PTR}
    },
#endif
#ifdef SYS_sched_yield
    [SYS_sched_yield] = {
        .name = "sched_yield",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_seccomp
    [SYS_seccomp] = {
        .name = "seccomp",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, VOID_PTR}
    },
#endif
#ifdef SYS_select
    [SYS_select] = {
        .name = "select",
        .n_params = 5,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT___KERNEL_OLD_TIMEVAL_PTR}
    },
#endif
#ifdef SYS_semctl
    [SYS_semctl] = {
        .name = "semctl",
        .n_params = 4,
        .params = {INT, INT, INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_semget
    [SYS_semget] = {
        .name = "semget",
        .n_params = 3,
        .params = {KEY_T, INT, INT}
    },
#endif
#ifdef SYS_semop
    [SYS_semop] = {
        .name = "semop",
        .n_params = 3,
        .params = {INT, STRUCT_SEMBUF_PTR, UNSIGNED}
    },
#endif
#ifdef SYS_semtimedop
    [SYS_semtimedop] = {
        .name = "semtimedop",
        .n_params = 4,
        .params = {INT, STRUCT_SEMBUF_PTR, UNSIGNED_INT,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_semtimedop_time64
    [SYS_semtimedop_time64] = {
        .name = "semtimedop",
        .n_params = 4,
        .params = {INT, STRUCT_SEMBUF_PTR, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_send
    [SYS_send] = {
        .name = "send",
        .n_params = 4,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sendfile
    [SYS_sendfile] = {
        .name = "sendfile",
        .n_params = 4,
        .params = {INT, INT, OFF_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_sendfile64
    [SYS_sendfile64] = {
        .name = "sendfile64",
        .n_params = 4,
        .params = {INT, INT, LOFF_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_sendmmsg
    [SYS_sendmmsg] = {
        .name = "sendmmsg",
        .n_params = 4,
        .params = {INT, STRUCT_MMSGHDR_PTR, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sendmsg
    [SYS_sendmsg] = {
        .name = "sendmsg",
        .n_params = 3,
        .params = {INT, STRUCT_USER_MSGHDR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sendto
    [SYS_sendto] = {
        .name = "sendto",
        .n_params = 6,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT, STRUCT_SOCKADDR_PTR,
            INT}
    },
#endif
#ifdef SYS_setdomainname
    [SYS_setdomainname] = {
        .name = "setdomainname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_setfsgid
    [SYS_setfsgid] = {
        .name = "setfsgid",
        .n_params = 1,
        .params = {OLD_GID_T}
    },
#endif
#ifdef SYS_setfsgid32
    [SYS_setfsgid32] = {
        .name = "setfsgid32",
        .n_params = 1,
        .params = {GID_T}
    },
#endif
#ifdef SYS_setfsuid
    [SYS_setfsuid] = {
        .name = "setfsuid",
        .n_params = 1,
        .params = {OLD_UID_T}
    },
#endif
#ifdef SYS_setfsuid32
    [SYS_setfsuid32] = {
        .name = "setfsuid32",
        .n_params = 1,
        .params = {UID_T}
    },
#endif
#ifdef SYS_setgid
    [SYS_setgid] = {
        .name = "setgid",
        .n_params = 1,
        .params = {OLD_GID_T}
    },
#endif
#ifdef SYS_setgid32
    [SYS_setgid32] = {
        .name = "setgid32",
        .n_params = 1,
        .params = {GID_T}
    },
#endif
#ifdef SYS_setgroups
    [SYS_setgroups] = {
        .name = "setgroups32",
        .n_params = 2,
        .params = {INT, OLD_GID_T_PTR}
    },
#endif
#ifdef SYS_setgroups32
    [SYS_setgroups32] = {
        .name = "setgroups32",
        .n_params = 2,
        .params = {INT, GID_T_PTR}
    },
#endif
#ifdef SYS_sethae
    [SYS_sethae] = {
        .name = "sethae",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_sethostname
    [SYS_sethostname] = {
        .name = "sethostname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_setitimer
    [SYS_setitimer] = {
        .name = "setitimer",
        .n_params = 3,
        .params = {INT, STRUCT___KERNEL_OLD_ITIMERVAL_PTR,
            STRUCT___KERNEL_OLD_ITIMERVAL_PTR}
    },
#endif
#ifdef SYS_set_mempolicy
    [SYS_set_mempolicy] = {
        .name = "set_mempolicy",
        .n_params = 3,
        .params = {INT, UNSIGNED_LONG_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_setns
    [SYS_setns] = {
        .name = "setns",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_setpgid
    [SYS_setpgid] = {
        .name = "setpgid",
        .n_params = 2,
        .params = {PID_T, PID_T}
    },
#endif
#ifdef SYS_setpriority
    [SYS_setpriority] = {
        .name = "setpriority",
        .n_params = 3,
        .params = {INT, INT, INT}
    },
#endif
#ifdef SYS_setregid
    [SYS_setregid] = {
        .name = "setregid",
        .n_params = 2,
        .params = {OLD_GID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_setregid32
    [SYS_setregid32] = {
        .name = "setregid32",
        .n_params = 2,
        .params = {GID_T, GID_T}
    },
#endif
#ifdef SYS_setresgid
    [SYS_setresgid] = {
        .name = "setresgid",
        .n_params = 3,
        .params = {OLD_GID_T, OLD_GID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_setresgid32
    [SYS_setresgid32] = {
        .name = "setresgid32",
        .n_params = 3,
        .params = {GID_T, GID_T, GID_T}
    },
#endif
#ifdef SYS_setresuid
    [SYS_setresuid] = {
        .name = "setresuid",
        .n_params = 3,
        .params = {OLD_UID_T, OLD_UID_T, OLD_UID_T}
    },
#endif
#ifdef SYS_setresuid32
    [SYS_setresuid32] = {
        .name = "setresuid32",
        .n_params = 3,
        .params = {UID_T, UID_T, UID_T}
    },
#endif
#ifdef SYS_setreuid
    [SYS_setreuid] = {
        .name = "setreuid",
        .n_params = 2,
        .params = {OLD_UID_T, OLD_UID_T}
    },
#endif
#ifdef SYS_setreuid32
    [SYS_setreuid32] = {
        .name = "setreuid32",
        .n_params = 2,
        .params = {UID_T, UID_T}
    },
#endif
#ifdef SYS_setrlimit
    [SYS_setrlimit] = {
        .name = "setrlimit",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_RLIMIT_PTR}
    },
#endif
#ifdef SYS_set_robust_list
    [SYS_set_robust_list] = {
        .name = "set_robust_list",
        .n_params = 2,
        .params = {STRUCT_ROBUST_LIST_HEAD_PTR, SIZE_T}
    },
#endif
#ifdef SYS_setsid
    [SYS_setsid] = {
        .name = "setsid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_setsockopt
    [SYS_setsockopt] = {
        .name = "setsockopt",
        .n_params = 5,
        .params = {INT, INT, INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_set_thread_area
    [SYS_set_thread_area] = {
        .name = "set_thread_area",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_set_tid_address
    [SYS_set_tid_address] = {
        .name = "set_tid_address",
        .n_params = 1,
        .params = {INT_PTR}
    },
#endif
#ifdef SYS_settimeofday
    [SYS_settimeofday] = {
        .name = "settimeofday",
        .n_params = 2,
        .params = {STRUCT___KERNEL_OLD_TIMEVAL_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_setuid
    [SYS_setuid] = {
        .name = "setuid",
        .n_params = 1,
        .params = {OLD_UID_T}
    },
#endif
#ifdef SYS_setuid32
    [SYS_setuid32] = {
        .name = "setuid32",
        .n_params = 1,
        .params = {UID_T}
    },
#endif
#ifdef SYS_setxattr
    [SYS_setxattr] = {
        .name = "setxattr",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_sgetmask
    [SYS_sgetmask] = {
        .name = "sgetmask",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_shmat
    [SYS_shmat] = {
        .name = "shmat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_shmctl
    [SYS_shmctl] = {
        .name = "shmctl",
        .n_params = 3,
        .params = {INT, INT, STRUCT_SHMID_DS_PTR}
    },
#endif
#ifdef SYS_shmdt
    [SYS_shmdt] = {
        .name = "shmdt",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_shmget
    [SYS_shmget] = {
        .name = "shmget",
        .n_params = 3,
        .params = {KEY_T, SIZE_T, INT}
    },
#endif
#ifdef SYS_shutdown
    [SYS_shutdown] = {
        .name = "shutdown",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_sigaction
    [SYS_sigaction] = {
        .name = "sigaction",
        .n_params = 3,
#if defined(__mips__) && defined(__32BIT__)
        .params = {LONG, STRUCT_COMPAT_SIGACTION_PTR,
            STRUCT_COMPAT_SIGACTION_PTR}
#else
        .params = {INT, STRUCT_OLD_SIGACTION_PTR, STRUCT_OLD_SIGACTION_PTR}
#endif
    },
#endif
#ifdef SYS_sigaltstack
    [SYS_sigaltstack] = {
        .name = "sigaltstack",
        .n_params = 2,
        .params = {STACK_T_PTR, STACK_T_PTR}
    },
#endif
#ifdef SYS_signal
    [SYS_signal] = {
        .name = "signal",
        .n_params = 2,
        .params = {INT, __SIGHANDLER_T}
    },
#endif
#ifdef SYS_signalfd
    [SYS_signalfd] = {
        .name = "signalfd",
        .n_params = 3,
        .params = {INT, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_signalfd4
    [SYS_signalfd4] = {
        .name = "signalfd4",
        .n_params = 4,
        .params = {INT, SIGSET_T_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_sigpending
    [SYS_sigpending] = {
        .name = "sigpending",
        .n_params = 1,
        .params = {OLD_SIGSET_T_PTR}
    },
#endif
#ifdef SYS_sigprocmask
    [SYS_sigprocmask] = {
        .name = "sigprocmask",
        .n_params = 3,
        .params = {INT, OLD_SIGSET_T_PTR, OLD_SIGSET_T_PTR}
    },
#endif
#ifdef SYS_sigreturn
    [SYS_sigreturn] = {
        .name = "sigreturn",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_sigsuspend
    [SYS_sigsuspend] = {
        .name = "sigsuspend",
        .n_params = 1,
        .params = {OLD_SIGSET_T}
    },
#endif
#ifdef SYS_socket
    [SYS_socket] = {
        .name = "socket",
        .n_params = 3,
        .params = {INT, INT, INT}
    },
#endif
#ifdef SYS_socketcall
    [SYS_socketcall] = {
        .name = "socketcall",
        .n_params = 2,
        .params = {INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_socketpair
    [SYS_socketpair] = {
        .name = "socketpair",
        .n_params = 4,
        .params = {INT, INT, INT, INT_PTR}
    },
#endif
#ifdef SYS_splice
    [SYS_splice] = {
        .name = "splice",
        .n_params = 6,
        .params = {INT, LOFF_T_PTR, INT, LOFF_T_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_spu_create
    [SYS_spu_create] = {
        .name = "spu_create",
        .n_params = 4,
        .params = {CHAR_PTR, UNSIGNED_INT, UMODE_T, INT}
    },
#endif
#ifdef SYS_spu_run
    [SYS_spu_run] = {
        .name = "spu_run",
        .n_params = 3,
        .params = {INT, __U32_PTR, __U32_PTR}
    },
#endif
#ifdef SYS_ssetmask
    [SYS_ssetmask] = {
        .name = "ssetmask",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_oldstat
    [SYS_oldstat] = {
        .name = "oldstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT___OLD_KERNEL_STAT_PTR}
    },
#endif
#ifdef SYS_stat64
    [SYS_stat64] = {
        .name = "stat64",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT64_PTR}
    },
#endif
#ifdef SYS_statfs
    [SYS_statfs] = {
        .name = "statfs",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STATFS_PTR}
    },
#endif
#ifdef SYS_statfs64
    [SYS_statfs64] = {
        .name = "statfs64",
        .n_params = 3,
        .params = {CHAR_PTR, SIZE_T, STRUCT_STATFS64_PTR}
    },
#endif
#ifdef SYS_statx
    [SYS_statx] = {
        .name = "statx",
        .n_params = 5,
        .params = {INT, CHAR_PTR, UNSIGNED, UNSIGNED_INT, STRUCT_STATX_PTR}
    },
#endif
#ifdef SYS_stime
    [SYS_stime] = {
        .name = "stime",
        .n_params = 1,
#ifdef __32BIT__
        .params = {OLD_TIME32_T_PTR}
#else
        .params = {__KERNEL_OLD_TIME_T_PTR}
#endif
    },
#endif
#ifdef SYS_subpage_prot
    [SYS_subpage_prot] = {
        .name = "subpage_prot",
        .n_params = 3,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, U32_PTR}
    },
#endif
#ifdef SYS_swapcontext
    [SYS_swapcontext] = {
        .name = "swapcontext",
        .n_params = 3,
        .params = {STRUCT_UCONTEXT_PTR, STRUCT_UCONTEXT_PTR, LONG}
    },
#endif
#ifdef SYS_swapoff
    [SYS_swapoff] = {
        .name = "swapoff",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_swapon
    [SYS_swapon] = {
        .name = "swapon",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_switch_endian
    [SYS_switch_endian] = {
        .name = "switch_endian",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_symlink
    [SYS_symlink] = {
        .name = "symlink",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_symlinkat
    [SYS_symlinkat] = {
        .name = "symlinkat",
        .n_params = 3,
        .params = {CHAR_PTR, INT, CHAR_PTR}
    },
#endif
#ifdef SYS_sync
    [SYS_sync] = {
        .name = "sync",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_sync_file_range
    [SYS_sync_file_range] = {
        .name = "sync_file_range",
#ifdef __i386__
        .n_params = 6,
        .params = {INT, UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_INT,
            INT}
#else
        .n_params = 4,
        .params = {INT, LOFF_T, LOFF_T, UNSIGNED_INT}
#endif
    },
#endif
#ifdef SYS_sync_file_range2
    [SYS_sync_file_range2] = {
        .name = "sync_file_range2",
        .n_params = 4,
        .params = {INT, UNSIGNED_INT, LOFF_T, LOFF_T}
    },
#endif
#ifdef SYS_syncfs
    [SYS_syncfs] = {
        .name = "syncfs",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sysfs
    [SYS_sysfs] = {
        .name = "sysfs",
        .n_params = 3,
        .params = {INT, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_sysinfo
    [SYS_sysinfo] = {
        .name = "sysinfo",
        .n_params = 1,
        .params = {STRUCT_SYSINFO_PTR}
    },
#endif
#ifdef SYS_syslog
    [SYS_syslog] = {
        .name = "syslog",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_sysmips
    [SYS_sysmips] = {
        .name = "sysmips",
        .n_params = 3,
        .params = {LONG, LONG, LONG}
    },
#endif
#ifdef SYS_tee
    [SYS_tee] = {
        .name = "tee",
        .n_params = 4,
        .params = {INT, INT, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_tgkill
    [SYS_tgkill] = {
        .name = "tgkill",
        .n_params = 3,
        .params = {PID_T, PID_T, INT}
    },
#endif
#ifdef SYS_time
    [SYS_time] = {
        .name = "time",
        .n_params = 1,
#ifdef __32BIT__
        .params = {OLD_TIME32_T_PTR}
#else
        .params = {__KERNEL_OLD_TIME_T_PTR}
#endif
    },
#endif
#ifdef SYS_timer_create
    [SYS_timer_create] = {
        .name = "timer_create",
        .n_params = 3,
        .params = {CLOCKID_T, STRUCT_SIGEVENT_PTR, TIMER_T_PTR}
    },
#endif
#ifdef SYS_timer_delete
    [SYS_timer_delete] = {
        .name = "timer_delete",
        .n_params = 1,
        .params = {TIMER_T}
    },
#endif
#ifdef SYS_timerfd_create
    [SYS_timerfd_create] = {
        .name = "timerfd_create",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_timerfd_gettime
    [SYS_timerfd_gettime] = {
        .name = "timerfd_gettime",
        .n_params = 2,
        .params = {INT, STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timerfd_gettime64
    [SYS_timerfd_gettime64] = {
        .name = "timerfd_gettime",
        .n_params = 2,
        .params = {INT, STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_timerfd_settime
    [SYS_timerfd_settime] = {
        .name = "timerfd_settime",
        .n_params = 4,
        .params = {INT, INT, STRUCT_OLD_ITIMERSPEC32_PTR,
            STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timerfd_settime64
    [SYS_timerfd_settime64] = {
        .name = "timerfd_settime",
        .n_params = 4,
        .params = {INT, INT, STRUCT___KERNEL_ITIMERSPEC_PTR,
            STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_timer_getoverrun
    [SYS_timer_getoverrun] = {
        .name = "timer_getoverrun",
        .n_params = 1,
        .params = {TIMER_T}
    },
#endif
#ifdef SYS_timer_gettime
    [SYS_timer_gettime] = {
        .name = "timer_gettime",
        .n_params = 2,
        .params = {TIMER_T, STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timer_gettime64
    [SYS_timer_gettime64] = {
        .name = "timer_gettime",
        .n_params = 2,
        .params = {TIMER_T, STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_timer_settime
    [SYS_timer_settime] = {
        .name = "timer_settime",
        .n_params = 4,
        .params = {TIMER_T, INT, STRUCT_OLD_ITIMERSPEC32_PTR,
            STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timer_settime64
    [SYS_timer_settime64] = {
        .name = "timer_settime",
        .n_params = 4,
        .params = {TIMER_T, INT, STRUCT___KERNEL_ITIMERSPEC_PTR,
            STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_times
    [SYS_times] = {
        .name = "times",
        .n_params = 1,
        .params = {STRUCT_TMS_PTR}
    },
#endif
#ifdef SYS_tkill
    [SYS_tkill] = {
        .name = "tkill",
        .n_params = 2,
        .params = {PID_T, INT}
    },
#endif
#ifdef SYS_truncate
    [SYS_truncate] = {
        .name = "truncate",
        .n_params = 2,
        .params = {CHAR_PTR, LONG}
    },
#endif
#ifdef SYS_truncate64
    [SYS_truncate64] = {
        .name = "truncate64",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 4,
        .params = {CHAR_PTR, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG}
#elif defined(__i386__)
        .n_params = 3,
        .params = {CHAR_PTR, UNSIGNED_LONG, UNSIGNED_LONG}
#else
        .n_params = 2,
        .params = {CHAR_PTR, LOFF_T}
#endif
    },
#endif
#ifdef SYS_umask
    [SYS_umask] = {
        .name = "umask",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_umount
    [SYS_umount] = {
        .name = "umount",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_olduname
    [SYS_olduname] = {
        .name = "olduname",
        .n_params = 1,
        .params = {STRUCT_OLD_UTSNAME_PTR}
    },
#endif
#ifdef SYS_unlink
    [SYS_unlink] = {
        .name = "unlink",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_unlinkat
    [SYS_unlinkat] = {
        .name = "unlinkat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_unshare
    [SYS_unshare] = {
        .name = "unshare",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_uselib
    [SYS_uselib] = {
        .name = "uselib",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_userfaultfd
    [SYS_userfaultfd] = {
        .name = "userfaultfd",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_ustat
    [SYS_ustat] = {
        .name = "ustat",
        .n_params = 2,
        .params = {UNSIGNED, STRUCT_USTAT_PTR}
    },
#endif
#ifdef SYS_utime
    [SYS_utime] = {
        .name = "utime",
        .n_params = 2,
#ifdef __32BIT__
        .params = {CHAR_PTR, STRUCT_OLD_UTIMBUF32_PTR}
#else
        .params = {CHAR_PTR, STRUCT_UTIMBUF_PTR}
#endif
    },
#endif
#ifdef SYS_utimensat
    [SYS_utimensat] = {
        .name = "utimensat",
        .n_params = 4,
        .params = {UNSIGNED_INT, CHAR_PTR, STRUCT_OLD_TIMESPEC32_PTR, INT}
    },
#endif
#ifdef SYS_utimensat_time64
    [SYS_utimensat_time64] = {
        .name = "utimensat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT___KERNEL_TIMESPEC_PTR, INT}
    },
#endif
#ifdef SYS_utimes
    [SYS_utimes] = {
        .name = "utimes",
        .n_params = 2,
#ifdef __32BIT__
        .params = {CHAR_PTR, STRUCT_OLD_TIMEVAL32_PTR}
#else
        .params = {CHAR_PTR, STRUCT___KERNEL_OLD_TIMEVAL_PTR}
#endif
    },
#endif
#ifdef SYS_utrap_install
    [SYS_utrap_install] = {
        .name = "utrap_install",
        .n_params = 5,
        .params = {UTRAP_ENTRY_T, UTRAP_HANDLER_T, UTRAP_HANDLER_T,
            UTRAP_HANDLER_T_PTR, UTRAP_HANDLER_T_PTR}
    },
#endif
#ifdef SYS_vfork
    [SYS_vfork] = {
        .name = "vfork",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_vhangup
    [SYS_vhangup] = {
        .name = "vhangup",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_vm86
    [SYS_vm86] = {
        .name = "vm86",
        .n_params = 2,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_vm86old
    [SYS_vm86old] = {
        .name = "vm86old",
        .n_params = 1,
        .params = {STRUCT_VM86_STRUCT_PTR}
    },
#endif
#ifdef SYS_vmsplice
    [SYS_vmsplice] = {
        .name = "vmsplice",
        .n_params = 4,
        .params = {INT, STRUCT_IOVEC_PTR, UNSIGNED_LONG, UNSIGNED_INT}
    },
#endif
#ifdef SYS_wait4
    [SYS_wait4] = {
        .name = "wait4",
        .n_params = 4,
        .params = {PID_T, INT_PTR, INT, STRUCT_RUSAGE_PTR}
    },
#endif
#ifdef SYS_waitid
    [SYS_waitid] = {
        .name = "waitid",
        .n_params = 5,
        .params = {INT, PID_T, STRUCT_SIGINFO_PTR, INT, STRUCT_RUSAGE_PTR}
    },
#endif
#ifdef SYS_waitpid
    [SYS_waitpid] = {
        .name = "waitpid",
        .n_params = 3,
        .params = {PID_T, INT_PTR, INT}
    },
#endif
#ifdef SYS_writev
    [SYS_writev] = {
        .name = "writev",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG}
    },
#endif
// unimplemented start
#ifdef SYS_osf_adjtime
    [SYS_osf_adjtime] = {
        .name = "osf_adjtime",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_afs_syscall
    [SYS_osf_afs_syscall] = {
        .name = "osf_afs_syscall",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_alt_plock
    [SYS_osf_alt_plock] = {
        .name = "osf_alt_plock",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_alt_setsid
    [SYS_osf_alt_setsid] = {
        .name = "osf_alt_setsid",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_alt_sigpending
    [SYS_osf_alt_sigpending] = {
        .name = "osf_alt_sigpending",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_asynch_daemon
    [SYS_osf_asynch_daemon] = {
        .name = "osf_asynch_daemon",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_audcntl
    [SYS_osf_audcntl] = {
        .name = "osf_audcntl",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_audgen
    [SYS_osf_audgen] = {
        .name = "osf_audgen",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_chflags
    [SYS_osf_chflags] = {
        .name = "osf_chflags",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_execve
    [SYS_osf_execve] = {
        .name = "osf_execve",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_exportfs
    [SYS_osf_exportfs] = {
        .name = "osf_exportfs",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_fchflags
    [SYS_osf_fchflags] = {
        .name = "osf_fchflags",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_fdatasync
    [SYS_osf_fdatasync] = {
        .name = "osf_fdatasync",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_fpathconf
    [SYS_osf_fpathconf] = {
        .name = "osf_fpathconf",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_fuser
    [SYS_osf_fuser] = {
        .name = "osf_fuser",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_getaddressconf
    [SYS_osf_getaddressconf] = {
        .name = "osf_getaddressconf",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_getfh
    [SYS_osf_getfh] = {
        .name = "osf_getfh",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_getfsstat
    [SYS_osf_getfsstat] = {
        .name = "osf_getfsstat",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_gethostid
    [SYS_osf_gethostid] = {
        .name = "osf_gethostid",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_getlogin
    [SYS_osf_getlogin] = {
        .name = "osf_getlogin",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_getmnt
    [SYS_osf_getmnt] = {
        .name = "osf_getmnt",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_kloadcall
    [SYS_osf_kloadcall] = {
        .name = "osf_kloadcall",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_kmodcall
    [SYS_osf_kmodcall] = {
        .name = "osf_kmodcall",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_memcntl
    [SYS_osf_memcntl] = {
        .name = "osf_memcntl",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_mincore
    [SYS_osf_mincore] = {
        .name = "osf_mincore",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_mremap
    [SYS_osf_mremap] = {
        .name = "osf_mremap",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_msfs_syscall
    [SYS_osf_msfs_syscall] = {
        .name = "osf_msfs_syscall",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_msleep
    [SYS_osf_msleep] = {
        .name = "osf_msleep",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_mvalid
    [SYS_osf_mvalid] = {
        .name = "osf_mvalid",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_mwakeup
    [SYS_osf_mwakeup] = {
        .name = "osf_mwakeup",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_naccept
    [SYS_osf_naccept] = {
        .name = "osf_naccept",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_nfssvc
    [SYS_osf_nfssvc] = {
        .name = "osf_nfssvc",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_ngetpeername
    [SYS_osf_ngetpeername] = {
        .name = "osf_ngetpeername",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_ngetsockname
    [SYS_osf_ngetsockname] = {
        .name = "osf_ngetsockname",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_nrecvfrom
    [SYS_osf_nrecvfrom] = {
        .name = "osf_nrecvfrom",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_nrecvmsg
    [SYS_osf_nrecvmsg] = {
        .name = "osf_nrecvmsg",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_nsendmsg
    [SYS_osf_nsendmsg] = {
        .name = "osf_nsendmsg",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_ntp_adjtime
    [SYS_osf_ntp_adjtime] = {
        .name = "osf_ntp_adjtime",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_ntp_gettime
    [SYS_osf_ntp_gettime] = {
        .name = "osf_ntp_gettime",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_creat
    [SYS_osf_old_creat] = {
        .name = "osf_old_creat",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_fstat
    [SYS_osf_old_fstat] = {
        .name = "osf_old_fstat",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_getpgrp
    [SYS_osf_old_getpgrp] = {
        .name = "osf_old_getpgrp",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_killpg
    [SYS_osf_old_killpg] = {
        .name = "osf_old_killpg",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_lstat
    [SYS_osf_old_lstat] = {
        .name = "osf_old_lstat",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_open
    [SYS_osf_old_open] = {
        .name = "osf_old_open",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_oldquota
    [SYS_osf_oldquota] = {
        .name = "osf_oldquota",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_sigaction
    [SYS_osf_old_sigaction] = {
        .name = "osf_old_sigaction",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_sigblock
    [SYS_osf_old_sigblock] = {
        .name = "osf_old_sigblock",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_sigreturn
    [SYS_osf_old_sigreturn] = {
        .name = "osf_old_sigreturn",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_sigsetmask
    [SYS_osf_old_sigsetmask] = {
        .name = "osf_old_sigsetmask",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_sigvec
    [SYS_osf_old_sigvec] = {
        .name = "osf_old_sigvec",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_stat
    [SYS_osf_old_stat] = {
        .name = "osf_old_stat",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_vadvise
    [SYS_osf_old_vadvise] = {
        .name = "osf_old_vadvise",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_vtrace
    [SYS_osf_old_vtrace] = {
        .name = "osf_old_vtrace",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_old_wait
    [SYS_osf_old_wait] = {
        .name = "osf_old_wait",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_pathconf
    [SYS_osf_pathconf] = {
        .name = "osf_pathconf",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_pid_block
    [SYS_osf_pid_block] = {
        .name = "osf_pid_block",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_pid_unblock
    [SYS_osf_pid_unblock] = {
        .name = "osf_pid_unblock",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_plock
    [SYS_osf_plock] = {
        .name = "osf_plock",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_priocntlset
    [SYS_osf_priocntlset] = {
        .name = "osf_priocntlset",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_profil
    [SYS_osf_profil] = {
        .name = "osf_profil",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_reboot
    [SYS_osf_reboot] = {
        .name = "osf_reboot",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_revoke
    [SYS_osf_revoke] = {
        .name = "osf_revoke",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_sbrk
    [SYS_osf_sbrk] = {
        .name = "osf_sbrk",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_security
    [SYS_osf_security] = {
        .name = "osf_security",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_sethostid
    [SYS_osf_sethostid] = {
        .name = "osf_sethostid",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_setlogin
    [SYS_osf_setlogin] = {
        .name = "osf_setlogin",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_set_speculative
    [SYS_osf_set_speculative] = {
        .name = "osf_set_speculative",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_signal
    [SYS_osf_signal] = {
        .name = "osf_signal",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_sigsendset
    [SYS_osf_sigsendset] = {
        .name = "osf_sigsendset",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_sigwaitprim
    [SYS_osf_sigwaitprim] = {
        .name = "osf_sigwaitprim",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_sstk
    [SYS_osf_sstk] = {
        .name = "osf_sstk",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_subsys_info
    [SYS_osf_subsys_info] = {
        .name = "osf_subsys_info",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_swapctl
    [SYS_osf_swapctl] = {
        .name = "osf_swapctl",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_syscall
    [SYS_osf_syscall] = {
        .name = "osf_syscall",
        .n_params = 6,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_table
    [SYS_osf_table] = {
        .name = "osf_table",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_uadmin
    [SYS_osf_uadmin] = {
        .name = "osf_uadmin",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_uswitch
    [SYS_osf_uswitch] = {
        .name = "osf_uswitch",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_utc_adjtime
    [SYS_osf_utc_adjtime] = {
        .name = "osf_utc_adjtime",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_utc_gettime
    [SYS_osf_utc_gettime] = {
        .name = "osf_utc_gettime",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_waitid
    [SYS_osf_waitid] = {
        .name = "osf_waitid",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
// unimplemented end
// irregular start
#ifdef SYS_acl_get
    [SYS_acl_get] = {
        .name = "acl_get",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_acl_set
    [SYS_acl_set] = {
        .name = "acl_set",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_afs_syscall
    [SYS_afs_syscall] = {
        .name = "afs_syscall",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 0,
        .params = {}
#else
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_alloc_hugepages
    [SYS_alloc_hugepages] = {
        .name = "alloc_hugepages",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_arm_fadvise64_64
    [SYS_arm_fadvise64_64] = {
        .name = "arm_fadvise64_64",
        .n_params = 4,
        .params = {INT, INT, LOFF_T, LOFF_T}
    },
#endif
#ifdef SYS_arm_sync_file_range
    [SYS_arm_sync_file_range] = {
        .name = "arm_sync_file_range",
        .n_params = 4,
        .params = {INT, LOFF_T, LOFF_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_atomic_barrier
    [SYS_atomic_barrier] = {
        .name = "atomic_barrier",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_atomic_cmpxchg_32
    [SYS_atomic_cmpxchg_32] = {
        .name = "atomic_cmpxchg_32",
        .n_params = 6,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_attrctl
    [SYS_attrctl] = {
        .name = "attrctl",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_break
    [SYS_break] = {
        .name = "break",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_breakpoint
    [SYS_breakpoint] = {
        .name = "breakpoint",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_clone2
    [SYS_clone2] = {
        .name = "clone2",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, INT_PTR, UNSIGNED_LONG,
            INT_PTR}
    },
#endif
#ifdef SYS_cmpxchg_badaddr
    [SYS_cmpxchg_badaddr] = {
        .name = "cmpxchg_badaddr",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_create_module
    [SYS_create_module] = {
        .name = "create_module",
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_dipc
    [SYS_dipc] = {
        .name = "dipc",
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_epoll_ctl_old
    [SYS_epoll_ctl_old] = {
        .name = "epoll_ctl_old",
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_epoll_wait_old
    [SYS_epoll_wait_old] = {
        .name = "epoll_wait_old",
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_execv
    [SYS_execv] = {
        .name = "execv",
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_exec_with_loader
    [SYS_exec_with_loader] = {
        .name = "exec_with_loader",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_free_hugepages
    [SYS_free_hugepages] = {
        .name = "free_hugepages",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_ftime
    [SYS_ftime] = {
        .name = "ftime",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 1,
        .params = {VOID_PTR}
#else
        .n_params = 0,
        .params = {}
#endif
    },
#endif
#ifdef SYS_get_kernel_syms
    [SYS_get_kernel_syms] = {
        .name = "get_kernel_syms",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_getpmsg
    [SYS_getpmsg] = {
        .name = "getpmsg",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_get_tls
    [SYS_get_tls] = {
        .name = "get_tls",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getunwind
    [SYS_getunwind] = {
        .name = "getunwind",
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_gtty
    [SYS_gtty] = {
        .name = "gtty",
#ifdef __mips__
        .n_params = 0,
        .params = {}
#else
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_idle
    [SYS_idle] = {
        .name = "idle",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_lock
    [SYS_lock] = {
        .name = "lock",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_lookup_dcookie
    [SYS_lookup_dcookie] = {
        .name = "lookup_dcookie",
#ifndef __32BIT__
        .n_params = 3,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR}
#else
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_mpx
    [SYS_mpx] = {
        .name = "mpx",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_multiplexer
    [SYS_multiplexer] = {
        .name = "multiplexer",
        .n_params = 6,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_nfsservctl
    [SYS_nfsservctl] = {
        .name = "nfsservctl",
        .n_params = 3,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_getitimer
    [SYS_osf_getitimer] = {
        .name = "osf_getitimer",
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_setitimer
    [SYS_osf_setitimer] = {
        .name = "osf_setitimer",
        .n_params = 3,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_shmat
    [SYS_osf_shmat] = {
        .name = "osf_shmat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_osf_swapon
    [SYS_osf_swapon] = {
        .name = "osf_swapon",
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_perfctr
    [SYS_perfctr] = {
        .name = "perfctr",
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_perfmonctl
    [SYS_perfmonctl] = {
        .name = "perfmonctl",
        .n_params = 6,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_prof
    [SYS_prof] = {
        .name = "prof",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_profil
    [SYS_profil] = {
        .name = "profil",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 0,
        .params = {}
#else
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_putpmsg
    [SYS_putpmsg] = {
        .name = "putpmsg",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_query_module
    [SYS_query_module] = {
        .name = "query_module",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_sched_get_affinity
    [SYS_sched_get_affinity] = {
        .name = "sched_get_affinity",
        .n_params = 3,
        .params = {PID_T, UNSIGNED_INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_sched_set_affinity
    [SYS_sched_set_affinity] = {
        .name = "sched_set_affinity",
        .n_params = 3,
        .params = {PID_T, UNSIGNED_INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_security
    [SYS_security] = {
        .name = "security",
        .n_params = 3,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_setpgrp
    [SYS_setpgrp] = {
        .name = "setpgrp",
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_set_tls
    [SYS_set_tls] = {
        .name = "set_tls",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_stty
    [SYS_stty] = {
        .name = "stty",
#if defined(__mips__) && defined(__32BIT__)
        .n_params = 0,
        .params = {}
#else
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_syscall
    [SYS_syscall] = {
        .name = "syscall",
        .n_params = 6,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS__sysctl
    [SYS__sysctl] = {
        .name = "_sysctl",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_sys_epoll_create
    [SYS_sys_epoll_create] = {
        .name = "sys_epoll_create",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sys_epoll_ctl
    [SYS_sys_epoll_ctl] = {
        .name = "sys_epoll_ctl",
        .n_params = 4,
        .params = {INT, INT, INT, STRUCT_EPOLL_EVENT_PTR}
    },
#endif
#ifdef SYS_sys_epoll_wait
    [SYS_sys_epoll_wait] = {
        .name = "sys_epoll_wait",
        .n_params = 4,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT, INT}
    },
#endif
#ifdef SYS_timerfd
    [SYS_timerfd] = {
        .name = "timerfd",
        .n_params = 4,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_tuxcall
    [SYS_tuxcall] = {
        .name = "tuxcall",
#if defined(__x86_64__) || defined(__32BIT__)
        .n_params = 3,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR}
#else
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_ugetrlimit
    [SYS_ugetrlimit] = {
        .name = "ugetrlimit",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_RLIMIT_PTR}
    },
#endif
#ifdef SYS_ulimit
    [SYS_ulimit] = {
        .name = "ulimit",
#ifdef __mips__
        .n_params = 0,
        .params = {}
#else
        .n_params = 2,
        .params = {VOID_PTR, VOID_PTR}
#endif
    },
#endif
#ifdef SYS_umount2
    [SYS_umount2] = {
        .name = "umount2",
#ifdef __AVR__
        .n_params = 1,
        .params = {CHAR_PTR}
#else
        .n_params = 2,
        .params = {CHAR_PTR, INT}
#endif
    },
#endif
#ifdef SYS_usr26
    [SYS_usr26] = {
        .name = "usr26",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_usr32
    [SYS_usr32] = {
        .name = "usr32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_vserver
    [SYS_vserver] = {
        .name = "vserver",
        .n_params = 5,
        .params = {VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR, VOID_PTR}
    },
#endif
// irregular end
#ifdef SYS_write
    [SYS_write] = {
        .name = "write",
        .n_params = 3,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T}
    }
#endif
};

#endif // _CTRACE_H_
