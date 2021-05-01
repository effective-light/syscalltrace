#ifndef _CTRACE_H_
#define _CTRACE_H_

#if INTPTR_MAX == INT32_MAX
#define __32BIT__
#elif INTPTR_MAX != INT64_MAX
#error Unknown pointer size or missing size macros!
#endif

#include <stdint.h>

#include <unistd.h>
#include <sys/syscall.h>

typedef enum param_types {
    AIO_CONTEXT_T,
    AIO_CONTEXT_T_PTR,
    CAP_USER_DATA_T,
    CAP_USER_HEADER_T,
    CHAR__PTR,
    CHAR_PTR,
    CHAR_PTR__USER_PTR,
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
    uint64_t nr;
    char *name;
    size_t n_params;
    param_t params[6];
} syscall_t;

syscall_t syscalls[] = {
#ifdef SYS_accept
    {
        .nr = SYS_accept,
        .name = "accept",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_accept4
    {
        .nr = SYS_accept4,
        .name = "accept4",
        .n_params = 4,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR, INT}
    },
#endif
#ifdef SYS_access
    {
        .nr = SYS_access,
        .name = "access",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_acct
    {
        .nr = SYS_acct,
        .name = "acct",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_add_key
    {
        .nr = SYS_add_key,
        .name = "add_key",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T, KEY_SERIAL_T}
    },
#endif
#ifdef SYS_adjtimex
    {
        .nr = SYS_adjtimex,
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
    {
        .nr = SYS_old_adjtimex,
        .name = "old_adjtimex",
        .n_params = 1,
        .params = {STRUCT_TIMEX32_PTR}
    },
#endif
#ifdef SYS_alarm
    {
        .nr = SYS_alarm,
        .name = "alarm",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_alpha_pipe
    {
        .nr = SYS_alpha_pipe,
        .name = "alpha_pipe",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_arc_gettls
    {
        .nr = SYS_arc_gettls,
        .name = "arc_gettls",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_arch_prctl
    {
        .nr = SYS_arch_prctl,
        .name = "arch_prctl",
        .n_params = 2,
        .params = {INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_arc_settls
    {
        .nr = SYS_arc_settls,
        .name = "arc_settls",
        .n_params = 1,
        .params = {VOID_PTR}
    },
#endif
#ifdef SYS_arc_usr_cmpxchg
    {
        .nr = SYS_arc_usr_cmpxchg,
        .name = "arc_usr_cmpxchg",
        .n_params = 3,
        .params = {INT_PTR, INT, INT}
    },
#endif
#ifdef SYS_bdflush
    {
        .nr = SYS_bdflush,
        .name = "bdflush",
        .n_params = 2,
        .params = {INT, LONG}
    },
#endif
#ifdef SYS_bind
    {
        .nr = SYS_bind,
        .name = "bind",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT}
    },
#endif
#ifdef SYS_bpf
    {
        .nr = SYS_bpf,
        .name = "bpf",
        .n_params = 3,
        .params = {INT, UNION_BPF_ATTR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_brk
    {
        .nr = SYS_brk,
        .name = "brk",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_cachectl
    {
        .nr = SYS_cachectl,
        .name = "cachectl",
        .n_params = 3,
        .params = {CHAR_PTR, INT, INT}
    },
#endif
#ifdef SYS_cacheflush
    {
        .nr = SYS_cacheflush,
        .name = "cacheflush",
        .n_params = 3,
        .params = {VOID_PTR, UNSIGNED_LONG, INT}
    },
#endif
#ifdef SYS_capget
    {
        .nr = SYS_capget,
        .name = "capget",
        .n_params = 2,
        .params = {CAP_USER_HEADER_T, CAP_USER_DATA_T}
    },
#endif
#ifdef SYS_capset
    {
        .nr = SYS_capset,
        .name = "capset",
        .n_params = 2,
        .params = {CAP_USER_HEADER_T, CAP_USER_DATA_T}
    },
#endif
#ifdef SYS_chdir
    {
        .nr = SYS_chdir,
        .name = "chdir",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_chmod
    {
        .nr = SYS_chmod,
        .name = "chmod",
        .n_params = 2,
        .params = {CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_chown
    {
        .nr = SYS_chown,
        .name = "chown",
        .n_params = 3,
        .params = {CHAR_PTR, OLD_UID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_chown32
    {
        .nr = SYS_chown32,
        .name = "chown32",
        .n_params = 3,
        .params = {CHAR_PTR, UID_T, GID_T}
    },
#endif
#ifdef SYS_chroot
    {
        .nr = SYS_chroot,
        .name = "chroot",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_clock_adjtime
    {
        .nr = SYS_clock_adjtime,
        .name = "clock_adjtime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMEX32_PTR}
    },
#endif
#ifdef SYS_clock_adjtime64
    {
        .nr = SYS_clock_adjtime64,
        .name = "clock_adjtime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMEX_PTR}
    },
#endif
#ifdef SYS_clock_getres
    {
        .nr = SYS_clock_getres,
        .name = "clock_getres",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_getres_time64
    {
        .nr = SYS_clock_getres_time64,
        .name = "clock_getres",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clock_gettime
    {
        .nr = SYS_clock_gettime,
        .name = "clock_gettime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_gettime64
    {
        .nr = SYS_clock_gettime,
        .name = "clock_gettime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clock_nanosleep
    {
        .nr = SYS_clock_nanosleep,
        .name = "clock_nanosleep",
        .n_params = 4,
        .params = {CLOCKID_T, INT, STRUCT_OLD_TIMESPEC32_PTR,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_nanosleep_time64
    {
        .nr = SYS_clock_nanosleep_time64,
        .name = "clock_nanosleep",
        .n_params = 4,
        .params = {CLOCKID_T, INT, STRUCT___KERNEL_TIMESPEC_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clock_settime
    {
        .nr = SYS_clock_settime,
        .name = "clock_settime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_clock_settime64
    {
        .nr = SYS_clock_settime64,
        .name = "clock_settime",
        .n_params = 2,
        .params = {CLOCKID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_clone
    {
        .nr = SYS_clone,
        .name = "clone",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, INT_PTR, UNSIGNED_LONG,
            INT_PTR}
    },
#endif
#ifdef SYS_clone3
    {
        .nr = SYS_clone3,
        .name = "clone3",
        .n_params = 2,
        .params = {STRUCT_CLONE_ARGS_PTR, SIZE_T}
    },
#endif
#ifdef SYS_close
    {
        .nr = SYS_close,
        .name = "close",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_close_range
    {
        .nr = SYS_close_range,
        .name = "close_range",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_connect
    {
        .nr = SYS_connect,
        .name = "connect",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT}
    },
#endif
#ifdef SYS_copy_file_range
    {
        .nr = SYS_copy_file_range,
        .name = "copy_file_range",
        .n_params = 6,
        .params = {INT, LOFF_T_PTR, INT, LOFF_T_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_creat
    {
        .nr = SYS_creat,
        .name = "creat",
        .n_params = 2,
        .params = {CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_sys_debug_setcontext
    {
        .nr = SYS_sys_debug_setcontext,
        .name = "sys_debug_setcontext",
        .n_params = 3,
        .params = {STRUCT_UCONTEXT_PTR, INT, STRUCT_SIG_DBG_OP_PTR}
    },
#endif
#ifdef SYS_delete_module
    {
        .nr = SYS_delete_module,
        .name = "delete_module",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_dup
    {
        .nr = SYS_dup,
        .name = "dup",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_dup2
    {
        .nr = SYS_dup2,
        .name = "dup2",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_dup3
    {
        .nr = SYS_dup3,
        .name = "dup3",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_epoll_create
    {
        .nr = SYS_epoll_create,
        .name = "epoll_create",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_epoll_create1
    {
        .nr = SYS_epoll_create1,
        .name = "epoll_create1",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_epoll_ctl
    {
        .nr = SYS_epoll_ctl,
        .name = "epoll_ctl",
        .n_params = 4,
        .params = {INT, INT, INT, STRUCT_EPOLL_EVENT_PTR}
    },
#endif
#ifdef SYS_epoll_pwait
    {
        .nr = SYS_epoll_pwait,
        .name = "epoll_pwait",
        .n_params = 6,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT, INT, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_epoll_pwait2
    {
        .nr = SYS_epoll_pwait2,
        .name = "epoll_pwait2",
        .n_params = 6,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT,
            STRUCT___KERNEL_TIMESPEC_PTR, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_epoll_wait
    {
        .nr = SYS_epoll_wait,
        .name = "epoll_wait",
        .n_params = 4,
        .params = {INT, STRUCT_EPOLL_EVENT_PTR, INT, INT}
    },
#endif
#ifdef SYS_eventfd
    {
        .nr = SYS_eventfd,
        .name = "eventfd",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_eventfd2
    {
        .nr = SYS_eventfd2,
        .name = "eventfd2",
        .n_params = 2,
        .params = {UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_execve
    {
        .nr = SYS_execve,
        .name = "execve",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR__USER_PTR, CHAR_PTR__USER_PTR}
    },
#endif
#ifdef SYS_execveat
    {
        .nr = SYS_execveat,
        .name = "execveat",
        .n_params = 5,
        .params = {INT, CHAR_PTR, CHAR_PTR__USER_PTR, CHAR_PTR__USER_PTR, INT}
    },
#endif
#ifdef SYS_exit
    {
        .nr = SYS_exit,
        .name = "exit",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_exit_group
    {
        .nr = SYS_exit_group,
        .name = "exit_group",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_faccessat
    {
        .nr = SYS_faccessat,
        .name = "faccessat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_faccessat2
    {
        .nr = SYS_faccessat2,
        .name = "faccessat2",
        .n_params = 4,
        .params = {INT, CHAR_PTR, INT, INT}
    },
#endif
#ifdef SYS_fadvise64
    {
        .nr = SYS_fadvise64,
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
    {
        .nr = SYS_fadvise64_64,
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
    {
        .nr = SYS_fallocate,
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
    {
        .nr = SYS_fanotify_init,
        .name = "fanotify_init",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fanotify_mark
    {
        .nr = SYS_fanotify_mark,
        .name = "fanotify_mark",
        .n_params = 5,
        .params = {INT, UNSIGNED_INT, __U64, INT, CHAR__PTR}
    },
#endif
#ifdef SYS_fchdir
    {
        .nr = SYS_fchdir,
        .name = "fchdir",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_fchmod
    {
        .nr = SYS_fchmod,
        .name = "fchmod",
        .n_params = 2,
        .params = {UNSIGNED_INT, UMODE_T}
    },
#endif
#ifdef SYS_fchmodat
    {
        .nr = SYS_fchmodat,
        .name = "fchmodat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_fchown
    {
        .nr = SYS_fchown,
        .name = "fchown",
        .n_params = 3,
        .params = {UNSIGNED_INT, OLD_UID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_fchown32
    {
        .nr = SYS_fchown32,
        .name = "fchown32",
        .n_params = 3,
        .params = {UNSIGNED_INT, UID_T, GID_T}
    },
#endif
#ifdef SYS_fchownat
    {
        .nr = SYS_fchownat,
        .name = "fchownat",
        .n_params = 5,
        .params = {INT, CHAR_PTR, UID_T, GID_T, INT}
    },
#endif
#ifdef SYS_fcntl
    {
        .nr = SYS_fcntl,
        .name = "fcntl",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_fcntl64
    {
        .nr = SYS_fcntl64,
        .name = "fcntl64",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_fdatasync
    {
        .nr = SYS_fdatasync,
        .name = "fdatasync",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_fgetxattr
    {
        .nr = SYS_fgetxattr,
        .name = "fgetxattr",
        .n_params = 4,
        .params = {INT, CHAR_PTR, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_finit_module
    {
        .nr = SYS_finit_module,
        .name = "finit_module",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_flistxattr
    {
        .nr = SYS_flistxattr,
        .name = "flistxattr",
        .n_params = 3,
        .params = {INT, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_flock
    {
        .nr = SYS_flock,
        .name = "flock",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fork
    {
        .nr = SYS_fork,
        .name = "fork",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_fp_udfiex_crtl
    {
        .nr = SYS_fp_udfiex_crtl,
        .name = "fp_udfiex_crtl",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fremovexattr
    {
        .nr = SYS_fremovexattr,
        .name = "fremovexattr",
        .n_params = 2,
        .params = {INT, CHAR_PTR}
    },
#endif
#ifdef SYS_fsconfig
    {
        .nr = SYS_fsconfig,
        .name = "fsconfig",
        .n_params = 5,
        .params = {INT, UNSIGNED_INT, CHAR_PTR, VOID_PTR, INT}
    },
#endif
#ifdef SYS_fsetxattr
    {
        .nr = SYS_fsetxattr,
        .name = "fsetxattr",
        .n_params = 5,
        .params = {INT, CHAR_PTR, VOID_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_fsmount
    {
        .nr = SYS_fsmount,
        .name = "fsmount",
        .n_params = 3,
        .params = {INT, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fsopen
    {
        .nr = SYS_fsopen,
        .name = "fsopen",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_fspick
    {
        .nr = SYS_fspick,
        .name = "fspick",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_oldfstat
    {
        .nr = SYS_oldfstat,
        .name = "oldfstat",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT___OLD_KERNEL_STAT_PTR}
    },
#endif
#ifdef SYS_fstat64
    {
        .nr = SYS_fstat64,
        .name = "fstat64",
        .n_params = 2,
        .params = {UNSIGNED_LONG, STRUCT_STAT64_PTR}
    },
#endif
#ifdef SYS_fstatat64
    {
        .nr = SYS_fstatat64,
        .name = "fstatat64",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT_STAT64_PTR, INT}
    },
#endif
#ifdef SYS_fstatfs
    {
        .nr = SYS_fstatfs,
        .name = "fstatfs",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_STATFS_PTR}
    },
#endif
#ifdef SYS_fstatfs64
    {
        .nr = SYS_fstatfs64,
        .name = "fstatfs64",
        .n_params = 3,
        .params = {UNSIGNED_INT, SIZE_T, STRUCT_STATFS64_PTR}
    },
#endif
#ifdef SYS_fsync
    {
        .nr = SYS_fsync,
        .name = "fsync",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_ftruncate
    {
        .nr = SYS_ftruncate,
        .name = "ftruncate",
        .n_params = 2,
        .params = {UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_ftruncate64
    {
        .nr = SYS_ftruncate64,
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
    {
        .nr = SYS_futex,
        .name = "futex",
        .n_params = 6,
        .params = {U32_PTR, INT, U32, STRUCT_OLD_TIMESPEC32_PTR, U32_PTR, U32}
    },
#endif
#ifdef SYS_futex_time64
    {
        .nr = SYS_futex_time64,
        .name = "futex",
        .n_params = 6,
        .params = {U32_PTR, INT, U32, STRUCT___KERNEL_TIMESPEC_PTR, U32_PTR,
            U32}
    },
#endif
#ifdef SYS_futimesat
    {
        .nr = SYS_futimesat,
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
    {
        .nr = SYS_getcpu,
        .name = "getcpu",
        .n_params = 3,
        .params = {UNSIGNED_PTR, UNSIGNED_PTR, STRUCT_GETCPU_CACHE_PTR}
    },
#endif
#ifdef SYS_getcwd
    {
        .nr = SYS_getcwd,
        .name = "getcwd",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_getdents
    {
        .nr = SYS_getdents,
        .name = "getdents",
        .n_params = 3,
        .params = {UNSIGNED_INT, STRUCT_LINUX_DIRENT_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_getdents64
    {
        .nr = SYS_getdents64,
        .name = "getdents64",
        .n_params = 3,
        .params = {UNSIGNED_INT, STRUCT_LINUX_DIRENT64_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_getdomainname
    {
        .nr = SYS_getdomainname,
        .name = "getdomainname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_getdtablesize
    {
        .nr = SYS_getdtablesize,
        .name = "getdtablesize",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getegid
    {
        .nr = SYS_getegid,
        .name = "getegid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getegid32
    {
        .nr = SYS_getegid32,
        .name = "getegid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_geteuid
    {
        .nr = SYS_geteuid,
        .name = "geteuid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_geteuid32
    {
        .nr = SYS_geteuid32,
        .name = "geteuid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getgid
    {
        .nr = SYS_getgid,
        .name = "getgid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getgid32
    {
        .nr = SYS_getgid32,
        .name = "getgid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getgroups
    {
        .nr = SYS_getgroups,
        .name = "getgroups",
        .n_params = 2,
        .params = {INT, OLD_GID_T_PTR}
    },
#endif
#ifdef SYS_getgroups32
    {
        .nr = SYS_getgroups32,
        .name = "getgroups32",
        .n_params = 2,
        .params = {INT, GID_T_PTR}
    },
#endif
#ifdef SYS_gethostname
    {
        .nr = SYS_gethostname,
        .name = "gethostname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_getitimer
    {
        .nr = SYS_getitimer,
        .name = "getitimer",
        .n_params = 2,
        .params = {INT, STRUCT___KERNEL_OLD_ITIMERVAL_PTR}
    },
#endif
#ifdef SYS_get_mempolicy
    {
        .nr = SYS_get_mempolicy,
        .name = "get_mempolicy",
        .n_params = 5,
        .params = {INT_PTR, UNSIGNED_LONG_PTR, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_old_getpagesize
    {
        .nr = SYS_old_getpagesize,
        .name = "old_getpagesize",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpagesize
    {
        .nr = SYS_getpagesize,
        .name = "getpagesize",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpeername
    {
        .nr = SYS_getpeername,
        .name = "getpeername",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_getpgid
    {
        .nr = SYS_getpgid,
        .name = "getpgid",
        .n_params = 1,
        .params = {PID_T}
    },
#endif
#ifdef SYS_getpgrp
    {
        .nr = SYS_getpgrp,
        .name = "getpgrp",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpid
    {
        .nr = SYS_getpid,
        .name = "getpid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getppid
    {
        .nr = SYS_getppid,
        .name = "getppid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getpriority
    {
        .nr = SYS_getpriority,
        .name = "getpriority",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_getrandom
    {
        .nr = SYS_getrandom,
        .name = "getrandom",
        .n_params = 3,
        .params = {CHAR_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_getresgid
    {
        .nr = SYS_getresgid,
        .name = "getresgid",
        .n_params = 3,
        .params = {OLD_GID_T_PTR, OLD_GID_T_PTR, OLD_GID_T_PTR}
    },
#endif
#ifdef SYS_getresgid32
    {
        .nr = SYS_getresgid32,
        .name = "getresgid32",
        .n_params = 3,
        .params = {GID_T_PTR, GID_T_PTR, GID_T_PTR}
    },
#endif
#ifdef SYS_getresuid
    {
        .nr = SYS_getresuid,
        .name = "getresuid",
        .n_params = 3,
        .params = {OLD_UID_T_PTR, OLD_UID_T_PTR, OLD_UID_T_PTR}
    },
#endif
#ifdef SYS_getresuid32
    {
        .nr = SYS_getresuid32,
        .name = "getresuid32",
        .n_params = 3,
        .params = {UID_T_PTR, UID_T_PTR, UID_T_PTR}
    },
#endif
#ifdef SYS_getrlimit
    {
        .nr = SYS_getrlimit,
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
    {
        .nr = SYS_get_robust_list,
        .name = "get_robust_list",
        .n_params = 3,
        .params = {INT, STRUCT_ROBUST_LIST_HEAD_PTR_PTR, SIZE_T_PTR}
    },
#endif
#ifdef SYS_getrusage
    {
        .nr = SYS_getrusage,
        .name = "getrusage",
        .n_params = 2,
        .params = {INT, STRUCT_RUSAGE_PTR}
    },
#endif
#ifdef SYS_getsid
    {
        .nr = SYS_getsid,
        .name = "getsid",
        .n_params = 1,
        .params = {PID_T}
    },
#endif
#ifdef SYS_getsockname
    {
        .nr = SYS_getsockname,
        .name = "getsockname",
        .n_params = 3,
        .params = {INT, STRUCT_SOCKADDR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_getsockopt
    {
        .nr = SYS_getsockopt,
        .name = "getsockopt",
        .n_params = 5,
        .params = {INT, INT, INT, CHAR_PTR, INT_PTR}
    },
#endif
#ifdef SYS_get_thread_area
    {
        .nr = SYS_get_thread_area,
        .name = "get_thread_area",
        .n_params = 1,
        .params = {STRUCT_USER_DESC_PTR}
    },
#endif
#ifdef SYS_gettid
    {
        .nr = SYS_gettid,
        .name = "gettid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_gettimeofday
    {
        .nr = SYS_gettimeofday,
        .name = "gettimeofday",
        .n_params = 2,
        .params = {STRUCT___KERNEL_OLD_TIMEVAL_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_getuid
    {
        .nr = SYS_getuid,
        .name = "getuid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getuid32
    {
        .nr = SYS_getuid32,
        .name = "getuid32",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getxattr
    {
        .nr = SYS_getxattr,
        .name = "getxattr",
        .n_params = 4,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_getxgid
    {
        .nr = SYS_getxgid,
        .name = "getxgid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getxpid
    {
        .nr = SYS_getxpid,
        .name = "getxpid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_getxuid
    {
        .nr = SYS_getxuid,
        .name = "getxuid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_init_module
    {
        .nr = SYS_init_module,
        .name = "init_module",
        .n_params = 3,
        .params = {VOID_PTR, UNSIGNED_LONG, CHAR_PTR}
    },
#endif
#ifdef SYS_inotify_add_watch
    {
        .nr = SYS_inotify_add_watch,
        .name = "inotify_add_watch",
        .n_params = 3,
        .params = {INT, CHAR_PTR, U32}
    },
#endif
#ifdef SYS_inotify_init
    {
        .nr = SYS_inotify_init,
        .name = "inotify_init",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_inotify_init1
    {
        .nr = SYS_inotify_init1,
        .name = "inotify_init1",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_inotify_rm_watch
    {
        .nr = SYS_inotify_rm_watch,
        .name = "inotify_rm_watch",
        .n_params = 2,
        .params = {INT, __S32}
    },
#endif
#ifdef SYS_io_cancel
    {
        .nr = SYS_io_cancel,
        .name = "io_cancel",
        .n_params = 3,
        .params = {AIO_CONTEXT_T, STRUCT_IOCB_PTR, STRUCT_IO_EVENT_PTR}
    },
#endif
#ifdef SYS_ioctl
    {
        .nr = SYS_ioctl,
        .name = "ioctl",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_io_destroy
    {
        .nr = SYS_io_destroy,
        .name = "io_destroy",
        .n_params = 1,
        .params = {AIO_CONTEXT_T}
    },
#endif
#ifdef SYS_io_getevents
    {
        .nr = SYS_io_getevents,
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
    {
        .nr = SYS_ioperm,
        .name = "ioperm",
        .n_params = 3,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, INT}
    },
#endif
#ifdef SYS_io_pgetevents
    {
        .nr = SYS_io_pgetevents,
        .name = "io_pgetevents",
        .n_params = 6,
        .params = {AIO_CONTEXT_T, LONG, LONG, STRUCT_IO_EVENT_PTR,
            STRUCT_OLD_TIMESPEC32_PTR, STRUCT___AIO_SIGSET_PTR}
    },
#endif
#ifdef SYS_io_pgetevents_time64
    {
        .nr = SYS_io_pgetevents_time64,
        .name = "io_pgetevents",
        .n_params = 6,
        .params = {AIO_CONTEXT_T, LONG, LONG, STRUCT_IO_EVENT_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR, STRUCT___AIO_SIGSET_PTR}
    },
#endif
#ifdef SYS_iopl
    {
        .nr = SYS_iopl,
        .name = "iopl",
        .n_params = 1,
        .params = {UNSIGNED_INT}
    },
#endif
#ifdef SYS_ioprio_get
    {
        .nr = SYS_ioprio_get,
        .name = "ioprio_get",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_ioprio_set
    {
        .nr = SYS_ioprio_set,
        .name = "ioprio_set",
        .n_params = 3,
        .params = {INT, INT, INT}
    },
#endif
#ifdef SYS_io_setup
    {
        .nr = SYS_io_setup,
        .name = "io_setup",
        .n_params = 2,
        .params = {UNSIGNED, AIO_CONTEXT_T_PTR}
    },
#endif
#ifdef SYS_io_submit
    {
        .nr = SYS_io_submit,
        .name = "io_submit",
        .n_params = 3,
        .params = {AIO_CONTEXT_T, LONG, STRUCT_IOCB_PTR_PTR}
    },
#endif
#ifdef SYS_io_uring_enter
    {
        .nr = SYS_io_uring_enter,
        .name = "io_uring_enter",
        .n_params = 6,
        .params = {UNSIGNED_INT, U32, U32, U32, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_io_uring_register
    {
        .nr = SYS_io_uring_register,
        .name = "io_uring_register",
        .n_params = 4,
        .params = {UNSIGNED_INT, UNSIGNED_INT, VOID_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_io_uring_setup
    {
        .nr = SYS_io_uring_setup,
        .name = "io_uring_setup",
        .n_params = 2,
        .params = {U32, STRUCT_IO_URING_PARAMS_PTR}
    },
#endif
#ifdef SYS_ipc
    {
        .nr = SYS_ipc,
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
    {
        .nr = SYS_kcmp,
        .name = "kcmp",
        .n_params = 5,
        .params = {PID_T, PID_T, INT, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_kern_features
    {
        .nr = SYS_kern_features,
        .name = "kern_features",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_kexec_file_load
    {
        .nr = SYS_kexec_file_load,
        .name = "kexec_file_load",
        .n_params = 5,
        .params = {INT, INT, UNSIGNED_LONG, CHAR_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_kexec_load
    {
        .nr = SYS_kexec_load,
        .name = "kexec_load",
        .n_params = 4,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, STRUCT_KEXEC_SEGMENT_PTR,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_keyctl
    {
        .nr = SYS_keyctl,
        .name = "keyctl",
        .n_params = 5,
        .params = {INT, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_kill
    {
        .nr = SYS_kill,
        .name = "kill",
        .n_params = 2,
        .params = {PID_T, INT}
    },
#endif
#ifdef SYS_lchown
    {
        .nr = SYS_lchown,
        .name = "lchown",
        .n_params = 3,
        .params = {CHAR_PTR, OLD_UID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_lchown32
    {
        .nr = SYS_lchown32,
        .name = "lchown32",
        .n_params = 3,
        .params = {CHAR_PTR, UID_T, GID_T}
    },
#endif
#ifdef SYS_lgetxattr
    {
        .nr = SYS_lgetxattr,
        .name = "lgetxattr",
        .n_params = 4,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_link
    {
        .nr = SYS_link,
        .name = "link",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_linkat
    {
        .nr = SYS_linkat,
        .name = "linkat",
        .n_params = 5,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_listen
    {
        .nr = SYS_listen,
        .name = "listen",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_listxattr
    {
        .nr = SYS_listxattr,
        .name = "listxattr",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_llistxattr
    {
        .nr = SYS_llistxattr,
        .name = "llistxattr",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_llseek
    {
        .nr = SYS_llseek,
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
    {
        .nr = SYS__llseek,
        .name = "_llseek",
        .n_params = 5,
        .params = {UNSIGNED_INT, UNSIGNED_LONG, UNSIGNED_LONG, LOFF_T,
            UNSIGNED_INT}
    },
#endif
#ifdef SYS_lremovexattr
    {
        .nr = SYS_lremovexattr,
        .name = "lremovexattr",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_lseek
    {
        .nr = SYS_lseek,
        .name = "lseek",
        .n_params = 3,
        .params = {UNSIGNED_INT, OFF_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_lsetxattr
    {
        .nr = SYS_lsetxattr,
        .name = "lsetxattr",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_oldlstat
    {
        .nr = SYS_oldlstat,
        .name = "oldlstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT___OLD_KERNEL_STAT_PTR}
    },
#endif
#ifdef SYS_lstat64
    {
        .nr = SYS_lstat64,
        .name = "lstat64",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT64_PTR}
    },
#endif
#ifdef SYS_madvise
    {
        .nr = SYS_madvise,
        .name = "madvise",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, INT}
    },
#endif
#ifdef SYS_mbind
    {
        .nr = SYS_mbind,
        .name = "mbind",
        .n_params = 6,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG_PTR, UNSIGNED_LONG, UNSIGNED_INT}
    },
#endif
#ifdef SYS_membarrier
    {
        .nr = SYS_membarrier,
        .name = "membarrier",
        .n_params = 3,
        .params = {INT, UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_memfd_create
    {
        .nr = SYS_memfd_create,
        .name = "memfd_create",
        .n_params = 2,
        .params = {CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_memory_ordering
    {
        .nr = SYS_memory_ordering,
        .name = "memory_ordering",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_migrate_pages
    {
        .nr = SYS_migrate_pages,
        .name = "migrate_pages",
        .n_params = 4,
        .params = {PID_T, UNSIGNED_LONG, UNSIGNED_LONG_PTR, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_mincore
    {
        .nr = SYS_mincore,
        .name = "mincore",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, UNSIGNED_CHAR_PTR}
    },
#endif
#ifdef SYS_mkdir
    {
        .nr = SYS_mkdir,
        .name = "mkdir",
        .n_params = 2,
        .params = {CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_mkdirat
    {
        .nr = SYS_mkdirat,
        .name = "mkdirat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UMODE_T}
    },
#endif
#ifdef SYS_mknod
    {
        .nr = SYS_mknod,
        .name = "mknod",
        .n_params = 3,
        .params = {CHAR_PTR, UMODE_T, UNSIGNED}
    },
#endif
#ifdef SYS_mknodat
    {
        .nr = SYS_mknodat,
        .name = "mknodat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, UMODE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_mlock
    {
        .nr = SYS_mlock,
        .name = "mlock",
        .n_params = 2,
        .params = {UNSIGNED_LONG, SIZE_T}
    },
#endif
#ifdef SYS_mlock2
    {
        .nr = SYS_mlock2,
        .name = "mlock2",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, INT}
    },
#endif
#ifdef SYS_mlockall
    {
        .nr = SYS_mlockall,
        .name = "mlockall",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_mmap
    {
        .nr = SYS_mmap,
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
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
#endif
    },
#endif
#ifdef SYS_mmap2
    {
        .nr = SYS_mmap2,
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
    {
        .nr = SYS_modify_ldt,
        .name = "modify_ldt",
        .n_params = 3,
        .params = {INT, VOID_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_mount
    {
        .nr = SYS_mount,
        .name = "mount",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, CHAR_PTR, UNSIGNED_LONG, VOID_PTR}
    },
#endif
#ifdef SYS_mount_setattr
    {
        .nr = SYS_mount_setattr,
        .name = "mount_setattr",
        .n_params = 5,
        .params = {INT, CHAR_PTR, UNSIGNED_INT, STRUCT_MOUNT_ATTR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_move_mount
    {
        .nr = SYS_move_mount,
        .name = "move_mount",
        .n_params = 5,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_move_pages
    {
        .nr = SYS_move_pages,
        .name = "move_pages",
        .n_params = 6,
        .params = {PID_T, UNSIGNED_LONG, VOID_PTR_PTR, INT_PTR, INT_PTR, INT}
    },
#endif
#ifdef SYS_mprotect
    {
        .nr = SYS_mprotect,
        .name = "mprotect",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_mq_getsetattr
    {
        .nr = SYS_mq_getsetattr,
        .name = "mq_getsetattr",
        .n_params = 3,
        .params = {MQD_T, STRUCT_MQ_ATTR_PTR, STRUCT_MQ_ATTR_PTR}
    },
#endif
#ifdef SYS_mq_notify
    {
        .nr = SYS_mq_notify,
        .name = "mq_notify",
        .n_params = 2,
        .params = {MQD_T, STRUCT_SIGEVENT_PTR}
    },
#endif
#ifdef SYS_mq_open
    {
        .nr = SYS_mq_open,
        .name = "mq_open",
        .n_params = 4,
        .params = {CHAR_PTR, INT, UMODE_T, STRUCT_MQ_ATTR_PTR}
    },
#endif
#ifdef SYS_mq_timedreceive
    {
        .nr = SYS_mq_timedreceive,
        .name = "mq_timedreceive",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, UNSIGNED_INT, UNSIGNED_INT_PTR,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_mq_timedreceive_time64
    {
        .nr = SYS_mq_timedreceive_time64,
        .name = "mq_timedreceive",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, SIZE_T, UNSIGNED_INT_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_mq_timedsend
    {
        .nr = SYS_mq_timedsend,
        .name = "mq_timedsend",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, UNSIGNED_INT, UNSIGNED_INT,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_mq_timedsend_time64
    {
        .nr = SYS_mq_timedsend_time64,
        .name = "mq_timedsend",
        .n_params = 5,
        .params = {MQD_T, CHAR_PTR, SIZE_T, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_mq_unlink
    {
        .nr = SYS_mq_unlink,
        .name = "mq_unlink",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_mremap
    {
        .nr = SYS_mremap,
        .name = "mremap",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_msgctl
    {
        .nr = SYS_msgctl,
        .name = "msgctl",
        .n_params = 3,
        .params = {INT, INT, STRUCT_MSQID_DS_PTR}
    },
#endif
#ifdef SYS_msgget
    {
        .nr = SYS_msgget,
        .name = "msgget",
        .n_params = 2,
        .params = {KEY_T, INT}
    },
#endif
#ifdef SYS_msgrcv
    {
        .nr = SYS_msgrcv,
        .name = "msgrcv",
        .n_params = 5,
        .params = {INT, STRUCT_MSGBUF_PTR, SIZE_T, LONG, INT}
    },
#endif
#ifdef SYS_msgsnd
    {
        .nr = SYS_msgsnd,
        .name = "msgsnd",
        .n_params = 4,
        .params = {INT, STRUCT_MSGBUF_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_msync
    {
        .nr = SYS_msync,
        .name = "msync",
        .n_params = 3,
        .params = {UNSIGNED_LONG, SIZE_T, INT}
    },
#endif
#ifdef SYS_munlock
    {
        .nr = SYS_munlock,
        .name = "munlock",
        .n_params = 2,
        .params = {UNSIGNED_LONG, SIZE_T}
    },
#endif
#ifdef SYS_munlockall
    {
        .nr = SYS_munlockall,
        .name = "munlockall",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_munmap
    {
        .nr = SYS_munmap,
        .name = "munmap",
        .n_params = 2,
        .params = {UNSIGNED_LONG, SIZE_T}
    },
#endif
#ifdef SYS_name_to_handle_at
    {
        .nr = SYS_name_to_handle_at,
        .name = "name_to_handle_at",
        .n_params = 5,
        .params = {INT, CHAR_PTR, STRUCT_FILE_HANDLE_PTR, INT_PTR, INT}
    },
#endif
#ifdef SYS_nanosleep
    {
        .nr = SYS_nanosleep,
        .name = "nanosleep",
        .n_params = 2,
        .params = {STRUCT_OLD_TIMESPEC32_PTR, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_nanosleep_time64
    {
        .nr = SYS_nanosleep_time64,
        .name = "nanosleep",
        .n_params = 2,
        .params = {STRUCT___KERNEL_TIMESPEC_PTR, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_fstat
    {
        .nr = SYS_fstat,
        .name = "fstat",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_STAT_PTR}
    },
#endif
#ifdef SYS_newfstatat
    {
        .nr = SYS_newfstatat,
        .name = "newfstatat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT_STAT_PTR, INT}
    },
#endif
#ifdef SYS_lstat
    {
        .nr = SYS_lstat,
        .name = "lstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT_PTR}
    },
#endif
#ifdef SYS_stat
    {
        .nr = SYS_stat,
        .name = "stat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT_PTR}
    },
#endif
#ifdef SYS_uname
    {
        .nr = SYS_uname,
        .name = "uname",
        .n_params = 1,
        .params = {STRUCT_NEW_UTSNAME_PTR}
    },
#endif
#ifdef SYS_nice
    {
        .nr = SYS_nice,
        .name = "nice",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_ni_syscall
    {
        .nr = SYS_ni_syscall,
        .name = "ni_syscall",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_readdir
    {
        .nr = SYS_readdir,
        .name = "readdir",
        .n_params = 3,
        .params = {UNSIGNED_INT, STRUCT_OLD_LINUX_DIRENT_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS__newselect
    {
        .nr = SYS__newselect,
        .name = "_newselect",
        .n_params = 1,
        .params = {STRUCT_SEL_ARG_STRUCT_PTR}
    },
#endif
#ifdef SYS_oldumount
    {
        .nr = SYS_oldumount,
        .name = "oldumount",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_oldolduname
    {
        .nr = SYS_oldolduname,
        .name = "oldolduname",
        .n_params = 1,
        .params = {STRUCT_OLDOLD_UTSNAME_PTR}
    },
#endif
#ifdef SYS_open
    {
        .nr = SYS_open,
        .name = "open",
        .n_params = 3,
        .params = {CHAR_PTR, INT, UMODE_T}
    },
#endif
#ifdef SYS_openat
    {
        .nr = SYS_openat,
        .name = "openat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, INT, UMODE_T}
    },
#endif
#ifdef SYS_openat2
    {
        .nr = SYS_openat2,
        .name = "openat2",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT_OPEN_HOW_PTR, SIZE_T}
    },
#endif
#ifdef SYS_open_by_handle_at
    {
        .nr = SYS_open_by_handle_at,
        .name = "open_by_handle_at",
        .n_params = 3,
        .params = {INT, STRUCT_FILE_HANDLE_PTR, INT}
    },
#endif
#ifdef SYS_open_tree
    {
        .nr = SYS_open_tree,
        .name = "open_tree",
        .n_params = 3,
        .params = {INT, CHAR_PTR, UNSIGNED}
    },
#endif
#ifdef SYS_osf_sbrk
    {
        .nr = SYS_osf_sbrk,
        .name = "osf_sbrk",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_fstat
    {
        .nr = SYS_osf_fstat,
        .name = "osf_fstat",
        .n_params = 2,
        .params = {INT, STRUCT_OSF_STAT_PTR}
    },
#endif
#ifdef SYS_osf_fstatfs
    {
        .nr = SYS_osf_fstatfs,
        .name = "osf_fstatfs",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_OSF_STATFS_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_fstatfs64
    {
        .nr = SYS_osf_fstatfs64,
        .name = "osf_fstatfs64",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_OSF_STATFS64_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_getdirentries
    {
        .nr = SYS_osf_getdirentries,
        .name = "osf_getdirentries",
        .n_params = 4,
        .params = {UNSIGNED_INT, STRUCT_OSF_DIRENT_PTR, UNSIGNED_INT, LONG_PTR}
    },
#endif
#ifdef SYS_osf_getdomainname
    {
        .nr = SYS_osf_getdomainname,
        .name = "osf_getdomainname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_osf_getrusage
    {
        .nr = SYS_osf_getrusage,
        .name = "osf_getrusage",
        .n_params = 2,
        .params = {INT, STRUCT_RUSAGE32_PTR}
    },
#endif
#ifdef SYS_osf_getsysinfo
    {
        .nr = SYS_osf_getsysinfo,
        .name = "osf_getsysinfo",
        .n_params = 5,
        .params = {UNSIGNED_LONG, VOID_PTR, UNSIGNED_LONG, INT_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_gettimeofday
    {
        .nr = SYS_osf_gettimeofday,
        .name = "osf_gettimeofday",
        .n_params = 2,
        .params = {STRUCT_TIMEVAL32_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_osf_lstat
    {
        .nr = SYS_osf_lstat,
        .name = "osf_lstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_OSF_STAT_PTR}
    },
#endif
#ifdef SYS_osf_mount
    {
        .nr = SYS_osf_mount,
        .name = "osf_mount",
        .n_params = 4,
        .params = {UNSIGNED_LONG, CHAR_PTR, INT, VOID_PTR}
    },
#endif
#ifdef SYS_osf_proplist_syscall
    {
        .nr = SYS_osf_proplist_syscall,
        .name = "osf_proplist_syscall",
        .n_params = 2,
        .params = {ENUM_PL_CODE, UNION_PL_ARGS_PTR}
    },
#endif
#ifdef SYS_osf_select
    {
        .nr = SYS_osf_select,
        .name = "osf_select",
        .n_params = 5,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT_TIMEVAL32_PTR}
    },
#endif
#ifdef SYS_osf_set_program_attributes
    {
        .nr = SYS_osf_set_program_attributes,
        .name = "osf_set_program_attributes",
        .n_params = 4,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_setsysinfo
    {
        .nr = SYS_osf_setsysinfo,
        .name = "osf_setsysinfo",
        .n_params = 5,
        .params = {UNSIGNED_LONG, VOID_PTR, UNSIGNED_LONG, INT_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_osf_settimeofday
    {
        .nr = SYS_osf_settimeofday,
        .name = "osf_settimeofday",
        .n_params = 2,
        .params = {STRUCT_TIMEVAL32_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_osf_old_sigaction
    {
        .nr = SYS_osf_sigaction,
        .name = "SYS_osf_old_sigaction",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_osf_sigprocmask
    {
        .nr = SYS_osf_sigprocmask,
        .name = "osf_sigprocmask",
        .n_params = 2,
        .params = {INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_sigstack
    {
        .nr = SYS_osf_sigstack,
        .name = "osf_sigstack",
        .n_params = 2,
        .params = {STRUCT_SIGSTACK_PTR, STRUCT_SIGSTACK_PTR}
    },
#endif
#ifdef SYS_osf_stat
    {
        .nr = SYS_osf_stat,
        .name = "osf_stat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_OSF_STAT_PTR}
    },
#endif
#ifdef SYS_osf_statfs
    {
        .nr = SYS_osf_statfs,
        .name = "osf_statfs",
        .n_params = 3,
        .params = {CHAR_PTR, STRUCT_OSF_STATFS_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_statfs64
    {
        .nr = SYS_osf_statfs64,
        .name = "osf_statfs64",
        .n_params = 3,
        .params = {CHAR_PTR, STRUCT_OSF_STATFS64_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_osf_sysinfo
    {
        .nr = SYS_osf_sysinfo,
        .name = "osf_sysinfo",
        .n_params = 3,
        .params = {INT, CHAR_PTR, LONG}
    },
#endif
#ifdef SYS_osf_usleep_thread
    {
        .nr = SYS_osf_usleep_thread,
        .name = "osf_usleep_thread",
        .n_params = 2,
        .params = {STRUCT_TIMEVAL32_PTR, STRUCT_TIMEVAL32_PTR}
    },
#endif
#ifdef SYS_osf_utimes
    {
        .nr = SYS_osf_utimes,
        .name = "osf_utimes",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_TIMEVAL32_PTR}
    },
#endif
#ifdef SYS_osf_utsname
    {
        .nr = SYS_osf_utsname,
        .name = "osf_utsname",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_osf_wait4
    {
        .nr = SYS_osf_wait4,
        .name = "osf_wait4",
        .n_params = 4,
        .params = {PID_T, INT_PTR, INT, STRUCT_RUSAGE32_PTR}
    },
#endif
#ifdef SYS_pause
    {
        .nr = SYS_pause,
        .name = "pause",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_pciconfig_iobase
    {
        .nr = SYS_pciconfig_iobase,
        .name = "pciconfig_iobase",
        .n_params = 3,
        .params = {LONG, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pciconfig_read
    {
        .nr = SYS_pciconfig_read,
        .name = "pciconfig_read",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            VOID_PTR}
    },
#endif
#ifdef SYS_pciconfig_write
    {
        .nr = SYS_pciconfig_write,
        .name = "pciconfig_write",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            VOID_PTR}
    },
#endif
#ifdef SYS_perf_event_open
    {
        .nr = SYS_perf_event_open,
        .name = "perf_event_open",
        .n_params = 5,
        .params = {STRUCT_PERF_EVENT_ATTR_PTR, PID_T, INT, INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_personality
    {
        .nr = SYS_personality,
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
    {
        .nr = SYS_pidfd_getfd,
        .name = "pidfd_getfd",
        .n_params = 3,
        .params = {INT, INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_pidfd_open
    {
        .nr = SYS_pidfd_open,
        .name = "pidfd_open",
        .n_params = 2,
        .params = {PID_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_pidfd_send_signal
    {
        .nr = SYS_pidfd_send_signal,
        .name = "pidfd_send_signal",
        .n_params = 4,
        .params = {INT, INT, SIGINFO_T_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_pipe
    {
        .nr = SYS_pipe,
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
    {
        .nr = SYS_pipe2,
        .name = "pipe2",
        .n_params = 2,
        .params = {INT_PTR, INT}
    },
#endif
#ifdef SYS_pivot_root
    {
        .nr = SYS_pivot_root,
        .name = "pivot_root",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_pkey_alloc
    {
        .nr = SYS_pkey_alloc,
        .name = "pkey_alloc",
        .n_params = 2,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pkey_free
    {
        .nr = SYS_pkey_free,
        .name = "pkey_free",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_pkey_mprotect
    {
        .nr = SYS_pkey_mprotect,
        .name = "pkey_mprotect",
        .n_params = 4,
        .params = {UNSIGNED_LONG, SIZE_T, UNSIGNED_LONG, INT}
    },
#endif
#ifdef SYS_poll
    {
        .nr = SYS_poll,
        .name = "poll",
        .n_params = 3,
        .params = {STRUCT_POLLFD_PTR, UNSIGNED_INT, INT}
    },
#endif
#ifdef SYS_ppoll
    {
        .nr = SYS_ppoll,
        .name = "ppoll",
        .n_params = 5,
        .params = {STRUCT_POLLFD_PTR, UNSIGNED_INT, STRUCT_OLD_TIMESPEC32_PTR,
            SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_ppoll_time64
    {
        .nr = SYS_ppoll_time64,
        .name = "ppoll",
        .n_params = 5,
        .params = {STRUCT_POLLFD_PTR, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_prctl
    {
        .nr = SYS_prctl,
        .name = "prctl",
        .n_params = 5,
        .params = {INT, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pread64
    {
        .nr = SYS_pread64,
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
    {
        .nr = SYS_preadv,
        .name = "preadv",
        .n_params = 5,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_preadv2
    {
        .nr = SYS_preadv2,
        .name = "preadv2",
        .n_params = 6,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG, RWF_T}
    },
#endif
#ifdef SYS_prlimit64
    {
        .nr = SYS_prlimit64,
        .name = "prlimit64",
        .n_params = 4,
        .params = {PID_T, UNSIGNED_INT, STRUCT_RLIMIT64_PTR,
            STRUCT_RLIMIT64_PTR}
    },
#endif
#ifdef SYS_process_madvise
    {
        .nr = SYS_process_madvise,
        .name = "process_madvise",
        .n_params = 5,
        .params = {INT, STRUCT_IOVEC_PTR, SIZE_T, INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_process_vm_readv
    {
        .nr = SYS_process_vm_readv,
        .name = "process_vm_readv",
        .n_params = 6,
        .params = {PID_T, STRUCT_IOVEC_PTR, UNSIGNED_LONG, STRUCT_IOVEC_PTR,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_process_vm_writev
    {
        .nr = SYS_process_vm_writev,
        .name = "process_vm_writev",
        .n_params = 6,
        .params = {PID_T, STRUCT_IOVEC_PTR, UNSIGNED_LONG, STRUCT_IOVEC_PTR,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pselect6
    {
        .nr = SYS_pselect6,
        .name = "pselect6",
        .n_params = 6,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT_OLD_TIMESPEC32_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_pselect6_time64
    {
        .nr = SYS_pselect6_time64,
        .name = "pselect6",
        .n_params = 6,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT___KERNEL_TIMESPEC_PTR, VOID_PTR}
    },
#endif
#ifdef SYS_ptrace
    {
        .nr = SYS_ptrace,
        .name = "ptrace",
        .n_params = 4,
        .params = {LONG, LONG, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pwrite64
    {
        .nr = SYS_pwrite64,
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
    {
        .nr = SYS_pwritev,
        .name = "pwritev",
        .n_params = 5,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_pwritev2
    {
        .nr = SYS_pwritev2,
        .name = "pwritev2",
        .n_params = 6,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG,
            UNSIGNED_LONG, UNSIGNED_LONG, RWF_T}
    },
#endif
#ifdef SYS_quotactl
    {
        .nr = SYS_quotactl,
        .name = "quotactl",
        .n_params = 4,
        .params = {UNSIGNED_INT, CHAR_PTR, QID_T, VOID_PTR}
    },
#endif
#ifdef SYS_read
    {
        .nr = SYS_read,
        .name = "read",
        .n_params = 3,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T}
    },
#endif
#ifdef SYS_readahead
    {
        .nr = SYS_readahead,
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
    {
        .nr = SYS_readlink,
        .name = "readlink",
        .n_params = 3,
        .params = {CHAR_PTR, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_readlinkat
    {
        .nr = SYS_readlinkat,
        .name = "readlinkat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_readv
    {
        .nr = SYS_readv,
        .name = "readv",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_reboot
    {
        .nr = SYS_reboot,
        .name = "reboot",
        .n_params = 4,
        .params = {INT, INT, UNSIGNED_INT, VOID_PTR}
    },
#endif
#ifdef SYS_recv
    {
        .nr = SYS_recv,
        .name = "recv",
        .n_params = 4,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_recvfrom
    {
        .nr = SYS_recvfrom,
        .name = "recvfrom",
        .n_params = 6,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT, STRUCT_SOCKADDR_PTR,
            INT_PTR}
    },
#endif
#ifdef SYS_recvmmsg
    {
        .nr = SYS_recvmmsg,
        .name = "recvmmsg",
        .n_params = 5,
        .params = {INT, STRUCT_MMSGHDR_PTR, UNSIGNED_INT, UNSIGNED_INT,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_recvmmsg_time64
    {
        .nr = SYS_recvmmsg_time64,
        .name = "recvmmsg",
        .n_params = 5,
        .params = {INT, STRUCT_MMSGHDR_PTR, UNSIGNED_INT, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_recvmsg
    {
        .nr = SYS_recvmsg,
        .name = "recvmsg",
        .n_params = 3,
        .params = {INT, STRUCT_USER_MSGHDR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_remap_file_pages
    {
        .nr = SYS_remap_file_pages,
        .name = "remap_file_pages",
        .n_params = 5,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG, UNSIGNED_LONG,
            UNSIGNED_LONG}
    },
#endif
#ifdef SYS_removexattr
    {
        .nr = SYS_removexattr,
        .name = "removexattr",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_rename
    {
        .nr = SYS_rename,
        .name = "rename",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_renameat
    {
        .nr = SYS_renameat,
        .name = "renameat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR}
    },
#endif
#ifdef SYS_renameat2
    {
        .nr = SYS_renameat2,
        .name = "renameat2",
        .n_params = 5,
        .params = {INT, CHAR_PTR, INT, CHAR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_request_key
    {
        .nr = SYS_request_key,
        .name = "request_key",
        .n_params = 4,
        .params = {CHAR_PTR, CHAR_PTR, CHAR_PTR, KEY_SERIAL_T}
    },
#endif
#ifdef SYS_restart_syscall
    {
        .nr = SYS_restart_syscall,
        .name = "restart_syscall",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_riscv_flush_icache
    {
        .nr = SYS_riscv_flush_icache,
        .name = "riscv_flush_icache",
        .n_params = 3,
        .params = {UINTPTR_T, UINTPTR_T, UINTPTR_T}
    },
#endif
#ifdef SYS_rmdir
    {
        .nr = SYS_rmdir,
        .name = "rmdir",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_rseq
    {
        .nr = SYS_rseq,
        .name = "rseq",
        .n_params = 4,
        .params = {STRUCT_RSEQ_PTR, U32, INT, U32}
    },
#endif
#ifdef SYS_rtas
    {
        .nr = SYS_rtas,
        .name = "rtas",
        .n_params = 1,
        .params = {STRUCT_RTAS_ARGS_PTR}
    },
#endif
#ifdef SYS_rt_sigaction
    {
        .nr = SYS_rt_sigaction,
        .name = "rt_sigaction",
        .n_params = 4,
        .params = {INT, STRUCT_SIGACTION_PTR, STRUCT_SIGACTION_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigpending
    {
        .nr = SYS_rt_sigpending,
        .name = "rt_sigpending",
        .n_params = 2,
        .params = {SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigprocmask
    {
        .nr = SYS_rt_sigprocmask,
        .name = "rt_sigprocmask",
        .n_params = 4,
        .params = {INT, SIGSET_T_PTR, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigqueueinfo
    {
        .nr = SYS_rt_sigqueueinfo,
        .name = "rt_sigqueueinfo",
        .n_params = 3,
        .params = {PID_T, INT, SIGINFO_T_PTR}
    },
#endif
#ifdef SYS_rt_sigreturn
    {
        .nr = SYS_rt_sigreturn,
        .name = "rt_sigreturn",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_rt_sigsuspend
    {
        .nr = SYS_rt_sigsuspend,
        .name = "rt_sigsuspend",
        .n_params = 2,
        .params = {SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_rt_sigtimedwait
    {
        .nr = SYS_rt_sigtimedwait,
        .name = "rt_sigtimedwait",
        .n_params = 4,
        .params = {SIGSET_T_PTR, SIGINFO_T_PTR, STRUCT_OLD_TIMESPEC32_PTR,
            SIZE_T}
    },
#endif
#ifdef SYS_rt_sigtimedwait_time64
    {
        .nr = SYS_rt_sigtimedwait_time64,
        .name = "rt_sigtimedwait",
        .n_params = 4,
        .params = {SIGSET_T_PTR, SIGINFO_T_PTR, STRUCT___KERNEL_TIMESPEC_PTR,
            SIZE_T}
    },
#endif
#ifdef SYS_rt_tgsigqueueinfo
    {
        .nr = SYS_rt_tgsigqueueinfo,
        .name = "rt_tgsigqueueinfo",
        .n_params = 4,
        .params = {PID_T, PID_T, INT, SIGINFO_T_PTR}
    },
#endif
#ifdef SYS_s390_guarded_storage
    {
        .nr = SYS_s390_guarded_storage,
        .name = "s390_guarded_storage",
        .n_params = 2,
        .params = {INT, STRUCT_GS_CB_PTR}
    },
#endif
#ifdef SYS_s390_pci_mmio_read
    {
        .nr = SYS_s390_pci_mmio_read,
        .name = "s390_pci_mmio_read",
        .n_params = 3,
        .params = {UNSIGNED_LONG, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_s390_pci_mmio_write
    {
        .nr = SYS_s390_pci_mmio_write,
        .name = "s390_pci_mmio_write",
        .n_params = 3,
        .params = {UNSIGNED_LONG, VOID_PTR, SIZE_T}
    },
#endif
#ifdef SYS_s390_runtime_instr
    {
        .nr = SYS_s390_runtime_instr,
        .name = "s390_runtime_instr",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_s390_sthyi
    {
        .nr = SYS_s390_sthyi,
        .name = "s390_sthyi",
        .n_params = 4,
        .params = {UNSIGNED_LONG, VOID_PTR, U64_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_sched_getaffinity
    {
        .nr = SYS_sched_getaffinity,
        .name = "sched_getaffinity",
        .n_params = 3,
        .params = {PID_T, UNSIGNED_INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_sched_getattr
    {
        .nr = SYS_sched_getattr,
        .name = "sched_getattr",
        .n_params = 4,
        .params = {PID_T, STRUCT_SCHED_ATTR_PTR, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sched_getparam
    {
        .nr = SYS_sched_getparam,
        .name = "sched_getparam",
        .n_params = 2,
        .params = {PID_T, STRUCT_SCHED_PARAM_PTR}
    },
#endif
#ifdef SYS_sched_get_priority_max
    {
        .nr = SYS_sched_get_priority_max,
        .name = "sched_get_priority_max",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sched_get_priority_min
    {
        .nr = SYS_sched_get_priority_min,
        .name = "sched_get_priority_min",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sched_getscheduler
    {
        .nr = SYS_sched_getscheduler,
        .name = "sched_getscheduler",
        .n_params = 1,
        .params = {PID_T}
    },
#endif
#ifdef SYS_sched_rr_get_interval
    {
        .nr = SYS_sched_rr_get_interval,
        .name = "sched_rr_get_interval",
        .n_params = 2,
        .params = {PID_T, STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_sched_rr_get_interval_time64
    {
        .nr = SYS_sched_rr_get_interval_time64,
        .name = "sched_rr_get_interval",
        .n_params = 2,
        .params = {PID_T, STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_sched_setaffinity
    {
        .nr = SYS_sched_setaffinity,
        .name = "sched_setaffinity",
        .n_params = 3,
        .params = {PID_T, UNSIGNED_INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_sched_setattr
    {
        .nr = SYS_sched_setattr,
        .name = "sched_setattr",
        .n_params = 3,
        .params = {PID_T, STRUCT_SCHED_ATTR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sched_setparam
    {
        .nr = SYS_sched_setparam,
        .name = "sched_setparam",
        .n_params = 2,
        .params = {PID_T, STRUCT_SCHED_PARAM_PTR}
    },
#endif
#ifdef SYS_sched_setscheduler
    {
        .nr = SYS_sched_setscheduler,
        .name = "sched_setscheduler",
        .n_params = 3,
        .params = {PID_T, INT, STRUCT_SCHED_PARAM_PTR}
    },
#endif
#ifdef SYS_sched_yield
    {
        .nr = SYS_sched_yield,
        .name = "sched_yield",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_seccomp
    {
        .nr = SYS_seccomp,
        .name = "seccomp",
        .n_params = 3,
        .params = {UNSIGNED_INT, UNSIGNED_INT, VOID_PTR}
    },
#endif
#ifdef SYS_select
    {
        .nr = SYS_select,
        .name = "select",
        .n_params = 5,
        .params = {INT, FD_SET_PTR, FD_SET_PTR, FD_SET_PTR,
            STRUCT___KERNEL_OLD_TIMEVAL_PTR}
    },
#endif
#ifdef SYS_semctl
    {
        .nr = SYS_semctl,
        .name = "semctl",
        .n_params = 4,
        .params = {INT, INT, INT, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_semget
    {
        .nr = SYS_semget,
        .name = "semget",
        .n_params = 3,
        .params = {KEY_T, INT, INT}
    },
#endif
#ifdef SYS_semop
    {
        .nr = SYS_semop,
        .name = "semop",
        .n_params = 3,
        .params = {INT, STRUCT_SEMBUF_PTR, UNSIGNED}
    },
#endif
#ifdef SYS_semtimedop
    {
        .nr = SYS_semtimedop,
        .name = "semtimedop",
        .n_params = 4,
        .params = {INT, STRUCT_SEMBUF_PTR, UNSIGNED_INT,
            STRUCT_OLD_TIMESPEC32_PTR}
    },
#endif
#ifdef SYS_semtimedop_time64
    {
        .nr = SYS_semtimedop_time64,
        .name = "semtimedop",
        .n_params = 4,
        .params = {INT, STRUCT_SEMBUF_PTR, UNSIGNED_INT,
            STRUCT___KERNEL_TIMESPEC_PTR}
    },
#endif
#ifdef SYS_send
    {
        .nr = SYS_send,
        .name = "send",
        .n_params = 4,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sendfile
    {
        .nr = SYS_sendfile,
        .name = "sendfile",
        .n_params = 4,
        .params = {INT, INT, OFF_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_sendfile64
    {
        .nr = SYS_sendfile64,
        .name = "sendfile64",
        .n_params = 4,
        .params = {INT, INT, LOFF_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_sendmmsg
    {
        .nr = SYS_sendmmsg,
        .name = "sendmmsg",
        .n_params = 4,
        .params = {INT, STRUCT_MMSGHDR_PTR, UNSIGNED_INT, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sendmsg
    {
        .nr = SYS_sendmsg,
        .name = "sendmsg",
        .n_params = 3,
        .params = {INT, STRUCT_USER_MSGHDR_PTR, UNSIGNED_INT}
    },
#endif
#ifdef SYS_sendto
    {
        .nr = SYS_sendto,
        .name = "sendto",
        .n_params = 6,
        .params = {INT, VOID_PTR, SIZE_T, UNSIGNED_INT, STRUCT_SOCKADDR_PTR,
            INT}
    },
#endif
#ifdef SYS_setdomainname
    {
        .nr = SYS_setdomainname,
        .name = "setdomainname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_setfsgid
    {
        .nr = SYS_setfsgid,
        .name = "setfsgid",
        .n_params = 1,
        .params = {OLD_GID_T}
    },
#endif
#ifdef SYS_setfsgid32
    {
        .nr = SYS_setfsgid32,
        .name = "setfsgid32",
        .n_params = 1,
        .params = {GID_T}
    },
#endif
#ifdef SYS_setfsuid
    {
        .nr = SYS_setfsuid,
        .name = "setfsuid",
        .n_params = 1,
        .params = {OLD_UID_T}
    },
#endif
#ifdef SYS_setfsuid32
    {
        .nr = SYS_setfsuid32,
        .name = "setfsuid32",
        .n_params = 1,
        .params = {UID_T}
    },
#endif
#ifdef SYS_setgid
    {
        .nr = SYS_setgid,
        .name = "setgid",
        .n_params = 1,
        .params = {OLD_GID_T}
    },
#endif
#ifdef SYS_setgid32
    {
        .nr = SYS_setgid32,
        .name = "setgid32",
        .n_params = 1,
        .params = {GID_T}
    },
#endif
#ifdef SYS_setgroups
    {
        .nr = SYS_setgroups,
        .name = "setgroups32",
        .n_params = 2,
        .params = {INT, OLD_GID_T_PTR}
    },
#endif
#ifdef SYS_setgroups32
    {
        .nr = SYS_setgroups32,
        .name = "setgroups32",
        .n_params = 2,
        .params = {INT, GID_T_PTR}
    },
#endif
#ifdef SYS_sethae
    {
        .nr = SYS_sethae,
        .name = "sethae",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_sethostname
    {
        .nr = SYS_sethostname,
        .name = "sethostname",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_setitimer
    {
        .nr = SYS_setitimer,
        .name = "setitimer",
        .n_params = 3,
        .params = {INT, STRUCT___KERNEL_OLD_ITIMERVAL_PTR,
            STRUCT___KERNEL_OLD_ITIMERVAL_PTR}
    },
#endif
#ifdef SYS_set_mempolicy
    {
        .nr = SYS_set_mempolicy,
        .name = "set_mempolicy",
        .n_params = 3,
        .params = {INT, UNSIGNED_LONG_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_setns
    {
        .nr = SYS_setns,
        .name = "setns",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_setpgid
    {
        .nr = SYS_setpgid,
        .name = "setpgid",
        .n_params = 2,
        .params = {PID_T, PID_T}
    },
#endif
#ifdef SYS_setpriority
    {
        .nr = SYS_setpriority,
        .name = "setpriority",
        .n_params = 3,
        .params = {INT, INT, INT}
    },
#endif
#ifdef SYS_setregid
    {
        .nr = SYS_setregid,
        .name = "setregid",
        .n_params = 2,
        .params = {OLD_GID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_setregid32
    {
        .nr = SYS_setregid32,
        .name = "setregid32",
        .n_params = 2,
        .params = {GID_T, GID_T}
    },
#endif
#ifdef SYS_setresgid
    {
        .nr = SYS_setresgid,
        .name = "setresgid",
        .n_params = 3,
        .params = {OLD_GID_T, OLD_GID_T, OLD_GID_T}
    },
#endif
#ifdef SYS_setresgid32
    {
        .nr = SYS_setresgid32,
        .name = "setresgid32",
        .n_params = 3,
        .params = {GID_T, GID_T, GID_T}
    },
#endif
#ifdef SYS_setresuid
    {
        .nr = SYS_setresuid,
        .name = "setresuid",
        .n_params = 3,
        .params = {OLD_UID_T, OLD_UID_T, OLD_UID_T}
    },
#endif
#ifdef SYS_setresuid32
    {
        .nr = SYS_setresuid32,
        .name = "setresuid32",
        .n_params = 3,
        .params = {UID_T, UID_T, UID_T}
    },
#endif
#ifdef SYS_setreuid
    {
        .nr = SYS_setreuid,
        .name = "setreuid",
        .n_params = 2,
        .params = {OLD_UID_T, OLD_UID_T}
    },
#endif
#ifdef SYS_setreuid32
    {
        .nr = SYS_setreuid32,
        .name = "setreuid32",
        .n_params = 2,
        .params = {UID_T, UID_T}
    },
#endif
#ifdef SYS_setrlimit
    {
        .nr = SYS_setrlimit,
        .name = "setrlimit",
        .n_params = 2,
        .params = {UNSIGNED_INT, STRUCT_RLIMIT_PTR}
    },
#endif
#ifdef SYS_set_robust_list
    {
        .nr = SYS_set_robust_list,
        .name = "set_robust_list",
        .n_params = 2,
        .params = {STRUCT_ROBUST_LIST_HEAD_PTR, SIZE_T}
    },
#endif
#ifdef SYS_setsid
    {
        .nr = SYS_setsid,
        .name = "setsid",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_setsockopt
    {
        .nr = SYS_setsockopt,
        .name = "setsockopt",
        .n_params = 5,
        .params = {INT, INT, INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_set_thread_area
    {
        .nr = SYS_set_thread_area,
        .name = "set_thread_area",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_set_tid_address
    {
        .nr = SYS_set_tid_address,
        .name = "set_tid_address",
        .n_params = 1,
        .params = {INT_PTR}
    },
#endif
#ifdef SYS_settimeofday
    {
        .nr = SYS_settimeofday,
        .name = "settimeofday",
        .n_params = 2,
        .params = {STRUCT___KERNEL_OLD_TIMEVAL_PTR, STRUCT_TIMEZONE_PTR}
    },
#endif
#ifdef SYS_setuid
    {
        .nr = SYS_setuid,
        .name = "setuid",
        .n_params = 1,
        .params = {OLD_UID_T}
    },
#endif
#ifdef SYS_setuid32
    {
        .nr = SYS_setuid32,
        .name = "setuid32",
        .n_params = 1,
        .params = {UID_T}
    },
#endif
#ifdef SYS_setxattr
    {
        .nr = SYS_setxattr,
        .name = "setxattr",
        .n_params = 5,
        .params = {CHAR_PTR, CHAR_PTR, VOID_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_sgetmask
    {
        .nr = SYS_sgetmask,
        .name = "sgetmask",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_shmat
    {
        .nr = SYS_shmat,
        .name = "shmat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_shmctl
    {
        .nr = SYS_shmctl,
        .name = "shmctl",
        .n_params = 3,
        .params = {INT, INT, STRUCT_SHMID_DS_PTR}
    },
#endif
#ifdef SYS_shmdt
    {
        .nr = SYS_shmdt,
        .name = "shmdt",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_shmget
    {
        .nr = SYS_shmget,
        .name = "shmget",
        .n_params = 3,
        .params = {KEY_T, SIZE_T, INT}
    },
#endif
#ifdef SYS_shutdown
    {
        .nr = SYS_shutdown,
        .name = "shutdown",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_sigaction
    {
        .nr = SYS_sigaction,
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
    {
        .nr = SYS_sigaltstack,
        .name = "sigaltstack",
        .n_params = 2,
        .params = {STACK_T_PTR, STACK_T_PTR}
    },
#endif
#ifdef SYS_signal
    {
        .nr = SYS_signal,
        .name = "signal",
        .n_params = 2,
        .params = {INT, __SIGHANDLER_T}
    },
#endif
#ifdef SYS_signalfd
    {
        .nr = SYS_signalfd,
        .name = "signalfd",
        .n_params = 3,
        .params = {INT, SIGSET_T_PTR, SIZE_T}
    },
#endif
#ifdef SYS_signalfd4
    {
        .nr = SYS_signalfd4,
        .name = "signalfd4",
        .n_params = 4,
        .params = {INT, SIGSET_T_PTR, SIZE_T, INT}
    },
#endif
#ifdef SYS_sigpending
    {
        .nr = SYS_sigpending,
        .name = "sigpending",
        .n_params = 1,
        .params = {OLD_SIGSET_T_PTR}
    },
#endif
#ifdef SYS_sigprocmask
    {
        .nr = SYS_sigprocmask,
        .name = "sigprocmask",
        .n_params = 3,
        .params = {INT, OLD_SIGSET_T_PTR, OLD_SIGSET_T_PTR}
    },
#endif
#ifdef SYS_sigreturn
    {
        .nr = SYS_sigreturn,
        .name = "sigreturn",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_sigsuspend
    {
        .nr = SYS_sigsuspend,
        .name = "sigsuspend",
        .n_params = 1,
        .params = {OLD_SIGSET_T}
    },
#endif
#ifdef SYS_socket
    {
        .nr = SYS_socket,
        .name = "socket",
        .n_params = 3,
        .params = {INT, INT, INT}
    },
#endif
#ifdef SYS_socketcall
    {
        .nr = SYS_socketcall,
        .name = "socketcall",
        .n_params = 2,
        .params = {INT, UNSIGNED_LONG_PTR}
    },
#endif
#ifdef SYS_socketpair
    {
        .nr = SYS_socketpair,
        .name = "socketpair",
        .n_params = 4,
        .params = {INT, INT, INT, INT_PTR}
    },
#endif
#ifdef SYS_splice
    {
        .nr = SYS_splice,
        .name = "splice",
        .n_params = 6,
        .params = {INT, LOFF_T_PTR, INT, LOFF_T_PTR, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_spu_create
    {
        .nr = SYS_spu_create,
        .name = "spu_create",
        .n_params = 4,
        .params = {CHAR_PTR, UNSIGNED_INT, UMODE_T, INT}
    },
#endif
#ifdef SYS_spu_run
    {
        .nr = SYS_spu_run,
        .name = "spu_run",
        .n_params = 3,
        .params = {INT, __U32_PTR, __U32_PTR}
    },
#endif
#ifdef SYS_ssetmask
    {
        .nr = SYS_ssetmask,
        .name = "ssetmask",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_oldstat
    {
        .nr = SYS_oldstat,
        .name = "oldstat",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT___OLD_KERNEL_STAT_PTR}
    },
#endif
#ifdef SYS_stat64
    {
        .nr = SYS_stat64,
        .name = "stat64",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STAT64_PTR}
    },
#endif
#ifdef SYS_statfs
    {
        .nr = SYS_statfs,
        .name = "statfs",
        .n_params = 2,
        .params = {CHAR_PTR, STRUCT_STATFS_PTR}
    },
#endif
#ifdef SYS_statfs64
    {
        .nr = SYS_statfs64,
        .name = "statfs64",
        .n_params = 3,
        .params = {CHAR_PTR, SIZE_T, STRUCT_STATFS64_PTR}
    },
#endif
#ifdef SYS_statx
    {
        .nr = SYS_statx,
        .name = "statx",
        .n_params = 5,
        .params = {INT, CHAR_PTR, UNSIGNED, UNSIGNED_INT, STRUCT_STATX_PTR}
    },
#endif
#ifdef SYS_stime
    {
        .nr = SYS_stime,
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
    {
        .nr = SYS_subpage_prot,
        .name = "subpage_prot",
        .n_params = 3,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG, U32_PTR}
    },
#endif
#ifdef SYS_swapcontext
    {
        .nr = SYS_swapcontext,
        .name = "swapcontext",
        .n_params = 3,
        .params = {STRUCT_UCONTEXT_PTR, STRUCT_UCONTEXT_PTR, LONG}
    },
#endif
#ifdef SYS_swapoff
    {
        .nr = SYS_swapoff,
        .name = "swapoff",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_swapon
    {
        .nr = SYS_swapon,
        .name = "swapon",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_switch_endian
    {
        .nr = SYS_switch_endian,
        .name = "switch_endian",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_symlink
    {
        .nr = SYS_symlink,
        .name = "symlink",
        .n_params = 2,
        .params = {CHAR_PTR, CHAR_PTR}
    },
#endif
#ifdef SYS_symlinkat
    {
        .nr = SYS_symlinkat,
        .name = "symlinkat",
        .n_params = 3,
        .params = {CHAR_PTR, INT, CHAR_PTR}
    },
#endif
#ifdef SYS_sync
    {
        .nr = SYS_sync,
        .name = "sync",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_sync_file_range
    {
        .nr = SYS_sync_file_range,
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
    {
        .nr = SYS_sync_file_range2,
        .name = "sync_file_range2",
        .n_params = 4,
        .params = {INT, UNSIGNED_INT, LOFF_T, LOFF_T}
    },
#endif
#ifdef SYS_syncfs
    {
        .nr = SYS_syncfs,
        .name = "syncfs",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_sysfs
    {
        .nr = SYS_sysfs,
        .name = "sysfs",
        .n_params = 3,
        .params = {INT, UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_sysinfo
    {
        .nr = SYS_sysinfo,
        .name = "sysinfo",
        .n_params = 1,
        .params = {STRUCT_SYSINFO_PTR}
    },
#endif
#ifdef SYS_syslog
    {
        .nr = SYS_syslog,
        .name = "syslog",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_sysmips
    {
        .nr = SYS_sysmips,
        .name = "sysmips",
        .n_params = 3,
        .params = {LONG, LONG, LONG}
    },
#endif
#ifdef SYS_tee
    {
        .nr = SYS_tee,
        .name = "tee",
        .n_params = 4,
        .params = {INT, INT, SIZE_T, UNSIGNED_INT}
    },
#endif
#ifdef SYS_tgkill
    {
        .nr = SYS_tgkill,
        .name = "tgkill",
        .n_params = 3,
        .params = {PID_T, PID_T, INT}
    },
#endif
#ifdef SYS_time
    {
        .nr = SYS_time,
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
    {
        .nr = SYS_timer_create,
        .name = "timer_create",
        .n_params = 3,
        .params = {CLOCKID_T, STRUCT_SIGEVENT_PTR, TIMER_T_PTR}
    },
#endif
#ifdef SYS_timer_delete
    {
        .nr = SYS_timer_delete,
        .name = "timer_delete",
        .n_params = 1,
        .params = {TIMER_T}
    },
#endif
#ifdef SYS_timerfd_create
    {
        .nr = SYS_timerfd_create,
        .name = "timerfd_create",
        .n_params = 2,
        .params = {INT, INT}
    },
#endif
#ifdef SYS_timerfd_gettime
    {
        .nr = SYS_timerfd_gettime,
        .name = "timerfd_gettime",
        .n_params = 2,
        .params = {INT, STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timerfd_gettime64
    {
        .nr = SYS_timerfd_gettime64,
        .name = "timerfd_gettime",
        .n_params = 2,
        .params = {INT, STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_timerfd_settime
    {
        .nr = SYS_timerfd_settime,
        .name = "timerfd_settime",
        .n_params = 4,
        .params = {INT, INT, STRUCT_OLD_ITIMERSPEC32_PTR,
            STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timerfd_settime64
    {
        .nr = SYS_timerfd_settime64,
        .name = "timerfd_settime",
        .n_params = 4,
        .params = {INT, INT, STRUCT___KERNEL_ITIMERSPEC_PTR,
            STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_timer_getoverrun
    {
        .nr = SYS_timer_getoverrun,
        .name = "timer_getoverrun",
        .n_params = 1,
        .params = {TIMER_T}
    },
#endif
#ifdef SYS_timer_gettime
    {
        .nr = SYS_timer_gettime,
        .name = "timer_gettime",
        .n_params = 2,
        .params = {TIMER_T, STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timer_gettime64
    {
        .nr = SYS_timer_gettime64,
        .name = "timer_gettime",
        .n_params = 2,
        .params = {TIMER_T, STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_timer_settime
    {
        .nr = SYS_timer_settime,
        .name = "timer_settime",
        .n_params = 4,
        .params = {TIMER_T, INT, STRUCT_OLD_ITIMERSPEC32_PTR,
            STRUCT_OLD_ITIMERSPEC32_PTR}
    },
#endif
#ifdef SYS_timer_settime64
    {
        .nr = SYS_timer_settime64,
        .name = "timer_settime",
        .n_params = 4,
        .params = {TIMER_T, INT, STRUCT___KERNEL_ITIMERSPEC_PTR,
            STRUCT___KERNEL_ITIMERSPEC_PTR}
    },
#endif
#ifdef SYS_times
    {
        .nr = SYS_times,
        .name = "times",
        .n_params = 1,
        .params = {STRUCT_TMS_PTR}
    },
#endif
#ifdef SYS_tkill
    {
        .nr = SYS_tkill,
        .name = "tkill",
        .n_params = 2,
        .params = {PID_T, INT}
    },
#endif
#ifdef SYS_truncate
    {
        .nr = SYS_truncate,
        .name = "truncate",
        .n_params = 2,
        .params = {CHAR_PTR, LONG}
    },
#endif
#ifdef SYS_truncate64
    {
        .nr = SYS_truncate64,
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
    {
        .nr = SYS_umask,
        .name = "umask",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_umount
    {
        .nr = SYS_umount,
        .name = "umount",
        .n_params = 2,
        .params = {CHAR_PTR, INT}
    },
#endif
#ifdef SYS_olduname
    {
        .nr = SYS_olduname,
        .name = "olduname",
        .n_params = 1,
        .params = {STRUCT_OLD_UTSNAME_PTR}
    },
#endif
#ifdef SYS_unlink
    {
        .nr = SYS_unlink,
        .name = "unlink",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_unlinkat
    {
        .nr = SYS_unlinkat,
        .name = "unlinkat",
        .n_params = 3,
        .params = {INT, CHAR_PTR, INT}
    },
#endif
#ifdef SYS_unshare
    {
        .nr = SYS_unshare,
        .name = "unshare",
        .n_params = 1,
        .params = {UNSIGNED_LONG}
    },
#endif
#ifdef SYS_uselib
    {
        .nr = SYS_uselib,
        .name = "uselib",
        .n_params = 1,
        .params = {CHAR_PTR}
    },
#endif
#ifdef SYS_userfaultfd
    {
        .nr = SYS_userfaultfd,
        .name = "userfaultfd",
        .n_params = 1,
        .params = {INT}
    },
#endif
#ifdef SYS_ustat
    {
        .nr = SYS_ustat,
        .name = "ustat",
        .n_params = 2,
        .params = {UNSIGNED, STRUCT_USTAT_PTR}
    },
#endif
#ifdef SYS_utime
    {
        .nr = SYS_utime,
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
    {
        .nr = SYS_utimensat,
        .name = "utimensat",
        .n_params = 4,
        .params = {UNSIGNED_INT, CHAR_PTR, STRUCT_OLD_TIMESPEC32_PTR, INT}
    },
#endif
#ifdef SYS_utimensat_time64
    {
        .nr = SYS_utimensat_time64,
        .name = "utimensat",
        .n_params = 4,
        .params = {INT, CHAR_PTR, STRUCT___KERNEL_TIMESPEC_PTR, INT}
    },
#endif
#ifdef SYS_utimes
    {
        .nr = SYS_utimes,
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
    {
        .nr = SYS_utrap_install,
        .name = "utrap_install",
        .n_params = 5,
        .params = {UTRAP_ENTRY_T, UTRAP_HANDLER_T, UTRAP_HANDLER_T,
            UTRAP_HANDLER_T_PTR, UTRAP_HANDLER_T_PTR}
    },
#endif
#ifdef SYS_vfork
    {
        .nr = SYS_vfork,
        .name = "vfork",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_vhangup
    {
        .nr = SYS_vhangup,
        .name = "vhangup",
        .n_params = 0,
        .params = {}
    },
#endif
#ifdef SYS_vm86
    {
        .nr = SYS_vm86,
        .name = "vm86",
        .n_params = 2,
        .params = {UNSIGNED_LONG, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_vm86old
    {
        .nr = SYS_vm86old,
        .name = "vm86old",
        .n_params = 1,
        .params = {STRUCT_VM86_STRUCT_PTR}
    },
#endif
#ifdef SYS_vmsplice
    {
        .nr = SYS_vmsplice,
        .name = "vmsplice",
        .n_params = 4,
        .params = {INT, STRUCT_IOVEC_PTR, UNSIGNED_LONG, UNSIGNED_INT}
    },
#endif
#ifdef SYS_wait4
    {
        .nr = SYS_wait4,
        .name = "wait4",
        .n_params = 4,
        .params = {PID_T, INT_PTR, INT, STRUCT_RUSAGE_PTR}
    },
#endif
#ifdef SYS_waitid
    {
        .nr = SYS_waitid,
        .name = "waitid",
        .n_params = 5,
        .params = {INT, PID_T, STRUCT_SIGINFO_PTR, INT, STRUCT_RUSAGE_PTR}
    },
#endif
#ifdef SYS_waitpid
    {
        .nr = SYS_waitpid,
        .name = "waitpid",
        .n_params = 3,
        .params = {PID_T, INT_PTR, INT}
    },
#endif
#ifdef SYS_writev
    {
        .nr = SYS_writev,
        .name = "writev",
        .n_params = 3,
        .params = {UNSIGNED_LONG, STRUCT_IOVEC_PTR, UNSIGNED_LONG}
    },
#endif
#ifdef SYS_write
    {
        .nr = SYS_write,
        .name = "write",
        .n_params = 3,
        .params = {UNSIGNED_INT, CHAR_PTR, SIZE_T}
    }
#endif
};

#endif // _CTRACE_H_
