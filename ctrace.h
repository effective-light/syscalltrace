#ifndef _CTRACE_H_
#define _CTRACE_H_

#include <stdint.h>

#include <unistd.h>
#include <sys/syscall.h>

enum param_types {
    INT,
    STR
    // TODO: define all of the required types
};

typedef struct param_s {
    enum param_types type;
    uint64_t idx;
} param_t;

typedef struct syscall_s {
    uint64_t nr;
    char *name;
    param_t params[];
} syscall_t;

syscall_t syscalls[] = {
    { .nr = SYS_read, .name = "read" },
#ifdef SYS_FAST_atomic_update
    { .nr = SYS_FAST_atomic_update, .name = "FAST_atomic_update" },
#endif
#ifdef SYS_FAST_cmpxchg
    { .nr = SYS_FAST_cmpxchg, .name = "FAST_cmpxchg" },
#endif
#ifdef SYS_FAST_cmpxchg64
    { .nr = SYS_FAST_cmpxchg64, .name = "FAST_cmpxchg64" },
#endif
#ifdef SYS__llseek
    { .nr = SYS__llseek, .name = "_llseek" },
#endif
#ifdef SYS__newselect
    { .nr = SYS__newselect, .name = "_newselect" },
#endif
#ifdef SYS__sysctl
    { .nr = SYS__sysctl, .name = "_sysctl" },
#endif
#ifdef SYS_accept
    { .nr = SYS_accept, .name = "accept" },
#endif
#ifdef SYS_accept4
    { .nr = SYS_accept4, .name = "accept4" },
#endif
#ifdef SYS_access
    { .nr = SYS_access, .name = "access" },
#endif
#ifdef SYS_acct
    { .nr = SYS_acct, .name = "acct" },
#endif
#ifdef SYS_acl_get
    { .nr = SYS_acl_get, .name = "acl_get" },
#endif
#ifdef SYS_acl_set
    { .nr = SYS_acl_set, .name = "acl_set" },
#endif
#ifdef SYS_add_key
    { .nr = SYS_add_key, .name = "add_key" },
#endif
#ifdef SYS_adjtimex
    { .nr = SYS_adjtimex, .name = "adjtimex" },
#endif
#ifdef SYS_afs_syscall
    { .nr = SYS_afs_syscall, .name = "afs_syscall" },
#endif
#ifdef SYS_alarm
    { .nr = SYS_alarm, .name = "alarm" },
#endif
#ifdef SYS_alloc_hugepages
    { .nr = SYS_alloc_hugepages, .name = "alloc_hugepages" },
#endif
#ifdef SYS_arc_gettls
    { .nr = SYS_arc_gettls, .name = "arc_gettls" },
#endif
#ifdef SYS_arc_settls
    { .nr = SYS_arc_settls, .name = "arc_settls" },
#endif
#ifdef SYS_arc_usr_cmpxchg
    { .nr = SYS_arc_usr_cmpxchg, .name = "arc_usr_cmpxchg" },
#endif
#ifdef SYS_arch_prctl
    { .nr = SYS_arch_prctl, .name = "arch_prctl" },
#endif
#ifdef SYS_arm_fadvise64_64
    { .nr = SYS_arm_fadvise64_64, .name = "arm_fadvise64_64" },
#endif
#ifdef SYS_arm_sync_file_range
    { .nr = SYS_arm_sync_file_range, .name = "arm_sync_file_range" },
#endif
#ifdef SYS_atomic_barrier
    { .nr = SYS_atomic_barrier, .name = "atomic_barrier" },
#endif
#ifdef SYS_atomic_cmpxchg_32
    { .nr = SYS_atomic_cmpxchg_32, .name = "atomic_cmpxchg_32" },
#endif
#ifdef SYS_attrctl
    { .nr = SYS_attrctl, .name = "attrctl" },
#endif
#ifdef SYS_bdflush
    { .nr = SYS_bdflush, .name = "bdflush" },
#endif
#ifdef SYS_bind
    { .nr = SYS_bind, .name = "bind" },
#endif
#ifdef SYS_bpf
    { .nr = SYS_bpf, .name = "bpf" },
#endif
#ifdef SYS_break
    { .nr = SYS_break, .name = "break" },
#endif
#ifdef SYS_breakpoint
    { .nr = SYS_breakpoint, .name = "breakpoint" },
#endif
#ifdef SYS_brk
    { .nr = SYS_brk, .name = "brk" },
#endif
#ifdef SYS_cachectl
    { .nr = SYS_cachectl, .name = "cachectl" },
#endif
#ifdef SYS_cacheflush
    { .nr = SYS_cacheflush, .name = "cacheflush" },
#endif
#ifdef SYS_capget
    { .nr = SYS_capget, .name = "capget" },
#endif
#ifdef SYS_capset
    { .nr = SYS_capset, .name = "capset" },
#endif
#ifdef SYS_chdir
    { .nr = SYS_chdir, .name = "chdir" },
#endif
#ifdef SYS_chmod
    { .nr = SYS_chmod, .name = "chmod" },
#endif
#ifdef SYS_chown
    { .nr = SYS_chown, .name = "chown" },
#endif
#ifdef SYS_chown32
    { .nr = SYS_chown32, .name = "chown32" },
#endif
#ifdef SYS_chroot
    { .nr = SYS_chroot, .name = "chroot" },
#endif
#ifdef SYS_clock_adjtime
    { .nr = SYS_clock_adjtime, .name = "clock_adjtime" },
#endif
#ifdef SYS_clock_adjtime64
    { .nr = SYS_clock_adjtime64, .name = "clock_adjtime64" },
#endif
#ifdef SYS_clock_getres
    { .nr = SYS_clock_getres, .name = "clock_getres" },
#endif
#ifdef SYS_clock_getres_time64
    { .nr = SYS_clock_getres_time64, .name = "clock_getres_time64" },
#endif
#ifdef SYS_clock_gettime
    { .nr = SYS_clock_gettime, .name = "clock_gettime" },
#endif
#ifdef SYS_clock_gettime64
    { .nr = SYS_clock_gettime64, .name = "clock_gettime64" },
#endif
#ifdef SYS_clock_nanosleep
    { .nr = SYS_clock_nanosleep, .name = "clock_nanosleep" },
#endif
#ifdef SYS_clock_nanosleep_time64
    { .nr = SYS_clock_nanosleep_time64, .name = "clock_nanosleep_time64" },
#endif
#ifdef SYS_clock_settime
    { .nr = SYS_clock_settime, .name = "clock_settime" },
#endif
#ifdef SYS_clock_settime64
    { .nr = SYS_clock_settime64, .name = "clock_settime64" },
#endif
#ifdef SYS_clone
    { .nr = SYS_clone, .name = "clone" },
#endif
#ifdef SYS_clone2
    { .nr = SYS_clone2, .name = "clone2" },
#endif
#ifdef SYS_clone3
    { .nr = SYS_clone3, .name = "clone3" },
#endif
#ifdef SYS_close
    { .nr = SYS_close, .name = "close" },
#endif
#ifdef SYS_close_range
    { .nr = SYS_close_range, .name = "close_range" },
#endif
#ifdef SYS_cmpxchg_badaddr
    { .nr = SYS_cmpxchg_badaddr, .name = "cmpxchg_badaddr" },
#endif
#ifdef SYS_connect
    { .nr = SYS_connect, .name = "connect" },
#endif
#ifdef SYS_copy_file_range
    { .nr = SYS_copy_file_range, .name = "copy_file_range" },
#endif
#ifdef SYS_creat
    { .nr = SYS_creat, .name = "creat" },
#endif
#ifdef SYS_create_module
    { .nr = SYS_create_module, .name = "create_module" },
#endif
#ifdef SYS_delete_module
    { .nr = SYS_delete_module, .name = "delete_module" },
#endif
#ifdef SYS_dipc
    { .nr = SYS_dipc, .name = "dipc" },
#endif
#ifdef SYS_dup
    { .nr = SYS_dup, .name = "dup" },
#endif
#ifdef SYS_dup2
    { .nr = SYS_dup2, .name = "dup2" },
#endif
#ifdef SYS_dup3
    { .nr = SYS_dup3, .name = "dup3" },
#endif
#ifdef SYS_epoll_create
    { .nr = SYS_epoll_create, .name = "epoll_create" },
#endif
#ifdef SYS_epoll_create1
    { .nr = SYS_epoll_create1, .name = "epoll_create1" },
#endif
#ifdef SYS_epoll_ctl
    { .nr = SYS_epoll_ctl, .name = "epoll_ctl" },
#endif
#ifdef SYS_epoll_ctl_old
    { .nr = SYS_epoll_ctl_old, .name = "epoll_ctl_old" },
#endif
#ifdef SYS_epoll_pwait
    { .nr = SYS_epoll_pwait, .name = "epoll_pwait" },
#endif
#ifdef SYS_epoll_wait
    { .nr = SYS_epoll_wait, .name = "epoll_wait" },
#endif
#ifdef SYS_epoll_wait_old
    { .nr = SYS_epoll_wait_old, .name = "epoll_wait_old" },
#endif
#ifdef SYS_eventfd
    { .nr = SYS_eventfd, .name = "eventfd" },
#endif
#ifdef SYS_eventfd2
    { .nr = SYS_eventfd2, .name = "eventfd2" },
#endif
#ifdef SYS_exec_with_loader
    { .nr = SYS_exec_with_loader, .name = "exec_with_loader" },
#endif
#ifdef SYS_execv
    { .nr = SYS_execv, .name = "execv" },
#endif
#ifdef SYS_execve
    { .nr = SYS_execve, .name = "execve" },
#endif
#ifdef SYS_execveat
    { .nr = SYS_execveat, .name = "execveat" },
#endif
#ifdef SYS_exit
    { .nr = SYS_exit, .name = "exit" },
#endif
#ifdef SYS_exit_group
    { .nr = SYS_exit_group, .name = "exit_group" },
#endif
#ifdef SYS_faccessat
    { .nr = SYS_faccessat, .name = "faccessat" },
#endif
#ifdef SYS_faccessat2
    { .nr = SYS_faccessat2, .name = "faccessat2" },
#endif
#ifdef SYS_fadvise64
    { .nr = SYS_fadvise64, .name = "fadvise64" },
#endif
#ifdef SYS_fadvise64_64
    { .nr = SYS_fadvise64_64, .name = "fadvise64_64" },
#endif
#ifdef SYS_fallocate
    { .nr = SYS_fallocate, .name = "fallocate" },
#endif
#ifdef SYS_fanotify_init
    { .nr = SYS_fanotify_init, .name = "fanotify_init" },
#endif
#ifdef SYS_fanotify_mark
    { .nr = SYS_fanotify_mark, .name = "fanotify_mark" },
#endif
#ifdef SYS_fchdir
    { .nr = SYS_fchdir, .name = "fchdir" },
#endif
#ifdef SYS_fchmod
    { .nr = SYS_fchmod, .name = "fchmod" },
#endif
#ifdef SYS_fchmodat
    { .nr = SYS_fchmodat, .name = "fchmodat" },
#endif
#ifdef SYS_fchown
    { .nr = SYS_fchown, .name = "fchown" },
#endif
#ifdef SYS_fchown32
    { .nr = SYS_fchown32, .name = "fchown32" },
#endif
#ifdef SYS_fchownat
    { .nr = SYS_fchownat, .name = "fchownat" },
#endif
#ifdef SYS_fcntl
    { .nr = SYS_fcntl, .name = "fcntl" },
#endif
#ifdef SYS_fcntl64
    { .nr = SYS_fcntl64, .name = "fcntl64" },
#endif
#ifdef SYS_fdatasync
    { .nr = SYS_fdatasync, .name = "fdatasync" },
#endif
#ifdef SYS_fgetxattr
    { .nr = SYS_fgetxattr, .name = "fgetxattr" },
#endif
#ifdef SYS_finit_module
    { .nr = SYS_finit_module, .name = "finit_module" },
#endif
#ifdef SYS_flistxattr
    { .nr = SYS_flistxattr, .name = "flistxattr" },
#endif
#ifdef SYS_flock
    { .nr = SYS_flock, .name = "flock" },
#endif
#ifdef SYS_fork
    { .nr = SYS_fork, .name = "fork" },
#endif
#ifdef SYS_fp_udfiex_crtl
    { .nr = SYS_fp_udfiex_crtl, .name = "fp_udfiex_crtl" },
#endif
#ifdef SYS_free_hugepages
    { .nr = SYS_free_hugepages, .name = "free_hugepages" },
#endif
#ifdef SYS_fremovexattr
    { .nr = SYS_fremovexattr, .name = "fremovexattr" },
#endif
#ifdef SYS_fsconfig
    { .nr = SYS_fsconfig, .name = "fsconfig" },
#endif
#ifdef SYS_fsetxattr
    { .nr = SYS_fsetxattr, .name = "fsetxattr" },
#endif
#ifdef SYS_fsmount
    { .nr = SYS_fsmount, .name = "fsmount" },
#endif
#ifdef SYS_fsopen
    { .nr = SYS_fsopen, .name = "fsopen" },
#endif
#ifdef SYS_fspick
    { .nr = SYS_fspick, .name = "fspick" },
#endif
#ifdef SYS_fstat
    { .nr = SYS_fstat, .name = "fstat" },
#endif
#ifdef SYS_fstat64
    { .nr = SYS_fstat64, .name = "fstat64" },
#endif
#ifdef SYS_fstatat64
    { .nr = SYS_fstatat64, .name = "fstatat64" },
#endif
#ifdef SYS_fstatfs
    { .nr = SYS_fstatfs, .name = "fstatfs" },
#endif
#ifdef SYS_fstatfs64
    { .nr = SYS_fstatfs64, .name = "fstatfs64" },
#endif
#ifdef SYS_fsync
    { .nr = SYS_fsync, .name = "fsync" },
#endif
#ifdef SYS_ftime
    { .nr = SYS_ftime, .name = "ftime" },
#endif
#ifdef SYS_ftruncate
    { .nr = SYS_ftruncate, .name = "ftruncate" },
#endif
#ifdef SYS_ftruncate64
    { .nr = SYS_ftruncate64, .name = "ftruncate64" },
#endif
#ifdef SYS_futex
    { .nr = SYS_futex, .name = "futex" },
#endif
#ifdef SYS_futex_time64
    { .nr = SYS_futex_time64, .name = "futex_time64" },
#endif
#ifdef SYS_futimesat
    { .nr = SYS_futimesat, .name = "futimesat" },
#endif
#ifdef SYS_get_kernel_syms
    { .nr = SYS_get_kernel_syms, .name = "get_kernel_syms" },
#endif
#ifdef SYS_get_mempolicy
    { .nr = SYS_get_mempolicy, .name = "get_mempolicy" },
#endif
#ifdef SYS_get_robust_list
    { .nr = SYS_get_robust_list, .name = "get_robust_list" },
#endif
#ifdef SYS_get_thread_area
    { .nr = SYS_get_thread_area, .name = "get_thread_area" },
#endif
#ifdef SYS_get_tls
    { .nr = SYS_get_tls, .name = "get_tls" },
#endif
#ifdef SYS_getcpu
    { .nr = SYS_getcpu, .name = "getcpu" },
#endif
#ifdef SYS_getcwd
    { .nr = SYS_getcwd, .name = "getcwd" },
#endif
#ifdef SYS_getdents
    { .nr = SYS_getdents, .name = "getdents" },
#endif
#ifdef SYS_getdents64
    { .nr = SYS_getdents64, .name = "getdents64" },
#endif
#ifdef SYS_getdomainname
    { .nr = SYS_getdomainname, .name = "getdomainname" },
#endif
#ifdef SYS_getdtablesize
    { .nr = SYS_getdtablesize, .name = "getdtablesize" },
#endif
#ifdef SYS_getegid
    { .nr = SYS_getegid, .name = "getegid" },
#endif
#ifdef SYS_getegid32
    { .nr = SYS_getegid32, .name = "getegid32" },
#endif
#ifdef SYS_geteuid
    { .nr = SYS_geteuid, .name = "geteuid" },
#endif
#ifdef SYS_geteuid32
    { .nr = SYS_geteuid32, .name = "geteuid32" },
#endif
#ifdef SYS_getgid
    { .nr = SYS_getgid, .name = "getgid" },
#endif
#ifdef SYS_getgid32
    { .nr = SYS_getgid32, .name = "getgid32" },
#endif
#ifdef SYS_getgroups
    { .nr = SYS_getgroups, .name = "getgroups" },
#endif
#ifdef SYS_getgroups32
    { .nr = SYS_getgroups32, .name = "getgroups32" },
#endif
#ifdef SYS_gethostname
    { .nr = SYS_gethostname, .name = "gethostname" },
#endif
#ifdef SYS_getitimer
    { .nr = SYS_getitimer, .name = "getitimer" },
#endif
#ifdef SYS_getpagesize
    { .nr = SYS_getpagesize, .name = "getpagesize" },
#endif
#ifdef SYS_getpeername
    { .nr = SYS_getpeername, .name = "getpeername" },
#endif
#ifdef SYS_getpgid
    { .nr = SYS_getpgid, .name = "getpgid" },
#endif
#ifdef SYS_getpgrp
    { .nr = SYS_getpgrp, .name = "getpgrp" },
#endif
#ifdef SYS_getpid
    { .nr = SYS_getpid, .name = "getpid" },
#endif
#ifdef SYS_getpmsg
    { .nr = SYS_getpmsg, .name = "getpmsg" },
#endif
#ifdef SYS_getppid
    { .nr = SYS_getppid, .name = "getppid" },
#endif
#ifdef SYS_getpriority
    { .nr = SYS_getpriority, .name = "getpriority" },
#endif
#ifdef SYS_getrandom
    { .nr = SYS_getrandom, .name = "getrandom" },
#endif
#ifdef SYS_getresgid
    { .nr = SYS_getresgid, .name = "getresgid" },
#endif
#ifdef SYS_getresgid32
    { .nr = SYS_getresgid32, .name = "getresgid32" },
#endif
#ifdef SYS_getresuid
    { .nr = SYS_getresuid, .name = "getresuid" },
#endif
#ifdef SYS_getresuid32
    { .nr = SYS_getresuid32, .name = "getresuid32" },
#endif
#ifdef SYS_getrlimit
    { .nr = SYS_getrlimit, .name = "getrlimit" },
#endif
#ifdef SYS_getrusage
    { .nr = SYS_getrusage, .name = "getrusage" },
#endif
#ifdef SYS_getsid
    { .nr = SYS_getsid, .name = "getsid" },
#endif
#ifdef SYS_getsockname
    { .nr = SYS_getsockname, .name = "getsockname" },
#endif
#ifdef SYS_getsockopt
    { .nr = SYS_getsockopt, .name = "getsockopt" },
#endif
#ifdef SYS_gettid
    { .nr = SYS_gettid, .name = "gettid" },
#endif
#ifdef SYS_gettimeofday
    { .nr = SYS_gettimeofday, .name = "gettimeofday" },
#endif
#ifdef SYS_getuid
    { .nr = SYS_getuid, .name = "getuid" },
#endif
#ifdef SYS_getuid32
    { .nr = SYS_getuid32, .name = "getuid32" },
#endif
#ifdef SYS_getunwind
    { .nr = SYS_getunwind, .name = "getunwind" },
#endif
#ifdef SYS_getxattr
    { .nr = SYS_getxattr, .name = "getxattr" },
#endif
#ifdef SYS_getxgid
    { .nr = SYS_getxgid, .name = "getxgid" },
#endif
#ifdef SYS_getxpid
    { .nr = SYS_getxpid, .name = "getxpid" },
#endif
#ifdef SYS_getxuid
    { .nr = SYS_getxuid, .name = "getxuid" },
#endif
#ifdef SYS_gtty
    { .nr = SYS_gtty, .name = "gtty" },
#endif
#ifdef SYS_idle
    { .nr = SYS_idle, .name = "idle" },
#endif
#ifdef SYS_init_module
    { .nr = SYS_init_module, .name = "init_module" },
#endif
#ifdef SYS_inotify_add_watch
    { .nr = SYS_inotify_add_watch, .name = "inotify_add_watch" },
#endif
#ifdef SYS_inotify_init
    { .nr = SYS_inotify_init, .name = "inotify_init" },
#endif
#ifdef SYS_inotify_init1
    { .nr = SYS_inotify_init1, .name = "inotify_init1" },
#endif
#ifdef SYS_inotify_rm_watch
    { .nr = SYS_inotify_rm_watch, .name = "inotify_rm_watch" },
#endif
#ifdef SYS_io_cancel
    { .nr = SYS_io_cancel, .name = "io_cancel" },
#endif
#ifdef SYS_io_destroy
    { .nr = SYS_io_destroy, .name = "io_destroy" },
#endif
#ifdef SYS_io_getevents
    { .nr = SYS_io_getevents, .name = "io_getevents" },
#endif
#ifdef SYS_io_pgetevents
    { .nr = SYS_io_pgetevents, .name = "io_pgetevents" },
#endif
#ifdef SYS_io_pgetevents_time64
    { .nr = SYS_io_pgetevents_time64, .name = "io_pgetevents_time64" },
#endif
#ifdef SYS_io_setup
    { .nr = SYS_io_setup, .name = "io_setup" },
#endif
#ifdef SYS_io_submit
    { .nr = SYS_io_submit, .name = "io_submit" },
#endif
#ifdef SYS_io_uring_enter
    { .nr = SYS_io_uring_enter, .name = "io_uring_enter" },
#endif
#ifdef SYS_io_uring_register
    { .nr = SYS_io_uring_register, .name = "io_uring_register" },
#endif
#ifdef SYS_io_uring_setup
    { .nr = SYS_io_uring_setup, .name = "io_uring_setup" },
#endif
#ifdef SYS_ioctl
    { .nr = SYS_ioctl, .name = "ioctl" },
#endif
#ifdef SYS_ioperm
    { .nr = SYS_ioperm, .name = "ioperm" },
#endif
#ifdef SYS_iopl
    { .nr = SYS_iopl, .name = "iopl" },
#endif
#ifdef SYS_ioprio_get
    { .nr = SYS_ioprio_get, .name = "ioprio_get" },
#endif
#ifdef SYS_ioprio_set
    { .nr = SYS_ioprio_set, .name = "ioprio_set" },
#endif
#ifdef SYS_ipc
    { .nr = SYS_ipc, .name = "ipc" },
#endif
#ifdef SYS_kcmp
    { .nr = SYS_kcmp, .name = "kcmp" },
#endif
#ifdef SYS_kern_features
    { .nr = SYS_kern_features, .name = "kern_features" },
#endif
#ifdef SYS_kexec_file_load
    { .nr = SYS_kexec_file_load, .name = "kexec_file_load" },
#endif
#ifdef SYS_kexec_load
    { .nr = SYS_kexec_load, .name = "kexec_load" },
#endif
#ifdef SYS_keyctl
    { .nr = SYS_keyctl, .name = "keyctl" },
#endif
#ifdef SYS_kill
    { .nr = SYS_kill, .name = "kill" },
#endif
#ifdef SYS_lchown
    { .nr = SYS_lchown, .name = "lchown" },
#endif
#ifdef SYS_lchown32
    { .nr = SYS_lchown32, .name = "lchown32" },
#endif
#ifdef SYS_lgetxattr
    { .nr = SYS_lgetxattr, .name = "lgetxattr" },
#endif
#ifdef SYS_link
    { .nr = SYS_link, .name = "link" },
#endif
#ifdef SYS_linkat
    { .nr = SYS_linkat, .name = "linkat" },
#endif
#ifdef SYS_listen
    { .nr = SYS_listen, .name = "listen" },
#endif
#ifdef SYS_listxattr
    { .nr = SYS_listxattr, .name = "listxattr" },
#endif
#ifdef SYS_llistxattr
    { .nr = SYS_llistxattr, .name = "llistxattr" },
#endif
#ifdef SYS_llseek
    { .nr = SYS_llseek, .name = "llseek" },
#endif
#ifdef SYS_lock
    { .nr = SYS_lock, .name = "lock" },
#endif
#ifdef SYS_lookup_dcookie
    { .nr = SYS_lookup_dcookie, .name = "lookup_dcookie" },
#endif
#ifdef SYS_lremovexattr
    { .nr = SYS_lremovexattr, .name = "lremovexattr" },
#endif
#ifdef SYS_lseek
    { .nr = SYS_lseek, .name = "lseek" },
#endif
#ifdef SYS_lsetxattr
    { .nr = SYS_lsetxattr, .name = "lsetxattr" },
#endif
#ifdef SYS_lstat
    { .nr = SYS_lstat, .name = "lstat" },
#endif
#ifdef SYS_lstat64
    { .nr = SYS_lstat64, .name = "lstat64" },
#endif
#ifdef SYS_madvise
    { .nr = SYS_madvise, .name = "madvise" },
#endif
#ifdef SYS_mbind
    { .nr = SYS_mbind, .name = "mbind" },
#endif
#ifdef SYS_membarrier
    { .nr = SYS_membarrier, .name = "membarrier" },
#endif
#ifdef SYS_memfd_create
    { .nr = SYS_memfd_create, .name = "memfd_create" },
#endif
#ifdef SYS_memory_ordering
    { .nr = SYS_memory_ordering, .name = "memory_ordering" },
#endif
#ifdef SYS_migrate_pages
    { .nr = SYS_migrate_pages, .name = "migrate_pages" },
#endif
#ifdef SYS_mincore
    { .nr = SYS_mincore, .name = "mincore" },
#endif
#ifdef SYS_mkdir
    { .nr = SYS_mkdir, .name = "mkdir" },
#endif
#ifdef SYS_mkdirat
    { .nr = SYS_mkdirat, .name = "mkdirat" },
#endif
#ifdef SYS_mknod
    { .nr = SYS_mknod, .name = "mknod" },
#endif
#ifdef SYS_mknodat
    { .nr = SYS_mknodat, .name = "mknodat" },
#endif
#ifdef SYS_mlock
    { .nr = SYS_mlock, .name = "mlock" },
#endif
#ifdef SYS_mlock2
    { .nr = SYS_mlock2, .name = "mlock2" },
#endif
#ifdef SYS_mlockall
    { .nr = SYS_mlockall, .name = "mlockall" },
#endif
#ifdef SYS_mmap
    { .nr = SYS_mmap, .name = "mmap" },
#endif
#ifdef SYS_mmap2
    { .nr = SYS_mmap2, .name = "mmap2" },
#endif
#ifdef SYS_modify_ldt
    { .nr = SYS_modify_ldt, .name = "modify_ldt" },
#endif
#ifdef SYS_mount
    { .nr = SYS_mount, .name = "mount" },
#endif
#ifdef SYS_move_mount
    { .nr = SYS_move_mount, .name = "move_mount" },
#endif
#ifdef SYS_move_pages
    { .nr = SYS_move_pages, .name = "move_pages" },
#endif
#ifdef SYS_mprotect
    { .nr = SYS_mprotect, .name = "mprotect" },
#endif
#ifdef SYS_mpx
    { .nr = SYS_mpx, .name = "mpx" },
#endif
#ifdef SYS_mq_getsetattr
    { .nr = SYS_mq_getsetattr, .name = "mq_getsetattr" },
#endif
#ifdef SYS_mq_notify
    { .nr = SYS_mq_notify, .name = "mq_notify" },
#endif
#ifdef SYS_mq_open
    { .nr = SYS_mq_open, .name = "mq_open" },
#endif
#ifdef SYS_mq_timedreceive
    { .nr = SYS_mq_timedreceive, .name = "mq_timedreceive" },
#endif
#ifdef SYS_mq_timedreceive_time64
    { .nr = SYS_mq_timedreceive_time64, .name = "mq_timedreceive_time64" },
#endif
#ifdef SYS_mq_timedsend
    { .nr = SYS_mq_timedsend, .name = "mq_timedsend" },
#endif
#ifdef SYS_mq_timedsend_time64
    { .nr = SYS_mq_timedsend_time64, .name = "mq_timedsend_time64" },
#endif
#ifdef SYS_mq_unlink
    { .nr = SYS_mq_unlink, .name = "mq_unlink" },
#endif
#ifdef SYS_mremap
    { .nr = SYS_mremap, .name = "mremap" },
#endif
#ifdef SYS_msgctl
    { .nr = SYS_msgctl, .name = "msgctl" },
#endif
#ifdef SYS_msgget
    { .nr = SYS_msgget, .name = "msgget" },
#endif
#ifdef SYS_msgrcv
    { .nr = SYS_msgrcv, .name = "msgrcv" },
#endif
#ifdef SYS_msgsnd
    { .nr = SYS_msgsnd, .name = "msgsnd" },
#endif
#ifdef SYS_msync
    { .nr = SYS_msync, .name = "msync" },
#endif
#ifdef SYS_multiplexer
    { .nr = SYS_multiplexer, .name = "multiplexer" },
#endif
#ifdef SYS_munlock
    { .nr = SYS_munlock, .name = "munlock" },
#endif
#ifdef SYS_munlockall
    { .nr = SYS_munlockall, .name = "munlockall" },
#endif
#ifdef SYS_munmap
    { .nr = SYS_munmap, .name = "munmap" },
#endif
#ifdef SYS_name_to_handle_at
    { .nr = SYS_name_to_handle_at, .name = "name_to_handle_at" },
#endif
#ifdef SYS_nanosleep
    { .nr = SYS_nanosleep, .name = "nanosleep" },
#endif
#ifdef SYS_newfstatat
    { .nr = SYS_newfstatat, .name = "newfstatat" },
#endif
#ifdef SYS_nfsservctl
    { .nr = SYS_nfsservctl, .name = "nfsservctl" },
#endif
#ifdef SYS_ni_syscall
    { .nr = SYS_ni_syscall, .name = "ni_syscall" },
#endif
#ifdef SYS_nice
    { .nr = SYS_nice, .name = "nice" },
#endif
#ifdef SYS_old_adjtimex
    { .nr = SYS_old_adjtimex, .name = "old_adjtimex" },
#endif
#ifdef SYS_old_getpagesize
    { .nr = SYS_old_getpagesize, .name = "old_getpagesize" },
#endif
#ifdef SYS_oldfstat
    { .nr = SYS_oldfstat, .name = "oldfstat" },
#endif
#ifdef SYS_oldlstat
    { .nr = SYS_oldlstat, .name = "oldlstat" },
#endif
#ifdef SYS_oldolduname
    { .nr = SYS_oldolduname, .name = "oldolduname" },
#endif
#ifdef SYS_oldstat
    { .nr = SYS_oldstat, .name = "oldstat" },
#endif
#ifdef SYS_oldumount
    { .nr = SYS_oldumount, .name = "oldumount" },
#endif
#ifdef SYS_olduname
    { .nr = SYS_olduname, .name = "olduname" },
#endif
#ifdef SYS_open
    { .nr = SYS_open, .name = "open" },
#endif
#ifdef SYS_open_by_handle_at
    { .nr = SYS_open_by_handle_at, .name = "open_by_handle_at" },
#endif
#ifdef SYS_open_tree
    { .nr = SYS_open_tree, .name = "open_tree" },
#endif
#ifdef SYS_openat
    { .nr = SYS_openat, .name = "openat" },
#endif
#ifdef SYS_openat2
    { .nr = SYS_openat2, .name = "openat2" },
#endif
#ifdef SYS_osf_adjtime
    { .nr = SYS_osf_adjtime, .name = "osf_adjtime" },
#endif
#ifdef SYS_osf_afs_syscall
    { .nr = SYS_osf_afs_syscall, .name = "osf_afs_syscall" },
#endif
#ifdef SYS_osf_alt_plock
    { .nr = SYS_osf_alt_plock, .name = "osf_alt_plock" },
#endif
#ifdef SYS_osf_alt_setsid
    { .nr = SYS_osf_alt_setsid, .name = "osf_alt_setsid" },
#endif
#ifdef SYS_osf_alt_sigpending
    { .nr = SYS_osf_alt_sigpending, .name = "osf_alt_sigpending" },
#endif
#ifdef SYS_osf_asynch_daemon
    { .nr = SYS_osf_asynch_daemon, .name = "osf_asynch_daemon" },
#endif
#ifdef SYS_osf_audcntl
    { .nr = SYS_osf_audcntl, .name = "osf_audcntl" },
#endif
#ifdef SYS_osf_audgen
    { .nr = SYS_osf_audgen, .name = "osf_audgen" },
#endif
#ifdef SYS_osf_chflags
    { .nr = SYS_osf_chflags, .name = "osf_chflags" },
#endif
#ifdef SYS_osf_execve
    { .nr = SYS_osf_execve, .name = "osf_execve" },
#endif
#ifdef SYS_osf_exportfs
    { .nr = SYS_osf_exportfs, .name = "osf_exportfs" },
#endif
#ifdef SYS_osf_fchflags
    { .nr = SYS_osf_fchflags, .name = "osf_fchflags" },
#endif
#ifdef SYS_osf_fdatasync
    { .nr = SYS_osf_fdatasync, .name = "osf_fdatasync" },
#endif
#ifdef SYS_osf_fpathconf
    { .nr = SYS_osf_fpathconf, .name = "osf_fpathconf" },
#endif
#ifdef SYS_osf_fstat
    { .nr = SYS_osf_fstat, .name = "osf_fstat" },
#endif
#ifdef SYS_osf_fstatfs
    { .nr = SYS_osf_fstatfs, .name = "osf_fstatfs" },
#endif
#ifdef SYS_osf_fstatfs64
    { .nr = SYS_osf_fstatfs64, .name = "osf_fstatfs64" },
#endif
#ifdef SYS_osf_fuser
    { .nr = SYS_osf_fuser, .name = "osf_fuser" },
#endif
#ifdef SYS_osf_getaddressconf
    { .nr = SYS_osf_getaddressconf, .name = "osf_getaddressconf" },
#endif
#ifdef SYS_osf_getdirentries
    { .nr = SYS_osf_getdirentries, .name = "osf_getdirentries" },
#endif
#ifdef SYS_osf_getdomainname
    { .nr = SYS_osf_getdomainname, .name = "osf_getdomainname" },
#endif
#ifdef SYS_osf_getfh
    { .nr = SYS_osf_getfh, .name = "osf_getfh" },
#endif
#ifdef SYS_osf_getfsstat
    { .nr = SYS_osf_getfsstat, .name = "osf_getfsstat" },
#endif
#ifdef SYS_osf_gethostid
    { .nr = SYS_osf_gethostid, .name = "osf_gethostid" },
#endif
#ifdef SYS_osf_getitimer
    { .nr = SYS_osf_getitimer, .name = "osf_getitimer" },
#endif
#ifdef SYS_osf_getlogin
    { .nr = SYS_osf_getlogin, .name = "osf_getlogin" },
#endif
#ifdef SYS_osf_getmnt
    { .nr = SYS_osf_getmnt, .name = "osf_getmnt" },
#endif
#ifdef SYS_osf_getrusage
    { .nr = SYS_osf_getrusage, .name = "osf_getrusage" },
#endif
#ifdef SYS_osf_getsysinfo
    { .nr = SYS_osf_getsysinfo, .name = "osf_getsysinfo" },
#endif
#ifdef SYS_osf_gettimeofday
    { .nr = SYS_osf_gettimeofday, .name = "osf_gettimeofday" },
#endif
#ifdef SYS_osf_kloadcall
    { .nr = SYS_osf_kloadcall, .name = "osf_kloadcall" },
#endif
#ifdef SYS_osf_kmodcall
    { .nr = SYS_osf_kmodcall, .name = "osf_kmodcall" },
#endif
#ifdef SYS_osf_lstat
    { .nr = SYS_osf_lstat, .name = "osf_lstat" },
#endif
#ifdef SYS_osf_memcntl
    { .nr = SYS_osf_memcntl, .name = "osf_memcntl" },
#endif
#ifdef SYS_osf_mincore
    { .nr = SYS_osf_mincore, .name = "osf_mincore" },
#endif
#ifdef SYS_osf_mount
    { .nr = SYS_osf_mount, .name = "osf_mount" },
#endif
#ifdef SYS_osf_mremap
    { .nr = SYS_osf_mremap, .name = "osf_mremap" },
#endif
#ifdef SYS_osf_msfs_syscall
    { .nr = SYS_osf_msfs_syscall, .name = "osf_msfs_syscall" },
#endif
#ifdef SYS_osf_msleep
    { .nr = SYS_osf_msleep, .name = "osf_msleep" },
#endif
#ifdef SYS_osf_mvalid
    { .nr = SYS_osf_mvalid, .name = "osf_mvalid" },
#endif
#ifdef SYS_osf_mwakeup
    { .nr = SYS_osf_mwakeup, .name = "osf_mwakeup" },
#endif
#ifdef SYS_osf_naccept
    { .nr = SYS_osf_naccept, .name = "osf_naccept" },
#endif
#ifdef SYS_osf_nfssvc
    { .nr = SYS_osf_nfssvc, .name = "osf_nfssvc" },
#endif
#ifdef SYS_osf_ngetpeername
    { .nr = SYS_osf_ngetpeername, .name = "osf_ngetpeername" },
#endif
#ifdef SYS_osf_ngetsockname
    { .nr = SYS_osf_ngetsockname, .name = "osf_ngetsockname" },
#endif
#ifdef SYS_osf_nrecvfrom
    { .nr = SYS_osf_nrecvfrom, .name = "osf_nrecvfrom" },
#endif
#ifdef SYS_osf_nrecvmsg
    { .nr = SYS_osf_nrecvmsg, .name = "osf_nrecvmsg" },
#endif
#ifdef SYS_osf_nsendmsg
    { .nr = SYS_osf_nsendmsg, .name = "osf_nsendmsg" },
#endif
#ifdef SYS_osf_ntp_adjtime
    { .nr = SYS_osf_ntp_adjtime, .name = "osf_ntp_adjtime" },
#endif
#ifdef SYS_osf_ntp_gettime
    { .nr = SYS_osf_ntp_gettime, .name = "osf_ntp_gettime" },
#endif
#ifdef SYS_osf_old_creat
    { .nr = SYS_osf_old_creat, .name = "osf_old_creat" },
#endif
#ifdef SYS_osf_old_fstat
    { .nr = SYS_osf_old_fstat, .name = "osf_old_fstat" },
#endif
#ifdef SYS_osf_old_getpgrp
    { .nr = SYS_osf_old_getpgrp, .name = "osf_old_getpgrp" },
#endif
#ifdef SYS_osf_old_killpg
    { .nr = SYS_osf_old_killpg, .name = "osf_old_killpg" },
#endif
#ifdef SYS_osf_old_lstat
    { .nr = SYS_osf_old_lstat, .name = "osf_old_lstat" },
#endif
#ifdef SYS_osf_old_open
    { .nr = SYS_osf_old_open, .name = "osf_old_open" },
#endif
#ifdef SYS_osf_old_sigaction
    { .nr = SYS_osf_old_sigaction, .name = "osf_old_sigaction" },
#endif
#ifdef SYS_osf_old_sigblock
    { .nr = SYS_osf_old_sigblock, .name = "osf_old_sigblock" },
#endif
#ifdef SYS_osf_old_sigreturn
    { .nr = SYS_osf_old_sigreturn, .name = "osf_old_sigreturn" },
#endif
#ifdef SYS_osf_old_sigsetmask
    { .nr = SYS_osf_old_sigsetmask, .name = "osf_old_sigsetmask" },
#endif
#ifdef SYS_osf_old_sigvec
    { .nr = SYS_osf_old_sigvec, .name = "osf_old_sigvec" },
#endif
#ifdef SYS_osf_old_stat
    { .nr = SYS_osf_old_stat, .name = "osf_old_stat" },
#endif
#ifdef SYS_osf_old_vadvise
    { .nr = SYS_osf_old_vadvise, .name = "osf_old_vadvise" },
#endif
#ifdef SYS_osf_old_vtrace
    { .nr = SYS_osf_old_vtrace, .name = "osf_old_vtrace" },
#endif
#ifdef SYS_osf_old_wait
    { .nr = SYS_osf_old_wait, .name = "osf_old_wait" },
#endif
#ifdef SYS_osf_oldquota
    { .nr = SYS_osf_oldquota, .name = "osf_oldquota" },
#endif
#ifdef SYS_osf_pathconf
    { .nr = SYS_osf_pathconf, .name = "osf_pathconf" },
#endif
#ifdef SYS_osf_pid_block
    { .nr = SYS_osf_pid_block, .name = "osf_pid_block" },
#endif
#ifdef SYS_osf_pid_unblock
    { .nr = SYS_osf_pid_unblock, .name = "osf_pid_unblock" },
#endif
#ifdef SYS_osf_plock
    { .nr = SYS_osf_plock, .name = "osf_plock" },
#endif
#ifdef SYS_osf_priocntlset
    { .nr = SYS_osf_priocntlset, .name = "osf_priocntlset" },
#endif
#ifdef SYS_osf_profil
    { .nr = SYS_osf_profil, .name = "osf_profil" },
#endif
#ifdef SYS_osf_proplist_syscall
    { .nr = SYS_osf_proplist_syscall, .name = "osf_proplist_syscall" },
#endif
#ifdef SYS_osf_reboot
    { .nr = SYS_osf_reboot, .name = "osf_reboot" },
#endif
#ifdef SYS_osf_revoke
    { .nr = SYS_osf_revoke, .name = "osf_revoke" },
#endif
#ifdef SYS_osf_sbrk
    { .nr = SYS_osf_sbrk, .name = "osf_sbrk" },
#endif
#ifdef SYS_osf_security
    { .nr = SYS_osf_security, .name = "osf_security" },
#endif
#ifdef SYS_osf_select
    { .nr = SYS_osf_select, .name = "osf_select" },
#endif
#ifdef SYS_osf_set_program_attributes
    { .nr = SYS_osf_set_program_attributes, .name = "osf_set_program_attributes" },
#endif
#ifdef SYS_osf_set_speculative
    { .nr = SYS_osf_set_speculative, .name = "osf_set_speculative" },
#endif
#ifdef SYS_osf_sethostid
    { .nr = SYS_osf_sethostid, .name = "osf_sethostid" },
#endif
#ifdef SYS_osf_setitimer
    { .nr = SYS_osf_setitimer, .name = "osf_setitimer" },
#endif
#ifdef SYS_osf_setlogin
    { .nr = SYS_osf_setlogin, .name = "osf_setlogin" },
#endif
#ifdef SYS_osf_setsysinfo
    { .nr = SYS_osf_setsysinfo, .name = "osf_setsysinfo" },
#endif
#ifdef SYS_osf_settimeofday
    { .nr = SYS_osf_settimeofday, .name = "osf_settimeofday" },
#endif
#ifdef SYS_osf_shmat
    { .nr = SYS_osf_shmat, .name = "osf_shmat" },
#endif
#ifdef SYS_osf_signal
    { .nr = SYS_osf_signal, .name = "osf_signal" },
#endif
#ifdef SYS_osf_sigprocmask
    { .nr = SYS_osf_sigprocmask, .name = "osf_sigprocmask" },
#endif
#ifdef SYS_osf_sigsendset
    { .nr = SYS_osf_sigsendset, .name = "osf_sigsendset" },
#endif
#ifdef SYS_osf_sigstack
    { .nr = SYS_osf_sigstack, .name = "osf_sigstack" },
#endif
#ifdef SYS_osf_sigwaitprim
    { .nr = SYS_osf_sigwaitprim, .name = "osf_sigwaitprim" },
#endif
#ifdef SYS_osf_sstk
    { .nr = SYS_osf_sstk, .name = "osf_sstk" },
#endif
#ifdef SYS_osf_stat
    { .nr = SYS_osf_stat, .name = "osf_stat" },
#endif
#ifdef SYS_osf_statfs
    { .nr = SYS_osf_statfs, .name = "osf_statfs" },
#endif
#ifdef SYS_osf_statfs64
    { .nr = SYS_osf_statfs64, .name = "osf_statfs64" },
#endif
#ifdef SYS_osf_subsys_info
    { .nr = SYS_osf_subsys_info, .name = "osf_subsys_info" },
#endif
#ifdef SYS_osf_swapctl
    { .nr = SYS_osf_swapctl, .name = "osf_swapctl" },
#endif
#ifdef SYS_osf_swapon
    { .nr = SYS_osf_swapon, .name = "osf_swapon" },
#endif
#ifdef SYS_osf_syscall
    { .nr = SYS_osf_syscall, .name = "osf_syscall" },
#endif
#ifdef SYS_osf_sysinfo
    { .nr = SYS_osf_sysinfo, .name = "osf_sysinfo" },
#endif
#ifdef SYS_osf_table
    { .nr = SYS_osf_table, .name = "osf_table" },
#endif
#ifdef SYS_osf_uadmin
    { .nr = SYS_osf_uadmin, .name = "osf_uadmin" },
#endif
#ifdef SYS_osf_usleep_thread
    { .nr = SYS_osf_usleep_thread, .name = "osf_usleep_thread" },
#endif
#ifdef SYS_osf_uswitch
    { .nr = SYS_osf_uswitch, .name = "osf_uswitch" },
#endif
#ifdef SYS_osf_utc_adjtime
    { .nr = SYS_osf_utc_adjtime, .name = "osf_utc_adjtime" },
#endif
#ifdef SYS_osf_utc_gettime
    { .nr = SYS_osf_utc_gettime, .name = "osf_utc_gettime" },
#endif
#ifdef SYS_osf_utimes
    { .nr = SYS_osf_utimes, .name = "osf_utimes" },
#endif
#ifdef SYS_osf_utsname
    { .nr = SYS_osf_utsname, .name = "osf_utsname" },
#endif
#ifdef SYS_osf_wait4
    { .nr = SYS_osf_wait4, .name = "osf_wait4" },
#endif
#ifdef SYS_osf_waitid
    { .nr = SYS_osf_waitid, .name = "osf_waitid" },
#endif
#ifdef SYS_pause
    { .nr = SYS_pause, .name = "pause" },
#endif
#ifdef SYS_pciconfig_iobase
    { .nr = SYS_pciconfig_iobase, .name = "pciconfig_iobase" },
#endif
#ifdef SYS_pciconfig_read
    { .nr = SYS_pciconfig_read, .name = "pciconfig_read" },
#endif
#ifdef SYS_pciconfig_write
    { .nr = SYS_pciconfig_write, .name = "pciconfig_write" },
#endif
#ifdef SYS_perf_event_open
    { .nr = SYS_perf_event_open, .name = "perf_event_open" },
#endif
#ifdef SYS_perfctr
    { .nr = SYS_perfctr, .name = "perfctr" },
#endif
#ifdef SYS_perfmonctl
    { .nr = SYS_perfmonctl, .name = "perfmonctl" },
#endif
#ifdef SYS_personality
    { .nr = SYS_personality, .name = "personality" },
#endif
#ifdef SYS_pidfd_getfd
    { .nr = SYS_pidfd_getfd, .name = "pidfd_getfd" },
#endif
#ifdef SYS_pidfd_open
    { .nr = SYS_pidfd_open, .name = "pidfd_open" },
#endif
#ifdef SYS_pidfd_send_signal
    { .nr = SYS_pidfd_send_signal, .name = "pidfd_send_signal" },
#endif
#ifdef SYS_pipe
    { .nr = SYS_pipe, .name = "pipe" },
#endif
#ifdef SYS_pipe2
    { .nr = SYS_pipe2, .name = "pipe2" },
#endif
#ifdef SYS_pivot_root
    { .nr = SYS_pivot_root, .name = "pivot_root" },
#endif
#ifdef SYS_pkey_alloc
    { .nr = SYS_pkey_alloc, .name = "pkey_alloc" },
#endif
#ifdef SYS_pkey_free
    { .nr = SYS_pkey_free, .name = "pkey_free" },
#endif
#ifdef SYS_pkey_mprotect
    { .nr = SYS_pkey_mprotect, .name = "pkey_mprotect" },
#endif
#ifdef SYS_poll
    { .nr = SYS_poll, .name = "poll" },
#endif
#ifdef SYS_ppoll
    { .nr = SYS_ppoll, .name = "ppoll" },
#endif
#ifdef SYS_ppoll_time64
    { .nr = SYS_ppoll_time64, .name = "ppoll_time64" },
#endif
#ifdef SYS_prctl
    { .nr = SYS_prctl, .name = "prctl" },
#endif
#ifdef SYS_pread64
    { .nr = SYS_pread64, .name = "pread64" },
#endif
#ifdef SYS_preadv
    { .nr = SYS_preadv, .name = "preadv" },
#endif
#ifdef SYS_preadv2
    { .nr = SYS_preadv2, .name = "preadv2" },
#endif
#ifdef SYS_prlimit64
    { .nr = SYS_prlimit64, .name = "prlimit64" },
#endif
#ifdef SYS_process_madvise
    { .nr = SYS_process_madvise, .name = "process_madvise" },
#endif
#ifdef SYS_process_vm_readv
    { .nr = SYS_process_vm_readv, .name = "process_vm_readv" },
#endif
#ifdef SYS_process_vm_writev
    { .nr = SYS_process_vm_writev, .name = "process_vm_writev" },
#endif
#ifdef SYS_prof
    { .nr = SYS_prof, .name = "prof" },
#endif
#ifdef SYS_profil
    { .nr = SYS_profil, .name = "profil" },
#endif
#ifdef SYS_pselect6
    { .nr = SYS_pselect6, .name = "pselect6" },
#endif
#ifdef SYS_pselect6_time64
    { .nr = SYS_pselect6_time64, .name = "pselect6_time64" },
#endif
#ifdef SYS_ptrace
    { .nr = SYS_ptrace, .name = "ptrace" },
#endif
#ifdef SYS_putpmsg
    { .nr = SYS_putpmsg, .name = "putpmsg" },
#endif
#ifdef SYS_pwrite64
    { .nr = SYS_pwrite64, .name = "pwrite64" },
#endif
#ifdef SYS_pwritev
    { .nr = SYS_pwritev, .name = "pwritev" },
#endif
#ifdef SYS_pwritev2
    { .nr = SYS_pwritev2, .name = "pwritev2" },
#endif
#ifdef SYS_query_module
    { .nr = SYS_query_module, .name = "query_module" },
#endif
#ifdef SYS_quotactl
    { .nr = SYS_quotactl, .name = "quotactl" },
#endif
#ifdef SYS_readahead
    { .nr = SYS_readahead, .name = "readahead" },
#endif
#ifdef SYS_readdir
    { .nr = SYS_readdir, .name = "readdir" },
#endif
#ifdef SYS_readlink
    { .nr = SYS_readlink, .name = "readlink" },
#endif
#ifdef SYS_readlinkat
    { .nr = SYS_readlinkat, .name = "readlinkat" },
#endif
#ifdef SYS_readv
    { .nr = SYS_readv, .name = "readv" },
#endif
#ifdef SYS_reboot
    { .nr = SYS_reboot, .name = "reboot" },
#endif
#ifdef SYS_recv
    { .nr = SYS_recv, .name = "recv" },
#endif
#ifdef SYS_recvfrom
    { .nr = SYS_recvfrom, .name = "recvfrom" },
#endif
#ifdef SYS_recvmmsg
    { .nr = SYS_recvmmsg, .name = "recvmmsg" },
#endif
#ifdef SYS_recvmmsg_time64
    { .nr = SYS_recvmmsg_time64, .name = "recvmmsg_time64" },
#endif
#ifdef SYS_recvmsg
    { .nr = SYS_recvmsg, .name = "recvmsg" },
#endif
#ifdef SYS_remap_file_pages
    { .nr = SYS_remap_file_pages, .name = "remap_file_pages" },
#endif
#ifdef SYS_removexattr
    { .nr = SYS_removexattr, .name = "removexattr" },
#endif
#ifdef SYS_rename
    { .nr = SYS_rename, .name = "rename" },
#endif
#ifdef SYS_renameat
    { .nr = SYS_renameat, .name = "renameat" },
#endif
#ifdef SYS_renameat2
    { .nr = SYS_renameat2, .name = "renameat2" },
#endif
#ifdef SYS_request_key
    { .nr = SYS_request_key, .name = "request_key" },
#endif
#ifdef SYS_restart_syscall
    { .nr = SYS_restart_syscall, .name = "restart_syscall" },
#endif
#ifdef SYS_riscv_flush_icache
    { .nr = SYS_riscv_flush_icache, .name = "riscv_flush_icache" },
#endif
#ifdef SYS_rmdir
    { .nr = SYS_rmdir, .name = "rmdir" },
#endif
#ifdef SYS_rseq
    { .nr = SYS_rseq, .name = "rseq" },
#endif
#ifdef SYS_rt_sigaction
    { .nr = SYS_rt_sigaction, .name = "rt_sigaction" },
#endif
#ifdef SYS_rt_sigpending
    { .nr = SYS_rt_sigpending, .name = "rt_sigpending" },
#endif
#ifdef SYS_rt_sigprocmask
    { .nr = SYS_rt_sigprocmask, .name = "rt_sigprocmask" },
#endif
#ifdef SYS_rt_sigqueueinfo
    { .nr = SYS_rt_sigqueueinfo, .name = "rt_sigqueueinfo" },
#endif
#ifdef SYS_rt_sigreturn
    { .nr = SYS_rt_sigreturn, .name = "rt_sigreturn" },
#endif
#ifdef SYS_rt_sigsuspend
    { .nr = SYS_rt_sigsuspend, .name = "rt_sigsuspend" },
#endif
#ifdef SYS_rt_sigtimedwait
    { .nr = SYS_rt_sigtimedwait, .name = "rt_sigtimedwait" },
#endif
#ifdef SYS_rt_sigtimedwait_time64
    { .nr = SYS_rt_sigtimedwait_time64, .name = "rt_sigtimedwait_time64" },
#endif
#ifdef SYS_rt_tgsigqueueinfo
    { .nr = SYS_rt_tgsigqueueinfo, .name = "rt_tgsigqueueinfo" },
#endif
#ifdef SYS_rtas
    { .nr = SYS_rtas, .name = "rtas" },
#endif
#ifdef SYS_s390_guarded_storage
    { .nr = SYS_s390_guarded_storage, .name = "s390_guarded_storage" },
#endif
#ifdef SYS_s390_pci_mmio_read
    { .nr = SYS_s390_pci_mmio_read, .name = "s390_pci_mmio_read" },
#endif
#ifdef SYS_s390_pci_mmio_write
    { .nr = SYS_s390_pci_mmio_write, .name = "s390_pci_mmio_write" },
#endif
#ifdef SYS_s390_runtime_instr
    { .nr = SYS_s390_runtime_instr, .name = "s390_runtime_instr" },
#endif
#ifdef SYS_s390_sthyi
    { .nr = SYS_s390_sthyi, .name = "s390_sthyi" },
#endif
#ifdef SYS_sched_get_affinity
    { .nr = SYS_sched_get_affinity, .name = "sched_get_affinity" },
#endif
#ifdef SYS_sched_get_priority_max
    { .nr = SYS_sched_get_priority_max, .name = "sched_get_priority_max" },
#endif
#ifdef SYS_sched_get_priority_min
    { .nr = SYS_sched_get_priority_min, .name = "sched_get_priority_min" },
#endif
#ifdef SYS_sched_getaffinity
    { .nr = SYS_sched_getaffinity, .name = "sched_getaffinity" },
#endif
#ifdef SYS_sched_getattr
    { .nr = SYS_sched_getattr, .name = "sched_getattr" },
#endif
#ifdef SYS_sched_getparam
    { .nr = SYS_sched_getparam, .name = "sched_getparam" },
#endif
#ifdef SYS_sched_getscheduler
    { .nr = SYS_sched_getscheduler, .name = "sched_getscheduler" },
#endif
#ifdef SYS_sched_rr_get_interval
    { .nr = SYS_sched_rr_get_interval, .name = "sched_rr_get_interval" },
#endif
#ifdef SYS_sched_rr_get_interval_time64
    { .nr = SYS_sched_rr_get_interval_time64, .name = "sched_rr_get_interval_time64" },
#endif
#ifdef SYS_sched_set_affinity
    { .nr = SYS_sched_set_affinity, .name = "sched_set_affinity" },
#endif
#ifdef SYS_sched_setaffinity
    { .nr = SYS_sched_setaffinity, .name = "sched_setaffinity" },
#endif
#ifdef SYS_sched_setattr
    { .nr = SYS_sched_setattr, .name = "sched_setattr" },
#endif
#ifdef SYS_sched_setparam
    { .nr = SYS_sched_setparam, .name = "sched_setparam" },
#endif
#ifdef SYS_sched_setscheduler
    { .nr = SYS_sched_setscheduler, .name = "sched_setscheduler" },
#endif
#ifdef SYS_sched_yield
    { .nr = SYS_sched_yield, .name = "sched_yield" },
#endif
#ifdef SYS_seccomp
    { .nr = SYS_seccomp, .name = "seccomp" },
#endif
#ifdef SYS_security
    { .nr = SYS_security, .name = "security" },
#endif
#ifdef SYS_select
    { .nr = SYS_select, .name = "select" },
#endif
#ifdef SYS_semctl
    { .nr = SYS_semctl, .name = "semctl" },
#endif
#ifdef SYS_semget
    { .nr = SYS_semget, .name = "semget" },
#endif
#ifdef SYS_semop
    { .nr = SYS_semop, .name = "semop" },
#endif
#ifdef SYS_semtimedop
    { .nr = SYS_semtimedop, .name = "semtimedop" },
#endif
#ifdef SYS_semtimedop_time64
    { .nr = SYS_semtimedop_time64, .name = "semtimedop_time64" },
#endif
#ifdef SYS_send
    { .nr = SYS_send, .name = "send" },
#endif
#ifdef SYS_sendfile
    { .nr = SYS_sendfile, .name = "sendfile" },
#endif
#ifdef SYS_sendfile64
    { .nr = SYS_sendfile64, .name = "sendfile64" },
#endif
#ifdef SYS_sendmmsg
    { .nr = SYS_sendmmsg, .name = "sendmmsg" },
#endif
#ifdef SYS_sendmsg
    { .nr = SYS_sendmsg, .name = "sendmsg" },
#endif
#ifdef SYS_sendto
    { .nr = SYS_sendto, .name = "sendto" },
#endif
#ifdef SYS_set_mempolicy
    { .nr = SYS_set_mempolicy, .name = "set_mempolicy" },
#endif
#ifdef SYS_set_robust_list
    { .nr = SYS_set_robust_list, .name = "set_robust_list" },
#endif
#ifdef SYS_set_thread_area
    { .nr = SYS_set_thread_area, .name = "set_thread_area" },
#endif
#ifdef SYS_set_tid_address
    { .nr = SYS_set_tid_address, .name = "set_tid_address" },
#endif
#ifdef SYS_set_tls
    { .nr = SYS_set_tls, .name = "set_tls" },
#endif
#ifdef SYS_setdomainname
    { .nr = SYS_setdomainname, .name = "setdomainname" },
#endif
#ifdef SYS_setfsgid
    { .nr = SYS_setfsgid, .name = "setfsgid" },
#endif
#ifdef SYS_setfsgid32
    { .nr = SYS_setfsgid32, .name = "setfsgid32" },
#endif
#ifdef SYS_setfsuid
    { .nr = SYS_setfsuid, .name = "setfsuid" },
#endif
#ifdef SYS_setfsuid32
    { .nr = SYS_setfsuid32, .name = "setfsuid32" },
#endif
#ifdef SYS_setgid
    { .nr = SYS_setgid, .name = "setgid" },
#endif
#ifdef SYS_setgid32
    { .nr = SYS_setgid32, .name = "setgid32" },
#endif
#ifdef SYS_setgroups
    { .nr = SYS_setgroups, .name = "setgroups" },
#endif
#ifdef SYS_setgroups32
    { .nr = SYS_setgroups32, .name = "setgroups32" },
#endif
#ifdef SYS_sethae
    { .nr = SYS_sethae, .name = "sethae" },
#endif
#ifdef SYS_sethostname
    { .nr = SYS_sethostname, .name = "sethostname" },
#endif
#ifdef SYS_setitimer
    { .nr = SYS_setitimer, .name = "setitimer" },
#endif
#ifdef SYS_setns
    { .nr = SYS_setns, .name = "setns" },
#endif
#ifdef SYS_setpgid
    { .nr = SYS_setpgid, .name = "setpgid" },
#endif
#ifdef SYS_setpgrp
    { .nr = SYS_setpgrp, .name = "setpgrp" },
#endif
#ifdef SYS_setpriority
    { .nr = SYS_setpriority, .name = "setpriority" },
#endif
#ifdef SYS_setregid
    { .nr = SYS_setregid, .name = "setregid" },
#endif
#ifdef SYS_setregid32
    { .nr = SYS_setregid32, .name = "setregid32" },
#endif
#ifdef SYS_setresgid
    { .nr = SYS_setresgid, .name = "setresgid" },
#endif
#ifdef SYS_setresgid32
    { .nr = SYS_setresgid32, .name = "setresgid32" },
#endif
#ifdef SYS_setresuid
    { .nr = SYS_setresuid, .name = "setresuid" },
#endif
#ifdef SYS_setresuid32
    { .nr = SYS_setresuid32, .name = "setresuid32" },
#endif
#ifdef SYS_setreuid
    { .nr = SYS_setreuid, .name = "setreuid" },
#endif
#ifdef SYS_setreuid32
    { .nr = SYS_setreuid32, .name = "setreuid32" },
#endif
#ifdef SYS_setrlimit
    { .nr = SYS_setrlimit, .name = "setrlimit" },
#endif
#ifdef SYS_setsid
    { .nr = SYS_setsid, .name = "setsid" },
#endif
#ifdef SYS_setsockopt
    { .nr = SYS_setsockopt, .name = "setsockopt" },
#endif
#ifdef SYS_settimeofday
    { .nr = SYS_settimeofday, .name = "settimeofday" },
#endif
#ifdef SYS_setuid
    { .nr = SYS_setuid, .name = "setuid" },
#endif
#ifdef SYS_setuid32
    { .nr = SYS_setuid32, .name = "setuid32" },
#endif
#ifdef SYS_setxattr
    { .nr = SYS_setxattr, .name = "setxattr" },
#endif
#ifdef SYS_sgetmask
    { .nr = SYS_sgetmask, .name = "sgetmask" },
#endif
#ifdef SYS_shmat
    { .nr = SYS_shmat, .name = "shmat" },
#endif
#ifdef SYS_shmctl
    { .nr = SYS_shmctl, .name = "shmctl" },
#endif
#ifdef SYS_shmdt
    { .nr = SYS_shmdt, .name = "shmdt" },
#endif
#ifdef SYS_shmget
    { .nr = SYS_shmget, .name = "shmget" },
#endif
#ifdef SYS_shutdown
    { .nr = SYS_shutdown, .name = "shutdown" },
#endif
#ifdef SYS_sigaction
    { .nr = SYS_sigaction, .name = "sigaction" },
#endif
#ifdef SYS_sigaltstack
    { .nr = SYS_sigaltstack, .name = "sigaltstack" },
#endif
#ifdef SYS_signal
    { .nr = SYS_signal, .name = "signal" },
#endif
#ifdef SYS_signalfd
    { .nr = SYS_signalfd, .name = "signalfd" },
#endif
#ifdef SYS_signalfd4
    { .nr = SYS_signalfd4, .name = "signalfd4" },
#endif
#ifdef SYS_sigpending
    { .nr = SYS_sigpending, .name = "sigpending" },
#endif
#ifdef SYS_sigprocmask
    { .nr = SYS_sigprocmask, .name = "sigprocmask" },
#endif
#ifdef SYS_sigreturn
    { .nr = SYS_sigreturn, .name = "sigreturn" },
#endif
#ifdef SYS_sigsuspend
    { .nr = SYS_sigsuspend, .name = "sigsuspend" },
#endif
#ifdef SYS_socket
    { .nr = SYS_socket, .name = "socket" },
#endif
#ifdef SYS_socketcall
    { .nr = SYS_socketcall, .name = "socketcall" },
#endif
#ifdef SYS_socketpair
    { .nr = SYS_socketpair, .name = "socketpair" },
#endif
#ifdef SYS_splice
    { .nr = SYS_splice, .name = "splice" },
#endif
#ifdef SYS_spu_create
    { .nr = SYS_spu_create, .name = "spu_create" },
#endif
#ifdef SYS_spu_run
    { .nr = SYS_spu_run, .name = "spu_run" },
#endif
#ifdef SYS_ssetmask
    { .nr = SYS_ssetmask, .name = "ssetmask" },
#endif
#ifdef SYS_stat
    { .nr = SYS_stat, .name = "stat" },
#endif
#ifdef SYS_stat64
    { .nr = SYS_stat64, .name = "stat64" },
#endif
#ifdef SYS_statfs
    { .nr = SYS_statfs, .name = "statfs" },
#endif
#ifdef SYS_statfs64
    { .nr = SYS_statfs64, .name = "statfs64" },
#endif
#ifdef SYS_statx
    { .nr = SYS_statx, .name = "statx" },
#endif
#ifdef SYS_stime
    { .nr = SYS_stime, .name = "stime" },
#endif
#ifdef SYS_stty
    { .nr = SYS_stty, .name = "stty" },
#endif
#ifdef SYS_subpage_prot
    { .nr = SYS_subpage_prot, .name = "subpage_prot" },
#endif
#ifdef SYS_swapcontext
    { .nr = SYS_swapcontext, .name = "swapcontext" },
#endif
#ifdef SYS_swapoff
    { .nr = SYS_swapoff, .name = "swapoff" },
#endif
#ifdef SYS_swapon
    { .nr = SYS_swapon, .name = "swapon" },
#endif
#ifdef SYS_switch_endian
    { .nr = SYS_switch_endian, .name = "switch_endian" },
#endif
#ifdef SYS_symlink
    { .nr = SYS_symlink, .name = "symlink" },
#endif
#ifdef SYS_symlinkat
    { .nr = SYS_symlinkat, .name = "symlinkat" },
#endif
#ifdef SYS_sync
    { .nr = SYS_sync, .name = "sync" },
#endif
#ifdef SYS_sync_file_range
    { .nr = SYS_sync_file_range, .name = "sync_file_range" },
#endif
#ifdef SYS_sync_file_range2
    { .nr = SYS_sync_file_range2, .name = "sync_file_range2" },
#endif
#ifdef SYS_syncfs
    { .nr = SYS_syncfs, .name = "syncfs" },
#endif
#ifdef SYS_sys_debug_setcontext
    { .nr = SYS_sys_debug_setcontext, .name = "sys_debug_setcontext" },
#endif
#ifdef SYS_sys_epoll_create
    { .nr = SYS_sys_epoll_create, .name = "sys_epoll_create" },
#endif
#ifdef SYS_sys_epoll_ctl
    { .nr = SYS_sys_epoll_ctl, .name = "sys_epoll_ctl" },
#endif
#ifdef SYS_sys_epoll_wait
    { .nr = SYS_sys_epoll_wait, .name = "sys_epoll_wait" },
#endif
#ifdef SYS_syscall
    { .nr = SYS_syscall, .name = "syscall" },
#endif
#ifdef SYS_sysfs
    { .nr = SYS_sysfs, .name = "sysfs" },
#endif
#ifdef SYS_sysinfo
    { .nr = SYS_sysinfo, .name = "sysinfo" },
#endif
#ifdef SYS_syslog
    { .nr = SYS_syslog, .name = "syslog" },
#endif
#ifdef SYS_sysmips
    { .nr = SYS_sysmips, .name = "sysmips" },
#endif
#ifdef SYS_tee
    { .nr = SYS_tee, .name = "tee" },
#endif
#ifdef SYS_tgkill
    { .nr = SYS_tgkill, .name = "tgkill" },
#endif
#ifdef SYS_time
    { .nr = SYS_time, .name = "time" },
#endif
#ifdef SYS_timer_create
    { .nr = SYS_timer_create, .name = "timer_create" },
#endif
#ifdef SYS_timer_delete
    { .nr = SYS_timer_delete, .name = "timer_delete" },
#endif
#ifdef SYS_timer_getoverrun
    { .nr = SYS_timer_getoverrun, .name = "timer_getoverrun" },
#endif
#ifdef SYS_timer_gettime
    { .nr = SYS_timer_gettime, .name = "timer_gettime" },
#endif
#ifdef SYS_timer_gettime64
    { .nr = SYS_timer_gettime64, .name = "timer_gettime64" },
#endif
#ifdef SYS_timer_settime
    { .nr = SYS_timer_settime, .name = "timer_settime" },
#endif
#ifdef SYS_timer_settime64
    { .nr = SYS_timer_settime64, .name = "timer_settime64" },
#endif
#ifdef SYS_timerfd
    { .nr = SYS_timerfd, .name = "timerfd" },
#endif
#ifdef SYS_timerfd_create
    { .nr = SYS_timerfd_create, .name = "timerfd_create" },
#endif
#ifdef SYS_timerfd_gettime
    { .nr = SYS_timerfd_gettime, .name = "timerfd_gettime" },
#endif
#ifdef SYS_timerfd_gettime64
    { .nr = SYS_timerfd_gettime64, .name = "timerfd_gettime64" },
#endif
#ifdef SYS_timerfd_settime
    { .nr = SYS_timerfd_settime, .name = "timerfd_settime" },
#endif
#ifdef SYS_timerfd_settime64
    { .nr = SYS_timerfd_settime64, .name = "timerfd_settime64" },
#endif
#ifdef SYS_times
    { .nr = SYS_times, .name = "times" },
#endif
#ifdef SYS_tkill
    { .nr = SYS_tkill, .name = "tkill" },
#endif
#ifdef SYS_truncate
    { .nr = SYS_truncate, .name = "truncate" },
#endif
#ifdef SYS_truncate64
    { .nr = SYS_truncate64, .name = "truncate64" },
#endif
#ifdef SYS_tuxcall
    { .nr = SYS_tuxcall, .name = "tuxcall" },
#endif
#ifdef SYS_udftrap
    { .nr = SYS_udftrap, .name = "udftrap" },
#endif
#ifdef SYS_ugetrlimit
    { .nr = SYS_ugetrlimit, .name = "ugetrlimit" },
#endif
#ifdef SYS_ulimit
    { .nr = SYS_ulimit, .name = "ulimit" },
#endif
#ifdef SYS_umask
    { .nr = SYS_umask, .name = "umask" },
#endif
#ifdef SYS_umount
    { .nr = SYS_umount, .name = "umount" },
#endif
#ifdef SYS_umount2
    { .nr = SYS_umount2, .name = "umount2" },
#endif
#ifdef SYS_uname
    { .nr = SYS_uname, .name = "uname" },
#endif
#ifdef SYS_unlink
    { .nr = SYS_unlink, .name = "unlink" },
#endif
#ifdef SYS_unlinkat
    { .nr = SYS_unlinkat, .name = "unlinkat" },
#endif
#ifdef SYS_unshare
    { .nr = SYS_unshare, .name = "unshare" },
#endif
#ifdef SYS_uselib
    { .nr = SYS_uselib, .name = "uselib" },
#endif
#ifdef SYS_userfaultfd
    { .nr = SYS_userfaultfd, .name = "userfaultfd" },
#endif
#ifdef SYS_usr26
    { .nr = SYS_usr26, .name = "usr26" },
#endif
#ifdef SYS_usr32
    { .nr = SYS_usr32, .name = "usr32" },
#endif
#ifdef SYS_ustat
    { .nr = SYS_ustat, .name = "ustat" },
#endif
#ifdef SYS_utime
    { .nr = SYS_utime, .name = "utime" },
#endif
#ifdef SYS_utimensat
    { .nr = SYS_utimensat, .name = "utimensat" },
#endif
#ifdef SYS_utimensat_time64
    { .nr = SYS_utimensat_time64, .name = "utimensat_time64" },
#endif
#ifdef SYS_utimes
    { .nr = SYS_utimes, .name = "utimes" },
#endif
#ifdef SYS_utrap_install
    { .nr = SYS_utrap_install, .name = "utrap_install" },
#endif
#ifdef SYS_vfork
    { .nr = SYS_vfork, .name = "vfork" },
#endif
#ifdef SYS_vhangup
    { .nr = SYS_vhangup, .name = "vhangup" },
#endif
#ifdef SYS_vm86
    { .nr = SYS_vm86, .name = "vm86" },
#endif
#ifdef SYS_vm86old
    { .nr = SYS_vm86old, .name = "vm86old" },
#endif
#ifdef SYS_vmsplice
    { .nr = SYS_vmsplice, .name = "vmsplice" },
#endif
#ifdef SYS_vserver
    { .nr = SYS_vserver, .name = "vserver" },
#endif
#ifdef SYS_wait4
    { .nr = SYS_wait4, .name = "wait4" },
#endif
#ifdef SYS_waitid
    { .nr = SYS_waitid, .name = "waitid" },
#endif
#ifdef SYS_waitpid
    { .nr = SYS_waitpid, .name = "waitpid" },
#endif
#ifdef SYS_writev
    { .nr = SYS_writev, .name = "writev" },
#endif
    { .nr = SYS_write, .name = "write" }
};

#endif // _CTRACE_H_
