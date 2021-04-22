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

#endif // _CTRACE_H_
