#define _GNU_SOURCE

#include "fdclose.h"

int fdclose(int pid, int fd){

        struct ptrace_do *target;
        target = ptrace_do_init(pid);
        ptrace_do_syscall(target, __NR_close, fd, 0, 0, 0, 0, 0);
        ptrace_do_cleanup(target);
        return(0);
}
