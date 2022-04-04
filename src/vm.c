#include <linux/version.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include "lkm.h"

unsigned long kv_get_elf_vm_start(pid_t pid) {
    struct vm_area_struct *vma;
    struct task_struct *tsk;

    if (pid <= 0) {
        prerr("invalid pid %d\n", pid);
        return 0L;
    }

    tsk = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if(!tsk) {
        prwarn("No such task for pid %d\n", pid);
        return 0L;
    }

    if(!tsk->mm) {
        prwarn("No such task for pid (kthread) %d\n", pid);
        return 0L;
    }

    vma = tsk->mm->mmap;
    if (!vma) {
        prerr("invalid vma for pid %d\n", pid);
        return 0L;
    }

    /** base address */
    return vma->vm_start;
}
