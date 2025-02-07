#include <linux/version.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include "lkm.h"
#include "log.h"

// Returns the starting virtual memory address of
// the ELF executable for a specified process.
// This function takes a process ID (PID) as
// input and retrieves the virtual memory area (VMA)
// corresponding to the ELF executable in
// that process's memory map.
unsigned long kv_get_elf_vm_start(pid_t pid)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;

	if (pid <= 0) {
		prerr("invalid pid %d\n", pid);
		return 0L;
	}

	tsk = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	if (!tsk) {
		prwarn("No such task for pid %d\n", pid);
		return 0L;
	}

	if (!tsk->mm) {
		prwarn("No such task for pid (kthread) %d\n", pid);
		return 0L;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	vma = find_vma(tsk->mm, 0);
#else
	vma = tsk->mm->mmap;
#endif
	if (!vma) {
		prerr("invalid vma for pid %d\n", pid);
		return 0L;
	}

	// base address
	return vma->vm_start;
}
