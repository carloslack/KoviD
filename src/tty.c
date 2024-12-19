
#include <linux/types.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/stat.h>
#include "fs.h"
#include "tty.h"
#include "log.h"

static DEFINE_SPINLOCK(tty_lock);
static struct file *filp;

bool kv_tty_open(const char *filename) {
    if (filename != NULL)
        filp = fs_kernel_open_file(filename);

    prinfo("FILP: %p [%d]\n", filp, filp ? true: false);
    return filp ? true: false;
}

void kv_tty_write(uid_t uid, char *buf, ssize_t len) {
    static loff_t offset;
    struct timespec64 ts;
    long msecs;
    size_t total;

    /**
     * We use a variable-length array (VLA) because the implementation of kernel_write
     * forces a conversion to a user pointer. If the variable is heap-allocated, the
     * pointer may be lost.
     *
     * VLA generates a warning since we're not in C99, but it's necessary for our use case.
     *
     * We allocate +32 bytes, which is enough to hold timestamp + "uid.%d".
     */
    char ttybuf[len+32];

    spin_lock(&tty_lock);

    ktime_get_boottime_ts64(&ts);
    msecs = ts.tv_nsec / 1000;

    total = snprintf(ttybuf,
            sizeof(ttybuf), "[%lld.%06ld] uid.%d %s",
            (long long)ts.tv_sec, msecs, uid, buf);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    fs_kernel_write_file(filp, (const void*)ttybuf, total, &offset);
#else
    fs_kernel_write_file(filp, (const char*)ttybuf, total, offset);
#endif
    spin_unlock(&tty_lock);
}

void kv_tty_close(void) {
    fs_kernel_close_file(filp);
    filp = NULL;
}
