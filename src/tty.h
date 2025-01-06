#ifndef __TTY_H
#define __TTY_H

#define KEY_LOG_BUF_MAX 512
enum { //tty flags
	R_NONE = 0,
	R_RETURN = 1,
	R_NEWLINE = 2,
	R_RANGE = 4
};

/**
 * TTY user context
 */
struct tty_ctx {
	struct file *fp;
	struct list_head *head;
};

struct tty_ctx kv_tty_open(struct tty_ctx *, const char *);
void kv_tty_write(struct tty_ctx *, uid_t, char *, ssize_t);
int kv_key_update(struct tty_ctx *, uid_t, char, int);
void kv_tty_close(struct tty_ctx *);
#endif //__TTY_H
