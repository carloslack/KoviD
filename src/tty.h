#ifndef __TTY_H
#define __TTY_H

enum { //tty flags
    R_NONE = 0,
    R_RETURN = 1,
    R_NEWLINE=2,
    R_RANGE=4
};
bool kv_tty_open(const char *);
void kv_tty_write(uid_t, char *, ssize_t);
void kv_tty_close(void);
#endif //__TTY_H
