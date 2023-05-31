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

