
/**
 * Linux Kernel version <= 5.10.0
 * - hash
 *
 *   KoviD
 */

#ifndef __BPF_H
#define __BPF_H

#define u64_to_user_ptr(x) (            \
    {                                   \
        typecheck(u64, (x));            \
        (void __user *)(uintptr_t)(x);  \
    }                                   \
)

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member)                 \
    ({                                                  \
        void *__mptr = (void *)(ptr);                   \
        ((type *)(__mptr - offsetof(type, member)));    \
    })
#endif

#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)

#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
        (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
        (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_PROG_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map) || \
        IS_FD_HASH(map))

struct pcpu_freelist_head {
    struct pcpu_freelist_node *first;
    raw_spinlock_t lock;
};

struct pcpu_freelist {
    struct pcpu_freelist_head __percpu *freelist;
    struct pcpu_freelist_head extralist;
};

struct pcpu_freelist_node {
    struct pcpu_freelist_node *next;
};
struct stack_map_bucket {
    struct pcpu_freelist_node fnode;
    u32 hash;
    u32 nr;
    u64 data[];
};

struct bpf_stack_map {
    struct bpf_map map;
    void *elems;
    struct pcpu_freelist freelist;
    u32 n_buckets;
    struct stack_map_bucket *buckets[];
};

static LIST_HEAD(sys_addr);
struct sys_addr_list {
    unsigned long addr;
    struct list_head list;
};

#endif
