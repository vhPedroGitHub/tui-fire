#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* CO-RE relocates these fields against the running kernel's BTF. */
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
struct inode { unsigned long i_ino; };
struct file { struct inode *f_inode; };
struct socket { struct file *file; struct sock *sk; };
struct sock_common { __u16 skc_family; };
struct sock { struct sock_common __sk_common; struct socket *sk_socket; };
struct sk_buff { struct sock *sk; };
struct task_struct {
    struct task_struct *group_leader;
    __u64 start_boottime;
    char comm[16];
};
#pragma clang attribute pop

struct process_key {
    __u64 start_ticks;
    __u32 pid;
    __u32 reserved;
};

struct owner {
    struct process_key key;
    char name[16];
};

struct traffic {
    __u64 rx, tx, dropped;
    char name[16];
};

#define HASH_MAP(name, kind, key_type, value_type, capacity) \
    struct {                                                \
        __uint(type, kind);                                 \
        __uint(max_entries, capacity);                      \
        __type(key, key_type);                              \
        __type(value, value_type);                          \
    } name SEC(".maps")

HASH_MAP(socket_owners, BPF_MAP_TYPE_HASH, __u64, struct owner, 131072);
HASH_MAP(socket_creators, BPF_MAP_TYPE_LRU_HASH, __u64, struct owner, 131072);
HASH_MAP(blocked_sockets, BPF_MAP_TYPE_HASH, __u64, struct owner, 131072);
HASH_MAP(blocked_pids, BPF_MAP_TYPE_HASH, struct process_key, __u8, 16384);
HASH_MAP(process_bytes, BPF_MAP_TYPE_HASH, struct process_key, struct traffic, 65536);

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct traffic);
} unassigned_bytes SEC(".maps");

extern void *bpf_cast_to_kern_ctx(void *ctx) __ksym;

SEC("fexit/sock_alloc_file")
int BPF_PROG(record_socket, struct socket *socket, int flags,
             const char *name, struct file *file)
{
    struct owner owner = {};
    struct sock *sk = BPF_CORE_READ(socket, sk);
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2 && family != 10) /* AF_INET, AF_INET6 */
        return 0;

    __u64 inode = BPF_CORE_READ(file, f_inode, i_ino);
    if (!inode)
        return 0;

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    owner.key.pid = bpf_get_current_pid_tgid() >> 32;
    /* /proc/<pid>/stat uses USER_HZ=100 on the supported architectures. */
    owner.key.start_ticks = BPF_CORE_READ(leader, start_boottime) / 10000000;
    bpf_core_read_str(owner.name, sizeof(owner.name), &leader->comm);
    bpf_map_update_elem(&socket_creators, &inode, &owner, BPF_ANY);
    return 0;
}

static __always_inline __u64 socket_inode(struct __sk_buff *ctx)
{
    struct sk_buff *skb = bpf_cast_to_kern_ctx(ctx);
    struct sock *sk = skb->sk;
    if (!sk)
        return 0;
    struct socket *socket = sk->sk_socket;
    if (!socket)
        return 0;
    struct file *file = socket->file;
    if (!file)
        return 0;
    struct inode *inode = file->f_inode;
    return inode ? inode->i_ino : 0;
}

static __always_inline int account(struct __sk_buff *ctx, int ingress)
{
    __u64 inode = socket_inode(ctx);
    struct owner *owner = 0;
    int blocked = 0;

    if (inode) {
        owner = bpf_map_lookup_elem(&blocked_sockets, &inode);
        if (owner && bpf_map_lookup_elem(&blocked_pids, &owner->key)) {
            blocked = 1;
        } else {
            owner = bpf_map_lookup_elem(&socket_owners, &inode);
            if (!owner)
                owner = bpf_map_lookup_elem(&socket_creators, &inode);
            if (owner && bpf_map_lookup_elem(&blocked_pids, &owner->key))
                blocked = 1;
        }
    }

    struct traffic *bytes = 0;
    if (owner) {
        bytes = bpf_map_lookup_elem(&process_bytes, &owner->key);
        if (!bytes) {
            struct traffic initial = {};
            __builtin_memcpy(initial.name, owner->name, sizeof(initial.name));
            bpf_map_update_elem(&process_bytes, &owner->key, &initial, BPF_NOEXIST);
            bytes = bpf_map_lookup_elem(&process_bytes, &owner->key);
        }
    }
    if (!bytes) {
        __u32 index = 0;
        bytes = bpf_map_lookup_elem(&unassigned_bytes, &index);
    }

    if (bytes) {
        __u64 len = ctx->len;
        if (blocked)
            __sync_fetch_and_add(&bytes->dropped, len);
        else if (ingress)
            __sync_fetch_and_add(&bytes->rx, len);
        else
            __sync_fetch_and_add(&bytes->tx, len);
    }
    return !blocked;
}

SEC("cgroup_skb/ingress")
int inspect_ingress(struct __sk_buff *skb)
{
    return account(skb, 1);
}

SEC("cgroup_skb/egress")
int inspect_egress(struct __sk_buff *skb)
{
    return account(skb, 0);
}

char LICENSE[] SEC("license") = "GPL";
