#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define AF_INET 2

char LICENSE[] SEC("license") = "GPL";

struct text_key_t {
    char name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} protected_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, struct text_key_t);
} blocked_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct text_key_t);
    __type(value, __u32);
} allowed_commands SEC(".maps");

static __always_inline int is_protected() {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *val = bpf_map_lookup_elem(&protected_pids, &pid);
    if (val) return 1;
    return 0;
}

static __always_inline int str_contains(const char *haystack, const char *needle) {
    for (int i = 0; i < 32; i++) {
        if (needle[i] == '\0') return 1;
        if (haystack[i] != needle[i]) return 0;
    }
    return 1;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 *val = bpf_map_lookup_elem(&protected_pids, &parent_pid);
    if (val) {
        __u32 child_pid = ctx->child_pid;
        __u32 secure = 1;
        bpf_map_update_elem(&protected_pids, &child_pid, &secure, BPF_ANY);
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    if (!is_protected()) return 0;

    char full_path[128];
    struct text_key_t exec_name = {};
    struct text_key_t full_name = {};
    
    long ret = bpf_probe_read_kernel_str(full_path, sizeof(full_path), bprm->filename);
    if (ret < 0) return 0;

    #pragma unroll
    for (int i = 0; i < 31; i++) {
        full_name.name[i] = full_path[i];
        if (full_path[i] == '\0') break;
    }

    if (bpf_map_lookup_elem(&allowed_commands, &full_name)) return 0;

    int start = 0;
    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (full_path[i] == '\0') break;
        if (full_path[i] == '/') start = i + 1;
    }

    #pragma unroll
    for (int i = 0; i < 31; i++) {
        unsigned int idx = (start + i) & 0x7F;
        char c = full_path[idx];
        exec_name.name[i] = c;
        if (c == '\0') break;
    }

    if (bpf_map_lookup_elem(&allowed_commands, &exec_name)) return 0;

    bpf_printk("BLOCK: Unauthorized Child Process: %s\n", full_path);
    return -EPERM;
}

SEC("lsm/socket_connect")
int BPF_PROG(restrict_network, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!is_protected()) return 0;
    if (address->sa_family != AF_INET) return 0;
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    __u32 dest_ip = addr->sin_addr.s_addr;
    if (dest_ip == 0x0100007F) return 0;
    __u32 *allowed = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    if (allowed) return 0;
    bpf_printk("BLOCK: Network Blocked! IP: %x\n", dest_ip);
    return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file) {
    if (!is_protected()) return 0;
    char filename[32];
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));
    for (int i = 0; i < 32; i++) {
        int idx = i;
        struct text_key_t *blocked = bpf_map_lookup_elem(&blocked_files, &idx);
        if (!blocked) break;
        if (blocked->name[0] == '\0') continue;
        if (str_contains(filename, blocked->name)) {
            bpf_printk("BLOCK: File Access Blocked! %s\n", filename);
            return -EPERM;
        }
    }
    return 0;
}
