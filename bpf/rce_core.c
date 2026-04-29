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

struct event_t {
    __u32 pid;
    __u32 uid;
    int event_type;
    int action;
    char target_data[128];
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB buffer */
} events_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, int);
    __type(value, struct text_key_t); 
} allowed_write_files SEC(".maps");

static __always_inline int is_protected() {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *val = bpf_map_lookup_elem(&protected_pids, &pid);
    if (val) return 1;
    return 0;
}


static __always_inline int str_contains(const char *haystack, const char *needle) {
    if (needle[0] == '\0') return 0;
    

    for (int i = 0; i < 64; i++) { 
        if (haystack[i] == '\0') break;
        
        int match = 1;
        for (int j = 0; j < 16; j++) { 
            if (needle[j] == '\0') break;
            
            if (i + j >= 128) {
                match = 0;
                break;
            }
            
            if (haystack[i + j] != needle[j]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// [NEW]: Helper function to check if a file can be created/modified/deleted
static __always_inline int is_write_allowed(const char *filename) {
    for (int i = 0; i < 32; i++) {
        int idx = i;
        struct text_key_t *allowed = bpf_map_lookup_elem(&allowed_write_files, &idx);
        if (!allowed) break;
        if (allowed->name[0] == '\0') continue; 
        
        if (str_contains(filename, allowed->name)) {
            return 1; // Allowed!
        }
    }
    return 0; // Blocked!
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

SEC("tp/sched/sched_process_exit")
int handle_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&protected_pids, &pid);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    if (!is_protected()) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct event_t), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = 0;
    e->action = 0;

    char full_path[128];
    struct text_key_t exec_name = {};
    struct text_key_t full_name = {};
    
    long ret = bpf_probe_read_kernel_str(full_path, sizeof(full_path), bprm->filename);
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_probe_read_kernel_str(e->target_data, sizeof(e->target_data), full_path);

    #pragma unroll
    for (int i = 0; i < 31; i++) {
        full_name.name[i] = full_path[i];
        if (full_path[i] == '\0') break;
    }

    if (bpf_map_lookup_elem(&allowed_commands, &full_name)) {
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

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

    if (bpf_map_lookup_elem(&allowed_commands, &exec_name)) {
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    e->action = 1;
    bpf_ringbuf_submit(e, 0);
    return -EPERM;
}

SEC("lsm/socket_connect")
int BPF_PROG(restrict_network, struct socket *sock, struct sockaddr *address, int addrlen) {
    if (!is_protected()) return 0;
    if (address->sa_family != AF_INET) return 0;
    
    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    __u32 dest_ip = addr->sin_addr.s_addr;
    if (dest_ip == 0x0100007F) return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct event_t), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = 1; 
    e->action = 0;

    e->target_data[0] = 'I'; e->target_data[1] = 'P'; e->target_data[2] = ':'; e->target_data[3] = ' ';
    e->target_data[4] = '\0'; 
    
    __u32 *allowed = bpf_map_lookup_elem(&allowed_ips, &dest_ip);
    if (allowed) {
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    e->action = 1; 
    bpf_ringbuf_submit(e, 0);
    return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_file_open, struct file *file) {
    if (!is_protected()) return 0;
    
    char filename[128];
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));
    
    struct event_t *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct event_t), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = 2; 
    e->action = 0; 
    bpf_probe_read_kernel_str(e->target_data, sizeof(e->target_data), filename);

    unsigned int f_flags = BPF_CORE_READ(file, f_flags);
    int is_write = ((f_flags & 3) != 0) || ((f_flags & 0100) != 0);

    if (is_write) {
        // [CHANGED]: Use the helper function here
        if (is_write_allowed(filename)) {
            bpf_ringbuf_discard(e, 0);
            return 0; 
        }

        e->action = 1; 
        e->target_data[0] = '['; e->target_data[1] = 'W'; e->target_data[2] = 'R'; 
        e->target_data[3] = 'T'; e->target_data[4] = ']'; e->target_data[5] = ' '; 
        bpf_probe_read_kernel_str(e->target_data + 6, sizeof(e->target_data) - 6, filename);
        
        bpf_ringbuf_submit(e, 0);
        return -EPERM; 
    }

    for (int i = 0; i < 32; i++) {
        int idx = i;
        struct text_key_t *blocked = bpf_map_lookup_elem(&blocked_files, &idx);
        if (!blocked) break;
        if (blocked->name[0] == '\0') continue;
        if (str_contains(filename, blocked->name)) {
            e->action = 1; 
            bpf_ringbuf_submit(e, 0);
            return -EPERM;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(restrict_unlink, struct inode *dir, struct dentry *dentry) {
    if (!is_protected()) return 0; 

    char filename[128];
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));
    
    // [CHANGED]: Use the helper function to allow valid unlink operations (like temporary files)
    if (is_write_allowed(filename)) {
        return 0;
    }

    struct event_t *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct event_t), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = 2; 
    e->action = 1;    

    e->target_data[0] = '['; e->target_data[1] = 'D'; e->target_data[2] = 'E'; 
    e->target_data[3] = 'L'; e->target_data[4] = ']'; e->target_data[5] = ' '; 
    bpf_probe_read_kernel_str(e->target_data + 6, sizeof(e->target_data) - 6, filename);

    bpf_ringbuf_submit(e, 0);
    return -EPERM; 
}

SEC("lsm/inode_create")
int BPF_PROG(restrict_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    if (!is_protected()) return 0; 

    char filename[128];
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));

    // [CHANGED]: Use the helper function to allow valid inode creation
    if (is_write_allowed(filename)) {
        return 0;
    }

    struct event_t *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct event_t), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->event_type = 2; 
    e->action = 1;     

    e->target_data[0] = '['; e->target_data[1] = 'C'; e->target_data[2] = 'R'; 
    e->target_data[3] = 'T'; e->target_data[4] = ']'; e->target_data[5] = ' '; 
    bpf_probe_read_kernel_str(e->target_data + 6, sizeof(e->target_data) - 6, filename);

    bpf_ringbuf_submit(e, 0);
    return -EPERM; 
}