 #include "common.h"  // Assuming this header includes necessary BPF helpers and macros

struct ext4_event {
    u32 pid;
    ext4_fsblk_t pblk;
    unsigned int len;
    char comm[16];
};

// Define the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/ext4/ext4_ext_map_blocks_exit")
int trace_ext4_ext_map_blocks_exit(struct trace_event_raw_ext4__map_blocks_exit *ctx) {
    struct ext4_event *event = bpf_ringbuf_reserve(&events, sizeof(struct ext4_event), 0);
    if (!event) {
        return 0; // Skip if ring buffer reservation fails
    }

    event->pid = bpf_get_current_pid_tgid();
    event->pblk = ctx->pblk;
    event->len = ctx->len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
