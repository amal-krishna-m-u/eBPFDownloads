#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/fs.h>

struct ext4_event {
    u32 pid;
    u64 pblk;
    u32 lblk_len;
    char comm[16];
};

// Define the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/ext4/ext4_ext_map_blocks_exit")
int trace_ext4_ext_map_blocks_exit(struct trace_event_raw_ext4_ext_map_blocks_exit *ctx) {
    struct ext4_event *event;

    // Reserve space in the ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(struct ext4_event), 0);
    if (!event) {
        return 0; // Skip if ring buffer reservation fails
    }

    // Populate event data
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->pblk = ctx->pblk;
    event->lblk_len = ctx->len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Submit data to the ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
