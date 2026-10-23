// SPDX-License-Identifier: GPL-2.0
//
// Minimal uprobe/uretprobe tracer for application function calls.

#include "../../capture/bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct probe_config {
	__u32 target_tgid; /* 0 = all processes */
	__u32 enabled;
};

struct start_key {
	__u32 pid;
	__u32 tid;
	__u64 cookie;
};

struct probe_event {
	__u64 ts_ns;
	__u64 duration_ns;
	__u32 pid;
	__u32 tid;
	__u64 cookie;
	__u64 cgroup_id;
	__u8 kind; /* 1 = return */
	__u8 comm[16];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct probe_config);
} probe_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct start_key);
	__type(value, __u64);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("uprobe")
int probe_entry(struct pt_regs *ctx)
{
	__u32 zero = 0;
	struct probe_config *cfg = bpf_map_lookup_elem(&probe_cfg, &zero);
	if (!cfg || !cfg->enabled)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	if (cfg->target_tgid && tgid != cfg->target_tgid)
		return 0;
	struct start_key key = {
		.pid = pid,
		.tid = tgid,
		.cookie = bpf_get_attach_cookie(ctx),
	};
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &key, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int probe_return(struct pt_regs *ctx)
{
	__u32 zero = 0;
	struct probe_config *cfg = bpf_map_lookup_elem(&probe_cfg, &zero);
	if (!cfg || !cfg->enabled)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	if (cfg->target_tgid && tgid != cfg->target_tgid)
		return 0;
	struct start_key key = {
		.pid = pid,
		.tid = tgid,
		.cookie = bpf_get_attach_cookie(ctx),
	};
	__u64 *start = bpf_map_lookup_elem(&starts, &key);
	if (!start)
		return 0;
	__u64 now = bpf_ktime_get_ns();
	struct probe_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->ts_ns = now;
		e->duration_ns = now - *start;
		e->pid = tgid;
		e->tid = pid;
		e->cookie = key.cookie;
		e->cgroup_id = bpf_get_current_cgroup_id();
		e->kind = 1;
		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&starts, &key);
	return 0;
}

char _license[] SEC("license") = "GPL";
