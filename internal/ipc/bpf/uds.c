// SPDX-License-Identifier: GPL-2.0
//
// Unix-domain-socket payload tracer.
//
// Send-side payloads are captured at the AF_UNIX sendmsg fentry hooks, before
// the payload is consumed. Stream receives are captured from
// unix_stream_read_actor, which runs once per skb chunk before data is copied
// into the reader. Datagram/seqpacket receives are captured at the fexit hook
// of unix_dgram_recvmsg and read back from the caller's original iovec.
//
// fentry/fexit is used instead of kprobes so the object is independent of the
// host pt_regs ABI (amd64, arm64, ...). The verifier still needs kernel BTF.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define UDS_MAX_PAYLOAD 4096
#define UDS_MAX_SEG 8

#define UDS_DIR_SEND 0
#define UDS_DIR_RECV 1

struct uds_config {
	__u32 enabled;
	__u32 max_payload;
	__u32 target_pid; /* tgid, 0 = all processes */
	__u32 _pad;
	__u64 target_cgroup; /* cgroup v2 id, 0 = all cgroups */
};

struct uds_stats {
	__u64 events;
	__u64 bytes;
	__u64 truncated;
	__u64 dropped;
};

struct uds_event {
	__u64 ts_ns;
	__u64 cgroup_id;
	__u64 inode;
	__u32 pid;
	__u32 tid;
	__u32 cap_len;
	__u32 orig_len;
	__u8 direction;
	__u8 type;
	__u8 truncated;
	__u8 part;
	__u8 parts;
	__u8 _pad[3];
	__u8 comm[16];
} __attribute__((packed));

/* Payload is assembled in a per-CPU scratch map, then emitted with
 * bpf_ringbuf_output(). This keeps verifier writes bounded and the output
 * record size constant. */
struct uds_record {
	struct uds_event event;
	__u8 data[UDS_MAX_PAYLOAD];
};

struct uds_iov {
	__u64 base;
	__u64 len;
};

/* Captured at unix_dgram_recvmsg entry so fexit can read the same user buffer
 * after the kernel has filled it. Only the first UDS_MAX_SEG iovecs are kept. */
struct recv_snapshot {
	__u64 inode;
	__u64 count;
	__u64 iov_offset;
	__u8 type;
	__u8 iter_type;
	__u8 nr_segs;
	__u8 truncated;
	__u32 _pad;
	struct uds_iov iov[UDS_MAX_SEG];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 23); /* 8 MiB, resized from userspace */
} uds_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct uds_config);
} uds_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct uds_stats);
} uds_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct uds_record);
} uds_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct recv_snapshot);
} uds_recv_state SEC(".maps");

static __always_inline int allowed(struct uds_config *cfg)
{
	if (!cfg->enabled)
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (cfg->target_pid && (__u32)(pid_tgid >> 32) != cfg->target_pid)
		return 0;
	if (cfg->target_cgroup &&
	    bpf_get_current_cgroup_id() != cfg->target_cgroup)
		return 0;
	return 1;
}

static __always_inline struct uds_stats *stats(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&uds_stats_map, &zero);
}

static __always_inline struct uds_record *scratch_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&uds_scratch, &zero);
}

static __always_inline __u32 clamp_payload(__u32 max)
{
	if (max == 0 || max > UDS_MAX_PAYLOAD)
		return UDS_MAX_PAYLOAD;
	return max;
}

static __always_inline void init_event(struct uds_record *rec, __u32 orig_len,
				       __u64 inode, __u8 direction, __u8 type,
				       __u8 part, __u8 parts)
{
	struct uds_event *e = &rec->event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->inode = inode;
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->cap_len = 0;
	e->orig_len = orig_len;
	e->direction = direction;
	e->type = type;
	e->truncated = 0;
	e->part = part;
	e->parts = parts;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void finish_event(struct uds_record *rec)
{
	struct uds_stats *st = stats();
	long ret = bpf_ringbuf_output(&uds_events, rec, sizeof(*rec), 0);
	if (ret < 0) {
		if (st)
			st->dropped++;
		return;
	}
	if (st) {
		st->events++;
		st->bytes += rec->event.cap_len;
		if (rec->event.truncated)
			st->truncated++;
	}
}

static __always_inline void emit_user_segment(__u64 inode, __u8 type,
					      __u8 direction, const void *base,
					      __u32 len, __u32 max,
					      __u8 part, __u8 parts,
					      __u8 global_truncated)
{
	if (len == 0)
		return;
	__u32 cap = len < max ? len : max;
	struct uds_record *rec = scratch_event();
	if (!rec)
		return;
	init_event(rec, len, inode, direction, type, part, parts);
	if (bpf_probe_read_user(rec->data, cap, base) < 0) {
		rec->event.truncated = 1;
		rec->event.cap_len = 0;
	} else {
		rec->event.cap_len = cap;
		rec->event.truncated = (global_truncated || cap < len) ? 1 : 0;
	}
	finish_event(rec);
}

static __always_inline void emit_kernel_segment(__u64 inode, __u8 type,
						__u8 direction, const void *base,
						__u32 len, __u32 max,
						__u8 part, __u8 parts)
{
	if (len == 0)
		return;
	__u32 cap = len < max ? len : max;
	struct uds_record *rec = scratch_event();
	if (!rec)
		return;
	init_event(rec, len, inode, direction, type, part, parts);
	if (bpf_probe_read_kernel(rec->data, cap, base) < 0) {
		rec->event.truncated = 1;
		rec->event.cap_len = 0;
	} else {
		rec->event.cap_len = cap;
		rec->event.truncated = cap < len ? 1 : 0;
	}
	finish_event(rec);
}

/* Send-side: emit one event per iovec segment so all segments are covered
 * without unbounded verifier pointer arithmetic. */
static __always_inline int trace_send(struct socket *sock, struct msghdr *msg,
				      size_t len)
{
	__u32 zero = 0;
	struct uds_config *cfg = bpf_map_lookup_elem(&uds_cfg, &zero);
	if (!cfg || !allowed(cfg))
		return 0;
	if (!sock || !msg)
		return 0;

	__u64 inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
	if (!inode)
		return 0;
	__u8 type = (__u8)BPF_CORE_READ(sock, type);
	__u32 max = clamp_payload(cfg->max_payload);

	struct iov_iter *iter = &msg->msg_iter;
	__u64 remaining = BPF_CORE_READ(iter, count);
	__u64 offset = BPF_CORE_READ(iter, iov_offset);
	__u8 iter_type = BPF_CORE_READ(iter, iter_type);
	__u64 nr = BPF_CORE_READ(iter, nr_segs);
	if (remaining == 0 && len != 0)
		remaining = len;
	if (nr == 0)
		nr = 1;

	if (iter_type == ITER_UBUF) {
		void *buf = (void *)BPF_CORE_READ(iter, ubuf);
		__u32 seg = remaining > max ? max : (__u32)remaining;
		emit_user_segment(inode, type, UDS_DIR_SEND,
				  (__u8 *)buf + offset, seg, max, 0, 1,
				  remaining > max ? 1 : 0);
		return 0;
	}

	if (iter_type == ITER_IOVEC) {
		const struct iovec *iov =
			(const struct iovec *)BPF_CORE_READ(iter, __iov);
#pragma unroll
		for (int i = 0; i < UDS_MAX_SEG; i++) {
			if (i >= nr || remaining == 0)
				break;
			struct iovec vec = {};
			if (bpf_probe_read_kernel(&vec, sizeof(vec), &iov[i]) < 0)
				break;
			__u64 skip = i == 0 ? offset : 0;
			if (vec.iov_len <= skip)
				continue;
			__u64 avail = vec.iov_len - skip;
			__u32 seg = avail < remaining ? (__u32)avail : (__u32)remaining;
			emit_user_segment(inode, type, UDS_DIR_SEND,
					  (__u8 *)vec.iov_base + skip, seg, max,
					  i, nr > UDS_MAX_SEG ? UDS_MAX_SEG : nr,
					  nr > UDS_MAX_SEG ? 1 : 0);
			remaining -= seg;
		}
		return 0;
	}

	if (iter_type == ITER_KVEC) {
		const struct kvec *kvec =
			(const struct kvec *)BPF_CORE_READ(iter, kvec);
#pragma unroll
		for (int i = 0; i < UDS_MAX_SEG; i++) {
			if (i >= nr || remaining == 0)
				break;
			struct kvec vec = {};
			if (bpf_probe_read_kernel(&vec, sizeof(vec), &kvec[i]) < 0)
				break;
			__u64 skip = i == 0 ? offset : 0;
			if (vec.iov_len <= skip)
				continue;
			__u64 avail = vec.iov_len - skip;
			__u32 seg = avail < remaining ? (__u32)avail : (__u32)remaining;
			emit_kernel_segment(inode, type, UDS_DIR_SEND,
					    (__u8 *)vec.iov_base + skip, seg, max,
					    i, nr > UDS_MAX_SEG ? UDS_MAX_SEG : nr);
			remaining -= seg;
		}
		return 0;
	}

	return 0;
}

SEC("fentry/unix_stream_sendmsg")
int BPF_PROG(uds_send_stream, struct socket *sock, struct msghdr *msg,
	     size_t len)
{
	return trace_send(sock, msg, len);
}

SEC("fentry/unix_dgram_sendmsg")
int BPF_PROG(uds_send_dgram, struct socket *sock, struct msghdr *msg,
	     size_t len)
{
	return trace_send(sock, msg, len);
}

SEC("fentry/unix_seqpacket_sendmsg")
int BPF_PROG(uds_send_seqpacket, struct socket *sock, struct msghdr *msg,
	     size_t len)
{
	return trace_send(sock, msg, len);
}

SEC("fentry/unix_stream_read_actor")
int BPF_PROG(uds_recv_stream, struct sk_buff *skb, int skip, int chunk,
	     struct unix_stream_read_state *state)
{
	__u32 zero = 0;
	struct uds_config *cfg = bpf_map_lookup_elem(&uds_cfg, &zero);
	if (!cfg || !allowed(cfg))
		return 0;
	if (!skb || !state || chunk <= 0 || skip < 0)
		return 0;

	__u64 inode = BPF_CORE_READ(state, socket, file, f_inode, i_ino);
	if (!inode)
		return 0;
	__u8 type = (__u8)BPF_CORE_READ(state, socket, type);
	__u32 max = clamp_payload(cfg->max_payload);
	__u8 *data = (__u8 *)BPF_CORE_READ(skb, data);
	if (!data)
		return 0;
	__u32 cap = (__u32)chunk < max ? (__u32)chunk : max;
	struct uds_record *rec = scratch_event();
	if (!rec)
		return 0;
	init_event(rec, (__u32)chunk, inode, UDS_DIR_RECV, type, 0, 1);
	if (bpf_probe_read_kernel(rec->data, cap, data + skip) < 0) {
		rec->event.truncated = 1;
		rec->event.cap_len = 0;
	} else {
		rec->event.cap_len = cap;
		rec->event.truncated = cap < (__u32)chunk ? 1 : 0;
	}
	finish_event(rec);
	return 0;
}

static __always_inline int trace_recv_enter(struct socket *sock,
					    struct msghdr *msg)
{
	__u32 zero = 0;
	struct uds_config *cfg = bpf_map_lookup_elem(&uds_cfg, &zero);
	if (!cfg || !allowed(cfg))
		return 0;
	if (!sock || !msg)
		return 0;
	__u64 inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
	if (!inode)
		return 0;

	struct recv_snapshot snap = {};
	snap.inode = inode;
	snap.type = (__u8)BPF_CORE_READ(sock, type);
	struct iov_iter *iter = &msg->msg_iter;
	snap.count = BPF_CORE_READ(iter, count);
	snap.iov_offset = BPF_CORE_READ(iter, iov_offset);
	snap.iter_type = BPF_CORE_READ(iter, iter_type);
	__u64 nr = BPF_CORE_READ(iter, nr_segs);
	if (nr == 0)
		nr = 1;
	snap.nr_segs = nr > UDS_MAX_SEG ? UDS_MAX_SEG : nr;
	snap.truncated = nr > UDS_MAX_SEG ? 1 : 0;

	if (snap.iter_type == ITER_UBUF) {
		snap.iov[0].base = (__u64)BPF_CORE_READ(iter, ubuf);
		snap.iov[0].len = snap.count;
		if (snap.nr_segs == 0)
			snap.nr_segs = 1;
	} else if (snap.iter_type == ITER_IOVEC) {
		const struct iovec *iov =
			(const struct iovec *)BPF_CORE_READ(iter, __iov);
#pragma unroll
		for (int i = 0; i < UDS_MAX_SEG; i++) {
			if (i >= snap.nr_segs)
				break;
			struct iovec vec = {};
			if (bpf_probe_read_kernel(&vec, sizeof(vec), &iov[i]) < 0)
				break;
			snap.iov[i].base = (__u64)vec.iov_base;
			snap.iov[i].len = vec.iov_len;
		}
	}

	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&uds_recv_state, &key, &snap, BPF_ANY);
	return 0;
}

static __always_inline int trace_recv_exit(long ret)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct recv_snapshot *snap = bpf_map_lookup_elem(&uds_recv_state, &key);
	if (!snap)
		return 0;
	struct recv_snapshot local = *snap;
	bpf_map_delete_elem(&uds_recv_state, &key);

	if (ret <= 0)
		return 0;
	__u32 zero = 0;
	struct uds_config *cfg = bpf_map_lookup_elem(&uds_cfg, &zero);
	if (!cfg || !allowed(cfg))
		return 0;
	__u32 max = clamp_payload(cfg->max_payload);
	__u64 remaining = (__u64)ret;
	/* MSG_TRUNC may report the full datagram length while copying only the
	 * caller's buffer capacity. Never read past the original iterator. */
	if (remaining > local.count)
		remaining = local.count;
	__u8 parts = local.nr_segs;
	__u8 truncated = local.truncated;

#pragma unroll
	for (int i = 0; i < UDS_MAX_SEG; i++) {
		if (i >= local.nr_segs || remaining == 0)
			break;
		__u64 skip = i == 0 ? local.iov_offset : 0;
		if (local.iov[i].len <= skip)
			continue;
		__u64 avail = local.iov[i].len - skip;
		__u32 seg = avail < remaining ? (__u32)avail : (__u32)remaining;
		emit_user_segment(local.inode, local.type, UDS_DIR_RECV,
				  (__u8 *)local.iov[i].base + skip, seg, max,
				  i, parts, truncated);
		remaining -= seg;
	}
	return 0;
}

SEC("fentry/unix_dgram_recvmsg")
int BPF_PROG(uds_recv_dgram_enter, struct socket *sock, struct msghdr *msg,
	     size_t size, int flags)
{
	return trace_recv_enter(sock, msg);
}

SEC("fexit/unix_dgram_recvmsg")
int BPF_PROG(uds_recv_dgram_exit, struct socket *sock, struct msghdr *msg,
	     size_t size, int flags, long ret)
{
	return trace_recv_exit(ret);
}

SEC("fentry/unix_seqpacket_recvmsg")
int BPF_PROG(uds_recv_seqpacket_enter, struct socket *sock,
	     struct msghdr *msg, size_t size, int flags)
{
	return trace_recv_enter(sock, msg);
}

SEC("fexit/unix_seqpacket_recvmsg")
int BPF_PROG(uds_recv_seqpacket_exit, struct socket *sock,
	     struct msghdr *msg, size_t size, int flags, long ret)
{
	return trace_recv_exit(ret);
}

char _license[] SEC("license") = "GPL";
