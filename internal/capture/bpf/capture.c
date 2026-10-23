// SPDX-License-Identifier: GPL-2.0
//
// ebpfshark capture program.
//
// Attached to the TC (traffic control) ingress and egress hooks of a network
// interface via TCX. Every packet is copied (up to the configured snaplen)
// into a BPF ring buffer together with a small metadata header. Protocol
// dissection happens in userspace so the kernel fast path stays tiny.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SNAPLEN_MAX 2048
#define EVENT_MAX_SIZE (sizeof(struct pkt_event) + SNAPLEN_MAX)

/* Values intentionally match TC_ACT_OK. */
#define ACT_OK 0

struct capture_config {
	__u32 enabled;
	__u32 snaplen;
	__u32 sample_rate;
	__u32 exclude_port; /* host byte order, 0 = disabled */
	__u64 cgroup_id;    /* target cgroup v2 id, 0 = no cgroup filter */
	__u32 filter_cgroup;
	__u32 _pad;
	/* Conservative L2-L4 capture filter, filled from the display filter. */
	__u32 filter_flags;
	__u32 filter_proto;
	__u32 filter_ipver;
	__u32 sport_lo;
	__u32 sport_hi;
	__u32 dport_lo;
	__u32 dport_hi;
	__u32 filter_vlan;
	__u32 src_ip4;      /* host byte order */
	__u32 dst_ip4;      /* host byte order */
	__u32 src_mask4;
	__u32 dst_mask4;
};

#define FILTER_PROTO  1
#define FILTER_IPVER  2
#define FILTER_SPORT  4
#define FILTER_DPORT  8
#define FILTER_VLAN   16
#define FILTER_SRC4   32
#define FILTER_DST4   64
#define VLAN_ANY      0xffff

struct capture_stats {
	__u64 packets;
	__u64 bytes;
	__u64 skipped;
	__u64 filtered;
};

struct pkt_event {
	__u64 ts_ns;
	__u32 ifindex;
	__u32 wirelen;
	__u32 caplen;
	__u16 protocol; /* Ethernet protocol, network byte order */
	__u8 direction; /* 0 = ingress, 1 = egress */
	__u8 flags;
	__u64 cgroup_id; /* cgroup v2 id of the socket, 0 if not attributable */
	__u8 data[];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB, resized from userspace */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct capture_config);
} capture_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct capture_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sample_counter SEC(".maps");

static __always_inline __u16 read_be16(const __u8 *p)
{
	return ((__u16)p[0] << 8) | p[1];
}

/*
 * Locate the TCP/UDP source and destination ports without copying the whole
 * packet. Returns -1 for anything that is not a simple IPv4/IPv6 TCP or UDP
 * packet (fragments, extension headers, ARP, ...).
 */
static __always_inline int packet_l4_ports(struct __sk_buff *skb, __u16 *sport,
					   __u16 *dport)
{
	__u8 first;
	if (bpf_skb_load_bytes(skb, 0, &first, 1) < 0)
		return -1;

	__u32 off = 0;
	__u8 ver = first >> 4;

	if (ver != 4 && ver != 6) {
		/* Ethernet II, possibly with up to four VLAN tags. */
		off = 12;
		ver = 0;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			__u8 et[2];
			if (bpf_skb_load_bytes(skb, off, et, 2) < 0)
				return -1;
			__u16 t = read_be16(et);
			if (t == 0x8100 || t == 0x88a8 || t == 0x9100) {
				off += 4;
				continue;
			}
			if (t == 0x0800)
				ver = 4;
			else if (t == 0x86dd)
				ver = 6;
			off += 2;
			break;
		}
	}

	if (ver == 4) {
		__u8 vihl, proto;
		__u8 ports[4];
		if (bpf_skb_load_bytes(skb, off, &vihl, 1) < 0)
			return -1;
		if ((vihl >> 4) != 4)
			return -1;
		__u32 ihl = (__u32)(vihl & 0xf) * 4;
		if (ihl < 20)
			return -1;
		if (bpf_skb_load_bytes(skb, off + 9, &proto, 1) < 0)
			return -1;
		if (proto != 6 && proto != 17)
			return -1;
		if (bpf_skb_load_bytes(skb, off + ihl, ports, 4) < 0)
			return -1;
		*sport = read_be16(ports);
		*dport = read_be16(ports + 2);
		return 0;
	}

	if (ver == 6) {
		__u8 next;
		__u8 ports[4];
		if (bpf_skb_load_bytes(skb, off + 6, &next, 1) < 0)
			return -1;
		if (next != 6 && next != 17)
			return -1;
		if (bpf_skb_load_bytes(skb, off + 40, ports, 4) < 0)
			return -1;
		*sport = read_be16(ports);
		*dport = read_be16(ports + 2);
		return 0;
	}

	return -1;
}

/*
 * Conservative prefilter for the kernel subset of a display filter. If the
 * packet layout is not understood, keep it: user space will apply the exact
 * filter. Only a positively parsed mismatch is dropped.
 */
static __always_inline int capture_filter_match(struct __sk_buff *skb,
						 struct capture_config *cfg)
{
	__u32 flags = cfg->filter_flags;
	if (!flags)
		return 1;

	__u8 first;
	if (bpf_skb_load_bytes(skb, 0, &first, 1) < 0)
		return 1;
	__u32 off = 0;
	__u8 ver = first >> 4;
	int vlan = -1;

	if (ver != 4 && ver != 6) {
		off = 12;
		ver = 0;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			__u8 et[2];
			if (bpf_skb_load_bytes(skb, off, et, 2) < 0)
				return 1;
			__u16 t = read_be16(et);
			if (t == 0x8100 || t == 0x88a8 || t == 0x9100) {
				__u8 tag[2];
				if (bpf_skb_load_bytes(skb, off + 2, tag, 2) < 0)
					return 1;
				vlan = read_be16(tag) & 0x0fff;
				off += 4;
				continue;
			}
			if (t == 0x0800)
				ver = 4;
			else if (t == 0x86dd)
				ver = 6;
			off += 2;
			break;
		}
	}

	if ((flags & FILTER_VLAN) && vlan < 0)
		return 0;
	if ((flags & FILTER_VLAN) && cfg->filter_vlan != VLAN_ANY &&
	    vlan != (int)cfg->filter_vlan)
		return 0;
	if ((flags & FILTER_IPVER) && ver != cfg->filter_ipver)
		return 0;

	if (ver == 4) {
		__u8 vihl, proto;
		__u8 addrs[8];
		if (bpf_skb_load_bytes(skb, off, &vihl, 1) < 0)
			return 1;
		if ((vihl >> 4) != 4)
			return 1;
		__u32 ihl = (__u32)(vihl & 0xf) * 4;
		if (ihl < 20)
			return 1;
		if (bpf_skb_load_bytes(skb, off + 9, &proto, 1) < 0)
			return 1;
		if ((flags & FILTER_PROTO) && proto != cfg->filter_proto)
			return 0;
		__u8 frag[2];
		if (bpf_skb_load_bytes(skb, off + 6, frag, 2) < 0)
			return 1;
		if ((read_be16(frag) & 0x1fff) != 0)
			return 1; /* non-first fragment: ports are not at ihl */
		if (bpf_skb_load_bytes(skb, off + 12, addrs, 8) < 0)
			return 1;
		__u32 src = bpf_ntohl(*(__u32 *)&addrs[0]);
		__u32 dst = bpf_ntohl(*(__u32 *)&addrs[4]);
		if ((flags & FILTER_SRC4) && (src & cfg->src_mask4) != (cfg->src_ip4 & cfg->src_mask4))
			return 0;
		if ((flags & FILTER_DST4) && (dst & cfg->dst_mask4) != (cfg->dst_ip4 & cfg->dst_mask4))
			return 0;
		if (flags & (FILTER_SPORT | FILTER_DPORT)) {
			if (proto != 6 && proto != 17)
				return 0;
			__u8 ports[4];
			if (bpf_skb_load_bytes(skb, off + ihl, ports, 4) < 0)
				return 1;
			__u16 sp = read_be16(ports);
			__u16 dp = read_be16(ports + 2);
			if ((flags & FILTER_SPORT) && (sp < cfg->sport_lo || sp > cfg->sport_hi))
				return 0;
			if ((flags & FILTER_DPORT) && (dp < cfg->dport_lo || dp > cfg->dport_hi))
				return 0;
		}
		return 1;
	}

	if (ver == 6) {
		if (flags & (FILTER_SRC4 | FILTER_DST4))
			return 0;
		__u8 next;
		if (bpf_skb_load_bytes(skb, off + 6, &next, 1) < 0)
			return 1;
		__u32 l4off = off + 40;
		int resolved = 0;
#pragma unroll
		for (int i = 0; i < 6; i++) {
			if (next == 0 || next == 43 || next == 60) {
				__u8 nh, hlen;
				if (bpf_skb_load_bytes(skb, l4off, &nh, 1) < 0 ||
				    bpf_skb_load_bytes(skb, l4off + 1, &hlen, 1) < 0)
					return 1;
				next = nh;
				l4off += ((__u32)hlen + 1) * 8;
				continue;
			}
			if (next == 44) {
				__u8 nh, frag[2];
				if (bpf_skb_load_bytes(skb, l4off, &nh, 1) < 0 ||
				    bpf_skb_load_bytes(skb, l4off + 2, frag, 2) < 0)
					return 1;
				if ((read_be16(frag) & 0xfff8) != 0)
					return 1; /* non-first fragment */
				next = nh;
				l4off += 8;
				continue;
			}
			if (next == 51) {
				__u8 nh, hlen;
				if (bpf_skb_load_bytes(skb, l4off, &nh, 1) < 0 ||
				    bpf_skb_load_bytes(skb, l4off + 1, &hlen, 1) < 0)
					return 1;
				next = nh;
				l4off += ((__u32)hlen + 2) * 4;
				continue;
			}
			resolved = 1;
			break;
		}
		if (!resolved)
			return 1; /* unknown extension chain: let user space decide */
		if ((flags & FILTER_PROTO) && next != cfg->filter_proto)
			return 0;
		if (flags & (FILTER_SPORT | FILTER_DPORT)) {
			if (next != 6 && next != 17)
				return 0;
			__u8 ports[4];
			if (bpf_skb_load_bytes(skb, l4off, ports, 4) < 0)
				return 1;
			__u16 sp = read_be16(ports);
			__u16 dp = read_be16(ports + 2);
			if ((flags & FILTER_SPORT) && (sp < cfg->sport_lo || sp > cfg->sport_hi))
				return 0;
			if ((flags & FILTER_DPORT) && (dp < cfg->dport_lo || dp > cfg->dport_hi))
				return 0;
		}
		return 1;
	}
	return 1;
}

static __always_inline int capture_pkt(struct __sk_buff *skb, __u8 direction)
{
	__u32 zero = 0;
	struct capture_config *cfg = bpf_map_lookup_elem(&capture_cfg, &zero);
	if (!cfg || !cfg->enabled)
		return ACT_OK;

	struct capture_stats *st = bpf_map_lookup_elem(&stats, &zero);
	if (!st)
		return ACT_OK;

	/* Optional cgroup/process scoping. bpf_skb_cgroup_id is available in TC
	 * programs on modern kernels and returns 0 for forwarded/no-socket skbs. */
	__u64 cgroup_id = bpf_skb_cgroup_id(skb);
	if (cfg->filter_cgroup) {
		if (cgroup_id == 0 || cgroup_id != cfg->cgroup_id) {
			st->filtered += 1;
			return ACT_OK;
		}
	}

	if (!capture_filter_match(skb, cfg)) {
		st->filtered += 1;
		return ACT_OK;
	}

	/* Drop traffic belonging to the analyzer's own HTTP API. */
	if (cfg->exclude_port) {
		__u16 sport = 0, dport = 0;
		if (packet_l4_ports(skb, &sport, &dport) == 0 &&
		    (sport == (__u16)cfg->exclude_port ||
		     dport == (__u16)cfg->exclude_port)) {
			st->filtered += 1;
			return ACT_OK;
		}
	}

	/* Per-CPU sampling counter, avoids a shared atomic in the fast path. */
	if (cfg->sample_rate > 1) {
		__u64 *cnt = bpf_map_lookup_elem(&sample_counter, &zero);
		if (cnt) {
			__u64 c = *cnt;
			*cnt = c + 1;
			if (c % cfg->sample_rate)
				return ACT_OK;
		}
	}

	__u32 wirelen = skb->len;
	if (wirelen == 0)
		return ACT_OK;

	__u32 snaplen = cfg->snaplen;
	if (snaplen > SNAPLEN_MAX)
		snaplen = SNAPLEN_MAX;
	if (snaplen > wirelen)
		snaplen = wirelen;
	if (snaplen == 0)
		return ACT_OK;

	/* ringbuf_reserve requires a compile time constant size. Reserve the
	 * maximum and let userspace use caplen to trim the sample. */
	struct pkt_event *e = bpf_ringbuf_reserve(&events, EVENT_MAX_SIZE, 0);
	if (!e) {
		st->skipped += 1;
		return ACT_OK;
	}
	e->ts_ns = bpf_ktime_get_ns();
	e->ifindex = skb->ifindex;
	e->wirelen = wirelen;
	e->caplen = snaplen;
	e->protocol = (__u16)skb->protocol;
	e->direction = direction;
	e->flags = snaplen < wirelen ? 1 : 0;
	e->cgroup_id = cgroup_id;
	if (bpf_skb_load_bytes(skb, 0, e->data, snaplen) < 0) {
		bpf_ringbuf_discard(e, 0);
		st->skipped += 1;
		return ACT_OK;
	}
	bpf_ringbuf_submit(e, 0);
	st->packets += 1;
	st->bytes += wirelen;
	return ACT_OK;
}

SEC("tc")
int capture_ingress(struct __sk_buff *skb)
{
	return capture_pkt(skb, 0);
}

SEC("tc")
int capture_egress(struct __sk_buff *skb)
{
	return capture_pkt(skb, 1);
}

char _license[] SEC("license") = "GPL";
