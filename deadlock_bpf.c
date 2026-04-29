// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

#define DEADLOCK_NS 5000000000ULL
#define EVENT_MONITORING 1
#define EVENT_DEADLOCK 2

struct cfg_ips {
	__u32 a;
	__u32 b;
};

struct flow_key {
	__u32 a_addr;
	__u32 b_addr;
	__u16 a_port;
	__u16 b_port;
	__u32 pad;
};

struct st {
	__u32 n_pkts;	/* segmentos TCP (handshake ~3). */
	__u8  estab;	/* 1: após 3.º seg. (contagem). */
	__u8  rst_mask;
	__u8  monitoring_sent;
	__u8  _pad1;
	__u64 t_estab_ns;
	__u64 last_data_ns; /* 0: nenhum byte de carga. */
};

struct event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 status;
	__u64 t_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg_ips);
} cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, struct flow_key);
	__type(value, struct st);
} st_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int ip_pair(const struct cfg_ips *c, __u32 s, __u32 d) {
	if (!c)
		return 0;
	if (s == c->a && d == c->b)
		return 1;
	if (s == c->b && d == c->a)
		return 1;
	return 0;
}

static __always_inline __u8 flow_key_init(struct flow_key *key, __u32 saddr, __u32 daddr,
		__u16 sport, __u16 dport) {
	if (saddr < daddr || (saddr == daddr && sport <= dport)) {
		key->a_addr = saddr;
		key->b_addr = daddr;
		key->a_port = sport;
		key->b_port = dport;
		return 0;
	}
	key->a_addr = daddr;
	key->b_addr = saddr;
	key->a_port = dport;
	key->b_port = sport;
	return 1;
}

static __always_inline int parse_ipv4_tcp(void *data, void *data_end, struct iphdr **ip4,
		struct tcphdr **tp) {
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *t;
	__u32 ihl;

	if ((void *)(eth + 1) > data_end)
		return 0;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return 0;
	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;
	if (ip->version != 4)
		return 0;
	ihl = ip->ihl;
	if (ihl < 5)
		return 0;
	if (ip->protocol != IPPROTO_TCP)
		return 0;
	{
		__u16 fo = bpf_ntohs(ip->frag_off);
		if (fo & (IP_OFFSET | IP_MF))
			return 0;
	}
	t = (void *)ip + (ihl * 4);
	if ((void *)(t + 1) > data_end)
		return 0;
	if (t->doff < 5)
		return 0;
	if ((void *)t + (t->doff * 4) > data_end)
		return 0;
	*ip4 = ip;
	*tp = t;
	return 1;
}

static __always_inline int tcp_data_len(const struct iphdr *ip, const struct tcphdr *t) {
	__s32 d = (__s32)bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - (t->doff * 4);
	if (d < 0)
		return 0;
	return d;
}

static __always_inline void emit_event_raw(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
		__u64 t_ns, __u32 status) {
	struct event ev = {};

	ev.saddr = saddr;
	ev.daddr = daddr;
	ev.sport = sport;
	ev.dport = dport;
	ev.status = status;
	ev.t_ns = t_ns;
	(void)bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

static __always_inline void emit_event(const struct iphdr *ip4, const struct tcphdr *t,
		__u64 t_ns, __u32 status) {
	emit_event_raw(ip4->saddr, ip4->daddr, t->source, t->dest, t_ns, status);
}

static __always_inline int tcp_inject_rst(struct __sk_buff *ctx, void *data, struct tcphdr *t) {
	__u8 b12, b13, lo;
	__u32 flags_o, csum_o, seq_o, oldw, neww, old_seq, new_seq;
	__s32 err;
	__u8 *tb = (void *)t;

	flags_o = (void *)tb - data + 12;
	seq_o = (void *)&t->seq - data;
	csum_o = (void *)&t->check - data;
	if (bpf_skb_load_bytes(ctx, seq_o, &old_seq, sizeof(old_seq)) < 0)
		return 0;
	if (bpf_skb_load_bytes(ctx, flags_o, &b12, 1) < 0)
		return 0;
	if (bpf_skb_load_bytes(ctx, flags_o + 1, &b13, 1) < 0)
		return 0;
	if (b13 == 0x14)
		return 0;
	lo = 0x14;
	oldw = ((__u32)b12 << 8) | b13;
	neww = ((__u32)b12 << 8) | lo;
	err = bpf_l4_csum_replace(ctx, csum_o, oldw, neww, 2);
	if (err)
		return 0;
	new_seq = bpf_htonl(bpf_ntohl(old_seq) + 1);
	err = bpf_l4_csum_replace(ctx, csum_o, old_seq, new_seq, 4);
	if (err)
		return 0;
	err = bpf_skb_store_bytes(ctx, seq_o, &new_seq, sizeof(new_seq), 0);
	if (err)
		return 0;
	err = bpf_skb_store_bytes(ctx, flags_o + 1, &lo, sizeof(lo), 0);
	if (err)
		return 0;
	return 1;
}

SEC("tc")
int mission_tc(struct __sk_buff *ctx) {
	void *data = (void *)(__u64)ctx->data;
	void *data_end = (void *)(__u64)ctx->data_end;
	const __u32 k0 = 0;
	struct cfg_ips *cfg;
	struct flow_key fkey = {};
	struct iphdr *ip4;
	struct tcphdr *t;
	struct st *s;
	struct st st0;
	__u64 t_ns;
	__u32 ev_saddr, ev_daddr;
	__u16 ev_sport, ev_dport;
	__u8 dir, rst_bit;
	int dlen;

	if ((void *)data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_OK;

	cfg = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!cfg || !cfg->a || !cfg->b)
		return TC_ACT_OK;
	if (!parse_ipv4_tcp(data, data_end, &ip4, &t))
		return TC_ACT_OK;
	if (!ip_pair(cfg, ip4->saddr, ip4->daddr))
		return TC_ACT_OK;
	if (t->rst)
		return TC_ACT_OK;

	dir = flow_key_init(&fkey, ip4->saddr, ip4->daddr, t->source, t->dest);
	rst_bit = dir ? 2 : 1;
	s = bpf_map_lookup_elem(&st_map, &fkey);
	__builtin_memset(&st0, 0, sizeof(st0));
	if (!s) {
		(void)bpf_map_update_elem(&st_map, &fkey, &st0, BPF_ANY);
		s = bpf_map_lookup_elem(&st_map, &fkey);
		if (!s)
			return TC_ACT_OK;
	}

	t_ns = bpf_ktime_get_ns();
	/* 3.º seg. TCP: após 2, incrementa. */
	{
		__u32 n;
		__u8  est;

		n = s->n_pkts;
		est = s->estab;
		n = n + 1;
		s->n_pkts = n;
		if (n >= 3) {
			if (est == 0) {
				est = 1;
				s->estab = 1;
				if (s->t_estab_ns == 0)
					s->t_estab_ns = t_ns;
				if (!s->monitoring_sent) {
					emit_event(ip4, t, t_ns, EVENT_MONITORING);
					s->monitoring_sent = 1;
				}
			}
		} else {
			return TC_ACT_OK;
		}
	}

	if (s->estab == 0)
		return TC_ACT_OK;

	dlen = tcp_data_len(ip4, t);
	if (dlen > 0) {
		s->last_data_ns = t_ns;
	}
	if (s->rst_mask == 3 || (s->rst_mask & rst_bit))
		return TC_ACT_OK;

	/* 5s sem segmento com payload de dados (last_data=0) ou >5s desde último. */
	if (s->last_data_ns) {
		if (t_ns - s->last_data_ns < (__u64)DEADLOCK_NS)
			return TC_ACT_OK;
	} else {
		if (t_ns - s->t_estab_ns < (__u64)DEADLOCK_NS)
			return TC_ACT_OK;
	}

	ev_saddr = ip4->saddr;
	ev_daddr = ip4->daddr;
	ev_sport = t->source;
	ev_dport = t->dest;
	if (tcp_inject_rst(ctx, data, t)) {
		s->rst_mask |= rst_bit;
		emit_event_raw(ev_saddr, ev_daddr, ev_sport, ev_dport, t_ns, EVENT_DEADLOCK);
	}
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
