// SPDX-License-Identifier: GPL-2.0
/* TC: par A/B, ausência de payload com dados > 5s pós-3WHS -> ringbuf + RST+ACK. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1fff
#endif

#define DEADLOCK_NS 5000000000ULL

struct cfg_ips {
	__u32 a;
	__u32 b;
};

struct st {
	__u32 n_pkts;	/* segmentos TCP (handshake ~3). */
	__u8  estab;	/* 1: após 3.º seg. (contagem). */
	__u8  reported;
	__u8  _pad1[2];
	__u64 t_estab_ns;
	__u64 last_data_ns; /* 0: nenhum byte de carga. */
};

struct event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  pad0[2];
	__u32 _pad1;
	__u64 t_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(value, struct cfg_ips);
} cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u64);
	__type(value, struct st);
} st_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline __u64 pair_key(__u32 a, __u32 b) {
	__u32 m, M;

	if (a <= b) {
		m = a;
		M = b;
	} else {
		m = b;
		M = a;
	}
	return ((__u64)m) << 32 | (__u64)M;
}

static __always_inline int ip_pair(const struct cfg_ips *c, __u32 s, __u32 d) {
	if (!c)
		return 0;
	if (s == c->a && d == c->b)
		return 1;
	if (s == c->b && d == c->a)
		return 1;
	return 0;
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

/* 16 bit na word do cabeçalho TCP a partir do offset 12: preserva 1.º byte (doff/res1), flags em byte2 = RST+ACK. */
static __always_inline int tcp_inject_rst(struct __sk_buff *ctx, void *data, struct tcphdr *t) {
	__u8 b12, b13, lo;
	__u32 o, old4, new4, oldw, neww;
	__s32 err;
	__u8 *tb = (void *)t;

	o = (void *)tb - data + 12;
	(void)data;
	if (bpf_skb_load_bytes(ctx, o, &b12, 1) < 0)
		return 0;
	if (bpf_skb_load_bytes(ctx, o + 1, &b13, 1) < 0)
		return 0;
	/* Preserva byte 0 da word (doff+res1); 2.º = ACK|RST. */
	if (b13 == 0x14)
		return 0;
	oldw = ((__u32)b12 << 8) | b13;
	lo = 0x14;
	neww = (((__u32)b12) << 8) | lo;
	old4 = oldw & 0xffffu;
	new4 = neww & 0xffffu;
	/* Substitui 16 bits no offset; 5.º parâmetro = flags (não tamanho). */
	err = bpf_l4_csum_replace(ctx, o, old4, new4, 0);
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
	struct iphdr *ip4;
	struct tcphdr *t;
	struct st *s;
	struct st st0;
	__u64 pkey;
	__u64 t_ns;
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

	pkey = pair_key(ip4->saddr, ip4->daddr);
	s = bpf_map_lookup_elem(&st_map, &pkey);
	__builtin_memset(&st0, 0, sizeof(st0));
	if (!s) {
		(void)bpf_map_update_elem(&st_map, &pkey, &st0, BPF_ANY);
		s = bpf_map_lookup_elem(&st_map, &pkey);
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
	if (s->reported)
		return TC_ACT_OK;

	/* 5s sem segmento com payload de dados (last_data=0) ou >5s desde último. */
	if (s->last_data_ns) {
		if (t_ns - s->last_data_ns < (__u64)DEADLOCK_NS)
			return TC_ACT_OK;
	} else {
		if (t_ns - s->t_estab_ns < (__u64)DEADLOCK_NS)
			return TC_ACT_OK;
	}

	{
		struct event ev = {};

		ev.saddr = ip4->saddr;
		ev.daddr = ip4->daddr;
		ev.sport = t->source;
		ev.dport = t->dest;
		ev.t_ns = t_ns;
		(void)bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
	}
	s->reported = 1;
	(void)tcp_inject_rst(ctx, data, t);
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
