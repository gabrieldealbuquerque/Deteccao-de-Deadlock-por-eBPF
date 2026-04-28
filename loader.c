/* SPDX-License-Identifier: MIT
 * Carrega deadlock_bpf (TC + ringbuf), cola na bridge Docker, imprime alertas.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "deadlock_bpf.skel.h"

static volatile sig_atomic_t stop;

static void on_sig(int s) {
	(void)s;
	stop = 1;
}

static int libbpf_pr(enum libbpf_print_level level, const char *fmt, va_list ap) {
	(void)level;
	return vfprintf(stderr, fmt, ap);
}

/* 172.28.0.0/16 — sub-rede do docker-compose. */
static int pick_mission_bridge(char *out, size_t outlen) {
	struct ifaddrs *ifa, *p;
	int r = -1;
	uint32_t a;

	if (getifaddrs(&ifa) < 0) {
		perror("getifaddrs");
		return -1;
	}
	for (p = ifa; p; p = p->ifa_next) {
		struct sockaddr_in *sin;

		if (!p->ifa_name)
			continue;
		if (strncmp(p->ifa_name, "br-", 3) != 0)
			continue;
		if (p->ifa_addr == NULL || p->ifa_addr->sa_family != AF_INET)
			continue;
		sin = (struct sockaddr_in *)p->ifa_addr;
		a = ntohl(sin->sin_addr.s_addr);
		/* 172.28.0.0/16 */
		if ((a >> 16) == 0xac1c) {
			(void)snprintf(out, outlen, "%s", p->ifa_name);
			r = 0;
			break;
		}
	}
	freeifaddrs(ifa);
	return r;
}

static int handle_event(void *ctx, void *data, size_t len) {
	(void)ctx;
	(void)data;
	(void)len;
	(void)printf(
		"[Mission Control] ALERTA: Deadlock detectado. Intervenção de rede (RST) executada pelo kernel.\n");
	(void)fflush(stdout);
	return 0;
}

int main(int argc, char **argv) {
	struct deadlock_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct bpf_tc_hook hook = {};
	struct bpf_tc_opts opts = {};
	struct bpf_tc_opts dopts = {};
	uint32_t k0 = 0;
	struct in_addr ia, ib;
	struct {
		uint32_t a;
		uint32_t b;
	} cfg = {};
	const char *ifname;
	char br[IF_NAMESIZE];
	int ifi, err, hook_ok, att_ok;

	hook_ok = 0;
	att_ok = 0;
	skel = NULL;
	rb = NULL;

	libbpf_set_print(libbpf_pr);
	{
		struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
		(void)setrlimit(RLIMIT_MEMLOCK, &lim);
	}
	(void)signal(SIGINT, on_sig);
	(void)signal(SIGTERM, on_sig);

	if (argc >= 2 && argv[1][0])
		ifname = argv[1];
	else {
		if (pick_mission_bridge(br, sizeof(br)) != 0) {
			fprintf(stderr,
				"Uso: %s <interface>  (ex.: br-<id> da rede mission_control_net)\n",
				argv[0]);
			return 1;
		}
		ifname = br;
	}
	ifi = (int)if_nametoindex(ifname);
	if (ifi <= 0) {
		fprintf(stderr, "Interface inválida: %s\n", ifname);
		return 1;
	}
	printf("A anexar TC em %s (ifindex %d)\n", ifname, ifi);

	if (inet_pton(AF_INET, "172.28.0.2", &ia) != 1 ||
	    inet_pton(AF_INET, "172.28.0.3", &ib) != 1) {
		fprintf(stderr, "inet_pton\n");
		return 1;
	}
	memcpy(&cfg.a, &ia, sizeof(cfg.a));
	memcpy(&cfg.b, &ib, sizeof(cfg.b));

	skel = deadlock_bpf__open();
	if (!skel) {
		fprintf(stderr, "deadlock_bpf__open\n");
		return 1;
	}
	err = deadlock_bpf__load(skel);
	if (err) {
		fprintf(stderr, "deadlock_bpf__load: %d\n", err);
		goto out;
	}
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.cfg_map), &k0, &cfg, 0);
	if (err) {
		fprintf(stderr, "cfg_map: %s\n", strerror(errno));
		goto out;
	}

	hook.sz = sizeof(hook);
	hook.ifindex = ifi;
	hook.attach_point = BPF_TC_INGRESS;

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "bpf_tc_hook_create: %d\n", err);
		goto out;
	}
	hook_ok = 1;

	opts.sz = sizeof(opts);
	opts.prog_fd = bpf_program__fd(skel->progs.mission_tc);
	opts.handle = 1;
	opts.priority = 1;

	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		fprintf(stderr, "bpf_tc_attach: %d\n", err);
		goto out;
	}
	att_ok = 1;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new\n");
		err = -1;
		goto out;
	}

	printf("Loader a correr (Ctrl+C). À espera do ringbuf…\n");
	while (!stop) {
		err = ring_buffer__poll(rb, 500);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "ring_buffer__poll: %d\n", err);
			break;
		}
	}
	err = 0;

out:
	if (rb)
		ring_buffer__free(rb);
	if (att_ok) {
		dopts.sz = sizeof(dopts);
		(void)bpf_tc_detach(&hook, &dopts);
	}
	if (hook_ok)
		(void)bpf_tc_hook_destroy(&hook);
	deadlock_bpf__destroy(skel);
	return err ? 1 : 0;
}
