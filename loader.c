/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
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

#define COLOR_RESET "\033[0m"
#define COLOR_BOLD "\033[1m"
#define COLOR_DIM "\033[2m"
#define COLOR_RED "\033[1;31m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_MAGENTA "\033[1;35m"

#define EVENT_MONITORING 1
#define EVENT_DEADLOCK 2
#define MAX_TC_TARGETS 16
#define TC_DIRECTIONS 2

struct event {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint32_t status;
	uint64_t t_ns;
};

struct tc_target {
	char ifname[IF_NAMESIZE];
	int ifindex;
	struct bpf_tc_hook qdisc_hook;
	struct bpf_tc_hook hooks[TC_DIRECTIONS];
	struct bpf_tc_opts opts[TC_DIRECTIONS];
	int qdisc_created;
	int attached[TC_DIRECTIONS];
};

static volatile sig_atomic_t stop;

static void on_sig(int s) {
	(void)s;
	stop = 1;
}

static int libbpf_pr(enum libbpf_print_level level, const char *fmt, va_list ap) {
	if (level > LIBBPF_WARN)
		return 0;
	(void)fmt;
	(void)ap;
	return 0;
}

static void draw_header(void) {
	printf("\033[H\033[J");
	printf(COLOR_CYAN COLOR_BOLD);
	printf("╔══════════════════════════════════════════════════════════════╗\n");
	printf("║              MISSION CONTROL EBPF DASHBOARD                 ║\n");
	printf("╚══════════════════════════════════════════════════════════════╝\n");
	printf(COLOR_RESET);
	printf(COLOR_DIM "Telemetria TCP via TC/eBPF + Ring Buffer\n\n" COLOR_RESET);
	fflush(stdout);
}

static void print_status_line(const char *ifname, int ifi, const struct tc_target *targets,
			      int target_count) {
	int i;

	printf(COLOR_MAGENTA "[🛰️ ]" COLOR_RESET " Ponte monitorada: "
	       COLOR_BOLD "%s" COLOR_RESET " " COLOR_DIM "(ifindex %d)" COLOR_RESET "\n",
	       ifname, ifi);
	printf(COLOR_MAGENTA "[🔗]" COLOR_RESET " Alvos TC: ");
	for (i = 0; i < target_count; i++) {
		printf("%s%s", i ? ", " : "", targets[i].ifname);
	}
	printf("\n");
	printf(COLOR_YELLOW "[⏳]" COLOR_RESET " Monitorando tráfego TCP na ponte...\n\n");
	fflush(stdout);
}

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

static int add_tc_target(struct tc_target *targets, int *count, int max, const char *ifname) {
	int ifindex;
	int i;

	ifindex = (int)if_nametoindex(ifname);
	if (ifindex <= 0)
		return 0;
	for (i = 0; i < *count; i++) {
		if (targets[i].ifindex == ifindex)
			return 0;
	}
	if (*count >= max)
		return -1;
	targets[*count].ifindex = ifindex;
	snprintf(targets[*count].ifname, sizeof(targets[*count].ifname), "%s", ifname);
	(*count)++;
	return 0;
}

static int collect_tc_targets(const char *ifname, struct tc_target *targets, int max) {
	char path[128];
	DIR *dir;
	struct dirent *de;
	int count = 0;

	if (add_tc_target(targets, &count, max, ifname) < 0)
		return -1;

	snprintf(path, sizeof(path), "/sys/class/net/%s/brif", ifname);
	dir = opendir(path);
	if (!dir)
		return count;

	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		if (add_tc_target(targets, &count, max, de->d_name) < 0) {
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);
	return count;
}

static int attach_tc_target(struct deadlock_bpf *skel, struct tc_target *target) {
	const enum bpf_tc_attach_point points[TC_DIRECTIONS] = { BPF_TC_INGRESS, BPF_TC_EGRESS };
	int err;
	int i;

	target->qdisc_hook.sz = sizeof(target->qdisc_hook);
	target->qdisc_hook.ifindex = target->ifindex;
	target->qdisc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

	err = bpf_tc_hook_create(&target->qdisc_hook);
	if (err && err != -EEXIST)
		return err;
	target->qdisc_created = err == 0;

	for (i = 0; i < TC_DIRECTIONS; i++) {
		target->hooks[i].sz = sizeof(target->hooks[i]);
		target->hooks[i].ifindex = target->ifindex;
		target->hooks[i].attach_point = points[i];

		target->opts[i].sz = sizeof(target->opts[i]);
		target->opts[i].prog_fd = bpf_program__fd(skel->progs.mission_tc);
		target->opts[i].handle = i + 1;
		target->opts[i].priority = 1;
		target->opts[i].flags = BPF_TC_F_REPLACE;

		err = bpf_tc_attach(&target->hooks[i], &target->opts[i]);
		if (err)
			return err;
		target->attached[i] = 1;
	}
	return 0;
}

static void detach_tc_targets(struct tc_target *targets, int count) {
	struct bpf_tc_opts dopts = {};
	int i, j;

	for (i = 0; i < count; i++) {
		for (j = 0; j < TC_DIRECTIONS; j++) {
			if (!targets[i].attached[j])
				continue;
			memset(&dopts, 0, sizeof(dopts));
			dopts.sz = sizeof(dopts);
			dopts.handle = targets[i].opts[j].handle;
			dopts.priority = targets[i].opts[j].priority;
			(void)bpf_tc_detach(&targets[i].hooks[j], &dopts);
		}
		if (targets[i].qdisc_created)
			(void)bpf_tc_hook_destroy(&targets[i].qdisc_hook);
	}
}

static int handle_event(void *ctx, void *data, size_t len) {
	const struct event *ev = data;
	struct in_addr src = {};
	struct in_addr dst = {};
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];

	(void)ctx;

	if (len < sizeof(*ev))
		return 0;

	src.s_addr = ev->saddr;
	dst.s_addr = ev->daddr;
	if (!inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip)))
		snprintf(src_ip, sizeof(src_ip), "?.?.?.?");
	if (!inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip)))
		snprintf(dst_ip, sizeof(dst_ip), "?.?.?.?");

	switch (ev->status) {
	case EVENT_MONITORING:
		printf(COLOR_YELLOW "[⏳]" COLOR_RESET
		       " Fluxo TCP ativo: " COLOR_CYAN "%s:%u" COLOR_RESET
		       " -> " COLOR_CYAN "%s:%u" COLOR_RESET
		       " | estado: " COLOR_GREEN "MONITORANDO DEADLOCK" COLOR_RESET "\n",
		       src_ip, ntohs(ev->sport), dst_ip, ntohs(ev->dport));
		break;
	case EVENT_DEADLOCK:
		printf(COLOR_RED "╔════════════ INCIDENTE DE REDE | TCP RST ════════════╗" COLOR_RESET "\n");
		printf(COLOR_RED "[🚨] DEADLOCK DETECTADO!" COLOR_RESET
		       " Alvo: " COLOR_BOLD "%s:%u -> %s:%u" COLOR_RESET
		       ". Injetando pacote RST... " COLOR_GREEN "[SUCESSO]" COLOR_RESET "\n",
		       src_ip, ntohs(ev->sport), dst_ip, ntohs(ev->dport));
		printf(COLOR_GREEN "[🛡️ ]" COLOR_RESET
		       " Conexão sinalizada. O processo alvo deve sair do recv().\n");
		printf(COLOR_CYAN "[🔁]" COLOR_RESET
		       " Sentinela rearmada. Voltando ao monitoramento da ponte TCP...\n");
		printf(COLOR_RED "╚══════════════════════════════════════════════════════╝" COLOR_RESET "\n");
		break;
	default:
		printf(COLOR_DIM "[?] Evento desconhecido (%u): %s:%u -> %s:%u" COLOR_RESET "\n",
		       ev->status, src_ip, ntohs(ev->sport), dst_ip, ntohs(ev->dport));
		break;
	}

	fflush(stdout);
	return 0;
}

int main(int argc, char **argv) {
	struct deadlock_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct tc_target targets[MAX_TC_TARGETS] = {};
	uint32_t k0 = 0;
	struct in_addr ia, ib;
	struct {
		uint32_t a;
		uint32_t b;
	} cfg = {};
	const char *ifname;
	char br[IF_NAMESIZE];
	int ifi, err, i, target_count;

	target_count = 0;
	skel = NULL;
	rb = NULL;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_pr);
	draw_header();
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
	target_count = collect_tc_targets(ifname, targets, MAX_TC_TARGETS);
	if (target_count <= 0) {
		fprintf(stderr, "Nenhum alvo TC válido encontrado para %s\n", ifname);
		return 1;
	}
	print_status_line(ifname, ifi, targets, target_count);

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

	for (i = 0; i < target_count; i++) {
		err = attach_tc_target(skel, &targets[i]);
		if (err) {
			fprintf(stderr, "bpf_tc_attach %s: %d\n", targets[i].ifname, err);
			goto out;
		}
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new\n");
		err = -1;
		goto out;
	}

	printf(COLOR_GREEN "[✅]" COLOR_RESET " eBPF anexado ao TC ingress/egress. "
	       COLOR_DIM "Ctrl+C para encerrar." COLOR_RESET "\n\n");
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
	detach_tc_targets(targets, target_count);
	deadlock_bpf__destroy(skel);
	return err ? 1 : 0;
}
