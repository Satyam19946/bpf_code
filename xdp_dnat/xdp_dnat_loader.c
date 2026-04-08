#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_dnat.h"

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open("xdp_dnat/xdp_dnat.bpf.o");
    if (!obj) { fprintf(stderr, "open failed\n"); return 1; }

    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_dnat");
    if (!prog) { fprintf(stderr, "prog not found\n"); return 1; }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "service_map");
    if (!map) { fprintf(stderr, "map not found\n"); return 1; }
    int map_fd = bpf_map__fd(map);

    /* pre-populate map with one test service:
     * VIP 10.96.0.10:80 TCP → backend 10.244.1.5:8080
     * you can change these to IPs relevant to your setup
    struct service_key key = {};
    inet_pton(AF_INET, "10.96.0.10", &key.vip);
    key.port  = htons(80);
    key.proto = 6;  IPPROTO_TCP 

    struct backend val = {};
    inet_pton(AF_INET, "10.244.1.5", &val.ip);
    val.port = htons(8080);

    */

    /* change to VIP 10.96.0.10:9999 -> 10.244.1.5:9999 (easier for testing of DNAT)*/
    struct service_key key = {};
    inet_pton(AF_INET, "10.96.0.10", &key.vip);
    key.port  = htons(9999);
    key.proto = 17;   /* IPPROTO_UDP */

    struct backend val = {};
    inet_pton(AF_INET, "10.244.1.5", &val.ip);
    val.port = htons(9999);

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
        fprintf(stderr, "map insert failed\n");
        return 1;
    }

    printf("inserted: 10.96.0.10:80 -> 10.244.1.5:8080\n");

    unsigned int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) { fprintf(stderr, "bad interface\n"); return 1; }

    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "attach failed\n");
        return 1;
    }

    printf("attached to %s — Ctrl-C to stop\n", argv[1]);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    while (keep_running) sleep(1);

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    printf("\ndetached\n");
    return 0;
}