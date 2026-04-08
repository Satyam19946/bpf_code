#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "mytcpdump.h"

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

const char *proto_name(__u8 proto)
{
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "other";
    }
}

int handle_event(void *ctx, void *data, size_t size)
{
    if (size < sizeof(struct packet_event))
        return 0;

    struct packet_event *e = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst_ip, dst, sizeof(dst));

    __u16 sport = __builtin_bswap16(e->src_port);
    __u16 dport = __builtin_bswap16(e->dst_port);

    if (e->proto == 1) {
        /* ICMP has no ports */
        printf("%-8s  %-15s          ->  %-15s          %5u bytes\n",
               proto_name(e->proto),
               src, dst,
               e->pkt_len);
    } else {
        printf("%-8s  %-15s:%-5u  ->  %-15s:%-5u  %5u bytes\n",
               proto_name(e->proto),
               src, sport,
               dst, dport,
               e->pkt_len);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open(
        "mytcpdump/mytcpdump.bpf.o");
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "mytcpdump");
    if (!prog) {
        fprintf(stderr, "failed to find program\n");
        return 1;
    }

    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "failed to find map\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    unsigned int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", argv[1]);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "failed to attach\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event,
                                              NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        return 1;
    }

    printf("mytcpdump listening on %s — Ctrl-C to stop\n\n", argv[1]);
    printf("%-8s  %-21s  ->  %-21s  %s\n",
           "proto", "src", "dst", "len");
    printf("%-8s  %-21s  ->  %-21s  %s\n",
           "--------", "---------------------",
           "---------------------", "---");

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running) {
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && keep_running)
            fprintf(stderr, "poll error: %d\n", ret);
    }

    ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    printf("\ndetached\n");
    return 0;
}