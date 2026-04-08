#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* must match the kernel-side struct exactly */
struct conn_key {
    __uint32_t src_ip;
    __uint32_t dst_ip;
    __uint8_t  proto;
    __uint8_t  pad[3];
};

struct conn_stats {
    __uint64_t packets;
    __uint64_t bytes;
};

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

const char *proto_name(__uint8_t proto)
{
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "other";
    }
}

void print_table(int map_fd)
{
    struct conn_key  key = {}, next_key;
    struct conn_stats stats;
    int first = 1;
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];

    printf("\n--- connection table ---\n");

    while (bpf_map_get_next_key(map_fd,
                                 first ? NULL : &key,
                                 &next_key) == 0) {
        first = 0;
        key = next_key;

        if (bpf_map_lookup_elem(map_fd, &key, &stats) != 0)
            continue;

        /* inet_ntop converts a network-order __be32 to dotted-decimal */
        inet_ntop(AF_INET, &key.src_ip, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &key.dst_ip, dst_str, sizeof(dst_str));

        printf("  %-15s -> %-15s  %-6s  pkts: %llu  bytes: %llu\n",
               src_str, dst_str,
               proto_name(key.proto),
               stats.packets,
               stats.bytes);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open(
        "connection_tracker/connection_tracker.bpf.o");
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "connection_tracker");
    if (!prog) {
        fprintf(stderr, "failed to find program\n");
        return 1;
    }

    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, "conn_table");
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

    printf("attached to %s — printing table every 3s (Ctrl-C to stop)\n",
           argv[1]);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running) {
        sleep(3);
        print_table(map_fd);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    printf("\ndetached\n");
    return 0;
}