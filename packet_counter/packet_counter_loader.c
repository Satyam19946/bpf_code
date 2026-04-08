#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile int keep_running = 1;
void handle_sig(int sig) { keep_running = 0; }

/* protocol number to name — covers the common ones */
const char *proto_name(__u8 proto)
{
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6-in-IPv4";
        case 47: return "GRE";
        case 50: return "ESP (IPSec)";
        case 58: return "ICMPv6";
        default: return "other";
    }
}

void print_counts(int map_fd)
{
    __u8  key = 0, next_key;
    __u64 value;
    int   first = 1;

    printf("\n--- protocol counts ---\n");

    /*
     * bpf_map_get_next_key iterates all keys in the map.
     * pass NULL as first key to get the very first entry.
     * returns -1 with errno=ENOENT when iteration is done.
     */
    while (bpf_map_get_next_key(map_fd,
                                 first ? NULL : &key,
                                 &next_key) == 0) {
        first = 0;
        key = next_key;

        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            printf("  proto %3d (%-15s): %llu packets\n",
                   key, proto_name(key), value);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open(
        "packet_counter/packet_counter.bpf.o");
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "packet_counter");
    if (!prog) {
        fprintf(stderr, "failed to find program\n");
        return 1;
    }

    /* get the map fd by name — matches the variable name in .bpf.c */
    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, "proto_count");
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

    printf("attached to %s — printing counts every 2s (Ctrl-C to stop)\n",
           argv[1]);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (keep_running) {
        sleep(2);
        print_counts(map_fd);
    }

    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    printf("\ndetached\n");
    return 0;
}