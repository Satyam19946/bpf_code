#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <linux/types.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u8);
    __type(value, __u64);
} proto_count SEC(".maps");


SEC("xdp")
int packet_counter(struct xdp_md *ctx)
{
    void *data      = (void *)(long)ctx->data;
    void *data_end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 proto = ip->protocol;

    /* look up the counter for this protocol */
    __u64 *count = bpf_map_lookup_elem(&proto_count, &proto);
    if (count) {
        /* entry exists — increment it */
        __sync_fetch_and_add(count, 1);
    } else {
        /* first packet for this protocol — create entry */
        __u64 init = 1;
        bpf_map_update_elem(&proto_count, &proto, &init, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";