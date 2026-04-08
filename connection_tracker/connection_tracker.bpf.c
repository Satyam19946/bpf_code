#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct conn_key {
    __be32  src_ip;
    __be32  dst_ip;
    __u8    proto;
    __u8    pad[3];
};

struct conn_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} conn_table SEC(".maps");

SEC("xdp")
int connection_tracker(struct xdp_md *ctx)
{
    void *data      = (void*)(long)(ctx->data);
    void *data_end  = (void*)(long)(ctx->data_end);

    struct ethhdr *eth = data;

    if ((void *)(eth+1) > data_end){
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth+1);

    if((void *)(ip+1) > data_end){
        return XDP_PASS;
    }

    __u16 pkt_len = bpf_ntohs(ip->tot_len);

    struct conn_key key = {};
    key.src_ip  =   ip->saddr;
    key.dst_ip  =   ip->daddr;

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_table, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
    } else {
        struct conn_stats init = { .packets = 1, .bytes = pkt_len };
        bpf_map_update_elem(&conn_table, &key, &init, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";