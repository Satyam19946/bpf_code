#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int packet_inspect(struct xdp_md *ctx)
{
    void *data      = (void *)(long)ctx->data;
    void *data_end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        return XDP_PASS;
    }

    // check for IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return XDP_PASS;
    }

    // parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end){
        return XDP_PASS;
    }

    bpf_printk("src: %x dst: %x proto: %d\n",
                    bpf_ntohl(ip->saddr),
                    bpf_ntohl(ip->daddr),
                    ip->protocol);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";