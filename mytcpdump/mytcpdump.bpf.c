#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#include "mytcpdump.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");


SEC("xdp")
int mytcpdump(struct xdp_md *ctx)
{
    void *data      = (void *)(long)ctx->data;
    void *data_end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth+1) > data_end){
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end){
        return XDP_PASS;
    }

    struct packet_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e){
        return XDP_PASS;
    }

    e->src_ip   = ip->saddr;
    e->dst_ip   = ip->daddr;
    e->src_port = 0;
    e->dst_port = 0;
    e->pkt_len  = bpf_ntohs(ip->tot_len);
    e->proto    = ip->protocol;
    e->pad1     = 0;


    __u8 ip_hdr_len = ip->ihl * 4;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            goto submit;

        e->src_port = tcp->source;
        e->dst_port = tcp->dest;
    }

    /* --- UDP --- */
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            goto submit;

        e->src_port = udp->source;
        e->dst_port = udp->dest;
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;

}

char LICENSE[] SEC("license") = "GPL";