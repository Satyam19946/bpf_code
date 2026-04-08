#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_dnat.h"

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         struct service_key);
    __type(value,       struct backend);
} service_map SEC(".maps");

static __always_inline __u16
csum_update(__u16 old_csum, __u16 old_val, __u16 new_val)
{
    __u32 csum = (~old_csum & 0xffff) + (~old_val & 0xffff) + new_val;
    csum = (csum >> 16) + (csum & 0xffff);
    return ~csum;
}

SEC("xdp")
int xdp_dnat(struct xdp_md *ctx)
{
    void *data      = (void *)(long)(ctx->data);
    void *data_end  = (void *)(long)(ctx->data_end);
    __be16 dst_port = 0;

    struct ethhdr *eth = data;
    if ((void *)(eth+1) > data_end){
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP){
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth+1);

    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct service_key key = {};

    // Get the number of bytes (ihl is 4 bits telling how many groups of 4 bytes)
    __u8 ip_hdr_len = (ip->ihl) * 4;

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;

    if (ip->protocol == IPPROTO_TCP){
        tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp+1) > data_end){
            return XDP_PASS;
        }
        dst_port = tcp->dest;
    }
    else if (ip->protocol == IPPROTO_UDP){
        udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp+1) > data_end){
            return XDP_PASS;
        }
        dst_port = udp->dest;
    }

    key.vip     = ip->daddr;
    key.proto   = ip->protocol;
    key.port    = dst_port;
    __be32 old_ip = ip->daddr;
    __be16 old_port = dst_port;

    struct backend *backend_val = bpf_map_lookup_elem(&service_map, &key);
    if (backend_val){
        bpf_printk("DNAT: %x:%d -> %x:%d\n",
           bpf_ntohl(ip->daddr), bpf_ntohs(key.port),
           bpf_ntohl(backend_val->ip), bpf_ntohs(backend_val->port));

        ip->daddr   = backend_val->ip;
        dst_port    = backend_val->port;
        
        ip->check   = csum_update(ip->check, 
                                    old_ip & 0xffff, 
                                    backend_val->ip & 0xffff);

        ip->check   = csum_update(ip->check,
                                    old_ip >> 16,
                                    backend_val->ip >> 16);

        if (tcp){
            tcp->dest = dst_port;
            /* 1. fix for the IP address change (affects pseudo-header) */
            tcp->check = csum_update(tcp->check,
                         old_ip & 0xffff,
                         backend_val->ip & 0xffff);
            tcp->check = csum_update(tcp->check,
                         old_ip >> 16,
                         backend_val->ip >> 16);

            tcp->check = csum_update(tcp->check, key.port, backend_val->port); 
        }

        if (udp) {
            udp->dest = dst_port;

            udp->check = csum_update(udp->check,
                         old_ip & 0xffff,
                         backend_val->ip & 0xffff);
            udp->check = csum_update(udp->check,
                         old_ip >> 16,
                         backend_val->ip >> 16);

            udp->check = csum_update(udp->check, old_port, backend_val->port); 
        }


        /* rewrite Ethernet header for veth0 — loopback frame has wrong MACs */
        __u8 veth0_mac[] = {0xee,0x74,0x24,0x4e,0x1b,0x2f};  /* your veth0 MAC */
        __u8 veth1_mac[] = {0xe6,0x6e,0xc4,0x29,0x17,0x12};  /* your veth1 MAC */
        __builtin_memcpy(eth->h_source, veth0_mac, ETH_ALEN);
        __builtin_memcpy(eth->h_dest,   veth1_mac, ETH_ALEN);

        return bpf_redirect(7, 0);
    } else {
        return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "GPL";