#ifndef MYTCPDUMP_H
#define MYTCPDUMP_H

#include <linux/types.h>

struct packet_event {
    __be32  src_ip;
    __be32  dst_ip;
    __be16  src_port;
    __be16  dst_port;
    __u16   pkt_len;
    __u8    proto;
    __u8    pad1;
};

#endif