#ifndef XDP_LB_H
#define XDP_LB_H

#include <linux/types.h>

struct service_key {
    __be32  vip;    /* virtual IP - Cluster IP */
    __be16  port;   /* service port */
    __u8    proto;  /* IPPROTO_TCP or IPPROTO_UDP */
    __u8    pad;    /* explicit padding */
};

struct backend {
    __be32  ip;     /* backend pod IP */
    __be16  port;   /* backend pod port */
    __u16   pad;    
};

#endif
