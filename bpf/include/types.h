#ifndef __TYPES_H
#define __TYPES_H

#include "common.h"

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
} __attribute__((packed));

#endif /* __TYPES_H */
