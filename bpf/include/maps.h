#ifndef __MAPS_H
#define __MAPS_H

#include "common.h"
#include "types.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // hash of flow_key
    __type(value, struct flow_key); // destination IP
    __uint(max_entries, 10240);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // incremental index {0,1,2,...,n}
    __type(value, struct flow_key); // destination IP
    __uint(max_entries, 10240);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, __u32); 
    __uint(max_entries, 1);
} num_backends SEC(".maps");

#endif /* __MAPS_H */
