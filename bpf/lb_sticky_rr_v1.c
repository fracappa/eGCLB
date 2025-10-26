//go:build ignore

#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"
#include "include/utils.h"
#include "include/network.h"

 __u32 current_backend_index;
struct backend_info load_balancer_info;

SEC("xdp/load_balancer")
int xdp_load_balancer_rr(struct xdp_md *ctx){
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct flow_key key = {};

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }

    __u32 hash = jhash(&key, sizeof(key), 0);
    struct backend_info *backend_info = bpf_map_lookup_elem(&flow_map, &hash);

    if(!backend_info){
        __u32 map_key = 0;
        __u32 *num_backends_elem = bpf_map_lookup_elem(&num_backends, &map_key);
        if(!num_backends_elem){
            bpf_printk("accessing num_backends BPF map error.\n");
            return XDP_DROP;
        }
        backend_info = bpf_map_lookup_elem(&backends, &current_backend_index);
        if(!backend_info) {
            bpf_printk("accessing backends BPF map error.\n");
            return XDP_DROP;
        }
        current_backend_index = (current_backend_index+1) % (*num_backends_elem);
        if(!bpf_map_update_elem(&flow_map, &hash, &backend_info, BPF_ANY)) {
            bpf_printk("updating flow_map BPF map error.\n");
            return XDP_DROP;
        }
    }


    ip->daddr = backend_info->ip;
    __builtin_memcpy(eth->h_dest, backend_info->mac, ETH_ALEN);
    ip->saddr = load_balancer_info.ip;
    __builtin_memcpy(eth->h_source, backend_info->mac, ETH_ALEN);

    ip->check = iph_csum(ip);

    
    return XDP_TX; // or XDP_REDIRECT to another interface
}


char LICENSE[] SEC("license") = "GPL";
