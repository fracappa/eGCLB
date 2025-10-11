//go:build ignore

#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"
#include "include/utils.h"
#include "include/network.h"

 __u32 current_backend_index;

SEC("tc/load_balancer")
int load_balancer_rr_v1(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct flow_key key = {};

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_SHOT;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_SHOT;
    
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_SHOT;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_SHOT;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_ICMP) {
        key.src_port = 0;
        key.dst_port = 0;
    } else {
        return TC_ACT_SHOT; 
    }


    __u32 hash = jhash(&key, sizeof(key), 0);
    // bpf_printk("hash: %u\n", hash);

    // Check if hash is already in the eBPF map
    __u32 *destination_ip = bpf_map_lookup_elem(&flow_map, &hash);

    if(!destination_ip){
        __u32 map_key = 0;
        __u32 *num_backends_elem = bpf_map_lookup_elem(&num_backends, &map_key);
        if(!num_backends_elem){
            bpf_printk("accessing num_backends BPF map error.\n");
            return TC_ACT_SHOT;
        }
        destination_ip = bpf_map_lookup_elem(&backends, &current_backend_index);
        if(!destination_ip) {
            bpf_printk("accessing backends BPF map error.\n");
            return TC_ACT_SHOT;
        }
        current_backend_index = (current_backend_index+1) % (*num_backends_elem);
        if(!bpf_map_update_elem(&flow_map, &hash, &destination_ip, BPF_ANY)) {
            bpf_printk("updating flow_map BPF map error.\n");
            return TC_ACT_SHOT;
        }
    }
   
    __u32 old_ip = ip->daddr;
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, *destination_ip, 4);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
