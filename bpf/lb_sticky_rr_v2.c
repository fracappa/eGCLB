//go:build ignore
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP6 0x86DD    
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#ifndef DEBUG
#define DEBUG 0
#endif

volatile __u32 num_backends = 4;

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);  // Backend ifindex
    __uint(max_entries, 10240);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);  // Backend interface indexes
    __uint(max_entries, 64);
} backend_map SEC(".maps");

// implement jhash for flow_key
static __always_inline __u32 jhash(const void *key, __u32 length, __u32 initval) {
    return 0;
}

SEC("tc/load_balancer")
int load_balancer_rr_v2(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct flow_key key = {};

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;
    if (eth->h_proto != bpf_htons(ETH_P_IP) || eth->h_proto != bpf_htons(ETH_P_IPV6))
        return TC_ACT_OK;
        
#if DEBUG
    bpf_printk("eth->h_proto: %s\n", eth->h_proto == bpf_htons(ETH_P_IP) ? "ETH_P_IP" : "ETH_P_IPV6");
#endif

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_ICMP) {
        key.src_port = 0;
        key.dst_port = 0;
    } else {
        return TC_ACT_OK;
    }

#if DEBUG
    bpf_printk("src_ip: %u, dst_ip: %u, src_port: %u, dst_port: %u, protocol: %u\n", key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.protocol);
#endif

    __u32 hash = jhash(&key, sizeof(key), 0);
    __u32 *ifindex = bpf_map_lookup_elem(&flow_map, &hash);

    if (!ifindex) {
        __u32 backend_idx = hash % num_backends;
    
#if DEBUG
        bpf_printk("hash: %u, backend_idx: %u\n", hash, backend_idx);
#endif

        __u32 *backend_ifindex = bpf_map_lookup_elem(&backend_map, &backend_idx);
        if (!backend_ifindex) {
            return TC_ACT_SHOT;
        }

#if DEBUG
        bpf_printk("backend_ifindex: %u\n", *backend_ifindex);
#endif

        int res = bpf_map_update_elem(&flow_map, &hash, backend_ifindex, BPF_ANY);
        if (res != 0) {
            return TC_ACT_OK;
        }
#if DEBUG
        bpf_printk("redirecting to backend_ifindex: %u\n", *backend_ifindex);
#endif
        return bpf_redirect(*backend_ifindex, 0);
    }
#if DEBUG
    bpf_printk("redirecting to ifindex: %u\n", *ifindex);
#endif

    return bpf_redirect(*ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";