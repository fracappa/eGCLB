//go:build ignore
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
// #include <linux/jhash.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#ifndef DEBUG
#define DEBUG 1
#endif

#define JHASH_INITVAL		0xdeadbeef
#define MAX_BACKENDS 3

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // hash of flow_key
    __type(value, __u32); // destination IP
    __uint(max_entries, 10240);
} flow_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // incremental index {0,1,2,...,n}
    __type(value, __u32); // destination IP
    __uint(max_entries, 10240);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); 
    __type(value, __u32); 
    __uint(max_entries, 1);
} num_backends SEC(".maps");


static __always_inline __u32 rol32(__u32 word, __u32 shift) {
    return (word << shift) | (word >> (32 - shift));
}

static __always_inline void jhash_mix(__u32 *a, __u32 *b, __u32 *c) {
    *a -= *c;  *a ^= rol32(*c, 4);  *c += *b;
    *b -= *a;  *b ^= rol32(*a, 6);  *a += *c;
    *c -= *b;  *c ^= rol32(*b, 8);  *b += *a;
    *a -= *c;  *a ^= rol32(*c,16);  *c += *b;
    *b -= *a;  *b ^= rol32(*a,19);  *a += *c;
    *c -= *b;  *c ^= rol32(*b, 4);  *b += *a;
}

static __always_inline __u32 jhash(const void *key, __u32 len, __u32 initval) {
    const __u8 *k = key;
    __u32 a, b, c;
    a = b = c = 0xdeadbeef + len + initval;

    __u32 k0 = 0, k1 = 0, k2 = 0;

    if (len > 0) k0 |= k[0];
    if (len > 1) k0 |= k[1] << 8;
    if (len > 2) k0 |= k[2] << 16;
    if (len > 3) k0 |= k[3] << 24;
    if (len > 4) k1 |= k[4];
    if (len > 5) k1 |= k[5] << 8;
    if (len > 6) k1 |= k[6] << 16;
    if (len > 7) k1 |= k[7] << 24;
    if (len > 8) k2 |= k[8];
    if (len > 9) k2 |= k[9] << 8;
    if (len > 10) k2 |= k[10] << 16;
    if (len > 11) k2 |= k[11] << 24;

    a += k0;
    b += k1;
    c += k2;

    jhash_mix(&a, &b, &c);

    return c;
}

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
    bpf_printk("hash: %u\n", hash);

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
        current_backend_index = (current_backend_index+1) % (*num_backends_elem);
    }
   
    __u32 old_ip = ip->daddr;
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, *destination_ip, 4);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
