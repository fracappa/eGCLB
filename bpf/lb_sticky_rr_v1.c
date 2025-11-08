// go:build ignore

#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"
#include "include/utils.h"
#include "include/network.h"

__u32 current_backend_index;

SEC("xdp/load_balancer")
int xdp_load_balancer_rr(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct flow_key key = {};

    bpf_printk("xdp program triggered.\n");

    if ((void *)(eth + 1) > data_end)
    {
        bpf_printk("pkt too big.\n");
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("not an IPv4 pkt.\n");
        return XDP_PASS;
    }

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        bpf_printk("IPv4 pkt too big.\n");
        return XDP_PASS;
    }

    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP)
    {
        tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        bpf_printk("TCP traffic\n");
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        bpf_printk("UDP traffic\n");
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }
    else if (ip->protocol == IPPROTO_ICMP)
    {
        bpf_printk("ICMP traffic\n");
        key.src_port = key.dst_port = 0;
    }
    else
    {
        bpf_printk("uknown protocol: not in {TCP,UDP,ICMP}\n");
        return XDP_PASS;
    }

    __u32 hash = jhash(&key, sizeof(key), 0);
    struct backend_info *backend_info = bpf_map_lookup_elem(&flow_map, &hash);

    if (!destination_ip)
    {
        if (!destination_ip)
        {
            __u32 map_key = 0;
            __u32 *num_backends_elem = bpf_map_lookup_elem(&num_backends, &map_key);
            if (!num_backends_elem)
            {
                bpf_printk("accessing num_backends BPF map error.\n");
                return TC_ACT_SHOT;
            }
            destination_ip = bpf_map_lookup_elem(&backends, &current_backend_index);
            if (!destination_ip)
            {
                bpf_printk("accessing backends BPF map error.\n");
                return TC_ACT_SHOT;
            }
            current_backend_index = (current_backend_index + 1) % (*num_backends_elem);
            if (!bpf_map_update_elem(&flow_map, &hash, &destination_ip, BPF_ANY))
            {
                bpf_printk("updating flow_map BPF map error.\n");
                return TC_ACT_SHOT;
            }
        }
    }

    // Rewrite destination IP manually
    ip->daddr = *destination_ip;
    // Must fix checksum manually here (XDP lacks helpers)
    // pseudo-code: recompute_ipv4_csum(ip);

    bpf_printk("pkt forwarded\n");

    return XDP_PASS;; // or XDP_REDIRECT to another interface
}

char LICENSE[] SEC("license") = "GPL";
