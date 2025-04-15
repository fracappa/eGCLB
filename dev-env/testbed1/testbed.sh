#!/bin/bash
set -e

# Clients
CLIENTS=(client1 client2 client3 client4 client5)
SERVERS=(server1 server2 server3)
LB="loadbalancer"

# IP prefixes
CLIENT_NET="10.0.0."
SERVER_NETS=("10.0.1." "10.0.2." "10.0.3.")

# Create namespaces
echo "Creating namespaces..."
for ns in "${CLIENTS[@]}" "$LB" "${SERVERS[@]}"; do
    ip netns add $ns
done

# Connect clients to loadbalancer
for i in "${!CLIENTS[@]}"; do
    cns="${CLIENTS[$i]}"
    veth_c="veth-${cns}"
    veth_lb="veth-lb-${cns}"

    ip link add $veth_c type veth peer name $veth_lb

    ip link set $veth_c netns $cns
    ip link set $veth_lb netns $LB

    ip netns exec $cns ip addr add ${CLIENT_NET}$((i+1))/24 dev $veth_c
    ip netns exec $cns ip link set $veth_c up
    ip netns exec $cns ip route add default via ${CLIENT_NET}100

    ip netns exec $LB ip addr add ${CLIENT_NET}100/24 dev $veth_lb
    ip netns exec $LB ip link set $veth_lb up
done

# Connect servers to loadbalancer
for i in "${!SERVERS[@]}"; do
    sns="${SERVERS[$i]}"
    net="${SERVER_NETS[$i]}"
    veth_s="veth-${sns}"
    veth_lb="veth-lb-${sns}"

    ip link add $veth_s type veth peer name $veth_lb

    ip link set $veth_s netns $sns
    ip link set $veth_lb netns $LB

    ip netns exec $sns ip addr add ${net}2/24 dev $veth_s
    ip netns exec $sns ip link set $veth_s up
    ip netns exec $sns ip route add default via ${net}1

    ip netns exec $LB ip addr add ${net}1/24 dev $veth_lb
    ip netns exec $LB ip link set $veth_lb up
done

# Loopback up in all namespaces
for ns in "${CLIENTS[@]}" "$LB" "${SERVERS[@]}"; do
    ip netns exec $ns ip link set lo up
done

# Mount bpffs if needed
mkdir -p /sys/fs/bpf
mount | grep -q "/sys/fs/bpf" || \
    mount -t bpf none /sys/fs/bpf || \
    mount -t bpffs bpffs /sys/fs/bpf


ip netns exec loadbalancer tc qdisc add dev veth-lb-client1 clsact
ip netns exec loadbalancer tc qdisc add dev veth-lb-client2 clsact
ip netns exec loadbalancer tc qdisc add dev veth-lb-client3 clsact
ip netns exec loadbalancer tc qdisc add dev veth-lb-client4 clsact
ip netns exec loadbalancer tc qdisc add dev veth-lb-client5 clsact

ip netns exec loadbalancer tc filter add dev veth-lb-client1 ingress bpf obj ../../src/lb_sticky_rr_v2_bpfel.o sec tc/load_balancer
ip netns exec loadbalancer tc filter add dev veth-lb-client2 ingress bpf obj ../../src/lb_sticky_rr_v2_bpfel.o sec tc/load_balancer
ip netns exec loadbalancer tc filter add dev veth-lb-client3 ingress bpf obj ../../src/lb_sticky_rr_v2_bpfel.o sec tc/load_balancer
ip netns exec loadbalancer tc filter add dev veth-lb-client4 ingress bpf obj ../../src/lb_sticky_rr_v2_bpfel.o sec tc/load_balancer
ip netns exec loadbalancer tc filter add dev veth-lb-client5 ingress bpf obj ../../src/lb_sticky_rr_v2_bpfel.o sec tc/load_balancer



echo "✅ Network namespaces created and interfaces connected."

