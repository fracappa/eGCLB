#!/usr/bin/env bash
set -e

echo "[*] Cleaning up load balancer network environment..."

### --- Disable IP forwarding ---
echo "[*] Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

### --- Remove iptables NAT/DNAT rules (optional) ---
echo "[*] Cleaning up iptables rules..."
iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -d 10.0.1.0/24 -j MASQUERADE 2>/dev/null || true
iptables -t nat -D PREROUTING -d 10.0.0.1 -p tcp --dport 80 -j DNAT --to-destination 10.0.1.11-10.0.1.13 2>/dev/null || true

### --- Remove XDP programs if attached (optional) ---
echo "[*] Detaching any XDP programs..."
for iface in br-client br-server veth_br_c1 veth_br_c2 veth_br_c3 veth_br_s1 veth_br_s2 veth_br_s3; do
    ip link set dev "$iface" xdp off 2>/dev/null || true
done

### --- Delete host-side veths and bridges ---
echo "[*] Removing host-side veths and bridges..."
for i in 1 2 3; do
    ip link del veth_br_c${i} 2>/dev/null || true
    ip link del veth_br_s${i} 2>/dev/null || true
done

ip link del br-client 2>/dev/null || true
ip link del br-server 2>/dev/null || true

### --- Delete namespaces ---
echo "[*] Deleting namespaces..."
for ns in client1 client2 client3 server1 server2 server3; do
    ip netns del "$ns" 2>/dev/null || true
done

### --- Verify cleanup ---
echo "[*] Remaining namespaces (should be none):"
ip netns list || echo "None"

echo "[✔] Cleanup complete."
