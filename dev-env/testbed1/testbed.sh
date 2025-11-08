#!/usr/bin/env bash
set -e

### --- CLEANUP ---
cleanup() {
    echo "[*] Cleaning up old namespaces and bridges..."
    for ns in client1 client2 client3 server1 server2 server3; do
        ip netns del $ns 2>/dev/null || true
    done
    ip link del br-client 2>/dev/null || true
    ip link del br-server 2>/dev/null || true
}
cleanup

### --- CREATE CLIENT & SERVER NAMESPACES ---
echo "[+] Creating namespaces..."
for i in 1 2 3; do
    ip netns add client$i
    ip netns add server$i
done

### --- CREATE BRIDGES ON HOST (LB) ---
echo "[+] Creating bridges on host..."
ip link add br-client type bridge
ip link add br-server type bridge
ip addr add 10.0.0.1/24 dev br-client
ip addr add 10.0.1.1/24 dev br-server
ip link set br-client up
ip link set br-server up

### --- CONNECT CLIENTS TO br-client ---
for i in 1 2 3; do
    echo "[+] Connecting client$i..."
    ip link add veth_c${i} type veth peer name veth_br_c${i}
    ip link set veth_c${i} netns client$i
    ip link set veth_br_c${i} master br-client
    ip link set veth_br_c${i} up

    ip netns exec client$i ip addr add 10.0.0.$((10 + i))/24 dev veth_c${i}
    ip netns exec client$i ip link set veth_c${i} up
    ip netns exec client$i ip link set lo up
    ip netns exec client$i ip route add default via 10.0.0.1
done

### --- CONNECT SERVERS TO br-server ---
for i in 1 2 3; do
    echo "[+] Connecting server$i..."
    ip link add veth_s${i} type veth peer name veth_br_s${i}
    ip link set veth_s${i} netns server$i
    ip link set veth_br_s${i} master br-server
    ip link set veth_br_s${i} up

    ip netns exec server$i ip addr add 10.0.1.$((10 + i))/24 dev veth_s${i}
    ip netns exec server$i ip link set veth_s${i} up
    ip netns exec server$i ip link set lo up
    ip netns exec server$i ip route add default via 10.0.1.1
done

### --- ENABLE FORWARDING ON HOST ---
sysctl -w net.ipv4.ip_forward=1 >/dev/null

### --- OPTIONAL: NAT (clients → servers through host) ---
# iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 10.0.1.0/24 -j MASQUERADE

echo
echo "[+] Setup complete. Host acts as load balancer."
echo
echo "Test connectivity:"
echo "  ip netns exec client1 ping -c2 10.0.0.1        # ping host (LB)"
echo "  ip netns exec server1 ping -c2 10.0.1.1        # ping host (LB)"
echo
echo "To route traffic from clients to servers through host:"
echo "  Enable NAT: iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 10.0.1.0/24 -j MASQUERADE"
echo
echo "Or set up load balancing (e.g., round robin):"
echo "  iptables -t nat -A PREROUTING -d 10.0.0.1 -p tcp --dport 80 -j DNAT --to-destination 10.0.1.11-10.0.1.13"
