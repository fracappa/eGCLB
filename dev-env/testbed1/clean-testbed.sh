#!/bin/bash
set -e

ALL_NS=(client1 client2 client3 client4 client5 loadbalancer server1 server2 server3)

echo "🔄 Cleaning up..."
for ns in "${ALL_NS[@]}"; do
    ip netns del $ns 2>/dev/null || echo "Namespace $ns not found, skipping."
done

if mountpoint -q /sys/fs/bpf; then
    umount /sys/fs/bpf
fi

echo "✅ Cleanup complete!"
