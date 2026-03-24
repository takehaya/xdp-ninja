#!/bin/bash
sudo ip link delete veth0 2>/dev/null || true
sudo ip netns delete xdptest 2>/dev/null || true
echo "cleanup done"
