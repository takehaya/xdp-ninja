#!/bin/bash
sudo ip link delete vtc0 2>/dev/null || true
sudo ip netns delete xdptctest 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/xdp_tailcall_test 2>/dev/null || true
