#!/bin/bash
# exit on error, show commands
set -ex
# treat unset vars as error
set -u

# name of our tmux session
readonly TMUX=ipv6

# kill any old tmux session by that name
tmux kill-session -t "${TMUX}" 2>/dev/null || true

# delete all existing network namespaces
ip -all netns delete

# create three namespaces: host0, host1, router
ip netns add h0
ip netns add h1
ip netns add r0

# create two veth pairs for linking h0<->r0 and r0<->h1
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3

# move one end of each veth into the appropriate ns
ip link set veth0 netns h0
ip link set veth1 netns r0
ip link set veth2 netns r0
ip link set veth3 netns h1

###################
#### Node: h0 #####
###################
echo -e "\nNode: h0"
# bring up loopback in h0
ip netns exec h0 ip link set dev lo up
# bring up veth0 in h0
ip netns exec h0 ip link set dev veth0 up
# assign IPv4 to h0 veth
ip netns exec h0 ip addr add 10.0.0.1/24 dev veth0
# assign IPv6 to h0 veth
ip netns exec h0 ip addr add cafe::1/64 dev veth0

# add default IPv6 route via router
ip netns exec h0 ip -6 route add default via cafe::254 dev veth0
# add default IPv4 route via router
ip netns exec h0 ip -4 route add default via 10.0.0.254 dev veth0

###################
#### Node: r0 #####
###################
echo -e "\nNode: r0"
# enable IPv4 forwarding on r0
ip netns exec r0 sysctl -w net.ipv4.ip_forward=1
# enable IPv6 forwarding on r0
ip netns exec r0 sysctl -w net.ipv6.conf.all.forwarding=1
# disable reverse-path filter on all r0 interfaces
ip netns exec r0 sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec r0 sysctl -w net.ipv4.conf.veth1.rp_filter=0
ip netns exec r0 sysctl -w net.ipv4.conf.veth2.rp_filter=0

# bring up loopback in r0
ip netns exec r0 ip link set dev lo up
# bring up both veth1 and veth2 in r0
ip netns exec r0 ip link set dev veth1 up
ip netns exec r0 ip link set dev veth2 up

# assign IPv6 & IPv4 to r0's veth1 (towards h0)
ip netns exec r0 ip addr add cafe::254/64 dev veth1
ip netns exec r0 ip addr add 10.0.0.254/24 dev veth1

# assign IPv6 & IPv4 to r0's veth2 (towards h1)
ip netns exec r0 ip addr add beef::254/64 dev veth2
ip netns exec r0 ip addr add 10.0.2.254/24 dev veth2

# allow failures beyond this point
set +e
# prepare an env script for r0 in tmux
read -r -d '' r0_env <<-EOF   
  # show commands as they run
  set -x
  # mount BPF filesystem
  mount -t bpf bpf /sys/fs/bpf/
  # create directories for our maps & progs
  mkdir -p /sys/fs/bpf/netprog/{progs,maps}
  # mount tracing fs (needed by some kernels)
  mount -t tracefs nodev /sys/kernel/tracing
  # allow unlimited BPF memory locking
  ulimit -l unlimited
  # load & pin our XDP BPF program and maps
  bpftool prog loadall xdp_app_proto_cls.bpf.o /sys/fs/bpf/netprog/progs pinmaps /sys/fs/bpf/netprog/maps
  # attach XDP to r0’s veth1 interface
  bpftool net attach xdp pinned /sys/fs/bpf/netprog/progs/xdp_app_proto_cls dev veth1
  # drop into a bash shell inside r0
  /bin/bash
EOF
# re-enable exit-on-error
set -e

###################
#### Node: h1 #####
###################
echo -e "\nNode: h1"
# bring up loopback in h1
ip netns exec h1 ip link set dev lo up
# bring up veth3 in h1
ip netns exec h1 ip link set dev veth3 up
# assign IPv4 to h1 veth
ip netns exec h1 ip addr add 10.0.2.1/24 dev veth3
# assign IPv6 to h1 veth
ip netns exec h1 ip addr add beef::1/64 dev veth3

# add default IPv4 route via r0
ip netns exec h1 ip -4 route add default via 10.0.2.254 dev veth3
# add default IPv6 route via r0
ip netns exec h1 ip -6 route add default via beef::254 dev veth3

## Create a new tmux session
# start h0 shell in window “h0”
tmux new-session -d -s "${TMUX}" -n h0 ip netns exec h0 bash
# start r0 shell (with our BPF loader) in window “r0”
tmux new-window -t "${TMUX}" -n r0 ip netns exec r0 bash -c "${r0_env}"
# start h1 shell in window “h1”
tmux new-window -t "${TMUX}" -n h1 ip netns exec h1 bash
# go back to the first (h0) window
tmux select-window -t :0
# enable mouse support in tmux
tmux set-option -g mouse on

# attach to the tmux session
tmux attach -t "${TMUX}"
