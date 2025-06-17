// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Protocol indices
#define PROTO_HTTP 0
#define PROTO_DNS  1
#define PROTO_SSH  2
#define PROTO_MAX  3

// Map #1: per-CPU counters for each protocol
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROTO_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Map #2: runtime-configurable port numbers
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PROTO_MAX);
    __type(key, __u32);
    __type(value, __u16);
} port_config_map SEC(".maps");

// XDP entry point
SEC("xdp")
int xdp_app_proto_cls(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- 1) Ethernet header ---
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // --- 2) IP header ---
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
    void *l4 = (void*)ip + ip->ihl * 4;
    if (l4 > data_end)
        return XDP_PASS;

    __u32 key;
    __u16 cfg_port;
    __u64 *counter;

    // --- 3) TCP: HTTP & SSH ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void*)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        __u16 sport = bpf_ntohs(tcp->source);
        __u16 dport = bpf_ntohs(tcp->dest);

        // HTTP?
        key = PROTO_HTTP;
        __u16 *p_http = bpf_map_lookup_elem(&port_config_map, &key);
        if (p_http) {
            cfg_port = *p_http;
            if (sport == cfg_port || dport == cfg_port) {
                counter = bpf_map_lookup_elem(&stats_map, &key);
                if (counter) __sync_fetch_and_add(counter, 1);
                return XDP_PASS;
            }
        }

        // SSH?
        key = PROTO_SSH;
        __u16 *p_ssh = bpf_map_lookup_elem(&port_config_map, &key);
        if (p_ssh) {
            cfg_port = *p_ssh;
            if (sport == cfg_port || dport == cfg_port) {
                counter = bpf_map_lookup_elem(&stats_map, &key);
                if (counter) __sync_fetch_and_add(counter, 1);
                return XDP_PASS;
            }
        }
    }
    // --- 4) UDP: DNS ---
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void*)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        __u16 sport = bpf_ntohs(udp->source);
        __u16 dport = bpf_ntohs(udp->dest);

        key = PROTO_DNS;
        __u16 *p_dns = bpf_map_lookup_elem(&port_config_map, &key);
        if (p_dns) {
            cfg_port = *p_dns;
            if (sport == cfg_port || dport == cfg_port) {
                counter = bpf_map_lookup_elem(&stats_map, &key);
                if (counter) __sync_fetch_and_add(counter, 1);
                return XDP_PASS;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

