// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>                // Core BPF definitions
#include <bpf/bpf_helpers.h>          // bpf helper macros (SEC, bpf_map_lookup_elem, etc.)
#include <bpf/bpf_endian.h>           // bpf_ntohs, bpf_htonl, etc.
#include <linux/if_ether.h>           // ETH_P_IP, struct ethhdr
#include <linux/ip.h>                 // struct iphdr
#include <linux/in.h>                 // IPPROTO_TCP, IPPROTO_UDP
#include <linux/tcp.h>                // struct tcphdr
#include <linux/udp.h>                // struct udphdr

// ------------------------------------------------------------------
// Protocol indices for our maps
#define PROTO_HTTP 0
#define PROTO_DNS  1
#define PROTO_SSH  2
#define PROTO_MAX  3

// ------------------------------------------------------------------
// Map #1: per-protocol packet counters (one 64-bit counter per CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // per-CPU array
    __uint(max_entries, PROTO_MAX);           // entries = HTTP, DNS, SSH
    __type(key, __u32);                       // protocol index
    __type(value, __u64);                     // counter
} stats_map SEC(".maps");

// ------------------------------------------------------------------
// Map #2: runtime-configurable port numbers for each protocol
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);         // simple array map
    __uint(max_entries, PROTO_MAX);           // same indices 0,1,2
    __type(key, __u32);                       // protocol index
    __type(value, __u16);                     // port number
} port_config_map SEC(".maps");

// ------------------------------------------------------------------
// XDP program entry point
SEC("xdp")
int xdp_app_proto_cls(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;  // packet end
    void *data     = (void *)(long)ctx->data;      // packet start

    // --- 1) Parse Ethernet header ---
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;                           // truncated, let kernel handle

    // --- 2) Only handle IPv4 packets ---
    __u16 eth_proto = bpf_ntohs(eth->h_proto);     // convert network→host order
    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    // --- 3) Parse IP header ---
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    // calculate start of L4 header
    __u32 ip_hdr_len = ip->ihl * 4;
    void *l4 = (void*)ip + ip_hdr_len;
    if (l4 > data_end)
        return XDP_PASS;

    __u32 key;
    __u16 cfg_port = 0;
    __u64 *cnt;

    // --- 4) Handle TCP (HTTP & SSH) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void*)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        __u16 sport = bpf_ntohs(tcp->source);
        __u16 dport = bpf_ntohs(tcp->dest);

        // check HTTP
        key = PROTO_HTTP;
        __u16 *p_http = bpf_map_lookup_elem(&port_config_map, &key);
        if (p_http)
            cfg_port = *p_http;                    // use configured port
        if (dport == cfg_port || sport == cfg_port) {
            cnt = bpf_map_lookup_elem(&stats_map, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_PASS;
        }

        // check SSH
        key = PROTO_SSH;
        __u16 *p_ssh = bpf_map_lookup_elem(&port_config_map, &key);
        if (p_ssh)
            cfg_port = *p_ssh;
        if (dport == cfg_port || sport == cfg_port) {
            cnt = bpf_map_lookup_elem(&stats_map, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_PASS;
        }
    }
    // --- 5) Handle UDP (DNS) ---
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void*)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        __u16 sport = bpf_ntohs(udp->source);
        __u16 dport = bpf_ntohs(udp->dest);

        key = PROTO_DNS;
        __u16 *p_dns = bpf_map_lookup_elem(&port_config_map, &key);
        if (p_dns)
            cfg_port = *p_dns;
        if (dport == cfg_port || sport == cfg_port) {
            cnt = bpf_map_lookup_elem(&stats_map, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_PASS;
        }
    }

    // --- 6) No match: pass it along ---
    return XDP_PASS;
}

// required license/version
char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

