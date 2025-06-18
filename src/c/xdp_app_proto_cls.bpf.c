// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>            // Core BPF definitions
#include <bpf/bpf_helpers.h>      // Helper macros (SEC, __uX types, etc.)
#include <bpf/bpf_endian.h>       // bpf_ntohs(), bpf_htonl(), etc.
#include <linux/if_ether.h>       // Ethernet headers and ETH_P_IP
#include <linux/ip.h>             // IPv4 header struct
#include <linux/in.h>             // IPPROTO_TCP, IPPROTO_UDP
#include <linux/tcp.h>            // TCP header struct
#include <linux/udp.h>            // UDP header struct

// Protocol indices for our maps
#define PROTO_HTTP 0              // HTTP index
#define PROTO_DNS  1              // DNS index
#define PROTO_SSH  2              // SSH index
#define PROTO_MAX  3              // Number of protocols

// Map #1: per-CPU counters for each protocol
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);  // array of per-CPU values
    __uint(max_entries, PROTO_MAX);           // one entry per protocol
    __type(key, __u32);                       // protocol index
    __type(value, __u64);                     // 64-bit counter
} stats_map SEC(".maps");

// Map #2: runtime-configurable port numbers
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);         // simple array
    __uint(max_entries, PROTO_MAX);           // one entry per protocol
    __type(key, __u32);                       // protocol index
    __type(value, __u16);                     // 16-bit port number
} port_config_map SEC(".maps");

// XDP program entry point
SEC("xdp")
int xdp_app_proto_cls(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;  // packet end pointer
    void *data     = (void *)(long)ctx->data;      // packet start pointer

    // --- 1) Parse Ethernet header ---
    struct ethhdr *eth = data;                     // Ethernet header
    if ((void*)eth + sizeof(*eth) > data_end)      // bounds check
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)       // only IPv4
        return XDP_PASS;

    // --- 2) Parse IPv4 header ---
    struct iphdr *ip = data + sizeof(*eth);        // IPv4 header
    if ((void*)ip + sizeof(*ip) > data_end)        // bounds check
        return XDP_PASS;
    void *l4 = (void*)ip + ip->ihl * 4;            // L4 header start
    if (l4 > data_end)                             // bounds check
        return XDP_PASS;

    __u32 key;                                     // protocol index
    __u16 cfg_port;                                // configured port
    __u64 *counter;                                // pointer to counter

    // --- 3) TCP: check HTTP & SSH ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;                   // TCP header
        if ((void*)tcp + sizeof(*tcp) > data_end)  // bounds check
            return XDP_PASS;
        __u16 sport = bpf_ntohs(tcp->source);      // sport
        __u16 dport = bpf_ntohs(tcp->dest);        // dport

        // HTTP?
        key = PROTO_HTTP;                          
        __u16 *p_http = bpf_map_lookup_elem(&port_config_map, &key); // lookup HTTP port
        if (p_http) {                              // if found
            cfg_port = *p_http;                    // read config
            if (sport == cfg_port || dport == cfg_port) {
                counter = bpf_map_lookup_elem(&stats_map, &key);     // get counter
                if (counter) __sync_fetch_and_add(counter, 1);      // increment
                return XDP_PASS;
            }
        }

        // SSH?
        key = PROTO_SSH;                          
        __u16 *p_ssh = bpf_map_lookup_elem(&port_config_map, &key);  // lookup SSH port
        if (p_ssh) {                              // if found
            cfg_port = *p_ssh;                    // read config
            if (sport == cfg_port || dport == cfg_port) {
                counter = bpf_map_lookup_elem(&stats_map, &key);     // get counter
                if (counter) __sync_fetch_and_add(counter, 1);      // increment
                return XDP_PASS;
            }
        }
    }
    // --- 4) UDP: check DNS ---
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;                   // UDP header
        if ((void*)udp + sizeof(*udp) > data_end)  // bounds check
            return XDP_PASS;
        __u16 sport = bpf_ntohs(udp->source);      // sport
        __u16 dport = bpf_ntohs(udp->dest);        // dport

        key = PROTO_DNS;                          
        __u16 *p_dns = bpf_map_lookup_elem(&port_config_map, &key);  // lookup DNS port
        if (p_dns) {                              // if found
            cfg_port = *p_dns;                    // read config
            if (sport == cfg_port || dport == cfg_port) {
                counter = bpf_map_lookup_elem(&stats_map, &key);     // get counter
                if (counter) __sync_fetch_and_add(counter, 1);      // increment
                return XDP_PASS;
            }
        }
    }

    return XDP_PASS;  // no match → let packet pass
}

// specify GPL license
char _license[] SEC("license") = "GPL";
// kernel version (ignored but required)
__u32 _version SEC("version") = 1;
