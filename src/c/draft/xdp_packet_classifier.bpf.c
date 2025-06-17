// File: xdp_packet_classifier.c
// Description: eBPF XDP program for packet classification (IPv4 vs IPv6, TCP vs UDP, DNS, HTTP),
//              per-CPU counters, DNS per-src counting, and dynamic drop map.
// Author: [Your Name]
// Date: June 2025

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Protocol indices
enum ProtocolType {
    PROTO_IPV4 = 0,
    PROTO_IPV6 = 1,
    PROTO_TCP  = 2,
    PROTO_UDP  = 3,
    PROTO_MAX  = 4,
};

// Per-CPU array for global protocol counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, PROTO_MAX);
} protocol_counters SEC("maps");

// Hash map: track DNS packet counts per source IPv4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} dns_counters SEC("maps");

// Hash map: dynamic drop map by IPv4 address
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} drop_map SEC("maps");

char LICENSE[] SEC("license") = "GPL";

// Helper to increment a per-CPU counter
static __always_inline void increment_counter(__u32 idx) {
    __u64 *value = bpf_map_lookup_elem(&protocol_counters, &idx);
    if (value) __sync_fetch_and_add(value, 1);
}

SEC("xdp")
int xdp_packet_classifier(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    __u16 h_proto = bpf_ntohs(eth->h_proto);

    // IPv4 path
    if (h_proto == ETH_P_IP) {
        increment_counter(PROTO_IPV4);
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // Dynamic drop if in drop_map
        __u32 src_ip = ip->saddr;
        if (bpf_map_lookup_elem(&drop_map, &src_ip))
            return XDP_DROP;

        // L4: TCP
        if (ip->protocol == IPPROTO_TCP) {
            increment_counter(PROTO_TCP);
            int ip_hlen = ip->ihl * 4;
            struct tcphdr *tcp = data + sizeof(*eth) + ip_hlen;
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
            __u16 sport = bpf_ntohs(tcp->source);
            __u16 dport = bpf_ntohs(tcp->dest);
            // Drop HTTP (port 80)
            if (sport == 80 || dport == 80) {
                bpf_printk("Dropping HTTP packet: src=%u dest=%u\n", sport, dport);
                return XDP_DROP;
            }
        }
        // L4: UDP
        else if (ip->protocol == IPPROTO_UDP) {
            increment_counter(PROTO_UDP);
            int ip_hlen = ip->ihl * 4;
            struct udphdr *udp = data + sizeof(*eth) + ip_hlen;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            __u16 sport = bpf_ntohs(udp->source);
            __u16 dport = bpf_ntohs(udp->dest);
            // Count DNS (port 53)
            if (sport == 53 || dport == 53) {
                __u64 init = 1, *cnt;
                cnt = bpf_map_lookup_elem(&dns_counters, &src_ip);
                if (cnt)
                    __sync_fetch_and_add(cnt, 1);
                else
                    bpf_map_update_elem(&dns_counters, &src_ip, &init, BPF_ANY);
            }
        }
    }
    // IPv6 path (basic counting; extend as needed)
    else if (h_proto == ETH_P_IPV6) {
        increment_counter(PROTO_IPV6);
        // TODO: parse IPv6 headers & L4 protocols similarly
    }

    return XDP_PASS;
}

