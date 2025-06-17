/*
 * xdp_http_filter.c
 *
 * eBPF XDP program to drop HTTP (port 80) TCP packets.
 *
 * Build:
 *   clang -O2 -g -target bpf -c xdp_http_filter.c -o xdp_http_filter.o
 *
 * Usage:
 *   # Load onto interface <iface>:
 *   sudo ip link set dev <iface> xdp obj xdp_http_filter.o sec xdp
 *
 *   # Verify HTTP traffic is dropped:
 *   sudo tcpdump -i <iface> port 80
 *   # Verify other traffic passes:
 *   ping -I <iface> <dest>
 *   # View drop logs:
 *   dmesg | tail
 *
 *   # To unload:
 *   sudo ip link set dev <iface> xdp off
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_http_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4 header
    struct iphdr *ip = data + sizeof(*eth);
    if (ip + 1 > (struct iphdr *)data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // TCP header
    int ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = data + sizeof(*eth) + ip_hdr_len;
    if (tcp + 1 > (struct tcphdr *)data_end)
        return XDP_PASS;

    // Drop if port 80 (HTTP)
    if (tcp->dest == bpf_htons(80) || tcp->source == bpf_htons(80)) {
        bpf_printk("Dropping HTTP packet\n");
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

