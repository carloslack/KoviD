// This file defines a simple eBPF socket filter program that monitors IPv4 TCP
// traffic. If the destination port is 22 (SSH) or 443 (HTTPS), it increments
// a counter in the port_count_map. The program then passes the packet up
// the stack (returns skb->len) without modifying or dropping it.
// To compile it, use:
// $ clang   -O2 -g -Wall   -target bpf   -D__TARGET_ARCH_x86   -c
// socket_filter_bpf.c -o socket_filter_bpf.o -I ./

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

// Map to store packet counts keyed by a port number
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u16);
  __type(value, __u64);
} port_count_map SEC(".maps");

// Helper function to read a 16-bit value at the given offset
static __always_inline int read_u16(struct __sk_buff *ctx, int offset,
                                    __u16 *val) {
  return bpf_skb_load_bytes(ctx, offset, val, 2);
}

SEC("socket")
int socket_filter_prog(struct __sk_buff *ctx) {
  // The packet length (in bytes)
  if (ctx->len < sizeof(struct ethhdr)) {
    // Not enough for even an Ethernet header
    return 0; // TODO: or return ctx->len if you prefer passing
  }

  // Check ethertype (offset 12..13 in Ethernet header)
  __u16 eth_type;
  if (read_u16(ctx, 12, &eth_type) < 0) {
    return 0;
  }
  eth_type = bpf_ntohs(eth_type);
  if (eth_type != ETH_P_IP) {
    // Not IPv4 => pass
    return ctx->len;
  }

  // Now check if we have enough bytes for IPv4 minimum header
  // Ethernet header is 14 bytes. IP min header is 20 bytes => 34 total
  if (ctx->len < 34) {
    return ctx->len;
  }

  // IP protocol field is at offset 23 from the Ethernet start:
  // [ Ethernet(14) + IP(9) = 23 total offset to ip->protocol ]
  __u8 ip_protocol;
  if (bpf_skb_load_bytes(ctx, 23, &ip_protocol, 1) < 0) {
    return ctx->len;
  }
  if (ip_protocol != IPPROTO_TCP) {
    return ctx->len;
  }

  // For a minimal approach, let's assume no IP options:
  // TCP header starts at offset 34 => we can read ports at
  // offsets 34..35, 36..37. TCP dest port is offset 36..37
  __u16 dest_port;
  if (bpf_skb_load_bytes(ctx, 36, &dest_port, 2) < 0) {
    return ctx->len;
  }
  dest_port = bpf_ntohs(dest_port);

  if (dest_port == 22 || dest_port == 443) {
    __u64 init_val = 1, *count;
    count = bpf_map_lookup_elem(&port_count_map, &dest_port);
    if (count) {
      __sync_fetch_and_add(count, 1);
    } else {
      bpf_map_update_elem(&port_count_map, &dest_port, &init_val, BPF_ANY);
    }
  }

  // Let the packet pass
  return ctx->len;
}

char _license[] SEC("license") = "GPL";
