// This file defines a simple eBPF socket filter program that:
//   - Increments counters for SSH(22) / HTTPS(443) traffic (port_count_map).
//   - Captures 64 bytes from the first packet of HTTP (port 8080) traffic
//     and stores them in http_snippet_map for user space to retrieve.
//
// Caveats:
//   - Assumes minimal IP/TCP headers (offset 54 for TCP payload).
//   - Only captures 64 bytes from a single packet. No reassembly.
//   - Overwrites the snippet each time we see a new port-8080 packet.

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u16);
	__type(value, __u64);
} port_count_map SEC(".maps");

#define HTTP_MAX_BYTES 64
struct http_snippet {
	__u8 data[HTTP_MAX_BYTES];
	__u32 used; // 1 => valid, 0 => no snippet
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct http_snippet);
} http_snippet_map SEC(".maps");

// Helper to read 16 bits at a given offset
static __always_inline int read_u16(struct __sk_buff *ctx, int offset,
				    __u16 *val)
{
	return bpf_skb_load_bytes(ctx, offset, val, 2);
}

SEC("socket")
int socket_filter_prog(struct __sk_buff *ctx)
{
	// Basic checks: must at least have Ethernet header
	if (ctx->len < sizeof(struct ethhdr)) {
		return 0; // or return ctx->len
	}

	// Check ethertype at offset 12..13 => must be IPv4
	__u16 eth_type;
	if (read_u16(ctx, 12, &eth_type) < 0) {
		return 0;
	}
	eth_type = bpf_ntohs(eth_type);
	if (eth_type != ETH_P_IP) {
		// Not IPv4 => pass
		return ctx->len;
	}

	// We need at least 34 bytes for Eth(14) + IP(20) to check IP protocol
	// offset=23
	if (ctx->len < 34) {
		return ctx->len;
	}

	// IP protocol at offset 23 => must be TCP (0x06)
	__u8 ip_proto;
	if (bpf_skb_load_bytes(ctx, 23, &ip_proto, 1) < 0) {
		return ctx->len;
	}
	if (ip_proto != IPPROTO_TCP) {
		return ctx->len;
	}

	// TCP dest port offset => 36..37
	__u16 dest_port;
	if (bpf_skb_load_bytes(ctx, 36, &dest_port, 2) < 0) {
		return ctx->len;
	}
	dest_port = bpf_ntohs(dest_port);

	// 2) If it's SSH(22) or HTTPS(443), increment counters
	if (dest_port == 22 || dest_port == 443) {
		__u64 init_val = 1, *count;
		count = bpf_map_lookup_elem(&port_count_map, &dest_port);
		if (count) {
			__sync_fetch_and_add(count, 1);
		} else {
			bpf_map_update_elem(&port_count_map, &dest_port,
					    &init_val, BPF_ANY);
		}
	}

	// read TCP source port at offset 34..35
	__u16 src_port;
	if (bpf_skb_load_bytes(ctx, 34, &src_port, 2) < 0) {
		return ctx->len;
	}

	src_port = bpf_ntohs(src_port);

	// 3) If it's HTTP (port 8080), capture HTTP_MAX_BYTES bytes from the TCP payload offset=54
	//    (assuming no IP/TCP options: 14 + 20 + 20 = 54).
	// TODO: Make dest_port dynamic.
	if (dest_port == 8080 || src_port == 8080) {
		// Make sure the packet is at least 54 + HTTP_MAX_BYTES
		if (ctx->len >= 54 + HTTP_MAX_BYTES) {
			// We'll do HTTP_MAX_BYTES single-byte reads so older verifiers are more likely to
			// allow it
			// TODO: Look for interesting keywords in snippet, such as `password`, or `certificate`.
			__u8 snippet[HTTP_MAX_BYTES];
#pragma unroll
			for (int i = 0; i < HTTP_MAX_BYTES; i++) {
				bpf_skb_load_bytes(ctx, 54 + i, &snippet[i], 1);
			}

			// Store snippet in http_snippet_map[0]
			__u32 key = 0;
			struct http_snippet s = {};
#pragma unroll
			for (int i = 0; i < HTTP_MAX_BYTES; i++) {
				s.data[i] = snippet[i];
			}
			s.used = 1; // Mark as valid
			bpf_map_update_elem(&http_snippet_map, &key, &s,
					    BPF_ANY);
		}
	}

	return ctx->len;
}

char _license[] SEC("license") = "Dual BSD/GPL";
