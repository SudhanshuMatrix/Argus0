// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define ARGUS_TCX_NEXT (-1)
#define MATCH4(bytes, text) ((bytes)[0] == (text)[0] && (bytes)[1] == (text)[1] && \
                             (bytes)[2] == (text)[2] && (bytes)[3] == (text)[3])

struct flow_map_def {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key_t);
    __type(value, struct flow_metrics_t);
} flow_template SEC(".maps"); /* Keep the inner key and value in the object BTF. */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct flow_map_def);
} flow_maps SEC(".maps");

struct observation_t {
    __u64 bytes;
    __u64 packets;
};

enum {
    TCP_INGRESS,
    TCP_EGRESS,
    UDP_INGRESS,
    UDP_EGRESS,
    MALFORMED,
    UNSUPPORTED,
    ACCOUNTING_FAILURE,
    OBSERVATION_SLOTS,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, OBSERVATION_SLOTS);
    __type(key, __u32);
    __type(value, struct observation_t);
} observations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} flow_update_failures SEC(".maps");

static __always_inline bool account(__u32 slot, __u64 bytes)
{
    struct observation_t *count = bpf_map_lookup_elem(&observations, &slot);
    if (!count)
        return false;

    __sync_fetch_and_add(&count->bytes, bytes);
    __sync_fetch_and_add(&count->packets, 1);
    return true;
}

static __always_inline int skip(__u32 reason)
{
    account(reason, 0);
    return ARGUS_TCX_NEXT;
}

static __always_inline void record_detail_failure(void)
{
    __u32 zero = 0;
    __u64 *failures = bpf_map_lookup_elem(&flow_update_failures, &zero);
    if (failures)
        __sync_fetch_and_add(failures, 1);
}

static __always_inline __u8 detect_l7(struct __sk_buff *skb, const struct flow_key_t *key,
                                      __u32 offset, __u32 length)
{
    __u8 prefix[4];
    if (length < sizeof(prefix) ||
        bpf_skb_load_bytes(skb, offset, prefix, sizeof(prefix)) < 0)
        return L7_UNKNOWN;

    if (key->protocol == PROTO_TCP) {
        if (MATCH4(prefix, "GET ") ||
            MATCH4(prefix, "PUT "))
            return L7_HTTP;
        if (MATCH4(prefix, "POST") ||
            MATCH4(prefix, "HEAD") ||
            MATCH4(prefix, "HTTP")) {
            __u8 next;
            if (length >= 5 && bpf_skb_load_bytes(skb, offset + 4, &next, 1) == 0 &&
                next == (prefix[1] == 'T' ? '/' : ' '))
                return L7_HTTP;
        }
        if (MATCH4(prefix, "DELE")) {
            __u8 suffix[3];
            if (length >= 7 && bpf_skb_load_bytes(skb, offset + 4, suffix, sizeof(suffix)) == 0 &&
                (suffix[0] == 'T' && suffix[1] == 'E' && suffix[2] == ' '))
                return L7_HTTP;
        }
        if (MATCH4(prefix, "SSH-"))
            return L7_SSH;
        if (prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] <= 0x03 && length >= 5) {
            __u8 size_lo;
            if (bpf_skb_load_bytes(skb, offset + 4, &size_lo, 1) == 0) {
                __u16 size = ((__u16)prefix[3] << 8) | size_lo;
                if (size >= 4 && size <= 16384)
                    return L7_TLS;
            }
        }
    }

    /* DNS needs port context and a plausible standard DNS header. */
    if (key->src_port != bpf_htons(53) && key->dst_port != bpf_htons(53))
        return L7_UNKNOWN;
    if (key->protocol == PROTO_TCP) {
        __u32 message_length = ((__u16)prefix[0] << 8) | prefix[1];
        if (message_length < 12 || message_length > length - 2)
            return L7_UNKNOWN;
        offset += 2;
        length = message_length;
    }

    __u8 dns[12];
    if (length < sizeof(dns) ||
        bpf_skb_load_bytes(skb, offset, dns, sizeof(dns)) < 0)
        return L7_UNKNOWN;
    __u16 questions = ((__u16)dns[4] << 8) | dns[5];
    if (!(dns[2] & 0x78) && !(dns[3] & 0x40) && questions > 0 &&
        questions <= (length - sizeof(dns)) / 5)
        return L7_DNS;

    return L7_UNKNOWN;
}

static __always_inline void update_flow(struct __sk_buff *skb, struct flow_key_t *key,
                                        __u32 payload, __u32 length, bool ingress)
{
    __u32 zero = 0;
    void *active = bpf_map_lookup_elem(&flow_maps, &zero);
    if (!active) {
        record_detail_failure();
        return;
    }

    struct flow_metrics_t *metrics = bpf_map_lookup_elem(active, key);
    __u64 now = bpf_ktime_get_ns();
    if (!metrics) {
        struct flow_metrics_t initial = {
            .first_seen_ns = now,
            .last_seen_ns = now,
            .l7_proto = detect_l7(skb, key, payload, length),
        };
        if (ingress) {
            initial.bytes_ingress = skb->len;
            initial.pkts_ingress = 1;
        } else {
            initial.bytes_egress = skb->len;
            initial.pkts_egress = 1;
        }

        if (bpf_map_update_elem(active, key, &initial, BPF_NOEXIST) == 0)
            return;

        /* Another CPU may have inserted the flow first. Preserve its counts. */
        metrics = bpf_map_lookup_elem(active, key);
        if (!metrics) {
            record_detail_failure();
            return;
        }
    }

    if (ingress) {
        __sync_fetch_and_add(&metrics->bytes_ingress, skb->len);
        __sync_fetch_and_add(&metrics->pkts_ingress, 1);
    } else {
        __sync_fetch_and_add(&metrics->bytes_egress, skb->len);
        __sync_fetch_and_add(&metrics->pkts_egress, 1);
    }
    if (metrics->l7_proto == L7_UNKNOWN) {
        __u8 detected = detect_l7(skb, key, payload, length);
        if (detected != L7_UNKNOWN)
            __sync_val_compare_and_swap(&metrics->l7_proto, L7_UNKNOWN, detected);
    }

    /* Concurrent updates may win, but last seen never moves backwards. */
    __u64 seen = metrics->last_seen_ns;
#pragma unroll
    for (int attempt = 0; attempt < 4 && now > seen; attempt++) {
        __u64 previous = __sync_val_compare_and_swap(&metrics->last_seen_ns, seen, now);
        if (previous == seen)
            break;
        seen = previous;
    }
}

static __always_inline int observe(struct __sk_buff *skb, bool ingress)
{
    const __u32 ethernet_length = sizeof(struct ethhdr);
    struct ethhdr eth;
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return skip(MALFORMED);
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return skip(UNSUPPORTED);
    if (bpf_skb_load_bytes(skb, ethernet_length, &ip, sizeof(ip)) < 0)
        return skip(MALFORMED);

    __u8 version_ihl = *(const __u8 *)&ip;
    __u32 ip_header_length = (version_ihl & 0x0f) * 4;
    __u32 ip_length = bpf_ntohs(ip.tot_len);
    if (version_ihl >> 4 != 4 || ip_header_length < sizeof(ip) ||
        ip_length < ip_header_length || ethernet_length + ip_length > skb->len)
        return skip(MALFORMED);
    if (ip.frag_off & bpf_htons(0x3fff))
        return skip(UNSUPPORTED);

    __u32 l4_offset = ethernet_length + ip_header_length;
    __u32 l4_length = ip_length - ip_header_length;
    __u32 header_length;
    struct flow_key_t key = {
        .src_ip = ip.saddr,
        .dst_ip = ip.daddr,
        .protocol = ip.protocol,
    };
    if (ip.protocol == PROTO_TCP) {
        struct tcphdr tcp;
        if (l4_length < sizeof(tcp) ||
            bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
            return skip(MALFORMED);
        header_length = (((const __u8 *)&tcp)[12] >> 4) * 4;
        if (header_length < sizeof(tcp) || header_length > l4_length)
            return skip(MALFORMED);
        key.src_port = tcp.source;
        key.dst_port = tcp.dest;
    } else if (ip.protocol == PROTO_UDP) {
        struct udphdr udp;
        if (l4_length < sizeof(udp) ||
            bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
            return skip(MALFORMED);
        __u32 udp_length = bpf_ntohs(udp.len);
        if (udp_length < sizeof(udp) || udp_length > l4_length)
            return skip(MALFORMED);
        l4_length = udp_length;
        header_length = sizeof(udp);
        key.src_port = udp.source;
        key.dst_port = udp.dest;
    } else {
        return skip(UNSUPPORTED);
    }

    __u32 slot = ip.protocol == PROTO_TCP ? TCP_INGRESS : UDP_INGRESS;
    if (!account(slot + !ingress, skb->len))
        account(ACCOUNTING_FAILURE, 0);
    update_flow(skb, &key, l4_offset + header_length, l4_length - header_length, ingress);
    return ARGUS_TCX_NEXT;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return observe(skb, true);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return observe(skb, false);
}

char LICENSE[] SEC("license") = "GPL";
