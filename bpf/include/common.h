/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARGUS_COMMON_H
#define ARGUS_COMMON_H

#include "vmlinux.h"

/* Directional IPv4 5-tuple. Addresses and ports use network byte order. */
struct flow_key_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

struct flow_metrics_t {
    __u64 bytes_ingress;
    __u64 bytes_egress;
    __u64 pkts_ingress;
    __u64 pkts_egress;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u32 l7_proto;
    __u32 pad;
};

#define PROTO_TCP 6
#define PROTO_UDP 17

#define L7_UNKNOWN 0
#define L7_HTTP    1
#define L7_TLS     2
#define L7_DNS     3
#define L7_SSH     4

#endif
