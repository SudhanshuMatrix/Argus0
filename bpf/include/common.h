/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h - Shared data structures between the eBPF kernel program and the
 *            Go userspace agent. Both sides must agree on the exact memory
 *            layout of these structs; any change here requires recompilation
 *            of both the C program and the Go bpf2go-generated bindings.
 *
 * NOTE: Padding bytes are added explicitly so the Go side (via unsafe.Sizeof)
 * sees exactly the same layout the kernel does. Always use __u8/__u16/__u32/
 * __u64 (from <linux/types.h> / vmlinux.h) rather than plain C int/long to
 * guarantee fixed widths across architectures.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"

/* -------------------------------------------------------------------------
 * flow_key_t
 *
 * The 5-tuple that uniquely identifies a network flow. Used as the key in
 * the BPF_MAP_TYPE_HASH "flow_map". The kernel and Go both hash on this
 * struct, so every field (including padding!) must be deterministic.
 *
 * Layout (20 bytes total, no compiler-inserted padding):
 *   src_ip    [0..3]   - IPv4 source address in network byte order
 *   dst_ip    [4..7]   - IPv4 destination address in network byte order
 *   src_port  [8..9]   - L4 source port in network byte order
 *   dst_port  [10..11] - L4 destination port in network byte order
 *   protocol  [12]     - IP protocol number (IPPROTO_TCP=6, IPPROTO_UDP=17)
 *   pad       [13..19] - Explicit zero padding so the struct is 8-byte
 *                        aligned and memcmp()-safe for BPF map keys.
 * -------------------------------------------------------------------------*/
struct flow_key_t {
    __u32 src_ip;      /* Source IPv4 address (network byte order)          */
    __u32 dst_ip;      /* Destination IPv4 address (network byte order)     */
    __u16 src_port;    /* Source port (network byte order)                  */
    __u16 dst_port;    /* Destination port (network byte order)             */
    __u8  protocol;    /* IP protocol: IPPROTO_TCP (6) / IPPROTO_UDP (17)  */
    __u8  pad[3];      /* Explicit padding — always zero-init on write      */
};

/* -------------------------------------------------------------------------
 * flow_metrics_t
 *
 * Per-flow counters and metadata stored as the value in "flow_map".
 * Updated atomically inside the eBPF program via __sync_fetch_and_add.
 *
 * Layout (32 bytes):
 *   bytes_ingress  [0..7]   - Total ingress bytes for this flow
 *   bytes_egress   [8..15]  - Total egress bytes for this flow
 *   pkts_ingress   [16..19] - Ingress packet count
 *   pkts_egress    [20..23] - Egress packet count
 *   pid            [24..27] - PID of the last process that touched this flow
 *                             (captured via bpf_get_current_pid_tgid)
 *   last_seen_ns   [28..35] - ktime_get_ns() timestamp of last packet
 * -------------------------------------------------------------------------*/
struct flow_metrics_t {
    __u64 bytes_ingress;  /* Running ingress byte counter                   */
    __u64 bytes_egress;   /* Running egress byte counter                    */
    __u32 pkts_ingress;   /* Ingress packet counter                         */
    __u32 pkts_egress;    /* Egress packet counter                          */
    __u32 pid;            /* PID of last process; 0 if not in process ctx   */
    __u8  l7_proto;       /* L7 protocol: HTTP, TLS, DNS, SSH, etc.         */
    __u8  last_dir;       /* Direction of the last seen packet (0=in, 1=out)*/
    __u8  _pad[2];        /* Align 64-bit fields to 8 bytes                 */
    __u64 first_seen_ns;  /* ktime nanoseconds of first packet in flow      */
    __u64 last_seen_ns;   /* ktime nanoseconds of most-recent packet        */
    __u64 latency_ns;     /* Transaction latency (RTT) in nanoseconds       */
};

/* -------------------------------------------------------------------------
 * Direction flags — stored in the TC classifier return codes and used by
 * userspace to interpret ingress vs egress counters.
 * -------------------------------------------------------------------------*/
#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS  1

/* -------------------------------------------------------------------------
 * Protocol shortcuts — matches IANA numbers, defined here so both the C
 * program and Go code can import a single source of truth.
 * -------------------------------------------------------------------------*/
#define PROTO_TCP  6
#define PROTO_UDP  17
#define PROTO_ICMP 1

/* -------------------------------------------------------------------------
 * L7 Protocols
 * ------------------------------------------------------------------------- */
#define L7_UNKNOWN 0
#define L7_HTTP    1
#define L7_TLS     2
#define L7_DNS     3
#define L7_SSH     4

#endif /* __COMMON_H__ */
