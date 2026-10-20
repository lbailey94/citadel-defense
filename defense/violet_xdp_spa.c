// violet_xdp_spa.c — eBPF / XDP Driver-Level Single-Packet Authorization.
// Drops unauthenticated packets at line speed in nanoseconds before sk_buff allocation.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))

#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __u16 h_proto;
};

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

// BPF Map definition compatible with modern kernel loader
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

// BPF Helpers
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;

// Map storing authorized client IPs and expiry timestamps
struct bpf_map_def SEC("maps") authorized_knocks = {
    .type = 1, // BPF_MAP_TYPE_HASH
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
    .map_flags = 0,
};

// Map for dropping telemetry counters
struct bpf_map_def SEC("maps") drop_stats = {
    .type = 2, // BPF_MAP_TYPE_ARRAY
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
    .map_flags = 0,
};

static inline __u16 bpf_ntohs(__u16 netshort) {
    return (netshort >> 8) | (netshort << 8);
}

SEC("xdp")
int xdp_spa_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Check TCP packets targeting protected services (SSH 22, x402 8787, Wire 7369)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 dst_port = bpf_ntohs(tcp->dest);
        if (dst_port == 22 || dst_port == 8787 || dst_port == 7369) {
            // Check if source IP exists in authorized knocks map
            __u64 *expiry = bpf_map_lookup_elem(&authorized_knocks, &src_ip);
            __u64 now = bpf_ktime_get_ns();

            if (!expiry || *expiry < now) {
                // Drop packet directly at NIC in nanoseconds
                __u32 stat_key = 0; // Index 0: unauthorized_dropped
                __u64 *count = bpf_map_lookup_elem(&drop_stats, &stat_key);
                if (count)
                    __sync_fetch_and_add(count, 1);
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
