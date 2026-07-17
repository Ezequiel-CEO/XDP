// SPDX-License-Identifier: GPL-2.0
// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 XDP HONEYPOINT FILTER — eBPF Kernel Bypass Program
// ═══════════════════════════════════════════════════════════════════════════════════
//
// Funciona em dois modos (configuráveis via BPF map em runtime):
//
//   HORNET_MODE_STRICT   — drop tudo exceto market data + tráfego essencial
//   HORNET_MODE_PERMISSIVE — pass tudo desconhecido (dev/debug)
//
// Hierarquia de decisão (hottest → coldest):
//   1. UDP + porta de market data → XDP_REDIRECT para AF_XDP socket
//   2. UDP + porta FIX/ITCH      → XDP_REDIRECT para AF_XDP socket
//   3. TCP porta SSH (22)        → XDP_PASS (gerência do servidor)
//   4. TCP porta DNS (53) / NTP  → XDP_PASS
//   5. ICMP                      → XDP_PASS (diagnóstico)
//   6. Tudo mais em STRICT       → XDP_DROP  (DDoS mitigation nativo)
//   7. Tudo mais em PERMISSIVE   → XDP_PASS
//
// BPF Maps:
//   xsks_map       — AF_XDP sockets por queue_id (XSKMAP)
//   config_map     — Configuração runtime (portas, modo)
//   stats_map      — Contadores por-CPU (redirect/pass/drop)
//
// Compilar:
//   clang -O2 -target bpf -D__TARGET_ARCH_x86_64 \
//         -I/usr/include/x86_64-linux-gnu \
//         -c xdp_hornet_filter.c -o xdp_hornet_filter.o
// ═══════════════════════════════════════════════════════════════════════════════════

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ─────────────────────────────────────────────────────────────────────────────
// Configuração runtime (carregada via BPF map pelo user space)
// ─────────────────────────────────────────────────────────────────────────────
struct hornet_config {
    __u16 market_data_port_udp;   // Ex: 4789 (Binance raw feed), 9999 (custom)
    __u16 fix_port_udp;           // Ex: 8888 (FIX over UDP)
    __u16 itch_port_udp;          // Ex: 20305 (NASDAQ ITCH 5.0)
    __u16 management_port_tcp;    // Ex: 22 (SSH)
    __u8  mode;                   // 0=STRICT (drop unknown), 1=PERMISSIVE (pass)
    __u8  enable_ipv6;            // 1 = processar IPv6 também
    __u8  pad[2];
};

// ─────────────────────────────────────────────────────────────────────────────
// Índices do stats_map (per-CPU array)
// ─────────────────────────────────────────────────────────────────────────────
#define STAT_REDIRECTED  0   // Pacotes redirecionados para AF_XDP
#define STAT_PASSED      1   // Pacotes passados para stack Linux
#define STAT_DROPPED     2   // Pacotes descartados (DDoS/lixo)
#define STAT_ERRORS      3   // Pacotes com headers malformados

// ─────────────────────────────────────────────────────────────────────────────
// BPF Maps
// ─────────────────────────────────────────────────────────────────────────────

// AF_XDP socket map: key = queue_id (rx_queue_index), value = xsk fd
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);     // Máx 64 filas de hardware (NIC queues)
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Configuração singleton (index 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hornet_config);
} config_map SEC(".maps");

// Contadores per-CPU: evita false sharing em cores dedicados
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────────
// Helpers inline
// ─────────────────────────────────────────────────────────────────────────────

static __always_inline void stat_inc(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) __sync_fetch_and_add(count, 1);
}

// Verifica se a porta (em network byte order) é de market data
static __always_inline int is_market_data_port(__be16 port, struct hornet_config *cfg) {
    __u16 p = bpf_ntohs(port);
    return (p == cfg->market_data_port_udp ||
            p == cfg->fix_port_udp         ||
            p == cfg->itch_port_udp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: processa pacote UDP e redireciona se for market data
// Retorna XDP_REDIRECT se redirecionado, -1 se não é market data
// ─────────────────────────────────────────────────────────────────────────────
static __always_inline int try_redirect_udp(struct xdp_md *ctx,
                                             void *data,
                                             void *data_end,
                                             void *udp_hdr_start,
                                             struct hornet_config *cfg) {
    struct udphdr *udp = udp_hdr_start;
    if ((void*)(udp + 1) > data_end) {
        stat_inc(STAT_ERRORS);
        return -1;
    }

    // Verifica porta de destino ou origem (market data chega no destino)
    if (!is_market_data_port(udp->dest, cfg) &&
        !is_market_data_port(udp->source, cfg)) {
        return -1;  // Não é market data
    }

    // Redireciona para AF_XDP socket da fila atual
    int ret = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    if (ret == XDP_REDIRECT) {
        stat_inc(STAT_REDIRECTED);
    }
    return ret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: verifica se porta TCP deve ser passada para o kernel
// ─────────────────────────────────────────────────────────────────────────────
static __always_inline int is_essential_tcp(__be16 port) {
    __u16 p = bpf_ntohs(port);
    return (p == 22   ||  // SSH
            p == 53   ||  // DNS (TCP fallback)
            p == 123  ||  // NTP
            p == 443  ||  // HTTPS (management APIs)
            p == 80);     // HTTP (health check endpoints)
}

// ─────────────────────────────────────────────────────────────────────────────
// Programa XDP principal — seção SEC("xdp") para libbpf
// ─────────────────────────────────────────────────────────────────────────────
SEC("xdp")
int xdp_hornet_filter(struct xdp_md *ctx) {
    void *data_end = (void*)(long)ctx->data_end;
    void *data     = (void*)(long)ctx->data;

    // ── Carrega configuração (array map, key=0) ───────────────────────────────
    __u32 cfg_key = 0;
    struct hornet_config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg) {
        // Config não inicializada — pass seguro
        stat_inc(STAT_PASSED);
        return XDP_PASS;
    }

    // ── Parse Ethernet ────────────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) {
        stat_inc(STAT_ERRORS);
        return XDP_DROP;
    }

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // Descarta 802.1Q VLAN tags não suportados neste nível
    // (VLANs são desencapsuladas antes por hardware offload normalmente)
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        stat_inc(STAT_PASSED);
        return XDP_PASS;
    }

    // ── IPv4 ──────────────────────────────────────────────────────────────────
    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = (void*)(eth + 1);
        if ((void*)(iph + 1) > data_end) {
            stat_inc(STAT_ERRORS);
            return XDP_DROP;
        }

        // Rejeita pacotes fragmentados — não são usados em feeds HFT
        if (iph->frag_off & bpf_htons(IP_MF | IP_OFFMASK)) {
            stat_inc(STAT_DROPPED);
            return XDP_DROP;
        }

        void *transport = (void*)iph + (iph->ihl * 4);

        if (iph->protocol == IPPROTO_UDP) {
            int ret = try_redirect_udp(ctx, data, data_end, transport, cfg);
            if (ret >= 0) return ret;

            // UDP desconhecido
            goto handle_unknown;
        }

        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = transport;
            if ((void*)(tcp + 1) > data_end) {
                stat_inc(STAT_ERRORS);
                return XDP_DROP;
            }
            if (is_essential_tcp(tcp->dest) || is_essential_tcp(tcp->source)) {
                stat_inc(STAT_PASSED);
                return XDP_PASS;
            }
            goto handle_unknown;
        }

        if (iph->protocol == IPPROTO_ICMP) {
            // ICMP: diagnóstico de rede — sempre permitir
            stat_inc(STAT_PASSED);
            return XDP_PASS;
        }

        goto handle_unknown;
    }

    // ── IPv6 (se habilitado via config) ───────────────────────────────────────
    if (eth_proto == ETH_P_IPV6 && cfg->enable_ipv6) {
        struct ipv6hdr *ip6h = (void*)(eth + 1);
        if ((void*)(ip6h + 1) > data_end) {
            stat_inc(STAT_ERRORS);
            return XDP_DROP;
        }

        void *transport = (void*)(ip6h + 1);

        if (ip6h->nexthdr == IPPROTO_UDP) {
            int ret = try_redirect_udp(ctx, data, data_end, transport, cfg);
            if (ret >= 0) return ret;
            goto handle_unknown;
        }

        if (ip6h->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = transport;
            if ((void*)(tcp + 1) > data_end) {
                stat_inc(STAT_ERRORS);
                return XDP_DROP;
            }
            if (is_essential_tcp(tcp->dest) || is_essential_tcp(tcp->source)) {
                stat_inc(STAT_PASSED);
                return XDP_PASS;
            }
            goto handle_unknown;
        }

        goto handle_unknown;
    }

    // ARP: necessário para resolução de endereços
    if (eth_proto == ETH_P_ARP) {
        stat_inc(STAT_PASSED);
        return XDP_PASS;
    }

handle_unknown:
    if (cfg->mode == 0) {  // STRICT: drop tudo desconhecido
        stat_inc(STAT_DROPPED);
        return XDP_DROP;
    }
    // PERMISSIVE: pass (útil em desenvolvimento)
    stat_inc(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";