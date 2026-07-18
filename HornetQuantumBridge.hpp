#pragma once
#ifndef HORNET_QUANTUM_BRIDGE_HPP
#define HORNET_QUANTUM_BRIDGE_HPP

// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 HORNET QUANTUM BRIDGE — XDP Frame → SOA Ring Hot Path
// ═══════════════════════════════════════════════════════════════════════════════════
//
// MISSÃO: Converter frames UDP brutos (UMEM) em ticks estruturados no SOA Ring.
//         É o último ponto de parsing antes do SIMD engine — zero heap, zero mutex.
//
// FLUXO COMPLETO DO HOT PATH:
//
//   NIC DMA → UMEM frame → [HornetPoint Rx Ring]
//                                   ↓
//              HornetQuantumBridge::ingest(umem, frame_info)
//                    ↓               ↓
//             parse_headers()   parse_market_payload()
//             (Eth+IP+UDP, ~10ns)   (protocolo binário, ~15ns)
//                                   ↓
//                         HornetSoaRing::push_raw()  ← ~5ns (SPSC, sem CAS)
//                                   ↓
//                          SIMD Indicator Engine
//                          (AVX-512, ~50ns por batch)
//
// PARSING DE PROTOCOLO:
//   O bridge suporta dois formatos de payload de market data:
//   1. HornetBinaryTick (formato proprietário, 40 bytes) — máxima velocidade
//   2. Detecção automática via magic bytes — extensível para ITCH, OUCH, etc.
//
//   Em produção real: o feed da exchange envia seu próprio protocolo binário.
//   O HornetBinaryTick é o formato que usamos quando controlamos o feed server.
//
// DESIGN ZERO-COPY:
//   O frame UMEM é lido uma única vez para extrair os campos.
//   Os campos vão direto para os arrays SOA (writes sequenciais = store-forwarding eficiente).
//   Após ingest(), o frame é devolvido ao pool pelo HornetPoint.
//   Não há cópia intermediária, não há allocação.
//
// DETECÇÃO DE GAPS (sequence_num):
//   Se sequence_num atual ≠ last_sequence + 1 → gap detectado.
//   Gap counter incrementado. Risk manager pode tomar ação.
//   Sem retransmissão no hot path — gaps são aceitáveis em market data UDP.
// ═══════════════════════════════════════════════════════════════════════════════════

#include "AfXdpHornetPoint.hpp"   // RxFrameInfo, RxCallback
#include "HornetSoaRing.hpp"      // DefaultSoaRing, MarketTickView
#include "umem_numa_allocator.hpp" // UmemNuma

#include <atomic>
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <netinet/in.h>   // ntohs, ntohl
#include <arpa/inet.h>

// Estruturas de header de rede (sem dependência de linux/ip.h aqui)
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// HornetBinaryTick V1 — formato legado de 40 bytes (preço ×1e6/uint32)
//
// Enviado pelo nosso feed server (ou gate de normalização de exchange).
// Magic bytes permitem identificação rápida antes do parsing completo.
//
// Layout (network byte order para campos numéricos):
//   [0..1]   magic: 0xC3BE (CerBerus tick magic)
//   [2..3]   asset_id: ID comprimido do ativo
//   [4..7]   sequence_num: número de sequência (detecção de gap)
//   [8..15]  timestamp_ns: nanosegundos Unix
//   [16..19] price_open:  × 1e-6
//   [20..23] price_high:  × 1e-6
//   [24..27] price_low:   × 1e-6
//   [28..31] price_close: × 1e-6
//   [32..39] volume:      × 1e-8
// ─────────────────────────────────────────────────────────────────────────────
struct __attribute__((packed)) HornetBinaryTick {
    uint16_t magic;          // 0xC3BE
    uint16_t asset_id;
    uint32_t sequence_num;
    uint64_t timestamp_ns;
    uint32_t price_open;
    uint32_t price_high;
    uint32_t price_low;
    uint32_t price_close;
    uint64_t volume;
};
static_assert(sizeof(HornetBinaryTick) == 40, "HornetBinaryTick deve ter 40 bytes");

// V2 removes the V1 price ceiling and preserves native exchange sequence IDs.
// All numeric fields are network byte order; decimal fields use exact ×1e8.
struct __attribute__((packed)) HornetBinaryTickV2 {
    uint16_t magic;          // 0xC3BF
    uint16_t asset_id;
    uint64_t sequence_num;
    uint64_t timestamp_ns;
    uint64_t price_open;
    uint64_t price_high;
    uint64_t price_low;
    uint64_t price_close;
    uint64_t volume;
};
static_assert(sizeof(HornetBinaryTickV2) == 60,
              "HornetBinaryTickV2 deve ter 60 bytes");

inline constexpr uint16_t HORNET_TICK_MAGIC_V1 = 0xC3BE;
inline constexpr uint16_t HORNET_TICK_MAGIC_V2 = 0xC3BF;
inline constexpr uint16_t HORNET_TICK_MAGIC    = HORNET_TICK_MAGIC_V1;
inline constexpr size_t   MIN_PAYLOAD_SIZE     = sizeof(HornetBinaryTick);
inline constexpr size_t   ETH_IP_UDP_HDRLEN    = sizeof(ether_header)    // 14
                                               + sizeof(struct iphdr)     // 20 (min, sem options)
                                               + sizeof(struct udphdr);   // 8

// ─────────────────────────────────────────────────────────────────────────────
// BridgeStats — estatísticas do bridge (lock-free, por instância)
// ─────────────────────────────────────────────────────────────────────────────
struct alignas(64) BridgeStats {
    std::atomic<uint64_t> frames_ingested{0};    // Total de frames processados
    std::atomic<uint64_t> ticks_pushed{0};        // Ticks escritos no SOA ring
    std::atomic<uint64_t> ticks_dropped_ring{0};  // Ring cheio (backpressure)
    std::atomic<uint64_t> frames_invalid{0};      // Frame malformado (header inválido)
    std::atomic<uint64_t> frames_unknown_proto{0};// Protocolo não reconhecido
    std::atomic<uint64_t> sequence_gaps{0};       // Gaps de sequência detectados
    std::atomic<uint64_t> bytes_processed{0};     // Bytes totais de payload
};

// ─────────────────────────────────────────────────────────────────────────────
// HornetQuantumBridge — Converte frames XDP em ticks no SOA Ring
//
// Design: stateless por default, estado mínimo apenas para gap detection.
// Thread-safety: designed para 1 thread (o poll loop do HornetPoint).
//                SOA ring push é SPSC — produz apenas aqui.
// ─────────────────────────────────────────────────────────────────────────────
class HornetQuantumBridge {
public:
    // ── Construção ────────────────────────────────────────────────────────────
    // soa_ring: o ring SOA onde ticks são depositados (o consumer é o SIMD engine)
    explicit HornetQuantumBridge(DefaultSoaRing& soa_ring) noexcept
        : soa_ring_(soa_ring) {}

    // Usa o ring global padrão
    HornetQuantumBridge() noexcept
        : soa_ring_(global_soa_ring()) {}

    // ── Callback compatível com AfXdpHornetPoint::set_rx_callback() ───────────
    // Retorna uma função lambda capturando this — usada diretamente como RxCallback.
    [[nodiscard]] RxCallback as_rx_callback() noexcept {
        return [this](UmemNuma& umem, const RxFrameInfo& frame) -> bool {
            return this->ingest<UmemNuma>(umem, frame);
        };
    }

    // ── Ponto de entrada principal: ingest() ──────────────────────────────────
    // Chamado pelo HornetPoint para cada frame recebido.
    // Retorna true se o frame foi consumido (parsado e pushado ao ring).
    // Retorna false se descartado (frame inválido, protocolo desconhecido, ring cheio).
    template<typename UmemT>
    [[nodiscard]] bool ingest(UmemT& umem, const RxFrameInfo& frame) noexcept {
        stats_.frames_ingested.fetch_add(1, std::memory_order_relaxed);

        // Validate every length before deriving a pointer from untrusted bytes.
        constexpr size_t min_headers = sizeof(ether_header) +
                                       sizeof(struct iphdr) +
                                       sizeof(struct udphdr);
        if (__builtin_expect(frame.options != 0 || frame.len < min_headers ||
                             frame.len > UMEM_FRAME_SIZE, 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if constexpr (requires {
            umem.valid_frame_range(frame.umem_offset,
                                   static_cast<size_t>(frame.len));
        }) {
            if (__builtin_expect(
                    !umem.valid_frame_range(
                        frame.umem_offset, static_cast<size_t>(frame.len)), 0)) {
                stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        }

        // Ponteiro para início do frame no UMEM
        const uint8_t* raw = static_cast<const uint8_t*>(
            umem.frame_ptr(frame.umem_offset));
        if (__builtin_expect(raw == nullptr, 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // ── Parse Ethernet header ─────────────────────────────────────────────
        ether_header eth{};
        std::memcpy(&eth, raw, sizeof(eth));
        const uint16_t eth_proto = ntohs(eth.ether_type);

        // Apenas IPv4 no hot path (IPv6 é tratado como unknown)
        if (__builtin_expect(eth_proto != ETHERTYPE_IP, 0)) {
            stats_.frames_unknown_proto.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // ── Parse IPv4 header ─────────────────────────────────────────────────
        struct iphdr iph{};
        std::memcpy(&iph, raw + sizeof(ether_header), sizeof(iph));

        if (__builtin_expect(iph.version != 4 || iph.protocol != IPPROTO_UDP, 0)) {
            stats_.frames_unknown_proto.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        const size_t ip_hdr_len = static_cast<size_t>(iph.ihl) * 4;
        const size_t bytes_after_eth = frame.len - sizeof(ether_header);
        if (__builtin_expect(iph.ihl < 5 || ip_hdr_len > bytes_after_eth ||
                             bytes_after_eth - ip_hdr_len < sizeof(struct udphdr), 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        const size_t ip_total_len = ntohs(iph.tot_len);
        const uint16_t fragment = ntohs(iph.frag_off);
        if (__builtin_expect(ip_total_len < ip_hdr_len + sizeof(struct udphdr) ||
                             ip_total_len > bytes_after_eth ||
                             (fragment & 0x3FFFu) != 0, 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // ── Parse UDP header ──────────────────────────────────────────────────
        struct udphdr udp{};
        std::memcpy(&udp, raw + sizeof(ether_header) + ip_hdr_len, sizeof(udp));

        const size_t udp_len = ntohs(udp.len);
        if (__builtin_expect(udp_len < sizeof(struct udphdr) ||
                             udp_len != ip_total_len - ip_hdr_len ||
                             sizeof(ether_header) + ip_hdr_len + udp_len > frame.len, 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Payload começa após UDP header
        const uint8_t* payload = raw + sizeof(ether_header) + ip_hdr_len +
                                 sizeof(struct udphdr);
        const size_t payload_len = udp_len - sizeof(struct udphdr);

        if (__builtin_expect(payload_len < MIN_PAYLOAD_SIZE, 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        stats_.bytes_processed.fetch_add(payload_len, std::memory_order_relaxed);

        // ── Identifica protocolo via magic bytes ──────────────────────────────
        uint16_t magic;
        std::memcpy(&magic, payload, sizeof(magic));
        magic = ntohs(magic);

        if (__builtin_expect(magic == HORNET_TICK_MAGIC_V2, 1)) {
            return parse_hornet_tick_v2(payload, payload_len, ntohs(udp.dest));
        }
        if (magic == HORNET_TICK_MAGIC_V1) {
            return parse_hornet_tick_v1(payload, payload_len, ntohs(udp.dest));
        }

        // Protocolo desconhecido — extensível aqui (ITCH 5.0, OUCH, MDP 3.0, etc.)
        stats_.frames_unknown_proto.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // ── Estatísticas ──────────────────────────────────────────────────────────
    [[nodiscard]] const BridgeStats& stats() const noexcept { return stats_; }

    void print_stats() const noexcept {
        std::printf("[BRIDGE] Ingested=%llu Pushed=%llu "
                    "Dropped(ring)=%llu Invalid=%llu Gaps=%llu\n",
                    (unsigned long long)stats_.frames_ingested.load(),
                    (unsigned long long)stats_.ticks_pushed.load(),
                    (unsigned long long)stats_.ticks_dropped_ring.load(),
                    (unsigned long long)stats_.frames_invalid.load(),
                    (unsigned long long)stats_.sequence_gaps.load());
    }

private:
    // ── Parser: HornetBinaryTick (formato proprietário 40 bytes) ─────────────
    [[nodiscard]] bool parse_hornet_tick_v1(const uint8_t* payload,
                                             size_t payload_len,
                                             uint16_t dest_port) noexcept {
        if (payload_len != sizeof(HornetBinaryTick)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // Load direto do payload — unaligned read (packed struct)
        HornetBinaryTick tick;
        std::memcpy(&tick, payload, sizeof(tick));

        // Converte de network byte order para host byte order
        const uint16_t asset_id     = ntohs(tick.asset_id);
        const uint32_t seq_num      = ntohl(tick.sequence_num);
        const uint64_t ts_ns        = be64toh(tick.timestamp_ns);
        // Exact scale conversion: V1 ×1e6 -> canonical ×1e8.
        const uint64_t price_open   = static_cast<uint64_t>(ntohl(tick.price_open)) * 100ULL;
        const uint64_t price_high   = static_cast<uint64_t>(ntohl(tick.price_high)) * 100ULL;
        const uint64_t price_low    = static_cast<uint64_t>(ntohl(tick.price_low)) * 100ULL;
        const uint64_t price_close  = static_cast<uint64_t>(ntohl(tick.price_close)) * 100ULL;
        const uint64_t volume       = be64toh(tick.volume);

        return publish_tick(asset_id, seq_num, ts_ns, price_open, price_high,
                            price_low, price_close, volume, dest_port);
    }

    [[nodiscard]] bool parse_hornet_tick_v2(const uint8_t* payload,
                                             size_t payload_len,
                                             uint16_t dest_port) noexcept {
        if (payload_len != sizeof(HornetBinaryTickV2)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        HornetBinaryTickV2 tick{};
        std::memcpy(&tick, payload, sizeof(tick));

        return publish_tick(
            ntohs(tick.asset_id), be64toh(tick.sequence_num),
            be64toh(tick.timestamp_ns), be64toh(tick.price_open),
            be64toh(tick.price_high), be64toh(tick.price_low),
            be64toh(tick.price_close), be64toh(tick.volume), dest_port);
    }

    [[nodiscard]] bool publish_tick(uint16_t asset_id, uint64_t seq_num,
                                    uint64_t ts_ns, uint64_t price_open,
                                    uint64_t price_high, uint64_t price_low,
                                    uint64_t price_close, uint64_t volume,
                                    uint16_t dest_port) noexcept {
        if (__builtin_expect(asset_id > 0xFFu || seq_num == 0 || ts_ns == 0 ||
                             price_open == 0 || price_high == 0 || price_low == 0 ||
                             price_close == 0 ||
                             price_high < price_open || price_high < price_close ||
                             price_low > price_open || price_low > price_close, 0)) {
            stats_.frames_invalid.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        // ── Detecção de gap de sequência ──────────────────────────────────────
        const uint64_t last_seq = last_sequence_[asset_id & 0xFF];
        if (__builtin_expect(last_seq != 0 && seq_num != last_seq + 1, 0)) {
            stats_.sequence_gaps.fetch_add(1, std::memory_order_relaxed);
            // Não retorna false — o tick é válido mesmo com gap
        }
        last_sequence_[asset_id & 0xFF] = seq_num;

        // ── Push direto para o SOA Ring ───────────────────────────────────────
        const bool ok = soa_ring_.push_raw(
            ts_ns,
            price_open, price_high, price_low, price_close,
            volume,
            static_cast<uint32_t>(asset_id),
            seq_num,
            dest_port,     // exchange_id codificado como porta de destino
            0              // flags: nenhum por default
        );

        if (__builtin_expect(!ok, 0)) {
            stats_.ticks_dropped_ring.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        stats_.ticks_pushed.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Estado mínimo: último sequence por asset (256 assets, ring por asset_id & 0xFF)
    // Stack-allocated, zero heap.
    // 256 × 8 bytes = 2KB — cabe em L1
    // ─────────────────────────────────────────────────────────────────────────
    DefaultSoaRing&           soa_ring_;
    alignas(64) uint64_t      last_sequence_[256]{};  // Zero-initialized
    BridgeStats               stats_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Fábrica: cria e conecta HornetPoint + Bridge + SOA Ring em uma chamada
// ─────────────────────────────────────────────────────────────────────────────
struct HornetSystem {
    UmemNuma           umem;
    AfXdpHornetPoint   hornet;
    HornetQuantumBridge bridge;
    DefaultSoaRing&    soa_ring;

    explicit HornetSystem(DefaultSoaRing& ring) noexcept
        : bridge(ring), soa_ring(ring) {}

    // Inicializa todo o sistema
    [[nodiscard]] bool initialize(
            const std::string& iface,
            uint32_t           queue_id,
            const std::string& bpf_obj_path,
            XdpMode            mode       = XdpMode::ZERO_COPY,
            bool               busy_poll  = true,
            FilterMode         filter     = FilterMode::STRICT) noexcept {

        if (!umem.initialize()) return false;
        if (!hornet.initialize(iface, queue_id, umem, mode, busy_poll)) {
            umem.shutdown();
            return false;
        }
        if (!bpf_obj_path.empty()) {
            if (!hornet.load_bpf_program(bpf_obj_path, filter)) {
                hornet.shutdown();
                umem.shutdown();
                return false;
            }
        }
        hornet.set_rx_callback(bridge.as_rx_callback());
        return true;
    }

    void shutdown() noexcept {
        hornet.shutdown();
        umem.shutdown();
    }
};

} // namespace hornet

#endif // HORNET_QUANTUM_BRIDGE_HPP
