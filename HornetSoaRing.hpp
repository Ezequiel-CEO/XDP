#pragma once
#ifndef HORNET_SOA_RING_HPP
#define HORNET_SOA_RING_HPP

// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 HORNET SOA RING — Phase 3A Hot Path Core
// ═══════════════════════════════════════════════════════════════════════════════════
//
// FILOSOFIA: Structure of Arrays (SOA) vs Array of Structures (AOS)
//
//   AOS (ruim para SIMD):
//     [{ts, open, high, low, close, vol}, {ts, open, high, low, close, vol}, ...]
//     → SIMD precisa de scatter/gather (lento, 1/4 da largura de banda)
//
//   SOA (ideal para SIMD):
//     timestamps_ns[0..N], prices_open[0..N], prices_high[0..N], ...
//     → SIMD carrega 8 preços por instrução AVX-512 (FP32) ou 4 (FP64)
//     → Prefetch de um array não polui cache dos outros
//     → Perfect for vectorized indicator computation
//
// LAYOUT DE MEMÓRIA:
//   Cada array é alignas(64) — começa em cache line boundary
//   Capacity = 64K slots = 65536 ticks
//   Tamanho total ≈ 65536 × (8+4+4+4+4+8+4+4+2+1+1) bytes ≈ 2.6MB
//   Cabe confortavelmente em LLC (8-32MB em CPUs modernas)
//
// SPSC LOCK-FREE:
//   Producer (HornetQuantumBridge): avança head após escrever todos os campos
//   Consumer (SIMD Engine):         avança tail após processar o slot
//   Sem CAS, sem mutex — apenas atomic load/store com barreiras mínimas
//
// PRESSÃO (backpressure):
//   Se ring cheio: producer descarta tick (market data → estatística de overflow)
//   Nunca bloqueia o caminho de recebimento de pacotes (XDP não pode bloquear)
// ═══════════════════════════════════════════════════════════════════════════════════

#include "hornet_config.hpp"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <immintrin.h>  // _mm_pause, _mm_sfence

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// MarketTickSoa — um slot completo em formato de "view" sobre os arrays SOA
// Usado pelo consumer para acessar um tick sem copiar os dados
// ─────────────────────────────────────────────────────────────────────────────
struct MarketTickView {
    uint64_t timestamp_ns;   // TSC ou exchange timestamp (nanosegundos)
    uint32_t price_open;     // Scaled × 1e-6 (int → elimina ponto flutuante no hot path)
    uint32_t price_high;
    uint32_t price_low;
    uint32_t price_close;
    uint64_t volume;         // Volume em unidades base (scaled × 1e-8 para crypto)
    uint32_t asset_id;       // ID do ativo (hash comprimido do símbolo)
    uint32_t sequence_num;   // Número de sequência do feed (para detecção de gaps)
    uint16_t exchange_id;    // FeedSource enum comprimido
    uint8_t  flags;          // Bitmask: bit0=bid_ask_imbalance, bit1=large_print, etc.
    uint8_t  _pad;

    // Conversores inline (sem overhead — eliminados pelo compilador)
    [[nodiscard]] inline double open()   const noexcept { return price_open   * 1e-6; }
    [[nodiscard]] inline double high()   const noexcept { return price_high   * 1e-6; }
    [[nodiscard]] inline double low()    const noexcept { return price_low    * 1e-6; }
    [[nodiscard]] inline double close()  const noexcept { return price_close  * 1e-6; }
    [[nodiscard]] inline double vol()    const noexcept { return volume       * 1e-8; }
    [[nodiscard]] inline bool is_bullish() const noexcept { return price_close > price_open; }
    [[nodiscard]] inline bool is_bearish() const noexcept { return price_close < price_open; }
    [[nodiscard]] inline uint32_t body() const noexcept {
        return (price_close > price_open)
               ? price_close - price_open
               : price_open  - price_close;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// HornetSoaRing<N> — SPSC lock-free ring em formato SOA
//
// Template param N: deve ser potência de 2.
// Default: SOA_RING_CAPACITY = 65536
// ─────────────────────────────────────────────────────────────────────────────
template<size_t N = SOA_RING_CAPACITY>
class HornetSoaRing {
    static_assert(N > 0 && (N & (N - 1)) == 0,
                  "HornetSoaRing: N deve ser potência de 2");
    static constexpr size_t MASK = N - 1;

public:
    // ── SOA Arrays — cada array alinhado em cache line boundary ──────────────
    // Ordem: campos acessados mais frequentemente primeiro
    // (SIMD engine processa prices em batch → ficam em L1/L2)
    alignas(64) uint64_t timestamps_ns [N];   // 64 × 64K = 512KB
    alignas(64) uint32_t prices_close  [N];   // 32 × 64K = 256KB — mais acessado
    alignas(64) uint32_t prices_open   [N];   // 256KB
    alignas(64) uint32_t prices_high   [N];   // 256KB
    alignas(64) uint32_t prices_low    [N];   // 256KB
    alignas(64) uint64_t volumes       [N];   // 512KB
    alignas(64) uint32_t asset_ids     [N];   // 256KB
    alignas(64) uint32_t sequence_nums [N];   // 256KB
    alignas(64) uint16_t exchange_ids  [N];   // 128KB
    alignas(64) uint8_t  flags_arr     [N];   // 64KB
    alignas(64) uint8_t  _pad_arr      [N];   // Alinhamento

    // ── SPSC Control (em cache lines separadas — evita false sharing) ─────────
    alignas(64) std::atomic<uint64_t> head_{0};       // Producer escreve aqui
    alignas(64) uint64_t              head_cache_{0};  // Cache local do producer
    alignas(64) std::atomic<uint64_t> tail_{0};       // Consumer lê daqui
    alignas(64) uint64_t              tail_cache_{0};  // Cache local do consumer

    // ── Estatísticas (relaxed, sem impacto na hot path) ───────────────────────
    alignas(64) std::atomic<uint64_t> stat_produced_{0};
    alignas(64) std::atomic<uint64_t> stat_consumed_{0};
    alignas(64) std::atomic<uint64_t> stat_dropped_{0};  // Ring cheio

    // ── Producer API ──────────────────────────────────────────────────────────
    // Escreve um tick no ring. Retorna true em sucesso, false se cheio.
    // Thread-safe para 1 producer apenas (SPSC).
    // NUNCA bloqueia — drop silencioso com contador de overflow.
    [[nodiscard]] inline bool push(const MarketTickView& tick) noexcept {
        const uint64_t h = head_cache_;
        const uint64_t t = tail_.load(std::memory_order_acquire);

        if (__builtin_expect(h - t >= N, 0)) {
            // Ring cheio — descarta tick, conta overflow
            stat_dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        const size_t idx = h & MASK;

        // Escreve todos os campos SOA (compilador usa stores sequenciais — ideal)
        timestamps_ns [idx] = tick.timestamp_ns;
        prices_close  [idx] = tick.price_close;
        prices_open   [idx] = tick.price_open;
        prices_high   [idx] = tick.price_high;
        prices_low    [idx] = tick.price_low;
        volumes       [idx] = tick.volume;
        asset_ids     [idx] = tick.asset_id;
        sequence_nums [idx] = tick.sequence_num;
        exchange_ids  [idx] = tick.exchange_id;
        flags_arr     [idx] = tick.flags;

        // Barreira release: garante que dados estejam visíveis ANTES do head avançar
        // O consumer usa acquire no load do head → memória sequencialmente consistente
        head_cache_ = h + 1;
        head_.store(head_cache_, std::memory_order_release);

        stat_produced_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Versão de push com campos individuais (evita construção do MarketTickView)
    [[nodiscard]] inline bool push_raw(
            uint64_t ts_ns, uint32_t open, uint32_t high, uint32_t low, uint32_t close,
            uint64_t vol, uint32_t asset_id, uint32_t seq, uint16_t exchange_id,
            uint8_t flags) noexcept {
        const uint64_t h = head_cache_;
        const uint64_t t = tail_.load(std::memory_order_acquire);

        if (__builtin_expect(h - t >= N, 0)) {
            stat_dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        const size_t idx = h & MASK;
        timestamps_ns [idx] = ts_ns;
        prices_open   [idx] = open;
        prices_high   [idx] = high;
        prices_low    [idx] = low;
        prices_close  [idx] = close;
        volumes       [idx] = vol;
        asset_ids     [idx] = asset_id;
        sequence_nums [idx] = seq;
        exchange_ids  [idx] = exchange_id;
        flags_arr     [idx] = flags;

        head_cache_ = h + 1;
        head_.store(head_cache_, std::memory_order_release);
        stat_produced_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // ── Consumer API ──────────────────────────────────────────────────────────
    // Verifica se há dados disponíveis
    [[nodiscard]] inline bool has_data() const noexcept {
        const uint64_t t = tail_cache_;
        const uint64_t h = head_.load(std::memory_order_acquire);
        return h > t;
    }

    // Retorna quantos slots estão disponíveis para consumo
    [[nodiscard]] inline uint64_t available() const noexcept {
        const uint64_t h = head_.load(std::memory_order_acquire);
        return h - tail_cache_;
    }

    // Peek: retorna view do próximo slot SEM avançar o tail
    // Usado para inspeção sem consumo
    [[nodiscard]] inline MarketTickView peek() const noexcept {
        const size_t idx = tail_cache_ & MASK;
        return MarketTickView{
            timestamps_ns [idx],
            prices_open   [idx],
            prices_high   [idx],
            prices_low    [idx],
            prices_close  [idx],
            volumes       [idx],
            asset_ids     [idx],
            sequence_nums [idx],
            exchange_ids  [idx],
            flags_arr     [idx],
            0
        };
    }

    // Consome 1 slot (avança tail)
    inline void consume_one() noexcept {
        tail_cache_++;
        tail_.store(tail_cache_, std::memory_order_release);
        stat_consumed_.fetch_add(1, std::memory_order_relaxed);
    }

    // ── SIMD Batch Consumer API ───────────────────────────────────────────────
    // Acesso direto aos arrays SOA para processamento SIMD em batch.
    // O consumer lê diretamente do array sem copiar — zero overhead.
    //
    // Uso típico no SIMD engine:
    //   auto [start, count] = ring.batch_view(64);
    //   // Processa ring.prices_close[start .. start+count] com AVX-512
    //   ring.consume_batch(count);

    struct BatchView {
        size_t   start_idx;   // Índice inicial no array SOA (já com mask aplicado)
        uint64_t count;       // Número de slots disponíveis (limitado por max_batch)
        bool     wraps;       // Se true: batch cruza o boundary do ring (dois segmentos)
    };

    [[nodiscard]] inline BatchView batch_view(uint64_t max_batch) const noexcept {
        const uint64_t h = head_.load(std::memory_order_acquire);
        const uint64_t t = tail_cache_;
        const uint64_t avail = (h > t) ? (h - t) : 0;
        const uint64_t count = (avail < max_batch) ? avail : max_batch;

        const size_t start = t & MASK;
        const bool wraps = (start + count) > N;  // cruza boundary?

        return BatchView{ start, count, wraps };
    }

    inline void consume_batch(uint64_t count) noexcept {
        tail_cache_ += count;
        tail_.store(tail_cache_, std::memory_order_release);
        stat_consumed_.fetch_add(count, std::memory_order_relaxed);
    }

    // ── Estatísticas ──────────────────────────────────────────────────────────
    [[nodiscard]] uint64_t produced() const noexcept { return stat_produced_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t consumed() const noexcept { return stat_consumed_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t dropped()  const noexcept { return stat_dropped_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t in_flight() const noexcept {
        return head_.load(std::memory_order_relaxed) -
               tail_.load(std::memory_order_relaxed);
    }

    void print_stats() const noexcept {
        const uint64_t prod = produced();
        const uint64_t cons = consumed();
        const uint64_t drop = dropped();
        const uint64_t total = prod + drop;
        std::printf("[SOA_RING] Produced=%llu Consumed=%llu Dropped=%llu"
                    " (%.2f%% loss) InFlight=%llu/%zu\n",
                    (unsigned long long)prod,
                    (unsigned long long)cons,
                    (unsigned long long)drop,
                    total ? drop * 100.0 / total : 0.0,
                    (unsigned long long)in_flight(),
                    N);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Instância global com tamanho default — singleton para o hot path
// ─────────────────────────────────────────────────────────────────────────────
using DefaultSoaRing = HornetSoaRing<SOA_RING_CAPACITY>;

// Singleton: alocado no BSS — zero overhead, sem heap, sem inicialização runtime
inline DefaultSoaRing& global_soa_ring() noexcept {
    static DefaultSoaRing ring;
    return ring;
}

} // namespace hornet

#endif // HORNET_SOA_RING_HPP