#pragma once
#ifndef HORNET_DEPTH_RING_HPP
#define HORNET_DEPTH_RING_HPP

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 HORNET DEPTH RING — Real L5 Order Book, Versioned Atomic Snapshot
// ═══════════════════════════════════════════════════════════════════════════════
//
// MISSÃO:
//   Expor os 5 níveis reais do book (bid+ask) ao hot-path por snapshot atômico.
//   Substitui a interpolação geométrica da tick_to_orderbook() por dados reais
//   provenientes do stream "btcusdt@depth5@100ms" da Binance.
//
// PADRÃO DE ACESSO (assimetria intencional):
//   Writer: DepthFeedAdapter thread (~10Hz, não latency-critical)
//   Reader: hot_path_thread         (~100kHz, latency-critical)
//
// DESIGN — Atomic Double-Buffer + version validation:
//
//   slots_[0]  ←─── slot inativo
//   slots_[1]  ←─── slot ativo
//   active_  ←─── índice atômico (0 ou 1)
//
//   WRITE: versão ímpar → 22 stores atômicos → versão par → flip
//   READ:  versão → 22 loads atômicos → confirma a mesma versão par
//
//   GARANTIA: mesmo após dois flips rápidos, não há data race, torn-read ou
//   ponteiro para um objeto comum enquanto ele está sendo sobrescrito.
//
//   LATÊNCIA:
//     write(): 22 stores atômicos + flip — cold path (~10Hz)
//     try_copy(): 22 loads atômicos, normalmente uma tentativa
//
// THREAD SAFETY:
//   SPSC: 1 writer (DepthFeedAdapter) + N readers (hot_path apenas na prática)
//   Readers entre si: OK — apenas leituras, sem modificação de estado
//   Writer + Reader: palavras atômicas + versão release/acquire
// ═══════════════════════════════════════════════════════════════════════════════

#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <type_traits>

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// DepthL5Snapshot — 5 níveis bid+ask com preço e quantidade
//
// Layout de memória (3 cache lines = 192 bytes com padding):
//   [bid_px 40B | ask_px 40B | bid_sz 40B | ask_sz 40B | meta 16B | pad 16B]
//
// Índice 0 = best bid/ask (L0 do book)
// Índice 4 = 5° nível    (maior spread do L0)
// ─────────────────────────────────────────────────────────────────────────────
struct alignas(64) DepthL5Snapshot {
    double   bid_px[5];    // Preços bid  — nível 0 é best bid
    double   ask_px[5];    // Preços ask  — nível 0 é best ask
    double   bid_sz[5];    // Quantidades bid (BTC ou unidade base)
    double   ask_sz[5];    // Quantidades ask
    uint64_t timestamp_ns; // Timestamp local (CLOCK_MONOTONIC_RAW) da recepção
    uint64_t update_id;    // lastUpdateId do response da Binance
    uint8_t  _pad[16];     // Padding → alinha próxima cache line
    // Total: 5×4×8 + 8 + 8 + 16 = 192 bytes = 3 cache lines
};
static_assert(sizeof(DepthL5Snapshot) == 192, "DepthL5Snapshot deve ter 192 bytes");
static_assert(alignof(DepthL5Snapshot) == 64, "DepthL5Snapshot deve ser alinhado em 64B");

// ─────────────────────────────────────────────────────────────────────────────
// DepthRing — Singleton. Lock-free double-buffer com snapshot consistente.
// ─────────────────────────────────────────────────────────────────────────────
class DepthRing {
public:
    // ── Producer API (DepthFeedAdapter thread, ~10Hz) ─────────────────────────
    //
    // Escreve o snapshot no slot inativo, depois faz flip atômico.
    // Após retornar, qualquer reader que chamar peek() verá este snapshot.
    //
    // NUNCA chamado do hot-path — latência irrelevante.
    void write(const DepthL5Snapshot& snap) noexcept {
        const uint32_t cur    = active_.load(std::memory_order_relaxed);
        const uint32_t next   = cur ^ 1u;  // toggle: 0↔1
        Slot& slot = slots_[next];
        uint64_t previous = slot.version.load(std::memory_order_acquire);
        // O contrato é SPSC. Um valor já ímpar prova violação por um segundo
        // producer; o slot permanece indisponível e os readers falham fechados.
        if ((previous & 1U) != 0) return;
        if (!slot.version.compare_exchange_strong(
                previous, previous + 1, std::memory_order_acq_rel,
                std::memory_order_acquire)) return; // odd: write in progress
        const FullWordArray words = std::bit_cast<FullWordArray>(snap);
        for (size_t i = 0; i < kDataWordCount; ++i)
            slot.words[i].store(words[i], std::memory_order_relaxed);
        slot.version.fetch_add(1, std::memory_order_release); // even: complete
        active_.store(next, std::memory_order_release);

        // Marca como válido (uma vez) — após o primeiro write
        if (!valid_.load(std::memory_order_relaxed)) {
            valid_.store(true, std::memory_order_release);
        }

        writes_.fetch_add(1, std::memory_order_relaxed);
    }

    // ── Consumer API HOT-PATH: snapshot estável compatível ───────────────────
    //
    // Retorna ponteiro para o snapshot ativo.
    // Retorna nullptr se nenhum snapshot foi recebido ainda (fallback para
    // interpolação geométrica em tick_to_orderbook).
    //
    // O ponteiro referencia uma cópia thread_local e permanece válido até o
    // próximo peek() realizado pela mesma thread.
    [[nodiscard]] const DepthL5Snapshot* peek() const noexcept {
        thread_local DepthL5Snapshot stable{};
        return try_copy(stable) ? &stable : nullptr;
    }

    // API canônica: cópia atômica versionada, no máximo oito tentativas.
    [[nodiscard]] bool try_copy(DepthL5Snapshot& out) const noexcept {
        if (__builtin_expect(!valid_.load(std::memory_order_acquire), 0))
            return false;
        for (unsigned attempt = 0; attempt < 8; ++attempt) {
            const uint32_t index = active_.load(std::memory_order_acquire);
            const Slot& slot = slots_[index];
            const uint64_t before = slot.version.load(std::memory_order_acquire);
            if ((before & 1U) != 0) continue;
            FullWordArray words{};
            for (size_t i = 0; i < kDataWordCount; ++i)
                words[i] = slot.words[i].load(std::memory_order_relaxed);
            const uint64_t after = slot.version.load(std::memory_order_acquire);
            if (before == after && (after & 1U) == 0) {
                out = std::bit_cast<DepthL5Snapshot>(words);
                return true;
            }
        }
        return false;
    }

    // ── Status ────────────────────────────────────────────────────────────────
    [[nodiscard]] bool     valid()  const noexcept { return valid_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t writes() const noexcept { return writes_.load(std::memory_order_relaxed); }

    void print_stats() const noexcept {
        const auto* p = peek();
        if (p) {
            std::printf(
                "[DEPTH_RING] Snapshots=%llu | "
                "BidL0=%.2f(%.4f) AskL0=%.2f(%.4f) | "
                "BidL1=%.2f BidL2=%.2f BidL3=%.2f | "
                "AskL1=%.2f AskL2=%.2f AskL3=%.2f\n",
                (unsigned long long)writes(),
                p->bid_px[0], p->bid_sz[0],
                p->ask_px[0], p->ask_sz[0],
                p->bid_px[1], p->bid_px[2], p->bid_px[3],
                p->ask_px[1], p->ask_px[2], p->ask_px[3]);
        } else {
            std::printf("[DEPTH_RING] Aguardando primeiro snapshot depth5...\n");
        }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────
    [[nodiscard]] static DepthRing& instance() noexcept {
        static DepthRing dr;
        return dr;
    }

    DepthRing(const DepthRing&)            = delete;
    DepthRing& operator=(const DepthRing&) = delete;

private:
    DepthRing() = default;

    static constexpr size_t kFullWordCount =
        sizeof(DepthL5Snapshot) / sizeof(uint64_t);
    static constexpr size_t kDataWordCount =
        offsetof(DepthL5Snapshot, _pad) / sizeof(uint64_t);
    using FullWordArray = std::array<uint64_t, kFullWordCount>;
    static_assert(std::is_trivially_copyable_v<DepthL5Snapshot>);
    static_assert(sizeof(FullWordArray) == sizeof(DepthL5Snapshot));
    static_assert(offsetof(DepthL5Snapshot, _pad) % sizeof(uint64_t) == 0);
    static_assert(std::atomic<uint64_t>::is_always_lock_free,
                  "DepthRing requires lock-free 64-bit atomics");

    struct alignas(64) Slot {
        std::atomic<uint64_t> version{0};
        std::array<std::atomic<uint64_t>, kDataWordCount> words{};
    };
    static_assert(sizeof(Slot) == 192,
                  "DepthRing slot must fit exactly three cache lines");

    // ── Estado ────────────────────────────────────────────────────────────────
    // Dois slots completos — writer usa o inativo, reader usa o ativo
    alignas(64) Slot slots_[2];

    // Índice do slot ativo (0 ou 1). Leitura acquire = sincroniza com write release.
    alignas(64) std::atomic<uint32_t> active_{0};

    // Flag de validade — false até o primeiro write()
    alignas(64) std::atomic<bool>     valid_{false};

    // Telemetria — escrita relaxed, lida apenas no cold-path
    alignas(64) std::atomic<uint64_t> writes_{0};
};

} // namespace hornet

#endif // HORNET_DEPTH_RING_HPP
