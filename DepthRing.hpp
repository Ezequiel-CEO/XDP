#pragma once
#ifndef HORNET_DEPTH_RING_HPP
#define HORNET_DEPTH_RING_HPP

// ═══════════════════════════════════════════════════════════════════════════════
// 🔥 HORNET DEPTH RING — Real L5 Order Book, Lock-Free Double Buffer
// ═══════════════════════════════════════════════════════════════════════════════
//
// MISSÃO:
//   Expor os 5 níveis reais do book (bid+ask) para o hot-path via zero-copy.
//   Substitui a interpolação geométrica da tick_to_orderbook() por dados reais
//   provenientes do stream "btcusdt@depth5@100ms" da Binance.
//
// PADRÃO DE ACESSO (assimetria intencional):
//   Writer: DepthFeedAdapter thread (~10Hz, não latency-critical)
//   Reader: hot_path_thread         (~100kHz, latency-critical → ZERO custo)
//
// DESIGN — Atomic Double-Buffer Flip (sem seqlock, sem spinloop):
//
//   buf_[0]  ←─── slot inativo (writer pode escrever aqui com segurança)
//   buf_[1]  ←─── slot ativo   (reader aponta aqui)
//   active_  ←─── índice atômico (0 ou 1)
//
//   WRITE: writer → escreve em buf_[1 - active_] → fence → flip active_
//   READ:  reader → load active_ (acquire) → &buf_[active_] → lê campos
//
//   GARANTIA: reader SEMPRE lê de um slot completo (o writer só toca no
//   slot inativo, nunca no slot que o reader está usando).
//
//   LATÊNCIA:
//     write(): 1 atomic store + 176B memcpy (~10ns) — não é hot path
//     peek():  1 atomic load + deref pointer   (~2ns) — hot path crítico
//
// THREAD SAFETY:
//   SPSC: 1 writer (DepthFeedAdapter) + N readers (hot_path apenas na prática)
//   Readers entre si: OK — apenas leituras, sem modificação de estado
//   Writer + Reader: garantido pelo double-buffer flip com fence release/acquire
// ═══════════════════════════════════════════════════════════════════════════════

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <immintrin.h>   // _mm_sfence

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
// DepthRing — Singleton. Lock-free double-buffer flip. Zero-copy no hot-path.
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
        // Slot inativo = o que NÃO está sendo lido agora
        const uint32_t cur    = active_.load(std::memory_order_relaxed);
        const uint32_t next   = cur ^ 1u;  // toggle: 0↔1

        // Escreve no slot inativo (reader nunca toca aqui)
        buf_[next] = snap;

        // Release fence: garante que todos os stores acima sejam visíveis
        // ANTES que o flip do active_ seja visto por outros threads.
        // (equivalente a _mm_sfence() + atomic store release)
        active_.store(next, std::memory_order_release);

        // Marca como válido (uma vez) — após o primeiro write
        if (!valid_.load(std::memory_order_relaxed)) {
            valid_.store(true, std::memory_order_release);
        }

        writes_.fetch_add(1, std::memory_order_relaxed);
    }

    // ── Consumer API HOT-PATH: zero-copy pointer (~2ns) ──────────────────────
    //
    // Retorna ponteiro para o snapshot ativo.
    // Retorna nullptr se nenhum snapshot foi recebido ainda (fallback para
    // interpolação geométrica em tick_to_orderbook).
    //
    // ATENÇÃO: o ponteiro é válido até o próximo write() (100ms).
    // No hot-path (ticks a cada ~100µs), o ponteiro é sempre válido.
    [[nodiscard]] const DepthL5Snapshot* peek() const noexcept {
        // Fast path: verifica validade com acquire para sincronizar com write()
        if (__builtin_expect(!valid_.load(std::memory_order_acquire), 0)) {
            return nullptr;
        }
        // Carrega o índice do slot ativo com acquire — sincroniza com o store
        // release do write(). Garante que buf_[idx] está completamente escrito.
        const uint32_t idx = active_.load(std::memory_order_acquire);
        return &buf_[idx];
    }

    // Versão com cópia para quando o caller precisa de snapshot estável
    // (ex: cold-path que processa mais de 100ms → risco de stale ptr)
    [[nodiscard]] bool try_copy(DepthL5Snapshot& out) const noexcept {
        const DepthL5Snapshot* p = peek();
        if (!p) return false;
        out = *p;
        return true;
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

    // ── Estado ────────────────────────────────────────────────────────────────
    // Dois slots completos — writer usa o inativo, reader usa o ativo
    alignas(64) DepthL5Snapshot buf_[2];

    // Índice do slot ativo (0 ou 1). Leitura acquire = sincroniza com write release.
    alignas(64) std::atomic<uint32_t> active_{0};

    // Flag de validade — false até o primeiro write()
    alignas(64) std::atomic<bool>     valid_{false};

    // Telemetria — escrita relaxed, lida apenas no cold-path
    alignas(64) std::atomic<uint64_t> writes_{0};
};

} // namespace hornet

#endif // HORNET_DEPTH_RING_HPP
