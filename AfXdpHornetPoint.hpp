#pragma once
#ifndef AF_XDP_HORNET_POINT_HPP
#define AF_XDP_HORNET_POINT_HPP

// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 AF_XDP HORNET POINT — Zero-Copy Network Controller
// ═══════════════════════════════════════════════════════════════════════════════════
//
// O "Hornet Point" é o ponto de entrada de pacotes no user space.
// Ele é a interface entre o eBPF filter (kernel) e o nosso hot path (CPU/SIMD).
//
// ARQUITETURA INTERNA:
//   Rx Ring  ← NIC deposita frame addresses (após eBPF redirect)
//   Fill Ring → HornetPoint preenche com frames livres (do UmemFramePool)
//   Tx Ring  → Futuro: ordens de saída (ACK, heartbeat)
//   Comp Ring → Futuro: confirmação de transmissão
//
// POLLING LOOP (busy-wait):
//   Uma thread dedicada (isolcpus) roda while(true), sem syscalls no hot path.
//   Drena o Rx Ring em batches de POLL_BATCH_SIZE.
//   Para cada frame: chama HornetQuantumBridge::ingest() → SOA ring.
//   Depois: reabastece o Fill Ring com frames livres do pool.
//
// MODO XDP:
//   XDP_ZEROCOPY: NIC escreve diretamente no UMEM (DMA → UMEM, zero cópias)
//   XDP_COPY:     kernel copia UMEM (fallback para NICs sem suporte ZC)
//
// WAKEUP vs BUSY-POLL:
//   Em HFT: busy-poll (100% de 1 core) — zero latência de acordar
//   Em dev:  poll() com timeout de 1ms — economiza CPU durante testes
//
// DEPENDÊNCIAS EXTERNAS:
//   - libxdp (xdp_program__open_file, xdp_program__attach)
//   - libbpf (bpf_map__fd, bpf_object__open)
//   - <linux/if_xdp.h> (xdp_desc, xsk_ring_prod/cons)
// ═══════════════════════════════════════════════════════════════════════════════════

#include "hornet_config.hpp"
#include "umem_numa_allocator.hpp"

// libbpf / libxdp headers
#include <bpf/libbpf.h>
#include <bpf/xsk.h>           // xsk_socket, xsk_umem, xsk_ring_prod/cons
#include <linux/if_xdp.h>

// Linux
#include <linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <sys/resource.h>

// std
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// RxFrameInfo — informação de um frame recebido (passado ao bridge)
// ─────────────────────────────────────────────────────────────────────────────
struct RxFrameInfo {
    uint64_t umem_offset;   // Offset do frame no UMEM (base para data)
    uint32_t len;           // Tamanho total do frame (Ethernet + IP + UDP + payload)
    uint32_t options;       // xdp_desc options (zerocopy metadata)
};

// ─────────────────────────────────────────────────────────────────────────────
// Callback chamado para cada frame recebido pelo HornetPoint
// Parâmetros:
//   umem    — ref ao UmemNuma (para acessar frame_ptr())
//   frame   — informações do frame (offset, len)
// Retorna: true se o frame foi consumido (deve ser devolvido ao pool)
//          false se descartado sem consumo (também deve ser devolvido)
// ─────────────────────────────────────────────────────────────────────────────
using RxCallback = std::function<bool(UmemNuma& umem, const RxFrameInfo& frame)>;

// ─────────────────────────────────────────────────────────────────────────────
// HornetStats — estatísticas de operação (acessíveis de qualquer thread)
// ─────────────────────────────────────────────────────────────────────────────
struct alignas(64) HornetStats {
    std::atomic<uint64_t> rx_frames{0};       // Frames recebidos total
    std::atomic<uint64_t> rx_bytes{0};        // Bytes recebidos total
    std::atomic<uint64_t> rx_batches{0};      // Iterações do poll loop
    std::atomic<uint64_t> fill_refills{0};    // Vezes que o fill ring foi reabastecido
    std::atomic<uint64_t> pool_exhausted{0};  // Fill ring sem frames (pool vazio)
    std::atomic<uint64_t> wakeup_calls{0};    // syscalls de wakeup (modo não-busy)
};

// ─────────────────────────────────────────────────────────────────────────────
// AfXdpHornetPoint — Controlador AF_XDP Zero-Copy
// ─────────────────────────────────────────────────────────────────────────────
class AfXdpHornetPoint {
public:
    AfXdpHornetPoint() = default;
    ~AfXdpHornetPoint() { shutdown(); }

    AfXdpHornetPoint(const AfXdpHornetPoint&)            = delete;
    AfXdpHornetPoint& operator=(const AfXdpHornetPoint&) = delete;

    // ── Inicialização ─────────────────────────────────────────────────────────
    // iface:      nome da interface (ex: "eth0", "enp1s0f0")
    // queue_id:   ID da fila de hardware da NIC (deve coincidir com eBPF xsks_map)
    // umem:       UMEM pré-alocado e inicializado
    // mode:       XDP_ZEROCOPY (preferido) ou XDP_COPY (fallback)
    // busy_poll:  true = hot path (100% CPU), false = usa poll() com timeout
    [[nodiscard]] bool initialize(
            const std::string& iface,
            uint32_t           queue_id,
            UmemNuma&          umem,
            XdpMode            mode      = XdpMode::ZERO_COPY,
            bool               busy_poll = true) noexcept;

    // ── Carrega e anexa o programa eBPF à interface ────────────────────────────
    // bpf_obj_path: caminho para o .o compilado (ex: "xdp_hornet_filter.o")
    // Configura config_map com as portas e modo do hornet_config.hpp
    [[nodiscard]] bool load_bpf_program(const std::string& bpf_obj_path,
                                         FilterMode filter_mode = FilterMode::STRICT) noexcept;

    // ── Desanexa eBPF e fecha sockets ─────────────────────────────────────────
    void shutdown() noexcept;

    // ── Registra callback de recebimento ──────────────────────────────────────
    void set_rx_callback(RxCallback cb) noexcept { rx_callback_ = std::move(cb); }

    // ── Poll Loop — chamar de thread dedicada (com isolcpus) ──────────────────
    // Roda indefinidamente até stop() ser chamado.
    // busy_poll=true: while(true) sem syscall → latência mínima, 100% CPU
    // busy_poll=false: usa poll() com timeout → para testes
    void run_poll_loop() noexcept;

    // Sinaliza parada do poll loop (thread-safe)
    void stop() noexcept { running_.store(false, std::memory_order_release); }

    // ── Estado ────────────────────────────────────────────────────────────────
    [[nodiscard]] bool is_running()     const noexcept { return running_.load(std::memory_order_acquire); }
    [[nodiscard]] bool is_initialized() const noexcept { return initialized_;   }
    [[nodiscard]] const HornetStats& stats() const noexcept { return stats_;    }
    [[nodiscard]] XdpMode mode()        const noexcept { return mode_;          }

    // Reabastece o fill ring com frames do pool (pode ser chamado externamente)
    void refill_fill_ring() noexcept;

private:
    // ── AF_XDP socket e rings ─────────────────────────────────────────────────
    struct xsk_socket*          xsk_     = nullptr;   // Socket AF_XDP
    struct xsk_umem*            umem_if_ = nullptr;   // Handle do UMEM registrado
    struct xsk_ring_prod        fill_ring_{};          // Fill ring (producer side)
    struct xsk_ring_cons        rx_ring_{};            // Rx ring (consumer side)
    struct xsk_ring_prod        tx_ring_{};            // Tx ring (futuro)
    struct xsk_ring_cons        comp_ring_{};          // Completion ring (futuro)

    // ── Referências externas ───────────────────────────────────────────────────
    UmemNuma*                   umem_    = nullptr;

    // ── Config ────────────────────────────────────────────────────────────────
    std::string                 iface_;
    uint32_t                    queue_id_   = 0;
    XdpMode                     mode_       = XdpMode::ZERO_COPY;
    bool                        busy_poll_  = true;
    bool                        initialized_= false;

    // ── BPF program ───────────────────────────────────────────────────────────
    struct bpf_object*          bpf_obj_    = nullptr;
    int                         prog_fd_    = -1;
    uint32_t                    xdp_flags_  = 0;

    // ── Hot path state ────────────────────────────────────────────────────────
    std::atomic<bool>           running_{false};
    RxCallback                  rx_callback_;
    HornetStats                 stats_;

    // Buffer temporário para batch processing (stack-allocated, sem heap)
    uint64_t                    frame_buf_[POLL_BATCH_SIZE];

    // ── Funções internas ──────────────────────────────────────────────────────
    [[nodiscard]] bool setup_umem_registration() noexcept;
    [[nodiscard]] bool setup_xsk_socket()        noexcept;
    void               process_rx_batch()         noexcept;
    void               initial_fill()             noexcept;

    // Garante que mlock unlimited está configurado (requer antes de xsk_umem__create)
    static bool ensure_memlock_unlimited() noexcept;
};

} // namespace hornet

#endif // AF_XDP_HORNET_POINT_HPP