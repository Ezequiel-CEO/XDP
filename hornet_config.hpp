#pragma once
#ifndef HORNET_CONFIG_HPP
#define HORNET_CONFIG_HPP

// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 HONEYPOINT — Compile-Time Configuration
// ═══════════════════════════════════════════════════════════════════════════════════
// Todos os parâmetros críticos em um lugar. Nenhum magic number espalhado.
// Portas e modos podem ser overridados em runtime via BPF map (config_map).
// ═══════════════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <cstddef>

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// Network Protocol Config
// ─────────────────────────────────────────────────────────────────────────────
inline constexpr uint16_t MARKET_DATA_PORT_UDP = 9999;   // Custom feed UDP
inline constexpr uint16_t FIX_PORT_UDP         = 8888;   // FIX over UDP
inline constexpr uint16_t ITCH_PORT_UDP        = 20305;  // NASDAQ ITCH 5.0
inline constexpr uint16_t MANAGEMENT_PORT_TCP  = 22;     // SSH

// ─────────────────────────────────────────────────────────────────────────────
// UMEM Layout (Shared Memory entre NIC DMA e User Space)
// ─────────────────────────────────────────────────────────────────────────────
// Frame: 2KB (max MTU=1500 + header room + alignment)
// Total: 512MB → 262144 frames
// HugePage: 2MB blocks (requer hugepages alocadas no sistema)
//   echo 512 > /proc/sys/vm/nr_hugepages   (256 × 2MB = 512MB)
//   echo 1   > /proc/sys/vm/nr_overcommit_hugepages

inline constexpr size_t UMEM_FRAME_SIZE        = 2048;      // 2KB por frame
inline constexpr size_t UMEM_NUM_FRAMES        = 262144;    // 256K frames
inline constexpr size_t UMEM_TOTAL_SIZE        = UMEM_FRAME_SIZE * UMEM_NUM_FRAMES; // 512MB
inline constexpr size_t UMEM_HEADROOM          = 256;       // Bytes reservados no início do frame

// Hugepages disponíveis
inline constexpr size_t HUGE_PAGE_2MB  = 2ULL  * 1024 * 1024;
inline constexpr size_t HUGE_PAGE_1GB  = 1024ULL * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// AF_XDP Ring Sizes (devem ser potência de 2)
// ─────────────────────────────────────────────────────────────────────────────
inline constexpr uint32_t XDP_RX_RING_SIZE     = 4096;  // Rx ring: 4K descritores
inline constexpr uint32_t XDP_TX_RING_SIZE     = 4096;  // Tx ring: 4K (futuro)
inline constexpr uint32_t XDP_FILL_RING_SIZE   = 4096;  // Fill ring: mesma que Rx
inline constexpr uint32_t XDP_COMP_RING_SIZE   = 4096;  // Completion ring

// ─────────────────────────────────────────────────────────────────────────────
// HornetPoint Polling Config
// ─────────────────────────────────────────────────────────────────────────────
// Busy-poll: thread dedicada queima 100% de 1 core, sem syscalls no hot path.
// BATCH_SIZE: frames processados por iteração do poll loop.
// Maior = maior throughput, menor = menor latência de início.
inline constexpr uint32_t POLL_BATCH_SIZE      = 64;    // Frames por iteração
inline constexpr uint32_t FILL_BATCH_SIZE      = 64;    // Reabastecimento do fill ring
inline constexpr uint32_t WAKEUP_THRESHOLD     = 1;     // Frames mínimos para acordar

// ─────────────────────────────────────────────────────────────────────────────
// SOA Ring (Phase 3A Hot Path)
// ─────────────────────────────────────────────────────────────────────────────
// 64K slots × ~80 bytes por slot (campos SOA) = ~5MB — cabe em LLC de qualquer CPU moderno
inline constexpr size_t  SOA_RING_CAPACITY     = 65536;  // Potência de 2
inline constexpr size_t  SOA_RING_MASK         = SOA_RING_CAPACITY - 1;

// ─────────────────────────────────────────────────────────────────────────────
// XDP Mode
// ─────────────────────────────────────────────────────────────────────────────
enum class XdpMode : uint8_t {
    ZERO_COPY = 0,  // Preferido: NIC DMA direta para UMEM (zero cópias)
    COPY      = 1,  // Fallback: kernel copia para UMEM (NIC sem suporte ZC)
};

// ─────────────────────────────────────────────────────────────────────────────
// eBPF Filter Mode
// ─────────────────────────────────────────────────────────────────────────────
enum class FilterMode : uint8_t {
    STRICT     = 0,  // Drop tudo exceto market data + tráfego essencial
    PERMISSIVE = 1,  // Pass tráfego desconhecido (dev/debug)
};

} // namespace hornet

#endif // HORNET_CONFIG_HPP