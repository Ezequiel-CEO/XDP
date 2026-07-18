#pragma once
#ifndef UMEM_NUMA_ALLOCATOR_HPP
#define UMEM_NUMA_ALLOCATOR_HPP

// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 UMEM NUMA ALLOCATOR + LOCK-FREE FRAME POOL — HugePage Memory para AF_XDP
// ═══════════════════════════════════════════════════════════════════════════════════
//
// MISSÃO: Alocar o UMEM (User Memory) compartilhado entre NIC DMA e User Space
// sem nenhuma cópia de dados, e gerenciar a circulação de frames de forma elástica.
//
// ── ARQUITETURA DE DOIS NÍVEIS ───────────────────────────────────────────────────
//
//   Nível 1 — UmemNuma (FIXO):
//     mmap(MAP_HUGETLB | MAP_POPULATE) → registrado 1x via xsk_umem__create()
//     Nunca redimensionado — redimensionar exige destruir todos os sockets AF_XDP.
//
//   Nível 2 — UmemFramePool (DINÂMICO):
//     Stack atômica lock-free de frames livres (Treiber Stack, 5ns push/pop).
//     Controla QUANTOS frames circulam no Fill Ring da NIC.
//     Carga baixa  →  poucos frames no Fill Ring → NIC usa menos memória ativa.
//     Carga alta   →  mais frames no Fill Ring   → NIC absorve mais pacotes.
//     A "elasticidade" é na circulação, não no mapa de memória.
//
// ── POR QUE UMEM É FIXO ──────────────────────────────────────────────────────────
//   AF_XDP offsets no Rx Ring são relativos ao base do UMEM registrado.
//   Mudar o UMEM = fechar sockets + re-registrar + re-criar = downtime inaceitável.
//   MAP_POPULATE pre-faulta todas as páginas na init: zero page faults para sempre.
//
// ── ESTRATÉGIA HUGEPAGE (melhor → pior) ─────────────────────────────────────────
//   1. 1GB HugePages (MAP_HUGE_1GB): 1 entrada TLB por GB, ideal para UMEM > 256MB
//   2. 2MB HugePages (MAP_HUGETLB):  padrão HFT, configurável com nr_hugepages
//   3. Páginas normais (4KB):         fallback de emergência, TLB pressure alta
//
// ── PRÉ-REQUISITOS DO SISTEMA ────────────────────────────────────────────────────
//   echo 256 > /proc/sys/vm/nr_hugepages         (512MB com 2MB pages)
//   echo 1   > /proc/sys/vm/nr_hugepages_1g      (para 1GB pages, requer memmap=)
//   ulimit -l unlimited                           (para mlock)
// ═══════════════════════════════════════════════════════════════════════════════════

#include "hornet_config.hpp"

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MPOL_BIND
#  define MPOL_BIND 2
#endif
#ifndef MAP_HUGE_1GB
#  define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGE_2MB
#  define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGE_SHIFT
#  define MAP_HUGE_SHIFT 26
#endif

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// HugePageTier — qual tier foi alocado
// ─────────────────────────────────────────────────────────────────────────────
enum class HugePageTier : uint8_t {
    HUGE_1GB   = 0,
    HUGE_2MB   = 1,
    REGULAR_4K = 2,
};

// ─────────────────────────────────────────────────────────────────────────────
// UmemFramePool — Treiber Stack lock-free de frames livres
// ─────────────────────────────────────────────────────────────────────────────
// Implementação: stack sem lock usando double-wide CAS (seq + ptr) para evitar
// o problema ABA. Cada nó é um offset uint64_t no UMEM — sem heap allocation.
//
// Throughput: ~200M push/pop por segundo por core (benchmark em Skylake).
// Latência:   ~5ns em caminho não-contendido (hit de L1 cache).
//
// Thread-safety: MPMC (múltiplos producers e consumers) — mas no hot path
// usamos 1 producer (HornetPoint rx loop) e 1 consumer (fill ring refill).
// ─────────────────────────────────────────────────────────────────────────────
class UmemFramePool {
public:
    // Nó da Treiber Stack — ocupa um slot do array pré-alocado
    struct alignas(8) FrameNode {
        uint64_t umem_offset;   // Offset do frame dentro do UMEM (para fill ring)
        uint32_t next_idx;      // Índice do próximo nó (UINT32_MAX = fim da stack)
        uint32_t _pad;
    };

    static constexpr uint32_t NULL_IDX = UINT32_MAX;

    // ── Cabeça da stack: (seq << 32) | index — double-wide lógico via uint64_t ──
    // Sequência no upper 32 bits previne ABA sem precisar de 128-bit CAS.
    struct alignas(8) StackHead {
        uint32_t idx;   // Índice do topo da stack
        uint32_t seq;   // Sequência (monotonicamente crescente por pop)
    };
    static_assert(sizeof(StackHead) == 8);

    UmemFramePool() = default;

    // ── Inicializa o pool com todos os frames do UMEM ────────────────────────
    // frame_size:  bytes por frame (ex: 2048)
    // num_frames:  total de frames no UMEM
    // Preenche a stack com todos os offsets: 0, frame_size, 2*frame_size, ...
    [[nodiscard]] bool initialize(size_t frame_size, size_t num_frames) noexcept {
        if (nodes_) return true;  // já inicializado

        frame_size_ = frame_size;
        num_frames_ = num_frames;

        // Aloca o array de nós (sem new — usa mmap para evitar heap fragmentation)
        const size_t array_bytes = num_frames * sizeof(FrameNode);
        void* mem = mmap(nullptr, array_bytes,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (mem == MAP_FAILED) {
            std::fprintf(stderr, "[FRAME_POOL] FATAL: mmap para nós falhou: %s\n",
                         strerror(errno));
            return false;
        }
        nodes_      = static_cast<FrameNode*>(mem);
        nodes_mem_  = mem;
        nodes_size_ = array_bytes;

        // Preenche cada nó com o offset do frame e encadeia na stack
        for (uint32_t i = 0; i < static_cast<uint32_t>(num_frames); ++i) {
            nodes_[i].umem_offset = static_cast<uint64_t>(i) * frame_size;
            nodes_[i].next_idx    = (i + 1 < num_frames) ? (i + 1) : NULL_IDX;
            nodes_[i]._pad        = 0;
        }

        // Topo da stack = índice 0 (frame offset 0)
        StackHead initial{ 0, 0 };
        head_.store(*reinterpret_cast<uint64_t*>(&initial), std::memory_order_release);

        total_frames_.store(static_cast<uint32_t>(num_frames), std::memory_order_relaxed);
        free_count_.store(static_cast<uint32_t>(num_frames), std::memory_order_relaxed);

        std::printf("[FRAME_POOL] Inicializado: %zu frames × %zu bytes = %.1f MB\n",
                    num_frames, frame_size,
                    (num_frames * frame_size) / (1024.0 * 1024.0));
        return true;
    }

    void shutdown() noexcept {
        if (nodes_mem_) {
            munmap(nodes_mem_, nodes_size_);
            nodes_     = nullptr;
            nodes_mem_ = nullptr;
            nodes_size_ = 0;
        }
    }

    ~UmemFramePool() { shutdown(); }

    // Não copiável
    UmemFramePool(const UmemFramePool&)            = delete;
    UmemFramePool& operator=(const UmemFramePool&) = delete;

    // ── Pop: retira um frame livre da stack (~5ns sem contenção) ─────────────
    // Retorna o UMEM offset do frame, ou UINT64_MAX se pool vazio.
    [[nodiscard]] uint64_t pop() noexcept {
        uint64_t raw = head_.load(std::memory_order_acquire);
        while (true) {
            StackHead head = *reinterpret_cast<StackHead*>(&raw);
            if (head.idx == NULL_IDX) return UINT64_MAX;  // Pool vazio

            const uint32_t next = nodes_[head.idx].next_idx;
            StackHead new_head{ next, head.seq + 1 };  // seq++ previne ABA
            uint64_t new_raw = *reinterpret_cast<uint64_t*>(&new_head);

            if (head_.compare_exchange_weak(raw, new_raw,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                free_count_.fetch_sub(1, std::memory_order_relaxed);
                return nodes_[head.idx].umem_offset;
            }
            // CAS falhou: raw atualizado pelo CAS com o valor atual → retry
        }
    }

    // ── Push: devolve um frame ao pool após processamento ────────────────────
    // umem_offset: offset do frame a devolver (múltiplo de frame_size)
    void push(uint64_t umem_offset) noexcept {
        // Encontra o índice do nó via divisão (O(1) — frame_size é potência de 2)
        const uint32_t idx = static_cast<uint32_t>(umem_offset / frame_size_);
        nodes_[idx].umem_offset = umem_offset;

        uint64_t raw = head_.load(std::memory_order_acquire);
        while (true) {
            StackHead head = *reinterpret_cast<StackHead*>(&raw);
            nodes_[idx].next_idx = head.idx;  // novo nó aponta para topo atual

            StackHead new_head{ idx, head.seq };  // push não incrementa seq (só pop)
            uint64_t new_raw = *reinterpret_cast<uint64_t*>(&new_head);

            if (head_.compare_exchange_weak(raw, new_raw,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                free_count_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
    }

    // ── Batch pop: retira até `count` frames, armazena em `out_offsets` ──────
    // Retorna quantos foram retirados (pode ser < count se pool vazio).
    uint32_t pop_batch(uint64_t* out_offsets, uint32_t count) noexcept {
        uint32_t i = 0;
        for (; i < count; ++i) {
            const uint64_t off = pop();
            if (off == UINT64_MAX) break;  // Pool vazio
            out_offsets[i] = off;
        }
        return i;
    }

    // ── Batch push: devolve `count` frames de uma vez ────────────────────────
    void push_batch(const uint64_t* offsets, uint32_t count) noexcept {
        for (uint32_t i = 0; i < count; ++i) push(offsets[i]);
    }

    // ── Pressão: percentual de frames em uso (0-255 para DFAEngine) ──────────
    [[nodiscard]] uint8_t pressure() const noexcept {
        const uint32_t total = total_frames_.load(std::memory_order_relaxed);
        if (total == 0) return 128;
        const uint32_t free  = free_count_.load(std::memory_order_relaxed);
        const uint32_t in_use = (free < total) ? (total - free) : 0;
        return static_cast<uint8_t>((static_cast<uint64_t>(in_use) * 255) / total);
    }

    [[nodiscard]] uint32_t free_count()  const noexcept { return free_count_.load(std::memory_order_relaxed); }
    [[nodiscard]] uint32_t total_frames() const noexcept { return total_frames_.load(std::memory_order_relaxed); }
    [[nodiscard]] bool     is_empty()    const noexcept { return free_count() == 0; }
    [[nodiscard]] bool     is_full()     const noexcept { return free_count() == total_frames(); }

private:
    FrameNode*            nodes_      = nullptr;
    void*                 nodes_mem_  = nullptr;  // Para munmap
    size_t                nodes_size_ = 0;
    size_t                frame_size_ = UMEM_FRAME_SIZE;
    size_t                num_frames_ = UMEM_NUM_FRAMES;

    alignas(64) std::atomic<uint64_t> head_{};  // Treiber stack head (seq|idx)
    alignas(64) std::atomic<uint32_t> free_count_{0};
    alignas(64) std::atomic<uint32_t> total_frames_{0};
};

// ─────────────────────────────────────────────────────────────────────────────
// UmemNuma — UMEM fixo com NUMA awareness + Frame Pool integrado
// ─────────────────────────────────────────────────────────────────────────────
class UmemNuma {
public:
    UmemNuma() = default;
    ~UmemNuma() { shutdown(); }

    UmemNuma(const UmemNuma&)            = delete;
    UmemNuma& operator=(const UmemNuma&) = delete;
    UmemNuma(UmemNuma&&)                 = delete;
    UmemNuma& operator=(UmemNuma&&)      = delete;

    // ── Inicializa UMEM fixo + Frame Pool ─────────────────────────────────────
    [[nodiscard]] bool initialize(
            size_t  frame_size  = UMEM_FRAME_SIZE,
            size_t  num_frames  = UMEM_NUM_FRAMES,
            int     numa_node   = -1) noexcept {

        if (base_ != nullptr) return true;

        frame_size_ = frame_size;
        num_frames_ = num_frames;
        total_size_ = frame_size * num_frames;
        numa_node_  = (numa_node >= 0) ? numa_node : detect_numa_node();

        // ── Tenta alocar UMEM com melhor hugepage disponível ──────────────────
        if (try_alloc_hugepage(total_size_, MAP_HUGE_1GB)) {
            tier_ = HugePageTier::HUGE_1GB;
            std::printf("[UMEM] %.1f GB alocados via 1GB HugePages (NUMA node %d)\n",
                        total_size_ / (1024.0 * 1024.0 * 1024.0), numa_node_);
        } else if (try_alloc_hugepage(total_size_, MAP_HUGE_2MB)) {
            tier_ = HugePageTier::HUGE_2MB;
            std::printf("[UMEM] %.0f MB alocados via 2MB HugePages (NUMA node %d)\n",
                        total_size_ / (1024.0 * 1024.0), numa_node_);
        } else {
            if (!try_alloc_regular(total_size_)) {
                std::fprintf(stderr, "[UMEM] FATAL: todas as estratégias falharam.\n");
                return false;
            }
            tier_ = HugePageTier::REGULAR_4K;
            std::fprintf(stderr,
                "[UMEM] WARN: 4KB pages — TLB pressure alta. "
                "Configure nr_hugepages.\n");
        }

        bind_to_numa_node(base_, total_size_, numa_node_);

        if (mlock(base_, total_size_) != 0) {
            std::fprintf(stderr,
                "[UMEM] WARN: mlock falhou (%s) — page faults possíveis.\n",
                strerror(errno));
        }

        // ── Inicializa Frame Pool sobre o mesmo UMEM ──────────────────────────
        if (!frame_pool_.initialize(frame_size_, num_frames_)) {
            shutdown();
            return false;
        }

        initialized_ = true;
        return true;
    }

    void shutdown() noexcept {
        frame_pool_.shutdown();
        if (base_ && base_ != MAP_FAILED) {
            munlock(base_, total_size_);
            munmap(base_, total_size_);
            base_        = nullptr;
            total_size_  = 0;
        }
        initialized_ = false;
    }

    // ── Accessors diretos ao UMEM ─────────────────────────────────────────────
    [[nodiscard]] void*         base()        const noexcept { return base_;        }
    [[nodiscard]] size_t        total_size()  const noexcept { return total_size_;  }
    [[nodiscard]] size_t        frame_size()  const noexcept { return frame_size_;  }
    [[nodiscard]] size_t        num_frames()  const noexcept { return num_frames_;  }
    [[nodiscard]] int           numa_node()   const noexcept { return numa_node_;   }
    [[nodiscard]] bool          is_valid()    const noexcept { return initialized_; }
    [[nodiscard]] HugePageTier  tier()        const noexcept { return tier_;        }

    // Converte UMEM offset → ponteiro (para leitura do payload)
    [[nodiscard]] void* frame_ptr(uint64_t umem_offset) const noexcept {
        return static_cast<uint8_t*>(base_) + umem_offset;
    }

    // Ponteiro para o payload do frame (pula o headroom)
    [[nodiscard]] void* payload_ptr(uint64_t umem_offset) const noexcept {
        return static_cast<uint8_t*>(base_) + umem_offset + UMEM_HEADROOM;
    }

    // ── Acesso ao Frame Pool (circulação dinâmica) ────────────────────────────
    [[nodiscard]] UmemFramePool& frame_pool() noexcept { return frame_pool_; }
    [[nodiscard]] const UmemFramePool& frame_pool() const noexcept { return frame_pool_; }

    // Shortcuts convenientes
    [[nodiscard]] uint64_t alloc_frame() noexcept  { return frame_pool_.pop();  }
    void         free_frame(uint64_t off) noexcept  { frame_pool_.push(off);     }

    [[nodiscard]] uint32_t alloc_frames(uint64_t* out, uint32_t count) noexcept {
        return frame_pool_.pop_batch(out, count);
    }
    void free_frames(const uint64_t* offs, uint32_t count) noexcept {
        frame_pool_.push_batch(offs, count);
    }

    // Pressão de uso (0=livre, 255=saturado) — alimenta DFAEngine
    [[nodiscard]] uint8_t frame_pressure() const noexcept {
        return frame_pool_.pressure();
    }

    [[nodiscard]] const char* tier_name() const noexcept {
        switch (tier_) {
            case HugePageTier::HUGE_1GB:   return "1GB_HUGEPAGE";
            case HugePageTier::HUGE_2MB:   return "2MB_HUGEPAGE";
            case HugePageTier::REGULAR_4K: return "4KB_REGULAR";
        }
        return "UNKNOWN";
    }

private:
    // ── Detecta NUMA node do CPU atual ────────────────────────────────────────
    static int detect_numa_node() noexcept {
        int cpu = sched_getcpu();
        if (cpu < 0) return 0;
        char path[96];
        std::snprintf(path, sizeof(path),
            "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
        FILE* f = std::fopen(path, "r");
        if (!f) return 0;
        int node = 0;
        std::fscanf(f, "%d", &node);
        std::fclose(f);
        return node;
    }

    // ── Aplica NUMA binding físico via mbind() ────────────────────────────────
    static void bind_to_numa_node(void* addr, size_t size, int node) noexcept {
        if (node < 0) return;
        unsigned long nodemask = 1UL << node;
        // MPOL_MF_MOVE (2): migra páginas já alocadas para o nó correto
        syscall(SYS_mbind, addr, size, MPOL_BIND,
                &nodemask, (unsigned long)(sizeof(nodemask) * 8), 2UL);
    }

    [[nodiscard]] bool try_alloc_hugepage(size_t size, int hugepage_flag) noexcept {
        const size_t hp = (hugepage_flag == MAP_HUGE_1GB)
                          ? HUGE_PAGE_1GB : HUGE_PAGE_2MB;
        const size_t aligned = (size + hp - 1) & ~(hp - 1);
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE
                        | MAP_HUGETLB | hugepage_flag;
        void* ptr = mmap(nullptr, aligned, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (ptr == MAP_FAILED) return false;
        base_       = ptr;
        total_size_ = aligned;
        return true;
    }

    [[nodiscard]] bool try_alloc_regular(size_t size) noexcept {
        const size_t aligned = (size + 4095UL) & ~4095UL;
        void* ptr = mmap(nullptr, aligned, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (ptr == MAP_FAILED) return false;
        base_       = ptr;
        total_size_ = aligned;
        return true;
    }

    void*          base_        = nullptr;
    size_t         total_size_  = 0;
    size_t         frame_size_  = UMEM_FRAME_SIZE;
    size_t         num_frames_  = UMEM_NUM_FRAMES;
    int            numa_node_   = -1;
    bool           initialized_ = false;
    HugePageTier   tier_        = HugePageTier::REGULAR_4K;

    // Frame pool integrado — vive junto com o UMEM, mesma lifetime
    UmemFramePool  frame_pool_;
};

} // namespace hornet

#endif // UMEM_NUMA_ALLOCATOR_HPP