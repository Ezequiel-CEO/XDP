// ═══════════════════════════════════════════════════════════════════════════════════
// 🔥 AF_XDP HORNET POINT — Implementation
// ═══════════════════════════════════════════════════════════════════════════════════

#include "AfXdpHornetPoint.hpp"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>      // ★ Necessário para bpf_map_update_elem
#include <bpf/xsk.h>
#include <errno.h>
#include <immintrin.h>    // _mm_pause
#include <linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <sys/resource.h>
#include <unistd.h>

// Para config_map: sincroniza com a estrutura definida no eBPF
struct hornet_bpf_config {
    uint16_t market_data_port_udp;
    uint16_t fix_port_udp;
    uint16_t itch_port_udp;
    uint16_t management_port_tcp;
    uint8_t  mode;
    uint8_t  enable_ipv6;
    uint8_t  pad[2];
};

namespace hornet {

// ─────────────────────────────────────────────────────────────────────────────
// ensure_memlock_unlimited
// ─────────────────────────────────────────────────────────────────────────────
bool AfXdpHornetPoint::ensure_memlock_unlimited() noexcept {
    struct rlimit rl{};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        std::fprintf(stderr, "[HORNET] getrlimit falhou: %s\n", strerror(errno));
        return false;
    }
    if (rl.rlim_cur == RLIM_INFINITY) return true;  // Já unlimited

    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        std::fprintf(stderr,
            "[HORNET] WARN: setrlimit(MEMLOCK, INFINITY) falhou: %s\n"
            "         Rode como root ou adicione CAP_IPC_LOCK.\n",
            strerror(errno));
        return false;
    }
    std::printf("[HORNET] MEMLOCK elevado para INFINITY.\n");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_umem_registration — Registra o UMEM no kernel via xsk_umem__create
// ─────────────────────────────────────────────────────────────────────────────
bool AfXdpHornetPoint::setup_umem_registration() noexcept {
    if (!umem_ || !umem_->is_valid()) {
        std::fprintf(stderr, "[HORNET] UMEM inválido — inicialize UmemNuma primeiro.\n");
        return false;
    }

    struct xsk_umem_config umem_cfg{};
    umem_cfg.fill_size      = XDP_FILL_RING_SIZE;
    umem_cfg.comp_size      = XDP_COMP_RING_SIZE;
    umem_cfg.frame_size     = static_cast<uint32_t>(umem_->frame_size());
    umem_cfg.frame_headroom = UMEM_HEADROOM;
    umem_cfg.flags          = 0;

    int ret = xsk_umem__create(
        &umem_if_,
        umem_->base(),
        umem_->total_size(),
        &fill_ring_,
        &comp_ring_,
        &umem_cfg
    );

    if (ret != 0) {
        std::fprintf(stderr,
            "[HORNET] xsk_umem__create falhou (ret=%d): %s\n"
            "         Verifique: root/CAP_NET_ADMIN, MEMLOCK unlimited, "
            "CONFIG_XDP_SOCKETS=y\n",
            ret, strerror(-ret));
        return false;
    }

    std::printf("[HORNET] UMEM registrado: base=%p size=%.0f MB frame=%zu\n",
                umem_->base(),
                umem_->total_size() / (1024.0 * 1024.0),
                umem_->frame_size());
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_xsk_socket — Cria o socket AF_XDP e tenta modo ZeroCopy
// ─────────────────────────────────────────────────────────────────────────────
bool AfXdpHornetPoint::setup_xsk_socket() noexcept {
    struct xsk_socket_config xsk_cfg{};
    xsk_cfg.rx_size         = XDP_RX_RING_SIZE;
    xsk_cfg.tx_size         = XDP_TX_RING_SIZE;
    xsk_cfg.bind_flags      = 0;

    // Tenta ZeroCopy primeiro
    if (mode_ == XdpMode::ZERO_COPY) {
        xsk_cfg.bind_flags |= XDP_ZEROCOPY;
    } else {
        xsk_cfg.bind_flags |= XDP_COPY;
    }

    // libbpf: libxdp gerencia o attach do programa XDP automaticamente
    // xsk_socket__create() cria e faz bind do socket à fila correta
    int ret = xsk_socket__create(
        &xsk_,
        iface_.c_str(),
        queue_id_,
        umem_if_,
        &rx_ring_,
        &tx_ring_,
        &xsk_cfg
    );

    if (ret != 0 && mode_ == XdpMode::ZERO_COPY) {
        std::fprintf(stderr,
            "[HORNET] WARN: ZeroCopy não suportado pela NIC (ret=%d). "
            "Fallback para XDP_COPY.\n", ret);

        // Fallback gracioso para XDP_COPY
        xsk_cfg.bind_flags &= ~XDP_ZEROCOPY;
        xsk_cfg.bind_flags |=  XDP_COPY;
        mode_ = XdpMode::COPY;

        ret = xsk_socket__create(
            &xsk_,
            iface_.c_str(),
            queue_id_,
            umem_if_,
            &rx_ring_,
            &tx_ring_,
            &xsk_cfg
        );
    }

    if (ret != 0) {
        std::fprintf(stderr,
            "[HORNET] xsk_socket__create falhou (ret=%d): %s\n"
            "         Verifique: interface '%s' existe, queue_id=%u válido.\n",
            ret, strerror(-ret), iface_.c_str(), queue_id_);
        return false;
    }

    std::printf("[HORNET] Socket AF_XDP criado: iface=%s queue=%u mode=%s\n",
                iface_.c_str(), queue_id_,
                mode_ == XdpMode::ZERO_COPY ? "ZERO_COPY" : "COPY");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// initial_fill — Preenche o fill ring com todos os frames disponíveis
// ─────────────────────────────────────────────────────────────────────────────
void AfXdpHornetPoint::initial_fill() noexcept {
    uint32_t idx_fill = 0;
    // Reserva slots no fill ring (quantidade = fill ring size)
    const uint32_t batch = XDP_FILL_RING_SIZE;
    uint32_t reserved = xsk_ring_prod__reserve(&fill_ring_, batch, &idx_fill);

    uint32_t actually_filled = 0;
    for (uint32_t i = 0; i < reserved; ++i) {
        const uint64_t off = umem_->alloc_frame();
        if (off == UINT64_MAX) {
            // Pool vazio (raro no início) — não há cancel em APIs novas,
            // apenas submetemos o que conseguimos.
            break;
        }
        *xsk_ring_prod__fill_addr(&fill_ring_, idx_fill++) = off;
        actually_filled++;
    }

    if (actually_filled > 0) {
        xsk_ring_prod__submit(&fill_ring_, actually_filled);
        std::printf("[HORNET] Fill ring inicial: %u frames\n", actually_filled);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// initialize — Inicialização completa do HornetPoint
// ─────────────────────────────────────────────────────────────────────────────
bool AfXdpHornetPoint::initialize(
        const std::string& iface,
        uint32_t           queue_id,
        UmemNuma&          umem,
        XdpMode            mode,
        bool               busy_poll) noexcept {

    if (initialized_) return true;

    iface_      = iface;
    queue_id_   = queue_id;
    umem_       = &umem;
    mode_       = mode;
    busy_poll_  = busy_poll;

    // 1. Garante memlock unlimited (necessário antes de xsk_umem__create)
    ensure_memlock_unlimited();

    // 2. Registra UMEM no kernel
    if (!setup_umem_registration()) return false;

    // 3. Cria socket AF_XDP (tenta ZC, fallback para COPY)
    if (!setup_xsk_socket()) {
        xsk_umem__delete(umem_if_);
        umem_if_ = nullptr;
        return false;
    }

    // 4. Preenche fill ring com todos os frames disponíveis
    initial_fill();

    initialized_ = true;
    running_.store(false, std::memory_order_relaxed);
    std::printf("[HORNET] Inicializado. Pronto para poll loop.\n");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// load_bpf_program — Carrega xdp_hornet_filter.o e configura maps
// ─────────────────────────────────────────────────────────────────────────────
bool AfXdpHornetPoint::load_bpf_program(const std::string& bpf_obj_path,
                                          FilterMode filter_mode) noexcept {
    if (bpf_obj_) return true;

    // Abre o objeto BPF
    struct bpf_object* obj = bpf_object__open(bpf_obj_path.c_str());
    if (!obj) {
        std::fprintf(stderr, "[HORNET] bpf_object__open(%s) falhou: %s\n",
                     bpf_obj_path.c_str(), strerror(errno));
        return false;
    }

    // Carrega (verifica e JIT-compila o eBPF)
    if (bpf_object__load(obj) != 0) {
        std::fprintf(stderr, "[HORNET] bpf_object__load falhou: %s\n",
                     strerror(errno));
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }

    // Busca o programa XDP pelo nome da seção
    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_hornet_filter");
    if (!prog) {
        std::fprintf(stderr, "[HORNET] Programa 'xdp_hornet_filter' não encontrado no .o\n");
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }
    prog_fd_ = bpf_program__fd(prog);
    if (prog_fd_ < 0) {
        std::fprintf(stderr, "[HORNET] Programa XDP carregado sem file descriptor válido\n");
        bpf_object__close(obj);
        return false;
    }

    // ── Configura config_map com as portas e modo ─────────────────────────────
    struct bpf_map* cfg_map = bpf_object__find_map_by_name(obj, "config_map");
    if (!cfg_map) {
        std::fprintf(stderr, "[HORNET] config_map ausente no objeto eBPF\n");
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }
    hornet_bpf_config cfg{};
    cfg.market_data_port_udp = MARKET_DATA_PORT_UDP;
    cfg.fix_port_udp         = FIX_PORT_UDP;
    cfg.itch_port_udp        = ITCH_PORT_UDP;
    cfg.management_port_tcp  = MANAGEMENT_PORT_TCP;
    cfg.mode                 = static_cast<uint8_t>(filter_mode);
    cfg.enable_ipv6          = 0;

    uint32_t key = 0;
    const int cfg_fd = bpf_map__fd(cfg_map);
    if (cfg_fd < 0 || bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY) != 0) {
        std::fprintf(stderr, "[HORNET] Falha ao configurar config_map: %s\n",
                     strerror(errno));
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }

    // ── Registra socket no xsks_map ──────────────────────────────────────────
    struct bpf_map* xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");
    if (!xsks_map || !xsk_) {
        std::fprintf(stderr, "[HORNET] xsks_map ou socket AF_XDP ausente\n");
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }
    const int xsk_fd = xsk_socket__fd(xsk_);
    key = queue_id_;
    const int xsks_fd = bpf_map__fd(xsks_map);
    if (xsk_fd < 0 || xsks_fd < 0 ||
        bpf_map_update_elem(xsks_fd, &key, &xsk_fd, BPF_ANY) != 0) {
        std::fprintf(stderr, "[HORNET] Falha ao registrar socket no xsks_map: %s\n",
                     strerror(errno));
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }

    // ── Anexa o programa à interface (XDP native mode) ───────────────────────
    unsigned int ifindex = if_nametoindex(iface_.c_str());
    if (ifindex == 0) {
        std::fprintf(stderr, "[HORNET] Interface '%s' não encontrada.\n", iface_.c_str());
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }

    xdp_flags_ = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    int ret = bpf_set_link_xdp_fd(ifindex, prog_fd_, xdp_flags_);
    if (ret != 0 && ret != -EEXIST) {
        // Fallback para SKB mode (funciona em qualquer NIC, inclusive virtual)
        std::fprintf(stderr,
            "[HORNET] Native XDP falhou (%s) — tentando SKB mode.\n",
            strerror(-ret));
        xdp_flags_ = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
        ret = bpf_set_link_xdp_fd(ifindex, prog_fd_, xdp_flags_);
    }

    if (ret != 0) {
        std::fprintf(stderr, "[HORNET] bpf_set_link_xdp_fd falhou: %s\n", strerror(-ret));
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }

    struct bpf_prog_info info{};
    uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd_, &info, &info_len) != 0 || info.id == 0) {
        std::fprintf(stderr, "[HORNET] Não foi possível identificar o programa anexado\n");
        const uint32_t mode_flags = xdp_flags_ &
            (XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE | XDP_FLAGS_HW_MODE);
        (void)bpf_set_link_xdp_fd(ifindex, -1, mode_flags);
        bpf_object__close(obj);
        prog_fd_ = -1;
        return false;
    }
    attached_prog_id_ = info.id;

    bpf_obj_ = obj;
    std::printf("[HORNET] eBPF carregado e anexado a '%s' (mode=%s, filter=%s)\n",
                iface_.c_str(),
                (xdp_flags_ & XDP_FLAGS_DRV_MODE) ? "native" : "skb",
                (filter_mode == FilterMode::STRICT) ? "STRICT" : "PERMISSIVE");
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// refill_fill_ring — Reabastece o fill ring com frames livres do pool
// Chamado automaticamente no poll loop após processar cada batch
// ─────────────────────────────────────────────────────────────────────────────
void AfXdpHornetPoint::refill_fill_ring() noexcept {
    uint32_t idx_fill = 0;
    // Quanto o fill ring pode receber agora
    const uint32_t free_slots = xsk_prod_nb_free(&fill_ring_, FILL_BATCH_SIZE);
    if (free_slots == 0) return;

    const uint32_t to_fill = (free_slots < FILL_BATCH_SIZE)
                             ? free_slots : FILL_BATCH_SIZE;
    const uint32_t reserved = xsk_ring_prod__reserve(&fill_ring_, to_fill, &idx_fill);
    if (reserved == 0) return;

    uint32_t filled = 0;
    for (uint32_t i = 0; i < reserved; ++i) {
        const uint64_t off = umem_->alloc_frame();
        if (off == UINT64_MAX) {
            // Pool vazio — não há cancel, submetemos o que temos
            if (i == 0) {
                stats_.pool_exhausted.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            break;
        }
        *xsk_ring_prod__fill_addr(&fill_ring_, idx_fill + i) = off;
        ++filled;
    }

    if (filled > 0) {
        xsk_ring_prod__submit(&fill_ring_, filled);
        stats_.fill_refills.fetch_add(1, std::memory_order_relaxed);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// process_rx_batch — Drena o Rx Ring e chama o callback para cada frame
// ─────────────────────────────────────────────────────────────────────────────
void AfXdpHornetPoint::process_rx_batch() noexcept {
    uint32_t idx_rx = 0;
    // Quantos frames chegaram no Rx Ring
    const uint32_t rcvd = xsk_ring_cons__peek(&rx_ring_, POLL_BATCH_SIZE, &idx_rx);
    if (rcvd == 0) return;

    stats_.rx_batches.fetch_add(1, std::memory_order_relaxed);

    for (uint32_t i = 0; i < rcvd; ++i) {
        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&rx_ring_, idx_rx + i);

        RxFrameInfo frame_info{};
        frame_info.umem_offset = desc->addr;
        frame_info.len         = desc->len;
        frame_info.options     = desc->options;

        stats_.rx_frames.fetch_add(1, std::memory_order_relaxed);
        stats_.rx_bytes.fetch_add(desc->len, std::memory_order_relaxed);

        // Chama o bridge (HornetQuantumBridge::ingest)
        if (rx_callback_) {
            rx_callback_(*umem_, frame_info);
        }

        // Frame processado: devolve ao pool para ser reciclado pelo fill ring
        umem_->free_frame(desc->addr & ~(umem_->frame_size() - 1));
    }

    // Libera os descritores do Rx Ring para a NIC reutilizar
    xsk_ring_cons__release(&rx_ring_, rcvd);

    // Reabastece fill ring com frames frescos do pool
    refill_fill_ring();
}

// ─────────────────────────────────────────────────────────────────────────────
// run_poll_loop — Loop principal de recebimento (chamar em thread dedicada)
// ─────────────────────────────────────────────────────────────────────────────
void AfXdpHornetPoint::run_poll_loop() noexcept {
    if (!initialized_) {
        std::fprintf(stderr, "[HORNET] run_poll_loop: não inicializado!\n");
        return;
    }

    running_.store(true, std::memory_order_release);
    std::printf("[HORNET] Poll loop iniciado (mode=%s)\n",
                busy_poll_ ? "BUSY_POLL" : "POLL_SLEEP");

    if (busy_poll_) {
        // ── HOT PATH: Busy-poll sem syscalls ─────────────────────────────────
        // Thread dedicada queima 100% de 1 core.
        // Latência: sub-microsegundo desde chegada do pacote.
        while (running_.load(std::memory_order_acquire)) {
            process_rx_batch();
            // Wakeup flag: em modo XDP_COPY o kernel pode precisar de kick
            // Em ZeroCopy não é necessário mas não causa overhead
            if (xsk_ring_prod__needs_wakeup(&fill_ring_)) {
                stats_.wakeup_calls.fetch_add(1, std::memory_order_relaxed);
                recvfrom(xsk_socket__fd(xsk_), nullptr, 0, MSG_DONTWAIT,
                         nullptr, nullptr);
            }
            _mm_pause();  // Reduz power sem aumentar latência
        }
    } else {
        // ── DEV/TEST: poll() com timeout ─────────────────────────────────────
        struct pollfd fds[1];
        fds[0].fd     = xsk_socket__fd(xsk_);
        fds[0].events = POLLIN;

        while (running_.load(std::memory_order_acquire)) {
            int ret = poll(fds, 1, 1);  // timeout 1ms
            if (ret > 0 && (fds[0].revents & POLLIN)) {
                process_rx_batch();
            }
        }
    }

    std::printf("[HORNET] Poll loop encerrado. "
                "Rx=%llu bytes=%llu batches=%llu\n",
                (unsigned long long)stats_.rx_frames.load(),
                (unsigned long long)stats_.rx_bytes.load(),
                (unsigned long long)stats_.rx_batches.load());
}

// ─────────────────────────────────────────────────────────────────────────────
// shutdown — Desanexa eBPF, fecha socket, libera UMEM registration
// ─────────────────────────────────────────────────────────────────────────────
void AfXdpHornetPoint::shutdown() noexcept {
    running_.store(false, std::memory_order_release);

    if (xsk_) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
    }

    if (umem_if_) {
        xsk_umem__delete(umem_if_);
        umem_if_ = nullptr;
    }

    // Desanexa somente se o programa ainda for o que esta instância anexou.
    if (prog_fd_ >= 0 && attached_prog_id_ != 0 && !iface_.empty()) {
        unsigned int ifindex = if_nametoindex(iface_.c_str());
        if (ifindex > 0) {
            const uint32_t mode_flags = xdp_flags_ &
                (XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE | XDP_FLAGS_HW_MODE);
            uint32_t current_id = 0;
            if (bpf_get_link_xdp_id(ifindex, &current_id, mode_flags) == 0 &&
                current_id == attached_prog_id_) {
                (void)bpf_set_link_xdp_fd(ifindex, -1, mode_flags);
            } else if (current_id != 0) {
                std::fprintf(stderr,
                    "[HORNET] Programa XDP da interface mudou; não será desanexado\n");
            }
        }
        prog_fd_ = -1;
        attached_prog_id_ = 0;
    }

    if (bpf_obj_) {
        bpf_object__close(bpf_obj_);
        bpf_obj_ = nullptr;
    }

    initialized_ = false;
    std::printf("[HORNET] Shutdown completo.\n");
}

} // namespace hornet
