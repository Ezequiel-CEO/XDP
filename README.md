# XDP — Hornet Zero-Copy Network Stack

> **Status:** Implementado e testado. Ativo em produção apenas com NIC AF_XDP-capable + feed server co-located. Em ambiente remoto (Binance WebSocket), o path ativo é `BinanceFeedAdapter`. Os dois paths são completamente independentes.

---

## Visão Geral

O módulo XDP é a camada de captura de pacotes de **latência ultra-baixa** do MegaZord Trader. Ele bypassa completamente o kernel TCP/IP stack usando **AF_XDP** (Address Family XDP), permitindo que frames de rede sejam lidos diretamente do DMA da NIC para o user space — sem nenhuma cópia de dados.

### Latência Comparada

| Path | Tecnologia | Latência estimada |
|------|-----------|-------------------|
| **XDP (co-located)** | AF_XDP zero-copy | ~200ns NIC→SOA Ring |
| **WebSocket (remoto)** | TLS/TCP kernel stack | ~10ms (network RTT) |

---

## Arquitetura — Pipeline Completo

```
NIC (hardware queue N)
        │
        │  DMA → UMEM (zero-copy, sem syscall)
        ▼
┌─────────────────────────────┐
│  eBPF Filter                │  kernel/xdp_hornet_filter.c
│  (roda no kernel, ~50ns)    │
│                             │
│  UDP:9999  → REDIRECT ──────┼──► AF_XDP socket (xsks_map[queue_id])
│  UDP:8888  → REDIRECT       │
│  UDP:20305 → REDIRECT       │
│  TCP:22    → PASS           │  SSH de gerência
│  TCP:443   → PASS           │  Binance WebSocket TLS (não capturado pelo XDP)
│  ICMP      → PASS           │
│  [STRICT]  → DROP           │  DDoS mitigation nativo
└─────────────────────────────┘
        │
        │  XSKMAP redirect
        ▼
┌─────────────────────────────┐
│  AfXdpHornetPoint           │  AfXdpHornetPoint.hpp/.cpp
│  (user space, busy-poll)    │
│                             │
│  Fill Ring ◄── UmemFramePool│  frames livres para a NIC
│  Rx Ring   ──► poll loop   │  frames recebidos pelo eBPF
│                             │
│  Para cada frame:           │
│    rx_callback(umem, frame) │
└─────────────────────────────┘
        │
        │  RxCallback
        ▼
┌─────────────────────────────┐
│  HornetQuantumBridge        │  HornetQuantumBridge.hpp
│  (~25ns parse total)        │
│                             │
│  Eth header parse    ~3ns   │
│  IPv4 header parse   ~3ns   │
│  UDP header parse    ~2ns   │
│  Magic check 0xC3BE  ~1ns   │
│  HornetBinaryTick parse ~5ns│
│  Network → host byte order  │
│  Gap detection (sequence)   │
└─────────────────────────────┘
        │
        │  push_raw()
        ▼
┌─────────────────────────────┐
│  HornetSoaRing              │  HornetSoaRing.hpp
│  SPSC Lock-Free SOA Ring    │
│  64K slots × ~44 bytes      │
│  ≈ 2.6MB total (LLC fit)    │
│                             │
│  timestamps_ns[64K]         │
│  prices_open[64K]           │
│  prices_high[64K]           │
│  prices_low[64K]            │
│  prices_close[64K]          │
│  volumes[64K]               │
│  asset_ids[64K]             │
│  sequence_nums[64K]         │
│  exchange_ids[64K]          │
│  flags_arr[64K]             │
└─────────────────────────────┘
        │
        │  batch_view() / consume_batch()
        ▼
┌─────────────────────────────┐
│  hot_path_thread            │  production_main.cpp
│  (Core 1, SCHED_FIFO RT)    │
│                             │
│  tick_to_orderbook()        │  ~3ns SOA → NanoOrderBook
│  nexus.process_pipeline_e2e │  ~50ns DFA+Neural+VPIN
│  order_router.route_signal  │  ~50ns OrderRouter
└─────────────────────────────┘
```

---

## Arquivos do Módulo

### `hornet_config.hpp`
Configuração compile-time centralizada. Zero magic numbers no código.

| Constante | Valor | Significado |
|-----------|-------|-------------|
| `MARKET_DATA_PORT_UDP` | 9999 | Porta do feed HornetBinaryTick |
| `FIX_PORT_UDP` | 8888 | FIX sobre UDP (futuro) |
| `ITCH_PORT_UDP` | 20305 | NASDAQ ITCH 5.0 (futuro) |
| `UMEM_FRAME_SIZE` | 2048 | 2KB por frame (suporta MTU=1500) |
| `UMEM_NUM_FRAMES` | 262144 | 256K frames |
| `UMEM_TOTAL_SIZE` | 512MB | UMEM total (requer hugepages) |
| `XDP_RX_RING_SIZE` | 4096 | Rx ring: 4K descritores (power-of-2) |
| `SOA_RING_CAPACITY` | 65536 | 64K slots no SOA Ring |
| `POLL_BATCH_SIZE` | 64 | Frames por iteração do poll loop |

Modos configuráveis:
```cpp
enum class XdpMode   : uint8_t { ZERO_COPY = 0, COPY = 1 };
enum class FilterMode: uint8_t { STRICT = 0, PERMISSIVE = 1 };
```

---

### `umem_numa_allocator.hpp`
Aloca o UMEM (memória compartilhada NIC↔user space) usando HugePages NUMA-aware.

**Estratégia de alocação (melhor → pior):**
1. **1GB HugePages** — 1 entrada TLB por GB, zero TLB pressure
2. **2MB HugePages** — padrão HFT (`nr_hugepages`)
3. **4KB normais** — fallback de emergência

**Pré-requisitos do sistema:**
```bash
echo 256 > /proc/sys/vm/nr_hugepages          # 512MB com 2MB pages
echo 1   > /proc/sys/vm/nr_hugepages_1g       # para 1GB pages
ulimit -l unlimited                            # mlock sem limite
```

**`UmemFramePool` — Treiber Stack lock-free:**
- `push()` / `pop()` em ~5ns (CAS atômico)
- Gerencia a circulação de frames entre Fill Ring e Rx Ring
- Elástico: carga baixa → menos frames no Fill Ring → menos memória ativa

**`UmemNuma` — Interface principal:**
```cpp
UmemNuma umem;
umem.initialize();            // aloca hugepages + registra xsk_umem
void* p = umem.frame_ptr(offset);  // ponteiro para frame no UMEM
umem.shutdown();
```

---

### `AfXdpHornetPoint.hpp / AfXdpHornetPoint.cpp`
Controla o socket AF_XDP e o poll loop de captura.

**Dependências externas:** `libxdp`, `libbpf`

**Interface:**
```cpp
AfXdpHornetPoint hornet;
hornet.initialize("eth0", queue_id=0, umem, XdpMode::ZERO_COPY, busy_poll=true);
hornet.load_bpf_program("xdp_hornet_filter.o", FilterMode::STRICT);
hornet.set_rx_callback(bridge.as_rx_callback());
hornet.start_poll_loop();   // bloqueia — rodar em thread dedicada
hornet.shutdown();
```

**Poll loop (busy-poll):**
```
while (!shutdown) {
    drain Rx Ring em batch de 64 frames
    para cada frame: rx_callback(umem, frame)
    repõe Fill Ring com frames livres do pool
    // sem sleep, sem syscall, sem yield
}
```

**`RxFrameInfo`:**
```cpp
struct RxFrameInfo {
    uint64_t umem_offset;  // posição do frame no UMEM
    uint32_t len;          // tamanho total do frame
    uint32_t options;      // metadados zerocopy
};
```

---

### `HornetQuantumBridge.hpp`
Converte frames UDP brutos (UMEM) em ticks estruturados no SOA Ring.

**Protocolo suportado: `HornetBinaryTick` (40 bytes, magic=0xC3BE)**

```
Offset  Tamanho  Campo
[0..1]    2B     magic: 0xC3BE
[2..3]    2B     asset_id
[4..7]    4B     sequence_num (detecção de gap)
[8..15]   8B     timestamp_ns (nanosegundos Unix)
[16..19]  4B     price_open  (× 1e-6)
[20..23]  4B     price_high  (× 1e-6)
[24..27]  4B     price_low   (× 1e-6)
[28..31]  4B     price_close (× 1e-6)
[32..39]  8B     volume      (× 1e-8)
          Total: 40 bytes
```

**Parse pipeline (~25ns total):**
```
Eth header → IPv4 check → UDP check → magic 0xC3BE check
→ ntohl todos os campos → gap detection → SoaRing::push_raw()
```

**Gap Detection:**
- `last_sequence_[asset_id & 0xFF]` — 256 assets, 1KB de estado em L1
- Gap incrementa `stats_.sequence_gaps` — risk manager pode agir
- Tick com gap ainda é processado (market data UDP sem retransmissão)

**`BridgeStats` (lock-free por instância):**
```cpp
frames_ingested      // total de frames processados
ticks_pushed         // ticks escritos no SOA Ring
ticks_dropped_ring   // drops por ring cheio (backpressure)
frames_invalid       // frames malformados
frames_unknown_proto // protocolo não reconhecido
sequence_gaps        // gaps de sequência detectados
bytes_processed      // bytes totais de payload
```

**`HornetSystem` — factory que conecta tudo:**
```cpp
HornetSystem sys(soa_ring);
sys.initialize("eth0", queue_id=0, "xdp_hornet_filter.o",
               XdpMode::ZERO_COPY, busy_poll=true, FilterMode::STRICT);
// Wiring interno automático:
// UmemNuma + AfXdpHornetPoint + HornetQuantumBridge conectados
// hornet.set_rx_callback(bridge.as_rx_callback()) já feito
```

---

### `HornetSoaRing.hpp`
Ring buffer SPSC lock-free em formato **Structure of Arrays (SOA)**.

**Por que SOA em vez de AOS?**
```
AOS (lento para SIMD):
  [{ts, open, high, low, close, vol}, ...]
  → SIMD precisa scatter/gather

SOA (ideal para SIMD):
  timestamps_ns[0..65535]
  prices_open[0..65535]
  prices_high[0..65535]
  ...
  → SIMD carrega 8 preços por instrução AVX-512 (ou 4 com AVX2)
  → Prefetch de um array não polui cache dos outros
```

**Layout de memória:**
- Capacidade: 65536 slots (power-of-2, máscara com `&`)
- Cada array: `alignas(64)` — começa em cache line boundary
- Tamanho total: ~2.6MB → cabe na LLC de qualquer CPU moderna

**SPSC Lock-Free:**
- Producer: `HornetQuantumBridge` → avança `head_` após escrever todos os arrays
- Consumer: `hot_path_thread` → avança `tail_` após processar o batch
- Zero CAS, zero mutex — apenas `atomic<uint64_t>` com barreiras mínimas

**Backpressure:**
- Ring cheio → `push_raw()` retorna `false` → tick descartado
- Contador `dropped_` para telemetria
- Nunca bloqueia o poll loop (XDP não pode bloquear)

**`MarketTickView` — view zero-copy sobre um slot:**
```cpp
struct MarketTickView {
    uint64_t timestamp_ns;
    uint32_t price_open;    // × 1e-6 (int → sem FP no hot path)
    uint32_t price_high;
    uint32_t price_low;
    uint32_t price_close;
    uint64_t volume;        // × 1e-8
    uint32_t asset_id;
    uint32_t sequence_num;
    uint16_t exchange_id;
    uint8_t  flags;         // bit0=bid_ask_imbalance, bit1=large_print
    uint8_t  _pad;

    double open()  const noexcept { return price_open  * 1e-6; }
    double high()  const noexcept { return price_high  * 1e-6; }
    double low()   const noexcept { return price_low   * 1e-6; }
    double close() const noexcept { return price_close * 1e-6; }
    double vol()   const noexcept { return volume      * 1e-8; }
};
```

**API do consumer:**
```cpp
auto batch = soa_ring.batch_view(POLL_BATCH_SIZE);  // sem cópia
for (uint64_t i = 0; i < batch.count; ++i) {
    const size_t idx = (batch.start_idx + i) & SOA_RING_MASK;
    const MarketTickView tick { soa_ring.timestamps_ns[idx], ... };
    // processamento
}
soa_ring.consume_batch(batch.count);  // avança tail_
```

---

### `kernel/xdp_hornet_filter.c`
Programa eBPF que roda no kernel e toma decisões por pacote em ~50ns.

**Compilação:**
```bash
clang -O2 -target bpf -D__TARGET_ARCH_x86_64 \
      -I/usr/include/x86_64-linux-gnu \
      -c kernel/xdp_hornet_filter.c -o xdp_hornet_filter.o
```

**BPF Maps:**
| Map | Tipo | Uso |
|-----|------|-----|
| `xsks_map` | `XSKMAP` | AF_XDP sockets por queue_id (redirect target) |
| `config_map` | `ARRAY[1]` | Configuração runtime (portas, modo) |
| `stats_map` | `PERCPU_ARRAY[4]` | Contadores per-CPU (sem false sharing) |

**Hierarquia de decisão:**
```
1. UDP dest_port == market_data_port (9999) → XDP_REDIRECT → AF_XDP
2. UDP dest_port == fix_port (8888)         → XDP_REDIRECT → AF_XDP
3. UDP dest_port == itch_port (20305)       → XDP_REDIRECT → AF_XDP
4. TCP dest_port == SSH (22)               → XDP_PASS
5. TCP dest_port == 443/80 (HTTP/S)        → XDP_PASS  ← Binance WSS passa por aqui
6. ICMP                                    → XDP_PASS
7. [STRICT mode] qualquer outro            → XDP_DROP
8. [PERMISSIVE mode]                       → XDP_PASS
```

> **NOTA:** O tráfego Binance WebSocket (TLS porta 9443/443) é passado para o kernel stack (`XDP_PASS`), **não capturado** pelo AF_XDP. O XDP foi projetado para feeds UDP co-located, não para WebSocket remoto.

**Contadores de telemetria (per-CPU):**
```c
#define STAT_REDIRECTED  0   // pacotes → AF_XDP
#define STAT_PASSED      1   // pacotes → kernel stack
#define STAT_DROPPED     2   // pacotes descartados
#define STAT_ERRORS      3   // headers malformados
```

---

## Protocolo de Feed: HornetBinaryTick

Para usar o path XDP em produção, é necessário um **servidor normalizador co-located** que converta o feed da exchange para o protocolo `HornetBinaryTick` UDP.

```
Exchange (Binance / co-located)
        │
        │  WebSocket / FIX / ITCH
        ▼
┌──────────────────────────┐
│  Normalizador / Gateway  │  (processo separado, mesmo rack)
│  (ex: feed_normalizer.py │
│   ou feed_normalizer.cpp)│
│                          │
│  Converte → HornetBinaryTick │
│  Envia UDP:9999 → NIC    │
└──────────────────────────┘
        │  UDP:9999
        ▼
       NIC
        │  AF_XDP
        ▼
   HornetSystem
```

O `HornetBinaryTick` é o "barramento interno" do sistema — um formato proprietário de 40 bytes otimizado para parsing em ~5ns.

---

## Ativação em `production_main.cpp`

O path XDP **não está ativo** por default. O sistema usa `BinanceFeedAdapter` (WebSocket) por padrão. Para ativar o XDP:

```cpp
// Após inicialização do soa_ring, antes de lançar threads:
#include "XDP/HornetQuantumBridge.hpp"

std::optional<hornet::HornetSystem> xdp_sys;
if (use_xdp_flag) {
    xdp_sys.emplace(soa_ring);
    if (!xdp_sys->initialize("eth0", 0, "xdp_hornet_filter.o",
                              hornet::XdpMode::ZERO_COPY,
                              true,
                              hornet::FilterMode::STRICT)) {
        fprintf(stderr, "[WARN] XDP init falhou — fallback WebSocket\n");
        xdp_sys.reset();
    }
}

// Lançar poll loop em thread dedicada (Core 0):
if (xdp_sys) {
    std::thread t_xdp([&]() {
        pin_thread_to_core(layout.feed_core);
        promote_to_realtime(95);
        xdp_sys->hornet.start_poll_loop();
    });
}
```

**Requisitos para ativar XDP:**
- NIC com suporte AF_XDP (Intel X710/XXV710, Mellanox ConnectX-4+, etc.)
- `CAP_NET_ADMIN` (ou root)
- HugePages alocadas: `echo 256 > /proc/sys/vm/nr_hugepages`
- `libxdp` e `libbpf` instaladas
- eBPF compilado: `xdp_hornet_filter.o`
- Feed server enviando `HornetBinaryTick` UDP na porta 9999

---

## Telemetria

```cpp
// Bridge stats (a cada heartbeat)
xdp_sys->bridge.print_stats();
// [BRIDGE] Ingested=1000000 Pushed=999987 Dropped(ring)=0 Invalid=13 Gaps=2

// SOA Ring stats
soa_ring.print_stats();
// [RING] Produced=999987 Consumed=999987 Dropped=0 InFlight=0

// eBPF stats (via bpftool ou BPF map read):
// REDIRECTED=999987 PASSED=42 DROPPED=0 ERRORS=0
```

---

## Roadmap do Módulo XDP

| Item | Status |
|------|--------|
| HornetSoaRing SPSC SOA | Completo |
| HornetQuantumBridge parser | Completo |
| AfXdpHornetPoint poll loop | Completo |
| umem_numa_allocator hugepages | Completo |
| xdp_hornet_filter.c eBPF | Completo |
| HornetSystem factory | Completo |
| Integração em production_main | Pendente (XDP opcional) |
| **DepthRing** (L5 bid/ask real) | **Próximo — Prioridade 2** |
| HornetDepthTick (protocolo depth) | Pendente |
| ITCH 5.0 parser no Bridge | Futuro |
