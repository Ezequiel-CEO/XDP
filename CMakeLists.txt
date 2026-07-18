cmake_minimum_required(VERSION 3.20)
project(HornetXDP LANGUAGES C CXX)

# ═══════════════════════════════════════════════════════════════════════════════════
# 🔥 HORNET XDP MODULE — Build System
# ═══════════════════════════════════════════════════════════════════════════════════
# Dois targets independentes:
#   1. xdp_hornet_filter (eBPF/BPF — compilado com clang para target bpf)
#   2. hornet_xdp        (C++20 user space — linkado com libbpf + libxdp)
# ═══════════════════════════════════════════════════════════════════════════════════

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# ─────────────────────────────────────────────────────────────────────────────
# Dependências: libbpf, libxdp
# ─────────────────────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBXDP REQUIRED libxdp)

if(NOT LIBBPF_FOUND)
    message(FATAL_ERROR
        "libbpf não encontrado.\n"
        "Ubuntu/Debian: sudo apt install libbpf-dev\n"
        "Fedora/RHEL:   sudo dnf install libbpf-devel\n"
        "Arch:          sudo pacman -S libbpf\n")
endif()

if(NOT LIBXDP_FOUND)
    message(STATUS
        "libxdp não encontrado — usando fallback sem xdp_program__attach.\n"
        "Ubuntu/Debian: sudo apt install libxdp-dev\n"
        "Fedora/RHEL:   sudo dnf install libxdp-devel")
    set(LIBXDP_LIBRARIES "")
    set(LIBXDP_INCLUDE_DIRS "")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# 1. eBPF TARGET: xdp_hornet_filter.o
# ─────────────────────────────────────────────────────────────────────────────
# Requer clang (não gcc) para compilar BPF bytecode.
find_program(CLANG clang REQUIRED)
find_program(LLC llc REQUIRED)

set(BPF_SRC   "${CMAKE_CURRENT_SOURCE_DIR}/kernel/xdp_hornet_filter.c")
set(BPF_OBJ   "${CMAKE_CURRENT_BINARY_DIR}/xdp_hornet_filter.o")

# Detecta arquitetura para o define correto do kernel
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    set(BPF_ARCH_FLAG "-D__TARGET_ARCH_x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(BPF_ARCH_FLAG "-D__TARGET_ARCH_arm64")
else()
    set(BPF_ARCH_FLAG "")
endif()

# Inclui dir do kernel para headers BPF
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_RELEASE
    OUTPUT_STRIP_TRAILING_WHITESPACE)

set(KERNEL_HEADERS "/usr/include")  # Fallback padrão
if(EXISTS "/usr/src/linux-headers-${KERNEL_RELEASE}/include")
    set(KERNEL_HEADERS "/usr/src/linux-headers-${KERNEL_RELEASE}/include")
endif()

add_custom_command(
    OUTPUT  ${BPF_OBJ}
    COMMAND ${CLANG}
            -O2
            -target bpf
            ${BPF_ARCH_FLAG}
            -Wall
            -Wno-unused-value
            -Wno-pointer-sign
            -Wno-compare-distinct-pointer-types
            -I${KERNEL_HEADERS}
            -I${LIBBPF_INCLUDE_DIRS}
            -I/usr/include/x86_64-linux-gnu
            -c ${BPF_SRC}
            -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "🔥 Compilando eBPF: xdp_hornet_filter.c → xdp_hornet_filter.o"
    VERBATIM
)

add_custom_target(hornet_bpf ALL DEPENDS ${BPF_OBJ})

# ─────────────────────────────────────────────────────────────────────────────
# 2. C++20 USER SPACE TARGET: libhornet_xdp
# ─────────────────────────────────────────────────────────────────────────────
add_library(hornet_xdp STATIC
    AfXdpHornetPoint.cpp
)

target_include_directories(hornet_xdp
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..         # Acesso aos módulos GhostMode/DFA
        ${LIBBPF_INCLUDE_DIRS}
        ${LIBXDP_INCLUDE_DIRS}
)

target_link_libraries(hornet_xdp
    PUBLIC
        ${LIBBPF_LIBRARIES}
        ${LIBXDP_LIBRARIES}
)

# ─────────────────────────────────────────────────────────────────────────────
# Flags de compilação — máxima performance, zero undefined behavior
# ─────────────────────────────────────────────────────────────────────────────
set(HORNET_CXX_FLAGS
    # Otimização
    -O3
    -march=native            # Usa todas as extensões do CPU local (AVX-512, etc.)
    -mtune=native
    -funroll-loops
    -fomit-frame-pointer
    # Segurança / Hardening (compatível com HFT — sem sanitizers em prod)
    -fstack-protector-strong
    # Warnings como erros (qualidade de código)
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter    # Normal em callbacks com assinatura fixa
    # Atomics e threading
    -pthread
    # Link-Time Optimization
    -flto
)

target_compile_options(hornet_xdp PRIVATE ${HORNET_CXX_FLAGS})
target_compile_definitions(hornet_xdp PRIVATE
    NDEBUG                   # Ativa OMEGA_INLINE [[gnu::always_inline]]
    _GNU_SOURCE              # mbind, sched_getcpu, etc.
)

# LTO requer linker flags também
set_target_properties(hornet_xdp PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION TRUE
)

# ─────────────────────────────────────────────────────────────────────────────
# Instala o .o do BPF junto com os headers para deployment
# ─────────────────────────────────────────────────────────────────────────────
install(FILES ${BPF_OBJ} DESTINATION lib/hornet/bpf)
install(FILES
    hornet_config.hpp
    umem_numa_allocator.hpp
    HornetSoaRing.hpp
    AfXdpHornetPoint.hpp
    HornetQuantumBridge.hpp
    DESTINATION include/hornet
)

# ─────────────────────────────────────────────────────────────────────────────
# Print de configuração
# ─────────────────────────────────────────────────────────────────────────────
message(STATUS "══════════════════════════════════════════════")
message(STATUS "🔥 HORNET XDP MODULE")
message(STATUS "   Clang:     ${CLANG}")
message(STATUS "   libbpf:    ${LIBBPF_VERSION}")
message(STATUS "   libxdp:    ${LIBXDP_VERSION}")
message(STATUS "   Kernel:    ${KERNEL_RELEASE}")
message(STATUS "   BPF obj:   ${BPF_OBJ}")
message(STATUS "   Arch flag: ${BPF_ARCH_FLAG}")
message(STATUS "══════════════════════════════════════════════")