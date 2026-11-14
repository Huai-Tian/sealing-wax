# Vendored libsodium — https://github.com/jedisct1/libsodium
# Source: stable branch @ db1238f0a509de16b4bc323def5e68fdee78adda (1.0.22)
# Upstream license: ISC (see LICENSE in this directory). Do not modify upstream
# sources; build wiring lives in this file only.
#
# Compiled without a configure-generated config.h: all optional feature macros
# are #ifdef-guarded upstream and simply default off. CONFIGURED=1 only silences
# the "undocumented build method" warning. This keeps one recipe working for
# host tests (gcc/clang) and all Android ABIs (NDK clang) alike.

set(SWX_SODIUM_VERSION      "1.0.22")
set(SWX_SODIUM_LIBVER_MAJOR 26)
set(SWX_SODIUM_LIBVER_MINOR 4)

file(GLOB_RECURSE SWX_SODIUM_SRC CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/*.c")

add_library(sodium STATIC ${SWX_SODIUM_SRC})

# Generated flat (not under sodium/): version.c does #include "version.h"
# (quoted), which searches include paths for a file named exactly version.h.
# Its own quoted #include "export.h" resolves via include/sodium below.
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium/version.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/version.h" @ONLY)

target_include_directories(sodium PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium")
target_compile_definitions(sodium PRIVATE CONFIGURED=1)
