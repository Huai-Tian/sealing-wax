# Vendored SPAKE2 (BoringSSL spake25519 C port) — see README.md in this dir.
add_library(spake2 STATIC
    spake2.c
    sha512.c)
target_include_directories(spake2 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(spake2 PUBLIC sodium)
