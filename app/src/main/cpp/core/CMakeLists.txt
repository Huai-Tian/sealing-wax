# 火漆 protocol core — pure C, zero Android dependencies, host-testable.
add_library(swx_core STATIC
    swx_frame.c
    swx_session.c
    swx_hash.c)
target_include_directories(swx_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(swx_core PUBLIC sodium)
