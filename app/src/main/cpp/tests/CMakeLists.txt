# Host test entry — build & run from the repository root:
#   cmake -S app/src/main/cpp/tests -B build/host -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/host -j && ctest --test-dir build/host --output-on-failure
cmake_minimum_required(VERSION 3.18)
project(swx_host_tests LANGUAGES C)

enable_testing()

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../libsodium"
                 "${CMAKE_CURRENT_BINARY_DIR}/libsodium")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../core"
                 "${CMAKE_CURRENT_BINARY_DIR}/core")

function(swx_add_test name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE swx_core sodium)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

swx_add_test(test_frame)
swx_add_test(test_session)

# Deterministic wire-spec vectors; self-verifies against the core and emits
# JSON to stdout (docs/vectors.json is the committed output).
add_executable(vector_gen vector_gen.c)
target_link_libraries(vector_gen PRIVATE swx_core sodium)
add_test(NAME vector_gen_selfcheck COMMAND vector_gen)
