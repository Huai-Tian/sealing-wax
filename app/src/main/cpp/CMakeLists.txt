cmake_minimum_required(VERSION 3.22.1)
project("wax")

# Vendored libsodium (static) + vendored SPAKE2 + protocol core, linked into
# the JNI bridge.
add_subdirectory(libsodium)
add_subdirectory(spake2)
add_subdirectory(core)

add_library(${CMAKE_PROJECT_NAME} SHARED wax_jni.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE core)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE swx_core sodium)
