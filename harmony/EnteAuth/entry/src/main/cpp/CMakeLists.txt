cmake_minimum_required(VERSION 3.5.0)
project(EnteAuthNative)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${NATIVERENDER_ROOT_PATH})

add_library(entry SHARED argon2/argon2_native.cpp)

target_compile_options(entry PRIVATE -O2)

target_link_libraries(entry PUBLIC libace_napi.z.so)
