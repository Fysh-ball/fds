# FDS native build.
#
# Ported from the upstream edslite CMakeLists (written for NDK r13b, 2016) to
# NDK 28.2.13676358 + CMake 3.22.1.
#
# Notes on the port:
#  * cmake_minimum_required raised 3.4.1 -> 3.22. CMake 3.22 deprecates <3.5
#    compatibility and CMake 4.x rejects it outright.
#  * project(... C) declares this as a C-only build. Upstream had no project()
#    call at all, which made CMake synthesise one with both C and CXX enabled
#    and probe for a C++ compiler that nothing here needs. Verified: no source
#    under src/main/native uses C++ (no std::, namespace, template, iostream).
#    The only "extern \"C\"" occurrences are inside #ifdef __cplusplus guards in
#    the checked-in JNI headers, which is plain C.
#  * No STL selection is made. The r13b-era gnustl/stlport knobs are gone from
#    modern NDKs and were never referenced here anyway.
#  * The two flavour include() files are now guarded. CMakeLists-full.txt and
#    CMakeLists-fsm.txt are 0-byte stubs left behind when the "full" and "fsm"
#    source sets were stripped from the public repo. They are kept and still
#    included so nothing changes for anyone who restores them, but a missing
#    file no longer breaks configure.

cmake_minimum_required(VERSION 3.22)

project(fds_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(ANDROID)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/main/native/crypto)

find_library(log-lib log)

# --- block ciphers ---------------------------------------------------------

add_library(edsaes SHARED
            src/main/native/aes/edsaes.c
            src/main/native/aes/aescrypt.c
            src/main/native/aes/aeskey.c
            src/main/native/aes/aestab.c)

target_link_libraries(edsaes ${log-lib})

add_library(edsserpent SHARED
            src/main/native/serpent/edsserpent.c
            src/main/native/serpent/serpent.c)

target_link_libraries(edsserpent ${log-lib})

add_library(edstwofish SHARED
            src/main/native/twofish/edstwofish.c
            src/main/native/twofish/twofish.c)

# edstwofish.c includes <android/log.h>; upstream never linked liblog into this
# target, which is a latent undefined-symbol at load time. Fixed here.
target_link_libraries(edstwofish ${log-lib})

add_library(edsgost SHARED
            src/main/native/gost/edsgost.c
            src/main/native/gost/gost89.c)

# Same latent liblog omission as edstwofish.
target_link_libraries(edsgost ${log-lib})

# --- hashes ----------------------------------------------------------------

add_library(edsripemd160 SHARED
            src/main/native/ripemd160/edsripemd160.c)

target_link_libraries(edsripemd160 ${log-lib})

add_library(edswhirlpool SHARED
            src/main/native/whirlpool/edswhirlpool.c
            src/main/native/whirlpool/whirlpool.c)

target_link_libraries(edswhirlpool ${log-lib})

# --- cipher modes ----------------------------------------------------------

add_library(edsxts SHARED
            src/main/native/xts/edsxts.c)

target_link_libraries(edsxts ${log-lib})

add_library(edsctr SHARED
            src/main/native/ctr/edsctr.c)

target_link_libraries(edsctr ${log-lib})

add_library(edscbc SHARED
            src/main/native/cbc/edscbc.c)

target_link_libraries(edscbc ${log-lib})

add_library(edscfb SHARED
            src/main/native/cfb/edscfb.c)

target_link_libraries(edscfb ${log-lib})

# --- file IO ---------------------------------------------------------------

add_library(fdraio SHARED
            src/main/native/fdraio/fdraio.c)

target_compile_definitions(fdraio PRIVATE _FILE_OFFSET_BITS=64)

target_link_libraries(fdraio ${log-lib})

add_library(localxts SHARED
            src/main/native/localxts/localxts.c)

target_compile_definitions(localxts PRIVATE _FILE_OFFSET_BITS=64)

target_link_libraries(localxts
                      edsxts
                      ${log-lib})

# --- stripped flavour source sets ------------------------------------------

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists-full.txt)
    include(${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists-full.txt)
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists-fsm.txt)
    include(${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists-fsm.txt)
endif()
