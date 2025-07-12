cmake_minimum_required(VERSION 3.10)
project(haetae_provider C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL 3 REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/haetae_ref/include)

set(HAETAE_SOURCES
    haetae_ref/src/haetae_provider.c
    haetae_ref/src/haetae_keymgmt.c
    haetae_ref/src/haetae_signature.c
    haetae_ref/src/sign.c
    haetae_ref/src/randombytes.c
    haetae_ref/src/encoding.c
    haetae_ref/src/fips202.c
    haetae_ref/src/packing.c
    haetae_ref/src/poly.c
    haetae_ref/src/polyfix.c
    haetae_ref/src/polyvec.c
    haetae_ref/src/polymat.c
    haetae_ref/src/decompose.c
    haetae_ref/src/fixpoint.c
    haetae_ref/src/fft.c
    haetae_ref/src/ntt.c
    haetae_ref/src/reduce.c
    haetae_ref/src/sampler.c
    haetae_ref/src/symmetric-shake.c
)

add_library(haetae MODULE ${HAETAE_SOURCES})
set_target_properties(haetae PROPERTIES PREFIX "" SUFFIX ".so")

target_link_libraries(haetae PRIVATE OpenSSL::Crypto OpenSSL::SSL)

message(STATUS "Building HAETAE provider")
