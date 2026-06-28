cmake_minimum_required(VERSION 3.10)

project(SecureAggregationSimulator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json for clangd / IDE tooling.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Performance flags for Release builds (NDEBUG comes from -DCMAKE_BUILD_TYPE=Release).
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -march=native)
endif()

# --- Find OpenFHE (CONFIG mode; expects OpenFHEConfig.cmake on CMAKE_PREFIX_PATH) ---
find_package(OpenFHE CONFIG REQUIRED)
message(STATUS "Found OpenFHE Version: ${OpenFHE_VERSION}")

# --- Find OpenSSL ---
find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL Version: ${OPENSSL_VERSION}")

# --- Main executable ---
add_executable(secure_aggregation_sim
    main.cpp
    compression.cpp
    mk_ckks.cpp
    client.cpp
    server.cpp
    masking.cpp
)

# OpenFHE's CONFIG file populates OpenFHE_INCLUDE (singular). All sub-includes live
# under that root, so the pke/core/binfhe subdirs are added explicitly for headers
# that use bare names like "key/keypair.h" rather than "pke/key/keypair.h".
target_include_directories(secure_aggregation_sim PRIVATE
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/binfhe
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(secure_aggregation_sim PRIVATE
    ${OpenFHE_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

find_package(OpenMP)
if(OpenMP_FOUND)
    message(STATUS "OpenMP found, enabling parallel execution.")
    target_link_libraries(secure_aggregation_sim PRIVATE OpenMP::OpenMP_CXX)
else()
    message(WARNING "OpenMP not found. The simulation will run on a single core.")
endif()

# --- Correctness oracle (ARC gate) ---
add_executable(test_correctness
    tests/test_correctness.cpp
    compression.cpp
    mk_ckks.cpp
    client.cpp
    server.cpp
    masking.cpp
)

target_include_directories(test_correctness PRIVATE
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/binfhe
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(test_correctness PRIVATE
    ${OpenFHE_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(OpenMP_FOUND)
    target_link_libraries(test_correctness PRIVATE OpenMP::OpenMP_CXX)
endif()

message(STATUS "SUCCESS: Configuration complete.")
