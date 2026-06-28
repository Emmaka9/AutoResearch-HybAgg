// common.h
//
// This header file defines all the shared data structures and common includes
// for the entire project. It acts as a central "dictionary" that all other
// modules use to communicate and understand each other's data types.

#ifndef COMMON_H
#define COMMON_H

// --- Library Includes ---
#include "pke/openfhe.h" // Your original, correct include path.
#include <openssl/evp.h> // For ECDH key objects
#include <vector>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <random>
#include <memory>    // For std::unique_ptr
#include <map>       // For std::map
#include <chrono>    // For high-resolution timing
#include <numeric>   // For std::accumulate
#include <stdexcept> // For std::runtime_error
#include <fstream>   // For CSV logging

#include "compression.h"

// Use the lbcrypto namespace for all OpenFHE types, as in your original design.
using namespace lbcrypto;

// --- Custom Data Structures for the MK-CKKS Protocol (Restored) ---

class MKeyGenSecretKey {
public:
    DCRTPoly s;
};

// The CRS polynomial `a` is shared by all clients and is passed explicitly
// to operations that need it (Encrypt, ...). Keeping a per-client copy here
// wasted O(N · ringDim · numTowers · 8) bytes at scale.
class MKeyGenPublicKey {
public:
    DCRTPoly b;
};

class MKeyGenKeyPair {
public:
    MKeyGenPublicKey pk;
    MKeyGenSecretKey sk;
};

// Output of the client-side Encrypt + PartialDecrypt step. `c0` is the
// CKKS first ciphertext component (v·b + m + e0); `d` is the partial
// decryption share ((v·a + e1)·s + e*), not a true ciphertext c1.
class MKCiphertext {
public:
    DCRTPoly c0;
    DCRTPoly d;
};

// High-resolution timer for instrumentation. Header-only so client.cpp,
// server.cpp, and any future consumer share a single definition.
class Timer {
public:
    void Start() { m_start = std::chrono::high_resolution_clock::now(); }
    double Stop() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - m_start).count();
    }
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_start;
};

// Represents the data a client sends to the server for aggregation.
struct ClientShare {
    DCRTPoly c0;
    DCRTPoly d_masked; // This now holds the masked value: d + r_i
};

// --- Custom Data Structures for the Masking Protocol (Restored) ---

struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* pkey) const;
};
using SafePKey = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using ECDHPublicKey = std::vector<unsigned char>;


// --- Data Structures for Performance Measurement ---

struct KeyGenTimings {
    double t_mkckks_ms{0.0};
    double t_ecdh_ms{0.0};
    double t_total_ms{0.0};
};

// MODIFIED: Cleaned up to reflect the new combined cryptographic step.
struct ClientTimings {
    KeyGenTimings key_gen;
    double t_encrypt_ms{0.0}; // This will now time the combined Encrypt operation
    // t_partial_dec_ms has been removed.
    double t_mask_gen_ms{0.0};
    double t_client_total_ms{0.0};
};

struct ClientResult {
    ClientShare share;
    ClientTimings timings;
};

struct ServerTimings {
    double t_aggregate_ms{0.0};
    double t_decode_ms{0.0};
    double t_server_total_ms{0.0};
};

struct ServerResult {
    std::vector<double> final_aggregated_vector;
    ServerTimings timings;
};

#endif // COMMON_H
