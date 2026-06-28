// masking.cpp
//
// Implementation of the masking engine using OpenSSL for ECDH and ChaCha20.
// This engine is responsible for generating pairwise masks between clients
// such that the sum of all masks across the system is zero.

#include "masking.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>
#ifdef _OPENMP
#include <omp.h>
#endif

namespace {

// RAII deleters for OpenSSL contexts so partial-success error paths can throw
// without leaking. Using std::unique_ptr means callers don't have to remember
// EVP_*_free in every error branch.
struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

// PRG parameters. ChaCha20 takes a 256-bit key and a 128-bit IV (4-byte
// counter || 12-byte nonce in OpenSSL's encoding). We derive both from the
// ECDH shared secret via HKDF-SHA256 so the PRG key is uniform even though
// the X25519 output is a curve point, not random bytes.
constexpr size_t kPRGKeyBytes   = 32;
constexpr size_t kPRGNonceBytes = 16;
constexpr char   kPRGInfoLabel[] = "secure_fl/PRG/v1";

// HKDF-SHA256(secret, "", kPRGInfoLabel) -> 48 bytes (32 key || 16 nonce).
std::array<unsigned char, kPRGKeyBytes + kPRGNonceBytes>
deriveChaChaKey(const std::vector<unsigned char>& secret) {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr)};
    if (!ctx) throw std::runtime_error("HKDF: failed to allocate context");

    if (EVP_PKEY_derive_init(ctx.get()) <= 0)
        throw std::runtime_error("HKDF: derive_init failed");
    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("HKDF: failed to set hash");
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(),
                                   static_cast<int>(secret.size())) <= 0)
        throw std::runtime_error("HKDF: failed to set key");
    if (EVP_PKEY_CTX_add1_hkdf_info(
            ctx.get(),
            reinterpret_cast<const unsigned char*>(kPRGInfoLabel),
            static_cast<int>(sizeof(kPRGInfoLabel) - 1)) <= 0)
        throw std::runtime_error("HKDF: failed to set info");

    std::array<unsigned char, kPRGKeyBytes + kPRGNonceBytes> out{};
    size_t out_len = out.size();
    if (EVP_PKEY_derive(ctx.get(), out.data(), &out_len) <= 0
        || out_len != out.size())
        throw std::runtime_error("HKDF: derive failed");
    return out;
}

} // namespace

// --- Implementation of the EVP_PKEY_Deleter for smart pointers ---
// This enables SafePKey (std::unique_ptr) to automatically manage the memory
// of OpenSSL's EVP_PKEY objects, preventing memory leaks.
void EVP_PKEY_Deleter::operator()(EVP_PKEY* pkey) const {
    EVP_PKEY_free(pkey);
}

/**
 * @brief MODIFIED: Generates a fresh key pair using the X25519 curve.
 * X25519 is a modern, high-performance, and safer-by-design elliptic curve
 * that provides a 128-bit security level, aligning well with the FHE scheme.
 * @return A SafePKey (smart pointer) containing the newly generated key pair.
 */
SafePKey GenerateECDHKeys() {
    // --- MODIFICATION START ---
    // Instead of creating a generic EC context, we create one specifically
    // for the X25519 algorithm.
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for X25519");

    // Initialize the key generation process.
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to initialize keygen for X25519");
    }

    // The step of setting a specific curve name (like secp384r1) is no longer
    // needed, as the key type itself defines the curve.
    // --- MODIFICATION END ---

    // Generate the key pair.
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to generate X25519 key pair");
    }

    EVP_PKEY_CTX_free(pctx);
    // Wrap the raw pointer in a smart pointer for automatic memory management.
    return SafePKey(pkey);
}

/**
 * @brief Serializes an OpenSSL public key into a byte vector for network transmission.
 * This function is generic and works for X25519 keys as well.
 * @param keys A SafePKey containing the key pair.
 * @return A byte vector (ECDHPublicKey) holding the serialized public key.
 */
ECDHPublicKey SerializePublicKey(const SafePKey& keys) {
    unsigned char* buf = NULL;
    // i2d_PUBKEY converts the public key into a standard binary format (DER).
    size_t len = i2d_PUBKEY(keys.get(), &buf);
    if (len <= 0) {
        throw std::runtime_error("Failed to serialize public key");
    }
    ECDHPublicKey pubKeyBytes(buf, buf + len);
    OPENSSL_free(buf); // The buffer allocated by i2d_PUBKEY must be freed.
    return pubKeyBytes;
}

/**
 * @brief Deserializes a byte vector back into a usable OpenSSL public key object.
 * This function is generic and works for X25519 keys as well.
 * @param pubKeyBytes The byte vector containing the serialized key.
 * @return A SafePKey holding the deserialized public key.
 */
SafePKey DeserializePublicKey(const ECDHPublicKey& pubKeyBytes) {
    const unsigned char* p = pubKeyBytes.data();
    // d2i_PUBKEY parses the binary format back into an EVP_PKEY structure.
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &p, pubKeyBytes.size());
    if (!pkey) {
        throw std::runtime_error("Failed to deserialize public key");
    }
    return SafePKey(pkey);
}

/**
 * @brief Computes a shared secret using my private key and a peer's public key (ECDH).
 * This function is generic and works for X25519 keys as well.
 * @param myKeys My key pair (containing my private key).
 * @param peerPubKey The public key of the other party.
 * @return A byte vector containing the derived shared secret.
 */
std::vector<unsigned char> ComputeSharedSecret(const SafePKey& myKeys, const SafePKey& peerPubKey) {
    // Create a context for key derivation.
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(myKeys.get(), NULL);
    if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for derivation");

    // Initialize the derivation process.
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize derivation");
    }

    // Provide the peer's public key to perform the ECDH calculation.
    if (EVP_PKEY_derive_set_peer(ctx, peerPubKey.get()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set peer public key");
    }

    // Determine the required length of the shared secret.
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine secret length");
    }

    // Derive the secret and store it in the vector.
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to derive secret");
    }

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

/**
 * @brief Expands an ECDH shared secret into a pseudo-random DCRTPoly for masking.
 *
 * Two clients deriving the same shared secret produce the same DCRTPoly — that
 * symmetry is what makes the pairwise masks cancel when summed across all
 * clients. The flow is HKDF-SHA256(secret) -> 48 bytes -> ChaCha20(key, nonce)
 * keystream, which is then chunked into 64-bit coefficients and reduced
 * modulo each RNS tower's prime.
 *
 * std::memcpy is used to extract each uint64_t to avoid the strict-aliasing UB
 * that a reinterpret_cast<uint64_t*> on a byte buffer would invoke.
 */
DCRTPoly PRGToDCRTPoly(const std::vector<unsigned char>& seed, CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams();

    auto kdf_out = deriveChaChaKey(seed);
    const unsigned char* key = kdf_out.data();
    const unsigned char* iv  = kdf_out.data() + kPRGKeyBytes;

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) throw std::runtime_error("PRG: failed to allocate cipher context");
    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20(), nullptr, key, iv) != 1)
        throw std::runtime_error("PRG: EVP_EncryptInit_ex failed");

    const size_t bytes_per_tower = params->GetRingDimension() * sizeof(uint64_t);
    const size_t total_bytes = params->GetParams().size() * bytes_per_tower;
    std::vector<unsigned char> random_bytes(total_bytes, 0);

    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), random_bytes.data(), &out_len,
                          random_bytes.data(),
                          static_cast<int>(random_bytes.size())) != 1)
        throw std::runtime_error("PRG: EVP_EncryptUpdate failed");
    if (static_cast<size_t>(out_len) != random_bytes.size())
        throw std::runtime_error("PRG: short ChaCha20 keystream");

    DCRTPoly random_poly(params, Format::EVALUATION, true);
    size_t byte_offset = 0;

    for (size_t i = 0; i < params->GetParams().size(); ++i) {
        auto tower_params = params->GetParams()[i];
        NativeVector tower_vec(params->GetRingDimension(), tower_params->GetModulus());
        const NativeInteger& modulus = tower_params->GetModulus();

        for (size_t j = 0; j < params->GetRingDimension(); ++j) {
            uint64_t coeff;
            std::memcpy(&coeff, random_bytes.data() + byte_offset, sizeof(uint64_t));
            byte_offset += sizeof(uint64_t);
            tower_vec[j] = NativeInteger(coeff) % modulus;
        }

        NativePoly tower_poly(tower_params);
        tower_poly.SetValues(std::move(tower_vec), Format::EVALUATION);
        random_poly.SetElementAtIndex(i, std::move(tower_poly));
    }
    return random_poly;
}


PeerKeyMap DeserializePeerKeys(const std::map<uint32_t, ECDHPublicKey>& serialized) {
    PeerKeyMap out;
    for (const auto& kv : serialized) {
        out.emplace(kv.first, DeserializePublicKey(kv.second));
    }
    return out;
}

/**
 * @brief Generates the final additive mask for a single client.
 *
 * For each peer it derives a pairwise random polynomial p_ij and adds or
 * subtracts based on the ID comparison: if myId < peerId, subtract; if
 * myId > peerId, add. Since two peers derive the same p_ij from the same
 * shared secret, the global sum of every client's mask is zero.
 *
 * The per-peer loop is OpenMP-parallelized: each thread accumulates into a
 * private DCRTPoly to avoid contention, then those partial sums are
 * reduced sequentially. This keeps memory at O(num_threads · poly_size)
 * instead of O(num_peers · poly_size).
 */
DCRTPoly GenerateMask(uint32_t myId, const SafePKey& myKeys,
                      const PeerKeyMap& peer_keys,
                      CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams();

    // Flatten map into an indexable vector of peer IDs for OpenMP.
    std::vector<uint32_t> peerIds;
    peerIds.reserve(peer_keys.size());
    for (const auto& kv : peer_keys) {
        if (kv.first != myId) peerIds.push_back(kv.first);
    }

#ifdef _OPENMP
    int nthreads = omp_get_max_threads();
#else
    int nthreads = 1;
#endif
    std::vector<DCRTPoly> partial(nthreads, DCRTPoly(params, Format::EVALUATION, true));

#pragma omp parallel
    {
#ifdef _OPENMP
        int tid = omp_get_thread_num();
#else
        int tid = 0;
#endif
#pragma omp for schedule(dynamic)
        for (size_t i = 0; i < peerIds.size(); ++i) {
            uint32_t peerId = peerIds[i];
            const SafePKey& peerKey = peer_keys.at(peerId);
            auto sharedSecret = ComputeSharedSecret(myKeys, peerKey);
            DCRTPoly p_ij = PRGToDCRTPoly(sharedSecret, cc);
            if (myId < peerId) partial[tid] -= p_ij;
            else               partial[tid] += p_ij;
        }
    }

    DCRTPoly final_mask = std::move(partial[0]);
    for (int t = 1; t < nthreads; ++t) {
        final_mask += partial[t];
    }
    return final_mask;
}
