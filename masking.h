// masking.h
//
// Header file for the masking engine. It declares all the functions
// for ECDH key exchange and ChaCha20-based mask generation.

#ifndef MASKING_H
#define MASKING_H

#include "common.h"

// Map of client ID -> deserialized peer public key, built once per protocol
// run so individual mask computations don't pay the deserialization cost
// each time. SafePKey is move-only; pass by const reference.
using PeerKeyMap = std::map<uint32_t, SafePKey>;

// Generates a new ECDH key pair using OpenSSL.
SafePKey GenerateECDHKeys();

// Serializes an ECDH public key into a byte vector for transmission.
ECDHPublicKey SerializePublicKey(const SafePKey& keys);

// Deserializes a byte vector back into an OpenSSL public key object.
SafePKey DeserializePublicKey(const ECDHPublicKey& pubKeyBytes);

// Parses every serialized peer key once. Call this at setup and reuse the
// returned map across all GenerateMask calls in the same protocol run.
PeerKeyMap DeserializePeerKeys(const std::map<uint32_t, ECDHPublicKey>& serialized);

// Computes a shared secret between my private key and a peer's public key.
std::vector<unsigned char> ComputeSharedSecret(const SafePKey& myKeys, const SafePKey& peerPubKey);

// Generates the final additive mask for a client. The inner per-peer loop
// (ECDH derive + ChaCha20 expand) is OpenMP-parallel; the outer caller
// should NOT run multiple clients concurrently in nested parallel regions.
DCRTPoly GenerateMask(uint32_t myId, const SafePKey& myKeys,
                      const PeerKeyMap& peer_keys,
                      CryptoContext<DCRTPoly>& cc);

#endif // MASKING_H
