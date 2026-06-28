// mk_ckks.h
//
// Header file for the MK-CKKS cryptographic engine. It declares all the
// low-level functions for the custom multi-key CKKS protocol.

#ifndef MK_CKKS_H
#define MK_CKKS_H

#include "common.h"

// --- Function Declarations for the Crypto Engine ---

DCRTPoly GenerateCRS(CryptoContext<DCRTPoly>& cc);

MKeyGenKeyPair KeyGenSingle(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a);

DCRTPoly encodeVector(CryptoContext<DCRTPoly>& cc, const std::vector<double>& vec);

// Encrypts m under pk and folds in the partial decryption share with sk.
// `crs_a` is the shared CRS polynomial (one per system, not per client).
// The returned MKCiphertext's `d` field is the share, not a CKKS c1.
MKCiphertext Encrypt(CryptoContext<DCRTPoly>& cc,
                     const MKeyGenPublicKey& pk,
                     const MKeyGenSecretKey& sk,
                     const DCRTPoly& crs_a,
                     const DCRTPoly& m);

std::vector<double> Decode(const DCRTPoly& finalPoly, CryptoContext<DCRTPoly>& cc, uint32_t dataSize);

#endif // MK_CKKS_H
