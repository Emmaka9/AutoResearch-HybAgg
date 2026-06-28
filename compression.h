// compression.h
//
// Quantization and slot-packing for reducing MK-CKKS communication overhead.
// Implements two modes:
//   QUANTIZED  — float64 → INT16, ~33% ciphertext size reduction
//   BATCHCRYPT — float64 → INT8 + slot packing via base-2^B encoding

#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <vector>
#include <cstdint>
#include <cmath>
#include <string>
#include <algorithm>

enum class CompressionMode { NONE, QUANTIZED, BATCHCRYPT };

struct CompressionConfig {
    CompressionMode mode           = CompressionMode::NONE;
    int             quantBits      = 16;    // 16 for QUANTIZED, 8 for BATCHCRYPT
    int             packFactor     = 1;     // CKKS slots packed per slot (filled by builder)
    double          clipRange      = 999.0; // matches default generateData range
    int             numClients     = 1;
    int             scalingModSize = 50;    // filled by builder
    int             bitsPerDigit   = 0;     // B, filled by builder
};

// Build a fully-populated config for `mode` with `numClients` participants.
// Prefer this over mutating numClients after construction — packFactor and
// scalingModSize depend on numClients and must be recomputed together.
CompressionConfig makeCompressionConfig(CompressionMode mode, int numClients);

// Number of CKKS slots needed (rounded up to next power of 2).
// Smaller than dataSize for BATCHCRYPT when packFactor > 1.
uint32_t getRequiredBatchSize(uint32_t dataSize, const CompressionConfig& cfg);

// Corresponding ring dimension: max(16384, 2 * batchSize)
uint32_t getRequiredRingDim(uint32_t dataSize, const CompressionConfig& cfg);

// Quantize float64 data → integer-valued doubles in [-levels, levels].
std::vector<double> quantize(const std::vector<double>& data, const CompressionConfig& cfg);

// BATCHCRYPT only: pack k quantized integers into one CKKS slot using base-2^B encoding.
// Input: quantized values in [-127, 127].
// Output: vector of length ceil(n/k) containing packed slot values.
std::vector<double> packSlots(const std::vector<double>& quantized, const CompressionConfig& cfg);

// BATCHCRYPT only: unpack aggregated packed slots back to per-element sums.
// Input: server-decoded slot values (sum over all clients).
// Output: sum of original quantized integers per position, length = originalSize.
std::vector<double> unpackSlots(const std::vector<double>& packed,
                                uint32_t originalSize,
                                const CompressionConfig& cfg);

// Map sum-of-quantized-integers → sum-of-original-floats.
std::vector<double> dequantize(const std::vector<double>& sumQ, const CompressionConfig& cfg);

std::string compressionModeName(CompressionMode mode);

#endif // COMPRESSION_H
