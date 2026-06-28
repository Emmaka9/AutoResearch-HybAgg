// compression.cpp

#include "compression.h"
#include <stdexcept>
#include <cmath>

namespace {

// Symmetric quantization levels: INT8 covers [-127, 127], INT16 [-32767, 32767].
// Using 127 (not 128) and 32767 (not 32768) preserves symmetry around zero.
constexpr int kInt8Levels  = 127;
constexpr int kInt16Levels = 32767;

// Constraint sources for BATCHCRYPT packing:
//   - kDoubleMantissaBits: an int64_t must fit losslessly in a double's
//     53-bit mantissa, so the packed value's MSB must be at bit ≤ 52.
//   - kCkksScalingOverheadBits: CKKS rescaling needs scalingModSize ≥
//     packed_bits + overhead to keep noise below the modulus.
//   - kCkksScalingMaxBits: scalingModSize must stay strictly < 60 in the
//     installed OpenFHE (validateParametersForCryptocontext enforces
//     14 ≤ scalingModSize < 60). The previous value of 120 produced
//     configurations that OpenFHE rejected at construction time.
constexpr int kDoubleMantissaBits      = 53;
constexpr int kCkksScalingOverheadBits = 16;
constexpr int kCkksScalingMaxBits      = 59;

// Default scalingModSize for full-precision (NONE) and INT16 (QUANTIZED) modes.
constexpr int kScalingModSizeNone      = 50;
constexpr int kScalingModSizeQuantized = 26;

uint32_t nextPow2(uint32_t n) {
    if (n == 0) return 1;
    if ((n & (n - 1)) == 0) return n;
    n--;
    n |= n >> 1; n |= n >> 2; n |= n >> 4; n |= n >> 8; n |= n >> 16;
    return n + 1;
}

void computePackFactor(CompressionConfig& cfg) {
    if (cfg.mode == CompressionMode::NONE) {
        cfg.packFactor     = 1;
        cfg.scalingModSize = kScalingModSizeNone;
        cfg.bitsPerDigit   = 0;
        return;
    }
    if (cfg.mode == CompressionMode::QUANTIZED) {
        cfg.quantBits      = 16;
        cfg.packFactor     = 1;
        cfg.scalingModSize = kScalingModSizeQuantized;
        cfg.bitsPerDigit   = 16;
        return;
    }
    // BATCHCRYPT: INT8 packing.
    cfg.quantBits         = 8;
    const int maxUnsigned = 2 * kInt8Levels;              // 254
    const int maxDigitSum = maxUnsigned * cfg.numClients;

    // B bits per digit: must fit maxDigitSum after aggregation across all clients,
    // with one bit of headroom.
    int B = static_cast<int>(std::ceil(std::log2(static_cast<double>(maxDigitSum + 1)))) + 1;

    // Constraint 1: packed value's high bit at B*(k-1) + (B-1) < 53 → k ≤ 53/B.
    int maxK_double  = static_cast<int>(std::floor(static_cast<double>(kDoubleMantissaBits) / B));
    // Constraint 2: scalingModSize = k*B + overhead ≤ max → k ≤ (max - overhead)/B.
    int maxK_scaling = (kCkksScalingMaxBits - kCkksScalingOverheadBits) / B;

    int k = std::max(1, std::min(maxK_double, maxK_scaling));
    cfg.packFactor     = k;
    cfg.bitsPerDigit   = B;
    cfg.scalingModSize = k * B + kCkksScalingOverheadBits;
}

} // namespace

CompressionConfig makeCompressionConfig(CompressionMode mode, int numClients) {
    CompressionConfig cfg;
    cfg.mode       = mode;
    cfg.numClients = numClients;
    computePackFactor(cfg);
    return cfg;
}

uint32_t getRequiredBatchSize(uint32_t dataSize, const CompressionConfig& cfg) {
    if (cfg.mode == CompressionMode::BATCHCRYPT && cfg.packFactor > 1) {
        uint32_t packedCount = (dataSize + static_cast<uint32_t>(cfg.packFactor) - 1)
                             / static_cast<uint32_t>(cfg.packFactor);
        return nextPow2(packedCount);
    }
    return nextPow2(dataSize);
}

uint32_t getRequiredRingDim(uint32_t dataSize, const CompressionConfig& cfg) {
    uint32_t batchSize = getRequiredBatchSize(dataSize, cfg);
    return (batchSize < 16384u) ? 16384u : 2u * batchSize;
}

std::vector<double> quantize(const std::vector<double>& data, const CompressionConfig& cfg) {
    int    levels = (cfg.quantBits == 8) ? kInt8Levels : kInt16Levels;
    double scale  = cfg.clipRange;
    std::vector<double> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        double clamped = std::max(-scale, std::min(scale, data[i]));
        result[i] = std::round(clamped / scale * static_cast<double>(levels));
    }
    return result;
}

std::vector<double> packSlots(const std::vector<double>& quantized, const CompressionConfig& cfg) {
    int      k          = cfg.packFactor;
    int      B          = cfg.bitsPerDigit;
    uint32_t n          = static_cast<uint32_t>(quantized.size());
    uint32_t packedSize = (n + static_cast<uint32_t>(k) - 1) / static_cast<uint32_t>(k);

    std::vector<double> result(packedSize, 0.0);
    for (uint32_t j = 0; j < packedSize; j++) {
        int64_t slot = 0;
        for (int l = 0; l < k; l++) {
            uint32_t idx = j * static_cast<uint32_t>(k) + static_cast<uint32_t>(l);
            int64_t unsigned_v = (idx < n)
                ? std::max(static_cast<int64_t>(0),
                           std::min(static_cast<int64_t>(2 * kInt8Levels),
                                    static_cast<int64_t>(std::round(quantized[idx])) + kInt8Levels))
                : int64_t{0};
            slot |= (unsigned_v << (B * l));
        }
        result[j] = static_cast<double>(slot);
    }
    return result;
}

std::vector<double> unpackSlots(const std::vector<double>& packed,
                                uint32_t originalSize,
                                const CompressionConfig& cfg) {
    int     k        = cfg.packFactor;
    int     B        = cfg.bitsPerDigit;
    int64_t baseMask = (int64_t{1} << B) - 1;
    int64_t offset   = static_cast<int64_t>(cfg.numClients) * kInt8Levels;

    std::vector<double> result(originalSize, 0.0);
    for (uint32_t j = 0; j < static_cast<uint32_t>(packed.size()); j++) {
        int64_t val = llround(packed[j]);
        for (int l = 0; l < k; l++) {
            uint32_t idx = j * static_cast<uint32_t>(k) + static_cast<uint32_t>(l);
            if (idx >= originalSize) break;
            int64_t digit = val & baseMask;
            result[idx]   = static_cast<double>(digit - offset);
            val >>= B;
        }
    }
    return result;
}

std::vector<double> dequantize(const std::vector<double>& sumQ, const CompressionConfig& cfg) {
    int    levels = (cfg.quantBits == 8) ? kInt8Levels : kInt16Levels;
    double scale  = cfg.clipRange / static_cast<double>(levels);
    std::vector<double> result(sumQ.size());
    for (size_t i = 0; i < sumQ.size(); i++) {
        result[i] = sumQ[i] * scale;
    }
    return result;
}

std::string compressionModeName(CompressionMode mode) {
    switch (mode) {
        case CompressionMode::NONE:       return "NONE";
        case CompressionMode::QUANTIZED:  return "QUANTIZED";
        case CompressionMode::BATCHCRYPT: return "BATCHCRYPT";
        default:                          return "UNKNOWN";
    }
}
