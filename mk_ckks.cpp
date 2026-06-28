// mk_ckks.cpp
//
// Implementation of the MK-CKKS cryptographic engine. This file contains the
// definitions of all the core cryptographic functions.

#include "mk_ckks.h"

namespace {
// Standard deviation of the smudging noise added to the partial decryption
// share so the share itself leaks negligible information about the secret.
// 4.0 matches the value used in the MK-CKKS literature for these parameters.
constexpr double kPartialDecryptionNoiseStddev = 4.0;
} // namespace

/**
 * @brief Generates the Common Reference String (CRS), which is the shared polynomial 'a'.
 */
DCRTPoly GenerateCRS(CryptoContext<DCRTPoly>& cc) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    return DCRTPoly(dug, params, Format::EVALUATION);
}

/**
 * @brief Generates a single key pair for a client using the provided CRS.
 */
MKeyGenKeyPair KeyGenSingle(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    auto cryptoParams = std::dynamic_pointer_cast<const CryptoParametersRNS>(cc->GetCryptoParameters());
    auto& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DCRTPoly s_i(dgg, params, Format::EVALUATION);
    DCRTPoly e_i(dgg, params, Format::EVALUATION);
    DCRTPoly b_i = s_i.Negate() * crs_a + e_i;

    MKeyGenKeyPair kp;
    kp.sk.s = s_i;
    kp.pk.b = b_i;
    return kp;
}

/**
 * @brief Encodes a vector of doubles into a DCRTPoly using the official library encoder.
 */
DCRTPoly encodeVector(CryptoContext<DCRTPoly>& cc, const std::vector<double>& vec) {
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec);
    return ptxt->GetElement<DCRTPoly>();
}

/**
 * @brief Encrypts a plaintext under pk and immediately folds the secret key
 * into a partial decryption share. The returned struct's `d` field is that
 * share (not a CKKS c1) — Sum_i d_i + Sum_i c0_i decrypts to Sum_i m_i.
 */
MKCiphertext Encrypt(CryptoContext<DCRTPoly>& cc,
                     const MKeyGenPublicKey& pk,
                     const MKeyGenSecretKey& sk,
                     const DCRTPoly& crs_a,
                     const DCRTPoly& m) {
    auto cryptoParams = std::dynamic_pointer_cast<const CryptoParametersRNS>(cc->GetCryptoParameters());
    auto params = cc->GetCryptoParameters()->GetElementParams();
    auto& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    DCRTPoly v(dgg, params, Format::EVALUATION);
    DCRTPoly e0(dgg, params, Format::EVALUATION);
    DCRTPoly e1(dgg, params, Format::EVALUATION);

    DCRTPoly m_ntt = m;
    if (m_ntt.GetFormat() == Format::COEFFICIENT) {
        m_ntt.SwitchFormat();
    }

    MKCiphertext ct;
    ct.c0 = v * pk.b + m_ntt + e0;

    DCRTPoly intermediate_c1 = v * crs_a + e1;

    DiscreteGaussianGeneratorImpl<NativeVector> dgg_smudging(kPartialDecryptionNoiseStddev);
    DCRTPoly e_star(dgg_smudging, params, Format::EVALUATION);

    ct.d = intermediate_c1 * sk.s + e_star;

    return ct;
}

/**
 * @brief Decodes a raw DCRTPoly back into a vector of doubles using the OpenFHE API.
 */
std::vector<double> Decode(const DCRTPoly& finalPoly, CryptoContext<DCRTPoly>& cc, uint32_t dataSize) {
    KeyPair<DCRTPoly> tempKeys = cc->KeyGen();
    std::vector<double> dummy_vec = {0.0};
    Plaintext ptxt_template = cc->MakeCKKSPackedPlaintext(dummy_vec);
    Ciphertext<DCRTPoly> dummyCiphertext = cc->Encrypt(tempKeys.publicKey, ptxt_template);
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly c1_zero(params, Format::EVALUATION, true);
    dummyCiphertext->SetElements({finalPoly, c1_zero});
    Plaintext resultPlaintext;
    cc->Decrypt(tempKeys.secretKey, dummyCiphertext, &resultPlaintext);
    resultPlaintext->SetLength(dataSize);
    return resultPlaintext->GetRealPackedValue();
}
