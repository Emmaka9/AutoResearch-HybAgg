// client.cpp
//
// Implementation of the Client class.

#include "client.h"
#include "mk_ckks.h"
#include "masking.h"

Client::Client(uint32_t id) : m_id(id) {}

void Client::generateKeys(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) {
    Timer timer;
    timer.Start();
    m_keys = KeyGenSingle(cc, crs_a);
    m_keyGenTimings.t_mkckks_ms = timer.Stop();

    timer.Start();
    m_ecdhKeys = GenerateECDHKeys();
    m_keyGenTimings.t_ecdh_ms = timer.Stop();

    m_keyGenTimings.t_total_ms = m_keyGenTimings.t_mkckks_ms + m_keyGenTimings.t_ecdh_ms;
}

void Client::generateData(uint32_t dataSize, double minVal, double maxVal) {
    // thread_local so std::random_device (slow, hits /dev/urandom) only fires
    // once per thread; subsequent calls reuse the seeded mt19937 state.
    thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_real_distribution<> distrib(minVal, maxVal);
    m_data.resize(dataSize);
    for (uint32_t i = 0; i < dataSize; ++i) {
        m_data[i] = distrib(gen);
    }
}

ClientResult Client::prepareShareForServer(CryptoContext<DCRTPoly>& cc,
                                           const DCRTPoly& crs_a,
                                           const PeerKeyMap& peer_keys,
                                           const CompressionConfig& cfg) {
    ClientResult result;
    Timer timer;

    result.timings.key_gen = m_keyGenTimings;

    // 1. Compress (quantize / pack) then encode and encrypt.
    timer.Start();
    std::vector<double> dataToEncode = m_data;
    if (cfg.mode != CompressionMode::NONE) {
        auto q = quantize(m_data, cfg);
        dataToEncode = (cfg.mode == CompressionMode::BATCHCRYPT) ? packSlots(q, cfg) : q;
    }
    DCRTPoly encoded_poly = encodeVector(cc, dataToEncode);
    MKCiphertext ciphertext = Encrypt(cc, m_keys.pk, m_keys.sk, crs_a, encoded_poly);
    result.timings.t_encrypt_ms = timer.Stop();

    // 2. Generate the additive mask from pre-deserialized peer keys.
    timer.Start();
    DCRTPoly mask = GenerateMask(m_id, m_ecdhKeys, peer_keys, cc);
    result.timings.t_mask_gen_ms = timer.Stop();

    // 3. Apply the mask to the partial decryption share and assemble the share.
    result.share.c0 = ciphertext.c0;
    result.share.d_masked = ciphertext.d + mask;

    result.timings.t_client_total_ms = result.timings.t_encrypt_ms + result.timings.t_mask_gen_ms;

    return result;
}

uint32_t Client::getId() const {
    return m_id;
}

const std::vector<double>& Client::getData() const {
    return m_data;
}

ECDHPublicKey Client::getECDHPublicKey() const {
    return SerializePublicKey(m_ecdhKeys);
}
