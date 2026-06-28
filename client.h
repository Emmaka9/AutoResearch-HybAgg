#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "masking.h"

class Client {
public:
    explicit Client(uint32_t id);

    void generateKeys(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a);
    void generateData(uint32_t dataSize, double minVal = -10.0, double maxVal = 10.0);
    ClientResult prepareShareForServer(CryptoContext<DCRTPoly>& cc,
                                       const DCRTPoly& crs_a,
                                       const PeerKeyMap& peer_keys,
                                       const CompressionConfig& cfg);

    uint32_t getId() const;
    const std::vector<double>& getData() const;
    ECDHPublicKey getECDHPublicKey() const;

private:
    uint32_t m_id;
    MKeyGenKeyPair m_keys;
    SafePKey m_ecdhKeys;
    std::vector<double> m_data;
    KeyGenTimings m_keyGenTimings;
};

#endif // CLIENT_H
