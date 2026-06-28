#ifndef SERVER_H
#define SERVER_H

#include "common.h"

class Server {
public:
    Server() = default;
    explicit Server(size_t expectedClients);

    // Lvalue copy and rvalue move overloads — callers that produce a ClientShare
    // by value should std::move into the server to skip a polynomial copy.
    void collectShare(const ClientShare& share);
    void collectShare(ClientShare&& share);

    // Aggregates all collected shares and decodes the result. Returns the
    // plaintext sum vector and per-stage timings.
    ServerResult getFinalResult(CryptoContext<DCRTPoly>& cc, uint32_t dataSize, const CompressionConfig& cfg);

private:
    DCRTPoly aggregateShares();

    std::vector<ClientShare> m_clientShares;
};

#endif // SERVER_H
