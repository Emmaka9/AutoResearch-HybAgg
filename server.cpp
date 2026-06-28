// server.cpp
//
// Implementation of the Server class.

#include "server.h"
#include "mk_ckks.h"
#ifdef _OPENMP
#include <omp.h>
#endif

Server::Server(size_t expectedClients) {
    m_clientShares.reserve(expectedClients);
}

void Server::collectShare(const ClientShare& share) {
    m_clientShares.push_back(share);
}

void Server::collectShare(ClientShare&& share) {
    m_clientShares.push_back(std::move(share));
}

// Sums c0 and d_masked across all collected shares. Per-thread partial sums
// avoid contention; the final reduction is sequential because DCRTPoly += is
// not associative-stable enough for an OpenMP user-defined reduction without
// extra ceremony, and N rarely exceeds a few hundred threads' worth of work.
DCRTPoly Server::aggregateShares() {
    if (m_clientShares.empty()) {
        throw std::runtime_error("No client shares to aggregate.");
    }

    auto params = m_clientShares[0].c0.GetParams();

#ifdef _OPENMP
    int nthreads = omp_get_max_threads();
#else
    int nthreads = 1;
#endif
    std::vector<DCRTPoly> partial_c0(nthreads, DCRTPoly(params, Format::EVALUATION, true));
    std::vector<DCRTPoly> partial_d (nthreads, DCRTPoly(params, Format::EVALUATION, true));

#pragma omp parallel
    {
#ifdef _OPENMP
        int tid = omp_get_thread_num();
#else
        int tid = 0;
#endif
#pragma omp for schedule(static) nowait
        for (size_t i = 0; i < m_clientShares.size(); ++i) {
            partial_c0[tid] += m_clientShares[i].c0;
            partial_d [tid] += m_clientShares[i].d_masked;
        }
    }

    DCRTPoly result_c0 = std::move(partial_c0[0]);
    DCRTPoly result_d  = std::move(partial_d [0]);
    for (int t = 1; t < nthreads; ++t) {
        result_c0 += partial_c0[t];
        result_d  += partial_d [t];
    }

    // Sum_i c0_i + Sum_i (d_i + mask_i) = Sum_i (c0_i + d_i) + 0,
    // which decrypts to Sum_i plaintext_i.
    return result_c0 + result_d;
}

ServerResult Server::getFinalResult(CryptoContext<DCRTPoly>& cc, uint32_t dataSize, const CompressionConfig& cfg) {
    ServerResult result;
    Timer timer;

    timer.Start();
    DCRTPoly finalPoly = aggregateShares();
    result.timings.t_aggregate_ms = timer.Stop();

    timer.Start();
    // BATCHCRYPT packs k values into each CKKS slot, so we must decode the
    // full packed length (ceil(dataSize/k) rounded to a power of two) before
    // unpacking back to per-element sums.
    uint32_t decodeSize = (cfg.mode == CompressionMode::BATCHCRYPT)
        ? getRequiredBatchSize(dataSize, cfg)
        : dataSize;
    std::vector<double> decoded = Decode(finalPoly, cc, decodeSize);

    if (cfg.mode == CompressionMode::BATCHCRYPT) {
        auto sumQ = unpackSlots(decoded, dataSize, cfg);
        result.final_aggregated_vector = dequantize(sumQ, cfg);
    } else if (cfg.mode == CompressionMode::QUANTIZED) {
        result.final_aggregated_vector = dequantize(decoded, cfg);
    } else {
        result.final_aggregated_vector = decoded;
    }
    result.final_aggregated_vector.resize(dataSize);
    result.timings.t_decode_ms = timer.Stop();

    return result;
}
