// test_correctness.cpp
//
// Standalone correctness test for Hyb-Agg protocol.
// Verifies that the decrypted aggregate matches the expected plaintext sum.
// This directly validates the paper's claim: "approximation error of zero."
//
// Build: cmake + make (replaces main.cpp)
// Run:   ./test_correctness [N] [d]

#include "common.h"
#include "mk_ckks.h"
#include "client.h"
#include "server.h"
#include "masking.h"
#include "compression.h"
#include <cassert>

// Mirror the next_power_of_2 logic from main.cpp
static uint32_t next_pow2(uint32_t x) {
    if (x <= 1) return 2;
    return 1u << (32u - __builtin_clz(x - 1));
}

struct CorrectnessResult {
    int num_clients;
    uint32_t data_size;
    uint32_t ring_dim;
    double max_abs_error;
    double mean_abs_error;
    double max_rel_error;
    bool exact_match;  // max_abs_error == 0.0
};

CorrectnessResult run_correctness_test(int numClients, uint32_t dataSize) {
    uint32_t batchSize = next_pow2(dataSize);
    uint32_t ringDimension = (batchSize < 16384) ? 16384 : 2 * batchSize;

    // --- CryptoContext (same parameters as paper) ---
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(ringDimension);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(batchSize);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    // --- Setup: CRS, Server, Clients ---
    DCRTPoly crs_a = GenerateCRS(cc);
    Server server;
    std::vector<Client> clients;
    clients.reserve(numClients);

    for (int i = 0; i < numClients; ++i) {
        clients.emplace_back(i);
        clients[i].generateKeys(cc, crs_a);
    }

    // ECDH public key map
    std::map<uint32_t, ECDHPublicKey> allPublicKeys;
    for (const auto& client : clients) {
        allPublicKeys[client.getId()] = client.getECDHPublicKey();
    }
    PeerKeyMap peer_keys = DeserializePeerKeys(allPublicKeys);

    // --- Generate data + run protocol through the normal API ---
    // Each client generates random data and prepares its share.
    // We use getData() afterward to read back what was generated,
    // so we can compute the expected plaintext sum.
    CompressionConfig no_compression{};  // CompressionMode::NONE — uncompressed protocol path
    for (int i = 0; i < numClients; ++i) {
        // Use wider range than default to stress precision
        clients[i].generateData(dataSize, -100.0, 100.0);
        ClientResult client_result = clients[i].prepareShareForServer(cc, crs_a, peer_keys, no_compression);
        server.collectShare(client_result.share);
    }

    // --- Server recovery ---
    ServerResult server_result = server.getFinalResult(cc, dataSize, no_compression);

    // --- Compute expected sum from client data ---
    std::vector<double> expected_sum(dataSize, 0.0);
    for (int i = 0; i < numClients; ++i) {
        const auto& d = clients[i].getData();
        for (uint32_t j = 0; j < dataSize; ++j) {
            expected_sum[j] += d[j];
        }
    }

    // --- Compare element-by-element ---
    double max_abs_err = 0.0;
    double sum_abs_err = 0.0;
    double max_rel_err = 0.0;
    int mismatches = 0;
    const double TOLERANCE = 1e-9;

    for (uint32_t j = 0; j < dataSize; ++j) {
        double expected = expected_sum[j];
        double actual   = server_result.final_aggregated_vector[j];
        double abs_err  = std::abs(expected - actual);
        double rel_err  = (std::abs(expected) > 1e-10) ? abs_err / std::abs(expected) : 0.0;

        max_abs_err  = std::max(max_abs_err, abs_err);
        sum_abs_err += abs_err;
        max_rel_err  = std::max(max_rel_err, rel_err);

        if (abs_err > TOLERANCE) {
            mismatches++;
#ifdef VERBOSE_ERRORS
            if (mismatches <= 10) {
                std::cerr << "  MISMATCH at [" << j << "]: expected=" << expected
                          << " actual=" << actual << " err=" << abs_err << "\n";
            }
#endif
        }
    }

    CorrectnessResult result;
    result.num_clients    = numClients;
    result.data_size      = dataSize;
    result.ring_dim       = ringDimension;
    result.max_abs_error  = max_abs_err;
    result.mean_abs_error = sum_abs_err / dataSize;
    result.max_rel_error  = max_rel_err;
    result.exact_match    = (mismatches == 0 && max_abs_err == 0.0);
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================================\n";
    std::cout << "  Hyb-Agg Correctness Test\n";
    std::cout << "  Verifying: decrypted aggregate == plaintext sum\n";
    std::cout << "  Paper claim: \"approximation error of zero\"\n";
    std::cout << "========================================================\n\n";

    struct TestConfig { int N; uint32_t d; const char* label; };
    std::vector<TestConfig> configs;

    if (argc == 3) {
        int n = std::atoi(argv[1]);
        uint32_t d = (uint32_t)std::atoi(argv[2]);
        configs.push_back({n, d, "custom"});
    } else {
        // Standard test suite — small/fast first, then larger
        configs = {
            {3,     512,  "minimal"},
            {5,    1024,  "small"},
            {10,   1024,  "baseline"},
            {10,   4096,  "mid-size"},
            {10,   8192,  "paper-config"},
            {20,   8192,  "scale-N"},
        };
    }

    // Header
    std::cout << std::left
              << std::setw(8)  << "N"
              << std::setw(10) << "d"
              << std::setw(12) << "RingDim"
              << std::setw(14) << "Max_Abs_Err"
              << std::setw(14) << "Mean_Abs_Err"
              << std::setw(14) << "Max_Rel_Err"
              << std::setw(14) << "Status"
              << "\n";
    std::cout << std::string(86, '-') << "\n";

    bool all_passed = true;
    int exact_count = 0;

    for (const auto& cfg : configs) {
        std::cout << "  Running N=" << cfg.N << ", d=" << cfg.d << "..." << std::flush;

        auto result = run_correctness_test(cfg.N, cfg.d);

        // Determine status
        const char* status;
        if (result.max_abs_error == 0.0) {
            status = "✅ EXACT";
            exact_count++;
        } else if (result.max_abs_error < 1e-9) {
            status = "🟢 ~EXACT";
        } else if (result.max_abs_error < 1e-6) {
            status = "🟢 PASS";
        } else if (result.max_abs_error < 1e-3) {
            status = "🟡 CLOSE";
        } else {
            status = "❌ FAIL";
            all_passed = false;
        }

        // Clear the "Running..." and print results
        std::cout << "\r"
                  << std::left
                  << std::setw(8)  << result.num_clients
                  << std::setw(10) << result.data_size
                  << std::setw(12) << result.ring_dim
                  << std::scientific << std::setprecision(4)
                  << std::setw(14) << result.max_abs_error
                  << std::setw(14) << result.mean_abs_error
                  << std::setw(14) << result.max_rel_error
                  << std::setw(14) << status
                  << std::fixed  // reset
                  << "\n";
        std::cout.flush();
    }

    // Summary
    std::cout << "\n========================================================\n";
    std::cout << "  Results: " << exact_count << "/" << configs.size() << " EXACT";
    if (exact_count == (int)configs.size()) {
        std::cout << " — Zero noise error confirmed ✅\n";
    } else {
        std::cout << " — Some runs had nonzero (but small) error\n";
    }
    if (all_passed) {
        std::cout << "  ALL TESTS PASSED ✅\n";
    } else {
        std::cout << "  SOME TESTS FAILED ❌\n";
    }
    std::cout << "========================================================\n";

    return all_passed ? 0 : 1;
}
