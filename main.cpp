// main.cpp
//
// Experimental harness for the secure aggregation simulator. Runs three
// experiment sweeps (varying client count, varying data size, comparing
// compression modes), measures per-stage compute time and communication
// volume, and verifies aggregation accuracy against the true plaintext sum.
//
// All raw measurements are written to CSVs under log_files/ for offline
// analysis.

#include "common.h"
#include "mk_ckks.h"
#include "client.h"
#include "server.h"
#include "masking.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// =================================================================================
// EXPERIMENT CONFIGURATION
// =================================================================================

// Sweep parameters used by all three experiments. Defaults match the
// publication-scale run; ::smoke() returns a tiny version for quick
// correctness checks (selectable via the --smoke CLI flag).
struct ExperimentSweepConfig {
    std::vector<int>      client_counts     = {10, 50, 100, 200, 350};
    uint32_t              exp1_data_size    = 65536;

    int                   exp2_client_count = 500;
    std::vector<uint32_t> data_sizes        = {4095, 8192, 16384, 32768, 50000, 65536};

    int                   exp3_client_count = 100;
    uint32_t              exp3_data_size    = 65536;

    static ExperimentSweepConfig smoke() {
        ExperimentSweepConfig c;
        c.client_counts     = {5};
        c.exp1_data_size    = 4096;
        c.exp2_client_count = 5;
        c.data_sizes        = {4096};
        c.exp3_client_count = 5;
        c.exp3_data_size    = 4096;
        return c;
    }
};

// =================================================================================
// HELPER FUNCTIONS FOR COMMUNICATION COST MEASUREMENT
// =================================================================================

// Serialized size of a representative MKCiphertext (c0, d) under this context.
size_t get_mkciphertext_size(CryptoContext<DCRTPoly>& cc, const DCRTPoly& crs_a) {
    auto params = cc->GetCryptoParameters()->GetElementParams();
    DCRTPoly dummy_plaintext(params, Format::EVALUATION, true);
    MKeyGenKeyPair dummy_keys = KeyGenSingle(cc, crs_a);

    MKCiphertext ct = Encrypt(cc, dummy_keys.pk, dummy_keys.sk, crs_a, dummy_plaintext);

    std::stringstream ss;
    lbcrypto::Serial::Serialize(ct.c0, ss, lbcrypto::SerType::BINARY);
    lbcrypto::Serial::Serialize(ct.d,  ss, lbcrypto::SerType::BINARY);
    return ss.str().size();
}

// Serialized size of a ClientShare — the real client uplink payload.
size_t get_client_share_size(const ClientShare& share) {
    std::stringstream ss;
    lbcrypto::Serial::Serialize(share.c0,       ss, lbcrypto::SerType::BINARY);
    lbcrypto::Serial::Serialize(share.d_masked, ss, lbcrypto::SerType::BINARY);
    return ss.str().size();
}

// =================================================================================
// FORWARD DECLARATION
// =================================================================================
void run_experiment(const std::string& experiment_name,
                    int numClients, uint32_t dataSize,
                    CompressionMode mode,
                    std::ofstream& compute_client_log,
                    std::ofstream& compute_server_log,
                    std::ofstream& comm_log,
                    std::ofstream& accuracy_log);

// =================================================================================
// MAIN ORCHESTRATOR
// =================================================================================

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [--smoke] [--help]\n"
              << "\n"
              << "  --smoke      Run a tiny configuration (5 clients, d=4096) covering all\n"
              << "               three experiments and all three compression modes. Finishes\n"
              << "               in under a minute; use for quick correctness checks.\n"
              << "  -h, --help   Show this message and exit.\n"
              << "\n"
              << "With no flags, runs the full publication-scale sweep (~1 hour).\n";
}

int main(int argc, char* argv[]) {
    ExperimentSweepConfig sweep;
    bool use_smoke = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--smoke") {
            use_smoke = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n\n";
            print_usage(argv[0]);
            return 2;
        }
    }
    if (use_smoke) sweep = ExperimentSweepConfig::smoke();

    std::cout << "Starting Secure Aggregation Performance Evaluation Harness"
              << (use_smoke ? "  [SMOKE TEST]" : "") << std::endl;

    std::string log_dir = "../log_files";
    try {
        std::filesystem::create_directory(log_dir);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating log directory: " << e.what() << std::endl;
        return 1;
    }

    std::ofstream compute_client_log(log_dir + "/log_computation_client.csv");
    compute_client_log << "Experiment,CompressionMode,NumClients,DataSize,RingDimension,ClientID,"
                          "T_KeyGen_MKCKKS_ms,T_KeyGen_ECDH_ms,T_KeyGen_Total_ms,"
                          "T_Encrypt_ms,T_MaskGen_ms,T_ClientTotal_ms\n";

    std::ofstream compute_server_log(log_dir + "/log_computation_server.csv");
    compute_server_log << "Experiment,CompressionMode,NumClients,DataSize,RingDimension,"
                          "T_Aggregate_ms,T_Decode_ms,T_ServerTotal_ms\n";

    std::ofstream comm_log(log_dir + "/log_communication_analysis.csv");
    comm_log << "Experiment,CompressionMode,PackFactor,QuantBits,NumClients,DataSize,RingDimension,"
                "PlaintextBytes,CiphertextBytes,ClientUplinkBytes,SetupBytes,FinalDownlinkBytes,"
                "CiphertextExpansion,CommExpansion\n";

    std::ofstream accuracy_log(log_dir + "/log_accuracy.csv");
    accuracy_log << "Experiment,CompressionMode,NumClients,DataSize,RingDimension,"
                    "Linf,RMSE,LinfRelative\n";

    std::cout << "\n=================================================================================="
              << "\n--- EXPERIMENT 1: SCALING NUMBER OF CLIENTS (Data Size = " << sweep.exp1_data_size << ") ---"
              << "\n==================================================================================" << std::endl;

    for (int numClients : sweep.client_counts) {
        run_experiment("ScalingClients", numClients, sweep.exp1_data_size,
                       CompressionMode::NONE,
                       compute_client_log, compute_server_log, comm_log, accuracy_log);
    }

    std::cout << "\n============================================================================"
              << "\n--- EXPERIMENT 2: SCALING DATA SIZE (Client Count = " << sweep.exp2_client_count << ") ---"
              << "\n============================================================================" << std::endl;

    for (uint32_t d : sweep.data_sizes) {
        run_experiment("ScalingDataSize", sweep.exp2_client_count, d,
                       CompressionMode::NONE,
                       compute_client_log, compute_server_log, comm_log, accuracy_log);
    }

    std::cout << "\n============================================================================"
              << "\n--- EXPERIMENT 3: COMPRESSION COMPARISON (N=" << sweep.exp3_client_count
              << ", d=" << sweep.exp3_data_size << ") ---"
              << "\n============================================================================" << std::endl;

    for (CompressionMode mode : {CompressionMode::NONE,
                                  CompressionMode::QUANTIZED,
                                  CompressionMode::BATCHCRYPT}) {
        run_experiment("CompressionComparison", sweep.exp3_client_count, sweep.exp3_data_size,
                       mode,
                       compute_client_log, compute_server_log, comm_log, accuracy_log);
    }

    std::cout << "\nAll experiments finished successfully." << std::endl;
    std::cout << "Raw data has been written under " << log_dir << "/." << std::endl;
    return 0;
}

// =================================================================================
// CORE EXPERIMENT RUNNER
// =================================================================================

void run_experiment(const std::string& experiment_name, int numClients, uint32_t dataSize,
                    CompressionMode mode,
                    std::ofstream& compute_client_log,
                    std::ofstream& compute_server_log,
                    std::ofstream& comm_log,
                    std::ofstream& accuracy_log) {

    CompressionConfig cfg = makeCompressionConfig(mode, numClients);

    uint32_t batchSize     = getRequiredBatchSize(dataSize, cfg);
    uint32_t ringDimension = getRequiredRingDim(dataSize, cfg);

    std::cout << "\n--- Running " << experiment_name
              << " [" << compressionModeName(cfg.mode) << "]"
              << " with N=" << numClients << ", d=" << dataSize
              << ", N_poly=" << ringDimension
              << ", scalingMod=" << cfg.scalingModSize
              << ", k=" << cfg.packFactor << " ---" << std::endl;

    // --- A. Per-run CryptoContext ---
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(ringDimension);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(cfg.scalingModSize);
    parameters.SetBatchSize(batchSize);
    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    // --- B. Setup: clients, server, keys ---
    DCRTPoly crs_a = GenerateCRS(cc);
    Server server(numClients);
    std::vector<Client> clients;
    clients.reserve(numClients);

    std::cout << "Generating keys for all " << numClients << " clients..." << std::endl;
    for (int i = 0; i < numClients; ++i) {
        clients.emplace_back(i);
        clients[i].generateKeys(cc, crs_a);
    }

    std::map<uint32_t, ECDHPublicKey> allPublicKeys;
    for (const auto& client : clients) {
        allPublicKeys[client.getId()] = client.getECDHPublicKey();
    }
    // Deserialize every peer key once; without this, mask generation
    // re-parses each peer key N times per protocol run.
    PeerKeyMap peer_keys = DeserializePeerKeys(allPublicKeys);
    std::cout << "Setup and KeyGen complete." << std::endl;

    ClientShare representative_share;
    ClientTimings last_client_timings;
    // True plaintext sum, computed in the same streaming pass so we never
    // hold all N client vectors in memory at once.
    std::vector<double> true_sum(dataSize, 0.0);

    // --- C. Streaming: process, accumulate true sum, collect share, log ---
    for (int i = 0; i < numClients; ++i) {
        clients[i].generateData(dataSize, -999.0, 999.0);
        const auto& d = clients[i].getData();
        for (uint32_t j = 0; j < dataSize; ++j) true_sum[j] += d[j];

        ClientResult client_result = clients[i].prepareShareForServer(cc, crs_a, peer_keys, cfg);

        if (i == 0) representative_share = client_result.share;
        server.collectShare(std::move(client_result.share));

        last_client_timings = client_result.timings;

        compute_client_log << experiment_name << "," << compressionModeName(cfg.mode) << ","
                           << numClients << "," << dataSize << "," << ringDimension << "," << i << ","
                           << last_client_timings.key_gen.t_mkckks_ms << ","
                           << last_client_timings.key_gen.t_ecdh_ms << ","
                           << last_client_timings.key_gen.t_total_ms << ","
                           << last_client_timings.t_encrypt_ms << ","
                           << last_client_timings.t_mask_gen_ms << ","
                           << last_client_timings.t_client_total_ms << std::endl;
    }
    std::cout << "All clients have prepared and sent shares." << std::endl;

    // --- D. Server-side aggregation + decode ---
    ServerResult server_result = server.getFinalResult(cc, dataSize, cfg);
    server_result.timings.t_server_total_ms =
        server_result.timings.t_aggregate_ms + server_result.timings.t_decode_ms;
    std::cout << "Server has aggregated and decoded the final result." << std::endl;

    // --- E. Accuracy verification ---
    const auto& computed = server_result.final_aggregated_vector;
    double linf = 0.0, sum_sq_err = 0.0, max_true_abs = 0.0;
    for (uint32_t j = 0; j < dataSize; ++j) {
        double err = computed[j] - true_sum[j];
        linf       = std::max(linf, std::abs(err));
        sum_sq_err += err * err;
        max_true_abs = std::max(max_true_abs, std::abs(true_sum[j]));
    }
    double rmse        = std::sqrt(sum_sq_err / dataSize);
    double linf_rel    = linf / std::max(1e-12, max_true_abs);

    // --- F. Communication cost ---
    size_t plaintext_bytes     = dataSize * sizeof(double);
    size_t ciphertext_bytes    = get_mkciphertext_size(cc, crs_a);
    size_t client_uplink_bytes = get_client_share_size(representative_share);
    size_t setup_bytes = 0;
    for (const auto& pair : allPublicKeys) setup_bytes += pair.second.size();

    size_t final_downlink_bytes = server_result.final_aggregated_vector.size() * sizeof(double);
    double ciphertext_expansion = static_cast<double>(ciphertext_bytes) / plaintext_bytes;
    size_t total_secure_per_client =
        (setup_bytes / numClients) + client_uplink_bytes + (final_downlink_bytes / numClients);
    double comm_expansion = static_cast<double>(total_secure_per_client) / plaintext_bytes;

    // --- G. Logging ---
    compute_server_log << experiment_name << "," << compressionModeName(cfg.mode) << ","
                       << numClients << "," << dataSize << "," << ringDimension << ","
                       << server_result.timings.t_aggregate_ms << ","
                       << server_result.timings.t_decode_ms << ","
                       << server_result.timings.t_server_total_ms << std::endl;

    comm_log << experiment_name << "," << compressionModeName(cfg.mode) << ","
             << cfg.packFactor << "," << cfg.quantBits << ","
             << numClients << "," << dataSize << "," << ringDimension << ","
             << plaintext_bytes << "," << ciphertext_bytes << "," << client_uplink_bytes << ","
             << setup_bytes << "," << final_downlink_bytes << ","
             << ciphertext_expansion << "," << comm_expansion << std::endl;

    accuracy_log << experiment_name << "," << compressionModeName(cfg.mode) << ","
                 << numClients << "," << dataSize << "," << ringDimension << ","
                 << linf << "," << rmse << "," << linf_rel << std::endl;

    // --- H. Console summary ---
    std::cout << "  Compute (last client):\n"
              << "    T_Encrypt: " << last_client_timings.t_encrypt_ms << " ms\n"
              << "    T_MaskGen: " << last_client_timings.t_mask_gen_ms << " ms\n";
    std::cout << "  Server: T_Aggregate " << server_result.timings.t_aggregate_ms
              << " ms, T_Decode " << server_result.timings.t_decode_ms << " ms\n";
    std::cout << "  Communication: uplink " << (client_uplink_bytes / 1024.0) << " KB, "
              << "ctxt expansion " << std::fixed << std::setprecision(2) << ciphertext_expansion << "x\n";
    std::cout << "  Accuracy vs true sum: Linf=" << std::scientific << std::setprecision(3) << linf
              << "  RMSE=" << rmse
              << "  Linf/max|true|=" << linf_rel << std::endl;
    std::cout.unsetf(std::ios::floatfield);
}
