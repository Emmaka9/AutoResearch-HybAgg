#!/bin/bash
#
# Build & run wrapper for the secure-aggregation simulator.
#
# Usage:
#   ./run.sh              # incremental rebuild + run (full sweep, ~1 hour)
#   ./run.sh --clean      # wipe build dir, configure from scratch, build, run
#   ./run.sh --no-run     # build only, skip the run step
#   ./run.sh --smoke      # build + run tiny config for quick correctness check
#   ./run.sh --test [N d] # build + run correctness oracle (ARC gate)

set -euo pipefail

BUILD_DIR="build"
CLEAN=0
RUN=1
TEST=0
BINARY_ARGS=()
TEST_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --clean)  CLEAN=1 ;;
        --no-run) RUN=0 ;;
        --smoke)  BINARY_ARGS+=("--smoke") ;;
        --test)   TEST=1 ;;
        -h|--help)
            sed -n '2,14p' "$0"; exit 0 ;;
        *)
            if [[ $TEST -eq 1 ]]; then
                TEST_ARGS+=("$arg")
            else
                echo "Unknown flag: $arg" >&2; exit 2
            fi ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
# Prefer a local .deps/openfhe; fall back to secure_fl's copy on the same machine.
if [[ -d "${PROJECT_ROOT}/.deps/openfhe" ]]; then
    OPENFHE_PATH="${PROJECT_ROOT}/.deps/openfhe"
else
    OPENFHE_PATH="${HOME}/secure_fl/.deps/openfhe"
fi

echo "Starting OpenFHE Secure Aggregation Build..."

if [[ $CLEAN -eq 1 || ! -d "${BUILD_DIR}" ]]; then
    echo "Configuring build directory: ./${BUILD_DIR}"
    rm -rf "${BUILD_DIR}"
    mkdir -p "${BUILD_DIR}"
    cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
        -DCMAKE_PREFIX_PATH="${OPENFHE_PATH}" \
        -DCMAKE_BUILD_TYPE=Release
fi

echo "Compiling with $(nproc) jobs..."
cmake --build "${BUILD_DIR}" --parallel "$(nproc)"

export LD_LIBRARY_PATH="${OPENFHE_PATH}/lib:${LD_LIBRARY_PATH:-}"

if [[ $TEST -eq 1 ]]; then
    echo "Running Hyb-Agg correctness oracle..."
    echo "--- Correctness Test Output ---"
    "${BUILD_DIR}/test_correctness" "${TEST_ARGS[@]}"
    echo "-------------------------------"
    echo "Correctness test complete."
elif [[ $RUN -eq 1 ]]; then
    echo "Running the secure aggregation simulation..."
    echo "--- Program Output ---"
    "${BUILD_DIR}/secure_aggregation_sim" "${BINARY_ARGS[@]}"
    echo "----------------------"
    echo "Build and run successful."
else
    echo "Build successful (run skipped)."
fi
