#!/usr/bin/env bash
# ==============================================================================
# reproduce-benchmark.sh — Turnkey Verification & Latency Micro-Benchmark Harness
# Project Aegis-Kernel (kshield) | Systems Architecture
#
# Builds and executes the kshield benchmark container with the kshield Seccomp
# filter applied (--security-opt seccomp=profiles/seccomp-kshield-default.json)
# to independently reproduce exploit gating and syscall latency measurements.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ITERATIONS=100000
MODE="container"
ENGINE=""
IMAGE_TAG="kshield-benchmark:local"

show_help() {
    cat << 'EOF'
Usage: ./scripts/reproduce-benchmark.sh [OPTIONS]

Options:
  --iterations <N>    Number of syscall benchmark iterations (default: 100000)
  --local             Run benchmark directly on local host (bypasses container)
  --engine <bin>      Explicit container engine to use (e.g. docker, podman)
  -h, --help          Display this help message and exit

Examples:
  ./scripts/reproduce-benchmark.sh
  ./scripts/reproduce-benchmark.sh --iterations 200000
  ./scripts/reproduce-benchmark.sh --local
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --local)
            MODE="local"
            shift
            ;;
        --engine)
            ENGINE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

if [[ "${MODE}" == "local" ]]; then
    echo "[INFO] Running benchmark directly on local host..."
    "${REPO_ROOT}/bin/kshield" verify-sandbox --iterations "${ITERATIONS}"
    exit 0
fi

# Detect container runtime engine
if [[ -z "${ENGINE}" ]]; then
    if command -v docker >/dev/null 2>&1; then
        ENGINE="docker"
    elif command -v podman >/dev/null 2>&1; then
        ENGINE="podman"
    else
        echo "[WARN] Neither docker nor podman found in PATH."
        echo "[INFO] Falling back to local host execution..."
        "${REPO_ROOT}/bin/kshield" verify-sandbox --iterations "${ITERATIONS}"
        exit 0
    fi
fi

SECCOMP_PROFILE="${REPO_ROOT}/profiles/seccomp-kshield-default.json"
DOCKERFILE="${REPO_ROOT}/docker/Dockerfile.benchmark"

if [[ ! -f "${SECCOMP_PROFILE}" ]]; then
    echo "[ERROR] Seccomp profile not found at: ${SECCOMP_PROFILE}" >&2
    exit 1
fi

if [[ ! -f "${DOCKERFILE}" ]]; then
    echo "[ERROR] Benchmark Dockerfile not found at: ${DOCKERFILE}" >&2
    exit 1
fi

echo "[INFO] Container Engine : ${ENGINE}"
echo "[INFO] Building Image   : ${IMAGE_TAG}"
"${ENGINE}" build -t "${IMAGE_TAG}" -f "${DOCKERFILE}" "${REPO_ROOT}"

echo ""
echo "[INFO] Executing Exploit-Gating & Micro-Benchmark in Sandbox..."
echo "[INFO] Active Profile   : ${SECCOMP_PROFILE}"
echo "-------------------------------------------------------------------------------"

"${ENGINE}" run --rm \
    --security-opt "seccomp=${SECCOMP_PROFILE}" \
    "${IMAGE_TAG}" \
    verify-sandbox --iterations "${ITERATIONS}"
