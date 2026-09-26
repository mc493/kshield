#!/usr/bin/env bash
# ==============================================================================
# Project Aegis-Kernel (UKDF) Universal Production Installer
# Universal Linux Kernel Attack Surface Hardening & Dual-Witness Notary Engine
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"
LIB_DIR="${PREFIX}/lib/kshield"
SYSCONF_DIR="/etc"
SECONMP_DIR="/var/lib/kubelet/seccomp"

echo "═══════════════════════════════════════════════════════════════════════════"
echo "      [AEGIS-KERNEL]  PROJECT AEGIS-KERNEL (UKDF) UNIVERSAL SYSTEM INSTALLER          "
echo "═══════════════════════════════════════════════════════════════════════════"

# Check root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] Error: Installer must be run as root (or with sudo)." >&2
  exit 1
fi

# Detect Architecture
ARCH="$(uname -m)"
echo "[INFO] Detected Architecture: ${ARCH}"
case "${ARCH}" in
  x86_64|aarch64|arm64)
    echo "  [OK] Supported Architecture: ${ARCH}"
    ;;
  *)
    echo "  [WARN] Warning: Non-tier 1 architecture (${ARCH}). Supported with generic syscall fallbacks."
    ;;
esac

# 1. Install CLI Core
echo "[INFO] Installing kshield CLI binary to ${BIN_DIR}/kshield..."
mkdir -p "${BIN_DIR}"
install -m 755 "${SCRIPT_DIR}/bin/kshield" "${BIN_DIR}/kshield"
echo "  [OK] Installed ${BIN_DIR}/kshield"

# 2. Install Daemons and Libraries
echo "[INFO] Installing daemon modules to ${LIB_DIR}..."
mkdir -p "${LIB_DIR}"
install -m 755 "${SCRIPT_DIR}/daemon/kshield_witness.py" "${LIB_DIR}/kshield_witness.py"
install -m 755 "${SCRIPT_DIR}/daemon/kshield_soak_monitor.py" "${LIB_DIR}/kshield_soak_monitor.py"
echo "  [OK] Installed daemon modules"

# 3. Install Seccomp Profile (if Kubelet or Docker/containerd present)
if [ -d "/var/lib/kubelet" ] || command -v kubelet >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1; then
  echo "[INFO] Detected Kubernetes / K3s environment. Installing Seccomp profile..."
  mkdir -p "${SECONMP_DIR}"
  install -m 644 "${SCRIPT_DIR}/profiles/seccomp-kshield-default.json" "${SECONMP_DIR}/seccomp-kshield-default.json"
  echo "  [OK] Installed Seccomp profile to ${SECONMP_DIR}/seccomp-kshield-default.json"
fi

# 4. Optional Systemd Unit Templates
if [ -d "/etc/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
  echo "[INFO] Installing systemd unit files..."
  cp "${SCRIPT_DIR}/systemd/"*.service /etc/systemd/system/ 2>/dev/null || true
  cp "${SCRIPT_DIR}/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  echo "  [OK] Systemd service templates staged in /etc/systemd/system/"
fi

echo "───────────────────────────────────────────────────────────────────────────"
echo "[HEALTH] Verifying installation..."
"${BIN_DIR}/kshield" status

echo "═══════════════════════════════════════════════════════════════════════════"
echo "[SUCCESS] PROJECT AEGIS-KERNEL INSTALLED SUCCESSFULLY!"
echo "   • Run 'kshield audit' to assess kernel attack surface."
echo "   • Run 'kshield disarm --dry-run' to preview fail-closed protections."
echo "   • Run 'kshield verify-sandbox' to benchmark and verify syscall defense."
echo "   • Run 'kshield verify-ledger' to inspect dual-witness WORM consensus."
echo "═══════════════════════════════════════════════════════════════════════════"
