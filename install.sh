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
SHARE_DIR="${PREFIX}/share/kshield/profiles"
SYSCONF_DIR="/etc"
SECCOMP_DIR="/var/lib/kubelet/seccomp"

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

# 2. Provision System Service Account & State Storage
echo "[INFO] Configuring system service account and vault directories..."
if ! getent group kshield >/dev/null 2>&1; then
  groupadd -r kshield
  echo "  [OK] Created system group: kshield"
fi

if ! getent passwd kshield >/dev/null 2>&1; then
  NOLOGIN_BIN="$(command -v nologin 2>/dev/null || echo "/usr/sbin/nologin")"
  [ -x "${NOLOGIN_BIN}" ] || NOLOGIN_BIN="/bin/false"
  useradd -r -g kshield -d /var/log/kshield -s "${NOLOGIN_BIN}" -c "KShield Daemon Service Account" kshield
  echo "  [OK] Created system user: kshield"
fi

# Ensure logging and WORM vault directories exist with secure ownership
mkdir -p /var/log/kshield/witness
touch /var/log/kshield/audit_chain.jsonl
chown -R kshield:kshield /var/log/kshield
chmod 755 /var/log/kshield
chmod 750 /var/log/kshield/witness
chmod 664 /var/log/kshield/audit_chain.jsonl
echo "  [OK] Vault state permissions configured in /var/log/kshield"

# 3. Install Daemons, Libraries and System Profiles
echo "[INFO] Installing daemon modules to ${LIB_DIR}..."
mkdir -p "${LIB_DIR}"
install -m 755 "${SCRIPT_DIR}/daemon/kshield_witness.py" "${LIB_DIR}/kshield_witness.py"
install -m 755 "${SCRIPT_DIR}/daemon/kshield_publisher.py" "${LIB_DIR}/kshield_publisher.py"
install -m 755 "${SCRIPT_DIR}/daemon/kshield_soak_monitor.py" "${LIB_DIR}/kshield_soak_monitor.py"
if [ -f "${SCRIPT_DIR}/daemon/requirements.txt" ]; then
  install -m 644 "${SCRIPT_DIR}/daemon/requirements.txt" "${LIB_DIR}/requirements.txt"
fi
echo "  [OK] Installed daemon modules"

mkdir -p "${SHARE_DIR}"
install -m 644 "${SCRIPT_DIR}/profiles/seccomp-kshield-default.json" "${SHARE_DIR}/seccomp-kshield-default.json"
echo "  [OK] Installed system profile to ${SHARE_DIR}/seccomp-kshield-default.json"

# 4. Install Seccomp Profile (if Kubelet or Docker/containerd present)
if [ -d "/var/lib/kubelet" ] || command -v kubelet >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1; then
  echo "[INFO] Detected Kubernetes / K3s environment. Installing Seccomp profile..."
  mkdir -p "${SECCOMP_DIR}"
  install -m 644 "${SCRIPT_DIR}/profiles/seccomp-kshield-default.json" "${SECCOMP_DIR}/seccomp-kshield-default.json"
  echo "  [OK] Installed Seccomp profile to ${SECCOMP_DIR}/seccomp-kshield-default.json"
fi

# 5. Optional Systemd Unit Templates
if [ -d "/etc/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
  echo "[INFO] Installing systemd unit files..."
  PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"
  for sfile in "${SCRIPT_DIR}/systemd/"*.service; do
    sed "s|/usr/local/bin/python3|${PYTHON_BIN}|g; s|/usr/bin/python3|${PYTHON_BIN}|g; s|/usr/local/lib/kshield|${LIB_DIR}|g" "${sfile}" > "/etc/systemd/system/$(basename "${sfile}")"
  done
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
