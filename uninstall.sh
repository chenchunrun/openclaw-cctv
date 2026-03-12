#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SERVICE_LABEL="com.openclaw.cctv"
INSTALL_DIR="/Library/Application Support/OpenClawCCTV"
LOG_DIR="/var/log/openclaw-cctv"
RUN_DIR="/var/run/openclaw-cctv"
POLICY_DIR="/etc/openclaw/security"
POLICY_FILE="$POLICY_DIR/SECURITY.md"
PLIST_DST="/Library/LaunchDaemons/com.openclaw.cctv.plist"
KEY_FILE="/etc/openclaw-cctv.key"
AUTH_KEY_FILE="/etc/openclaw-cctv.authkey"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] uninstall.sh must run as root"
    exit 1
  fi
}

unlock_flags() {
  local target="$1"
  [[ -e "$target" ]] || return 0
  chflags -R nouchg "$target" 2>/dev/null || true
  chflags -R noschg "$target" 2>/dev/null || true
}

main() {
  require_root

  launchctl bootout system/"$SERVICE_LABEL" >/dev/null 2>&1 || true
  launchctl disable system/"$SERVICE_LABEL" >/dev/null 2>&1 || true

  unlock_flags "$INSTALL_DIR"
  unlock_flags "$PLIST_DST"

  rm -f "$PLIST_DST"
  rm -rf "$INSTALL_DIR" "$RUN_DIR"

  if [[ "${1:-}" == "--purge-logs" || "${2:-}" == "--purge-logs" || "${3:-}" == "--purge-logs" ]]; then
    unlock_flags "$LOG_DIR"
    rm -rf "$LOG_DIR"
  fi

  if [[ "${1:-}" == "--purge-policy" || "${2:-}" == "--purge-policy" || "${3:-}" == "--purge-policy" ]]; then
    rm -f "$POLICY_FILE"
    rmdir "$POLICY_DIR" 2>/dev/null || true
  fi

  if [[ "${1:-}" == "--purge-key" || "${2:-}" == "--purge-key" || "${3:-}" == "--purge-key" ]]; then
    rm -f "$KEY_FILE" "$AUTH_KEY_FILE"
  fi

  echo "[+] OpenClaw CCTV uninstalled"
  echo "    logs preserved by default in: $LOG_DIR"
  echo "    policy preserved by default in: $POLICY_FILE"
}

main "$@"
