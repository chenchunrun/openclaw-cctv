#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/Library/Application Support/OpenClawCCTV"
LOG_DIR="/var/log/openclaw-cctv"
POLICY_FILE="/etc/openclaw/security/SECURITY.md"
SERVICE_LABEL="com.openclaw.cctv"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] harden_openclaw.sh must run as root"
    exit 1
  fi
}

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "[!] this hardening script is for macOS only"
    exit 1
  fi
}

detect_openclaw_users() {
  ps -axo user=,command= | awk 'tolower($0) ~ /openclaw/ {print $1}' | sort -u
}

validate_openclaw_presence() {
  local count
  count="$(pgrep -fal openclaw | wc -l | tr -d ' ')"
  if [[ "$count" == "0" ]]; then
    echo "[!] no running openclaw process found"
    echo "    continue anyway: CCTV will start and wait for openclaw process"
  else
    echo "[+] detected openclaw processes:"
    pgrep -fal openclaw || true
  fi
}

enforce_non_root_openclaw() {
  local root_count
  root_count="$(ps -axo user=,command= | awk 'tolower($0) ~ /openclaw/ && $1 == "root" {print $0}' | wc -l | tr -d ' ')"
  if [[ "$root_count" != "0" ]]; then
    echo "[!] openclaw is running as root. This breaks the non-admin isolation model."
    echo "    stop openclaw and rerun as a dedicated non-root user, then retry hardening."
    exit 1
  fi
}

check_openclaw_version_hint() {
  local ver
  ver="$(openclaw --version 2>/dev/null || true)"
  if [[ -z "$ver" ]]; then
    return 0
  fi
  echo "[+] openclaw version: $ver"
  if [[ "$ver" != *"2026.3."* ]]; then
    echo "[!] warning: this hardening profile is tuned for openclaw 2026.3.x behavior"
  fi
}

apply_runtime_hardening() {
  chown -R root:wheel "$INSTALL_DIR" "$LOG_DIR" /etc/openclaw/security
  chmod 0755 "$INSTALL_DIR"
  chmod 0750 "$LOG_DIR"
  chmod 0755 /etc/openclaw/security
  chmod 0640 "$LOG_DIR"/*.log "$LOG_DIR/state.sha256"
  chmod 0644 "$POLICY_FILE"
  chmod 0600 /etc/openclaw-cctv.key /etc/openclaw-cctv.authkey

  while read -r ouser; do
    [[ -n "$ouser" ]] || continue
    if [[ "$ouser" == "root" ]]; then
      echo "[!] warning: openclaw currently runs as root; CCTV cannot hide logs from root"
      continue
    fi
    if su -m "$ouser" -c "test -r $LOG_DIR/audit.log" >/dev/null 2>&1; then
      echo "[!] warning: user '$ouser' can read audit log, check ACL/permissions"
    else
      echo "[+] confirmed: user '$ouser' cannot read $LOG_DIR/audit.log"
    fi
  done < <(detect_openclaw_users)
}

verify_service() {
  launchctl print system/"$SERVICE_LABEL" >/dev/null
  echo "[+] service active: $SERVICE_LABEL"
}

main() {
  require_root
  require_macos
  validate_openclaw_presence
  enforce_non_root_openclaw
  check_openclaw_version_hint

  (cd "$ROOT_DIR" && ./install.sh)
  apply_runtime_hardening
  verify_service

  echo
  echo "[+] one-click hardening complete"
  echo "    policy loaded from: $POLICY_FILE"
  echo "    audit log path: $LOG_DIR/audit.log"
  echo "    token generator: $ROOT_DIR/gen_auth_token.sh"
}

main "$@"
