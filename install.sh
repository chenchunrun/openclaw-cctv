#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SERVICE_LABEL="com.openclaw.cctv"
INSTALL_DIR="/Library/Application Support/OpenClawCCTV"
LOG_DIR="/var/log/openclaw-cctv"
RUN_DIR="/var/run/openclaw-cctv"
POLICY_DIR="/etc/openclaw/security"
POLICY_FILE="$POLICY_DIR/SECURITY.md"
PLIST_SRC="com.openclaw.cctv.plist"
PLIST_DST="/Library/LaunchDaemons/com.openclaw.cctv.plist"
KEY_FILE="/etc/openclaw-cctv.key"
AUTH_KEY_FILE="/etc/openclaw-cctv.authkey"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] install.sh must run as root"
    exit 1
  fi
}

best_effort_chflags_lock() {
  local target="$1"
  chflags uchg "$target" 2>/dev/null || true
  chflags schg "$target" 2>/dev/null || true
}

best_effort_chflags_unlock() {
  local target="$1"
  [[ -e "$target" ]] || return 0
  chflags -R nouchg "$target" 2>/dev/null || true
  chflags -R noschg "$target" 2>/dev/null || true
}

main() {
  require_root

  best_effort_chflags_unlock "$INSTALL_DIR"
  best_effort_chflags_unlock "$PLIST_DST"

  mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$RUN_DIR" "$POLICY_DIR"

  install -m 0755 cctv.py "$INSTALL_DIR/cctv.py"
  install -m 0755 watchdog.py "$INSTALL_DIR/watchdog.py"
  install -m 0644 logger.py "$INSTALL_DIR/logger.py"
  install -m 0644 rules.json "$INSTALL_DIR/rules.json"
  install -m 0755 gen_auth_token.sh "$INSTALL_DIR/gen_auth_token.sh"
  install -m 0644 SECURITY.md "$POLICY_FILE"
  install -m 0644 "$PLIST_SRC" "$PLIST_DST"

  if [[ ! -f "$KEY_FILE" ]]; then
    /usr/bin/openssl rand -hex 32 > "$KEY_FILE"
  fi

  if [[ ! -f "$AUTH_KEY_FILE" ]]; then
    /usr/bin/openssl rand -hex 32 > "$AUTH_KEY_FILE"
  fi

  chown -R root:wheel "$INSTALL_DIR" "$LOG_DIR" "$RUN_DIR" "$POLICY_DIR"
  chmod 0755 "$INSTALL_DIR"
  chmod 0750 "$LOG_DIR"
  chmod 0755 "$RUN_DIR"
  chmod 0755 "$POLICY_DIR"
  chmod 0644 "$POLICY_FILE"
  chmod 0600 "$KEY_FILE" "$AUTH_KEY_FILE"

  touch "$LOG_DIR/audit.log" "$LOG_DIR/alerts.log" "$LOG_DIR/state.sha256" "$LOG_DIR/launchd.out.log" "$LOG_DIR/launchd.err.log"
  chmod 0640 "$LOG_DIR"/*.log "$LOG_DIR/state.sha256"
  chown root:wheel "$PLIST_DST"
  chmod 0644 "$PLIST_DST"

  launchctl bootout system/"$SERVICE_LABEL" >/dev/null 2>&1 || true
  launchctl bootstrap system "$PLIST_DST"
  launchctl enable system/"$SERVICE_LABEL"
  launchctl kickstart -k system/"$SERVICE_LABEL"

  best_effort_chflags_lock "$INSTALL_DIR"
  best_effort_chflags_lock "$PLIST_DST"

  echo "[+] OpenClaw CCTV installed"
  echo "    service: $SERVICE_LABEL"
  echo "    install: $INSTALL_DIR"
  echo "    policy : $POLICY_FILE"
  echo "    logs   : $LOG_DIR"
}

main "$@"
