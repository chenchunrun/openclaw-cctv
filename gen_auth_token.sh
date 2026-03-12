#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

AUTH_KEY_FILE="/etc/openclaw-cctv.authkey"
TTL_SECONDS="${1:-120}"
MODE="${2:---export}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] gen_auth_token.sh must run as root" >&2
  exit 1
fi

if [[ ! -f "$AUTH_KEY_FILE" ]]; then
  echo "[!] auth key file missing: $AUTH_KEY_FILE" >&2
  exit 1
fi

ts_ms="$(python3 -c 'import time; print(int(time.time()*1000))')"
nonce="$(/usr/bin/openssl rand -hex 12)"
sig="$(TS_MS="$ts_ms" NONCE="$nonce" python3 - <<'PY'
import hashlib
import hmac
import os

key_path = "/etc/openclaw-cctv.authkey"
key = open(key_path, "r", encoding="utf-8").read().strip().encode("utf-8")
ts = os.environ["TS_MS"]
nonce = os.environ["NONCE"]
msg = f"{ts}:{nonce}".encode("utf-8")
print(hmac.new(key, msg, hashlib.sha256).hexdigest())
PY
)"

token="${ts_ms}:${nonce}:${sig}"
if [[ "$MODE" == "--raw" ]]; then
  echo "$token"
else
  echo "export OPENCLAW_SEC_AUTH='${token}'"
fi
echo "# valid for about ${TTL_SECONDS}s by policy" >&2
