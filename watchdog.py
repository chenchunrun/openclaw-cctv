#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Watchdog for OpenClaw CCTV process."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import json
from pathlib import Path

from logger import AuditLogger

BASE_DIR = Path("/Library/Application Support/OpenClawCCTV")
CCTV_PATH = BASE_DIR / "cctv.py"
SECURITY_MD_PATH = Path("/etc/openclaw/security/SECURITY.md")
AUTH_KEY_PATH = Path("/etc/openclaw-cctv.authkey")
HEARTBEAT_PATH = Path("/var/run/openclaw-cctv/cctv.heartbeat")
PID_PATH = Path("/var/run/openclaw-cctv/cctv.pid")
AUDIT_LOG_PATH = Path("/var/log/openclaw-cctv/audit.log")
STATE_PATH = Path("/var/log/openclaw-cctv/state.sha256")
KEY_PATH = Path("/etc/openclaw-cctv.key")


class Watchdog:
    def __init__(self) -> None:
        self.logger = AuditLogger(str(AUDIT_LOG_PATH), str(STATE_PATH), str(KEY_PATH))

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0:
            print("watchdog.py must run as root", file=sys.stderr)
            raise SystemExit(1)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    @staticmethod
    def _read_pid() -> int:
        if not PID_PATH.exists():
            return -1
        try:
            return int(PID_PATH.read_text(encoding="utf-8").strip())
        except Exception:
            return -1

    @staticmethod
    def _heartbeat_age_sec() -> float:
        if not HEARTBEAT_PATH.exists():
            return float("inf")
        try:
            ts_ms = int(HEARTBEAT_PATH.read_text(encoding="utf-8").strip())
        except Exception:
            return float("inf")
        return max(0.0, time.time() - (ts_ms / 1000.0))

    @staticmethod
    def _policy_ready() -> bool:
        if not SECURITY_MD_PATH.exists() or not AUTH_KEY_PATH.exists():
            return False
        try:
            text = SECURITY_MD_PATH.read_text(encoding="utf-8")
            begin_marker = "<!-- POLICY_BEGIN -->"
            end_marker = "<!-- POLICY_END -->"
            if begin_marker not in text or end_marker not in text:
                return False
            segment = text.split(begin_marker, 1)[1].split(end_marker, 1)[0]
            lines = [ln.rstrip() for ln in segment.strip().splitlines()]
            if not lines or lines[0].strip() != "```json" or lines[-1].strip() != "```":
                return False
            policy = json.loads("\n".join(lines[1:-1]))
            auth = policy.get("auth", {})
            if str(auth.get("token_transport", "")).lower() != "env_only":
                return False
            if not auth.get("env_var_name") or not auth.get("hmac_key_file"):
                return False
            if not AUTH_KEY_PATH.read_text(encoding="utf-8").strip():
                return False
            return True
        except Exception:
            return False

    def _spawn_cctv(self) -> None:
        subprocess.Popen([sys.executable, str(CCTV_PATH)], close_fds=True)
        self.logger.write_event(
            event_type="watchdog_restart",
            pid=os.getpid(),
            user="root",
            command=str(CCTV_PATH),
            result="spawned",
        )

    def _stop_handler(self, signum: int, _frame) -> None:
        self.logger.write_event(
            event_type="watchdog_signal",
            pid=os.getpid(),
            user="root",
            result="received",
            details={"signal": signum},
        )
        raise SystemExit(0)

    def run(self) -> None:
        self._require_root()
        signal.signal(signal.SIGTERM, self._stop_handler)
        signal.signal(signal.SIGINT, self._stop_handler)

        self.logger.write_event(event_type="watchdog_start", pid=os.getpid(), user="root", result="ok")
        while True:
            if not self._policy_ready():
                self.logger.write_event(
                    event_type="watchdog_fail_closed",
                    pid=os.getpid(),
                    user="root",
                    result="policy_missing",
                    details={"security_md": str(SECURITY_MD_PATH), "auth_key": str(AUTH_KEY_PATH)},
                )
                time.sleep(5)
                continue

            pid = self._read_pid()
            hb_age = self._heartbeat_age_sec()
            if pid <= 0 or (not self._pid_alive(pid)) or hb_age > 15:
                self._spawn_cctv()
            time.sleep(3)


if __name__ == "__main__":
    Watchdog().run()
