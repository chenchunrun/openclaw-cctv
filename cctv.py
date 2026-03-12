#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""OpenClaw CCTV main monitor for process/file/network auditing on macOS."""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from logger import AuditLogger

BASE_DIR = Path("/Library/Application Support/OpenClawCCTV")
RULES_PATH = BASE_DIR / "rules.json"
SECURITY_MD_PATH = Path("/etc/openclaw/security/SECURITY.md")
HEARTBEAT_PATH = Path("/var/run/openclaw-cctv/cctv.heartbeat")
PID_PATH = Path("/var/run/openclaw-cctv/cctv.pid")
ALERT_PATH = Path("/var/log/openclaw-cctv/alerts.log")
AUDIT_LOG_PATH = Path("/var/log/openclaw-cctv/audit.log")
STATE_PATH = Path("/var/log/openclaw-cctv/state.sha256")
KEY_PATH = Path("/etc/openclaw-cctv.key")


class CCTVDaemon:
    def __init__(self) -> None:
        self.rules = self._load_rules()
        self.logger = AuditLogger(str(AUDIT_LOG_PATH), str(STATE_PATH), str(KEY_PATH))
        self.monitored: Dict[int, Dict[str, Any]] = {}
        self.file_integrity: Dict[str, str] = {}
        self._used_nonces: Dict[str, int] = {}

        self.security_policy = self._load_security_policy()
        self.auth_key = self._load_auth_key(self.security_policy)
        self._sensitive_patterns = self._compile_sensitive_patterns()
        self._init_integrity_map()

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0:
            print("cctv.py must run as root", file=sys.stderr)
            raise SystemExit(1)

    @staticmethod
    def _run(cmd: List[str]) -> str:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

    def _load_rules(self) -> Dict[str, Any]:
        with RULES_PATH.open("r", encoding="utf-8") as f:
            rules = json.load(f)
        return rules

    def _load_security_policy(self) -> Dict[str, Any]:
        if not SECURITY_MD_PATH.exists():
            raise RuntimeError(f"security policy missing: {SECURITY_MD_PATH}")

        text = SECURITY_MD_PATH.read_text(encoding="utf-8")
        begin_marker = "<!-- POLICY_BEGIN -->"
        end_marker = "<!-- POLICY_END -->"
        if begin_marker not in text or end_marker not in text:
            raise RuntimeError("SECURITY.md missing policy markers")

        segment = text.split(begin_marker, 1)[1].split(end_marker, 1)[0]
        lines = [ln.rstrip() for ln in segment.strip().splitlines()]
        if not lines or lines[0].strip() != "```json" or lines[-1].strip() != "```":
            raise RuntimeError("SECURITY.md policy block must be fenced json")

        policy = json.loads("\n".join(lines[1:-1]))
        self._validate_security_policy(policy)
        return policy

    @staticmethod
    def _validate_security_policy(policy: Dict[str, Any]) -> None:
        if not policy.get("enforce", False):
            raise RuntimeError("security policy enforce must be true")
        if not policy.get("fail_closed", False):
            raise RuntimeError("security policy fail_closed must be true")

        auth = policy.get("auth", {})
        for key in ["required_prefix", "token_ttl_seconds", "hmac_key_file", "token_transport", "env_var_name"]:
            if key not in auth:
                raise RuntimeError(f"security policy auth.{key} missing")
        if str(auth.get("token_transport", "")).lower() != "env_only":
            raise RuntimeError("security policy auth.token_transport must be env_only")

        for required_list_key in ["dangerous_command_patterns", "always_block_patterns"]:
            if not policy.get(required_list_key):
                raise RuntimeError(f"security policy {required_list_key} empty")

    @staticmethod
    def _load_auth_key(policy: Dict[str, Any]) -> bytes:
        key_file = Path(policy["auth"]["hmac_key_file"])
        if not key_file.exists():
            raise RuntimeError(f"auth key file missing: {key_file}")
        key = key_file.read_text(encoding="utf-8").strip()
        if not key:
            raise RuntimeError("auth key file empty")
        return key.encode("utf-8")

    @staticmethod
    def _compile_sensitive_patterns() -> List[Tuple[re.Pattern[str], str]]:
        return [
            (re.compile(r"SEC-AUTH:[^\s]+", re.IGNORECASE), "SEC-AUTH:****"),
            (re.compile(r"(OPENCLAW_SEC_AUTH=)([^\s\"']+)", re.IGNORECASE), r"\1****"),
            (re.compile(r"(Bearer\s+)[^\s]+", re.IGNORECASE), r"\1****"),
            (
                re.compile(
                    r"((?:--)?(?:password|passwd|token|secret|api[_-]?key|authorization)\s*[=:]\s*)([^\s]+)",
                    re.IGNORECASE,
                ),
                r"\1****",
            ),
            (
                re.compile(
                    r"((?:--)(?:password|passwd|token|secret|api[_-]?key)\s+)([^\s]+)",
                    re.IGNORECASE,
                ),
                r"\1****",
            ),
        ]

    def _sanitize_text(self, text: str) -> str:
        out = text
        for pattern, replacement in self._sensitive_patterns:
            out = pattern.sub(replacement, out)
        return out

    @staticmethod
    def _normalize_command(text: str) -> str:
        # Normalize mixed whitespace so pattern matching is not bypassed with tabs/newlines/multi-spaces.
        return re.sub(r"\s+", " ", text.strip()).lower()

    def _sanitize_any(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._sanitize_text(value)
        if isinstance(value, dict):
            return {str(k): self._sanitize_any(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_any(v) for v in value]
        return value

    def _write_event(
        self,
        *,
        event_type: str,
        pid: int | None = None,
        user: str | None = None,
        command: str = "",
        file_path: str = "",
        network: str = "",
        result: str = "ok",
        details: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return self.logger.write_event(
            event_type=event_type,
            pid=pid,
            user=user,
            command=self._sanitize_text(command),
            file_path=self._sanitize_text(file_path),
            network=self._sanitize_text(network),
            result=result,
            details=self._sanitize_any(details or {}),
        )

    def _init_integrity_map(self) -> None:
        for path in self.rules.get("integrity_files", []):
            self.file_integrity[path] = self._sha256_file(path)

    @staticmethod
    def _sha256_file(path: str) -> str:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return "MISSING"
        h = hashlib.sha256()
        try:
            with p.open("rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "UNREADABLE"

    @staticmethod
    def _username(uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except Exception:
            return str(uid)

    def _list_processes(self) -> List[Tuple[int, int, str]]:
        output = self._run(["ps", "-axo", "pid=,uid=,command="])
        items: List[Tuple[int, int, str]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                continue
            try:
                pid = int(parts[0])
                uid = int(parts[1])
            except ValueError:
                continue
            cmd = parts[2]
            items.append((pid, uid, cmd))
        return items

    def _is_target_process(self, cmd: str) -> bool:
        targets = self.rules.get("monitor_process", ["openclaw"])
        cmd_lower = cmd.lower()
        return any(t.lower() in cmd_lower for t in targets)

    def _collect_lsof_files_and_net(self, pid: int) -> Tuple[Set[str], Set[str]]:
        files: Set[str] = set()
        nets: Set[str] = set()
        try:
            output = self._run(["lsof", "-nP", "-p", str(pid)])
        except Exception:
            return files, nets

        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            fd_type = parts[4]
            name = parts[-1]
            if fd_type in {"REG", "DIR", "LINK"}:
                files.add(name)
            if fd_type in {"IPv4", "IPv6"}:
                nets.add(name)
        return files, nets

    def _matches_forbidden_file(self, path: str) -> bool:
        for pattern in self.rules.get("forbidden_files", []):
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def _alert(self, message: str, payload: Dict[str, Any]) -> None:
        safe_payload = self._sanitize_any(payload)
        line = json.dumps({"message": message, "payload": safe_payload}, ensure_ascii=True)
        with ALERT_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

        subprocess.run(["logger", "-t", "openclaw-cctv", line], check=False)

    def _write_heartbeat(self) -> None:
        HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
        HEARTBEAT_PATH.write_text(str(int(time.time() * 1000)) + "\n", encoding="utf-8")

    def _write_pid(self) -> None:
        PID_PATH.parent.mkdir(parents=True, exist_ok=True)
        PID_PATH.write_text(str(os.getpid()) + "\n", encoding="utf-8")

    def _maybe_kill(self, pid: int) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    def _token_in_argv(self, cmd: str) -> bool:
        prefix = self.security_policy["auth"]["required_prefix"]
        return bool(re.search(rf"{re.escape(prefix)}[^\s\"']+", cmd, flags=re.IGNORECASE))

    def _extract_token(self, cmd: str) -> str:
        env_var = self.security_policy["auth"]["env_var_name"]
        env_pattern = re.compile(rf"(?:^|\s){re.escape(env_var)}=(?:\"([^\"]+)\"|'([^']+)'|([^\s\"']+))")
        m = env_pattern.search(cmd)
        if not m:
            return ""
        token = m.group(1) or m.group(2) or m.group(3) or ""
        return token.strip()

    def _cleanup_nonces(self) -> None:
        now_ms = int(time.time() * 1000)
        ttl_ms = int(self.security_policy["auth"]["token_ttl_seconds"]) * 1000
        stale = [nonce for nonce, ts in self._used_nonces.items() if now_ms - ts > ttl_ms]
        for nonce in stale:
            self._used_nonces.pop(nonce, None)

    def _validate_auth_token(self, token: str) -> Tuple[bool, str]:
        parts = token.split(":")
        if len(parts) != 3:
            return False, "token_format_invalid"

        ts_str, nonce, sig = parts
        try:
            ts_ms = int(ts_str)
        except ValueError:
            return False, "token_timestamp_invalid"

        now_ms = int(time.time() * 1000)
        ttl_ms = int(self.security_policy["auth"]["token_ttl_seconds"]) * 1000
        if abs(now_ms - ts_ms) > ttl_ms:
            return False, "token_expired"

        if nonce in self._used_nonces:
            return False, "token_replay"

        expected = hmac.new(self.auth_key, f"{ts_ms}:{nonce}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False, "token_signature_invalid"

        self._used_nonces[nonce] = ts_ms
        self._cleanup_nonces()
        return True, "ok"

    def _check_security_contract(self, pid: int, uid: int, cmd: str) -> bool:
        user = self._username(uid)
        lower_cmd = self._normalize_command(cmd)

        for pattern in self.security_policy.get("always_block_patterns", []):
            if self._normalize_command(pattern) in lower_cmd:
                evt = self._write_event(
                    event_type="security_contract_violation",
                    pid=pid,
                    user=user,
                    command=cmd,
                    result="blocked",
                    details={"reason": "protected_asset_access_forbidden", "pattern": pattern},
                )
                self._alert("security contract violation", evt)
                if self.security_policy.get("kill_on_violation", True):
                    self._maybe_kill(pid)
                return False

        for pattern in self.security_policy.get("prohibited_reconfiguration_patterns", []):
            if self._normalize_command(pattern) in lower_cmd:
                evt = self._write_event(
                    event_type="security_contract_violation",
                    pid=pid,
                    user=user,
                    command=cmd,
                    result="blocked",
                    details={"reason": "reconfiguration_forbidden", "pattern": pattern},
                )
                self._alert("security contract violation", evt)
                if self.security_policy.get("kill_on_violation", True):
                    self._maybe_kill(pid)
                return False

        for pattern in self.security_policy.get("dangerous_command_patterns", []):
            if self._normalize_command(pattern) not in lower_cmd:
                continue

            if self._token_in_argv(cmd):
                reason = "token_transport_violation_env_only"
                evt = self._write_event(
                    event_type="dangerous_op_blocked",
                    pid=pid,
                    user=user,
                    command=cmd,
                    result="blocked",
                    details={"reason": reason, "pattern": pattern, "hint": "use OPENCLAW_SEC_AUTH env variable only"},
                )
                self._alert("dangerous operation blocked", evt)
                if self.security_policy.get("kill_on_violation", True):
                    self._maybe_kill(pid)
                return False

            token = self._extract_token(cmd)
            if not token:
                reason = "auth_required"
                evt = self._write_event(
                    event_type="dangerous_op_blocked",
                    pid=pid,
                    user=user,
                    command=cmd,
                    result="blocked",
                    details={"reason": reason, "pattern": pattern, "hint": "provide OPENCLAW_SEC_AUTH env token"},
                )
                self._alert("dangerous operation blocked", evt)
                if self.security_policy.get("kill_on_violation", True):
                    self._maybe_kill(pid)
                return False

            ok, reason = self._validate_auth_token(token)
            if not ok:
                evt = self._write_event(
                    event_type="dangerous_op_blocked",
                    pid=pid,
                    user=user,
                    command=cmd,
                    result="blocked",
                    details={"reason": reason, "pattern": pattern, "hint": "provide valid fresh OPENCLAW_SEC_AUTH token"},
                )
                self._alert("dangerous operation blocked", evt)
                if self.security_policy.get("kill_on_violation", True):
                    self._maybe_kill(pid)
                return False

            evt = self._write_event(
                event_type="dangerous_op_authorized",
                pid=pid,
                user=user,
                command=cmd,
                result="authorized",
                details={"pattern": pattern},
            )
            self._alert("dangerous operation authorized", evt)

        return True

    def _check_forbidden_actions(self, process_rows: List[Tuple[int, int, str]]) -> None:
        forbidden_actions = self.rules.get("forbidden_actions", [])
        for pid, uid, cmd in process_rows:
            if not self._is_target_process(cmd):
                continue
            for token in forbidden_actions:
                if token in cmd:
                    user = self._username(uid)
                    event = self._write_event(
                        event_type="forbidden_action",
                        pid=pid,
                        user=user,
                        command=cmd,
                        result="blocked_candidate",
                        details={"token": token},
                    )
                    self._alert("forbidden action observed", event)

    def _check_file_integrity(self) -> None:
        for path, old_hash in list(self.file_integrity.items()):
            new_hash = self._sha256_file(path)
            if new_hash != old_hash:
                event = self._write_event(
                    event_type="integrity_changed",
                    file_path=path,
                    result="alert",
                    details={"old_hash": old_hash, "new_hash": new_hash},
                )
                self._alert("integrity file changed", event)
                self.file_integrity[path] = new_hash

    def _audit_targets(self, process_rows: List[Tuple[int, int, str]]) -> None:
        current_targets: Set[int] = set()
        for pid, uid, cmd in process_rows:
            if not self._is_target_process(cmd):
                continue

            if not self._check_security_contract(pid, uid, cmd):
                continue

            current_targets.add(pid)
            user = self._username(uid)
            files, nets = self._collect_lsof_files_and_net(pid)

            if pid not in self.monitored:
                self.monitored[pid] = {
                    "cmd": cmd,
                    "user": user,
                    "files": set(files),
                    "nets": set(nets),
                }
                self._write_event(
                    event_type="process_start",
                    pid=pid,
                    user=user,
                    command=cmd,
                    result="observed",
                )
                continue

            snapshot = self.monitored[pid]
            new_files = files - snapshot["files"]
            new_nets = nets - snapshot["nets"]

            for fpath in sorted(new_files):
                evt = self._write_event(
                    event_type="file_access",
                    pid=pid,
                    user=user,
                    command=cmd,
                    file_path=fpath,
                    result="observed",
                )
                if self._matches_forbidden_file(fpath):
                    self._alert("forbidden file touched", evt)

            for net in sorted(new_nets):
                evt = self._write_event(
                    event_type="network_access",
                    pid=pid,
                    user=user,
                    command=cmd,
                    network=net,
                    result="observed",
                )
                if self.rules.get("alert_on_exfil", True):
                    self._alert("network egress observed", evt)

            snapshot["files"] = set(files)
            snapshot["nets"] = set(nets)
            snapshot["cmd"] = cmd

        ended = [pid for pid in self.monitored.keys() if pid not in current_targets]
        for pid in ended:
            data = self.monitored.pop(pid)
            self._write_event(
                event_type="process_exit",
                pid=pid,
                user=data.get("user", "unknown"),
                command=data.get("cmd", ""),
                result="observed",
            )

    def run(self) -> None:
        self._require_root()
        self._write_pid()
        self._write_event(
            event_type="cctv_start",
            pid=os.getpid(),
            user="root",
            result="ok",
            details={"security_md": str(SECURITY_MD_PATH)},
        )

        interval = int(self.rules.get("poll_interval_seconds", 2))
        while True:
            try:
                process_rows = self._list_processes()
                self._check_forbidden_actions(process_rows)
                self._check_file_integrity()
                self._audit_targets(process_rows)
                self._write_heartbeat()
            except Exception as exc:
                evt = self._write_event(
                    event_type="monitor_error",
                    pid=os.getpid(),
                    user="root",
                    result="error",
                    details={"error": str(exc)},
                )
                self._alert("monitor loop error", evt)
            time.sleep(interval)


if __name__ == "__main__":
    CCTVDaemon().run()
